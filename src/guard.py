"""Guardrails for the N.E.O.S. agents - the brakes every autonomous loop needs.

The famous LangChain disasters all have the same shape: an agent with no cap
on how often it runs, how much it spends, or how often it may act on the
outside world. A too-strict checker keeps sending work back (the "infinite
meeting"), a retry loop hammers a paid API over a weekend, or an outreach
agent fires 80 near-identical emails in ten minutes. None of that can happen
here, because every run passes through these checks - in code, not prompts:

  * a TOKEN CAP per run      - a run that reads or argues past it is stopped;
  * a DAILY TOKEN BUDGET     - per agent, and one for the whole service;
  * a RUN RATE per hour      - a scheduler or self-kick loop cannot spin;
  * a LOOP DETECTOR          - the same step saying the same thing over and
                               over is a stuck loop, not work;
  * an OUTBOUND GATE         - every write an agent makes (a Desk alert, a
                               ticket note, a block) is capped per hour, and an
                               identical write inside the quiet window is
                               dropped, so nothing ever spams Jean or the Desk.

Blocking is always safe: the run fails with a clear reason, one Desk alert
says which brake held, and nothing half-done is sent. Limits live in
/var/lib/neos-agents/guard.json (created with the defaults below) so Jean can
loosen one without a code change.

Pure standard library, so the rules are testable anywhere (test_guard.py).
"""
import contextvars
import hashlib
import json
import os
import threading
import time

DEFAULTS = {
    # Measured 2026-09-30: the heaviest run so far was a Ticket Worker pass at
    # 48k tokens, a heavy day 179k. A freelance research job reads ~300k.
    "run_tokens": {"*": 150_000, "broker": 250_000, "fl-*": 800_000, "repurpose": 250_000, "scout": 400_000},
    "day_tokens": {"*": 1_500_000, "fl-*": 3_000_000},
    "service_day_tokens": 8_000_000,
    # inbox: the Inbox Manager checks every 2 minutes but only starts when mail is waiting
    "runs_per_hour": {"*": 6, "assistant": 60, "broker": 12, "inbox": 30},
    # the same (step, line) this many times in one run = stuck in a loop
    "loop_repeats": 5,
    # outbound writes an agent run may make per hour, by hub path
    "writes_per_hour": {"/api/desk/alert": 12, "/api/support/work": 30, "/api/security/incident": 12,
                        "/api/security/device": 3, "/api/cdesk/ai": 60, "*": 20},
    # an identical write (same path + same body) inside this window is dropped
    "dedupe_s": 900,
}


class GuardBlocked(RuntimeError):
    """A brake held. RuntimeError on purpose: LangGraph's RetryPolicy does not retry it."""

    def __init__(self, brake, text):
        super().__init__(text)
        self.brake = brake


def _pick(table, aid):
    """Per-agent value: exact id, then a prefix pattern like 'fl-*', then '*'."""
    if not isinstance(table, dict):
        return table
    if aid in table:
        return table[aid]
    for k, v in table.items():
        if k.endswith("*") and k != "*" and aid.startswith(k[:-1]):
            return v
    return table.get("*")


class Guard:
    def __init__(self, path=None):
        self.path = path
        self.lock = threading.RLock()
        self.cfg = json.loads(json.dumps(DEFAULTS))
        self._writes = {}          # path -> [times] (agent-run writes only)
        self._seen = {}            # hash of path+body -> time
        self.blocks = []           # recent blocks, newest last, for the monitor
        self.load()

    # ------------------------------------------------------------ config
    def load(self):
        if not self.path:
            return
        try:
            with open(self.path) as f:
                user = json.load(f)
            for k, v in user.items():
                if isinstance(v, dict) and isinstance(self.cfg.get(k), dict):
                    self.cfg[k].update(v)
                elif k in self.cfg:
                    self.cfg[k] = v
        except FileNotFoundError:
            try:
                with open(self.path, "w") as f:
                    json.dump(DEFAULTS, f, indent=2)
            except OSError:
                pass
        except (OSError, ValueError) as e:
            print("guard: %s unreadable (%s) - using the defaults" % (self.path, e), flush=True)

    def limit(self, key, aid=""):
        return _pick(self.cfg.get(key), aid)

    def _block(self, brake, aid, text):
        with self.lock:
            self.blocks.append({"at": time.time(), "brake": brake, "agent": aid, "text": text})
            del self.blocks[:-50]
        return GuardBlocked(brake, text)

    # ------------------------------------------------------------ before a run
    def may_start(self, aid, runs_last_hour, agent_tokens_24h, service_tokens_24h):
        """Raise GuardBlocked if starting another run of `aid` now would break a limit."""
        rate = self.limit("runs_per_hour", aid)
        if rate is not None and runs_last_hour >= rate:
            raise self._block("run rate", aid, "%s already ran %d times in the last hour (limit %d) - "
                              "a loop is starting runs faster than any real need" % (aid, runs_last_hour, rate))
        day = self.limit("day_tokens", aid)
        if day is not None and agent_tokens_24h >= day:
            raise self._block("daily budget", aid, "%s used %s tokens in 24 h (budget %s)" % (
                aid, f"{agent_tokens_24h:,}", f"{day:,}"))
        svc = self.cfg.get("service_day_tokens")
        if svc and service_tokens_24h >= svc:
            raise self._block("service budget", aid, "all agents together used %s tokens in 24 h (budget %s)" % (
                f"{service_tokens_24h:,}", f"{svc:,}"))

    # ------------------------------------------------------------ during a run
    def check_tokens(self, aid, run_tokens):
        cap = self.limit("run_tokens", aid)
        if cap is not None and run_tokens > cap:
            raise self._block("run token cap", aid, "this run used %s tokens, over its cap of %s - stopped so a "
                              "runaway loop cannot keep spending" % (f"{run_tokens:,}", f"{cap:,}"))

    def loop_check(self, aid, counts, node, line):
        """counts: a dict the caller keeps per run. Raise when one step keeps repeating itself."""
        if line in ("done", "") or node in ("usage", "start", "approve"):
            return
        k = (node, line)
        counts[k] = counts.get(k, 0) + 1
        n = self.cfg.get("loop_repeats") or 0
        if n and counts[k] >= n:
            raise self._block("loop detector", aid, "step '%s' said the same thing %d times: %s" % (
                node, counts[k], line[:160]))

    # ------------------------------------------------------------ outbound
    def outbound(self, aid, path, body, now=None):
        """Called before an agent run writes to the hub. Returns False for a duplicate
        to drop quietly; raises GuardBlocked when the hourly cap is reached."""
        now = now or time.time()
        with self.lock:
            win = self.cfg.get("dedupe_s") or 0
            h = hashlib.sha256((path + "\n" + json.dumps(body, sort_keys=True, default=str)).encode()).hexdigest()
            for k in [k for k, t in self._seen.items() if now - t > max(win, 3600)]:
                del self._seen[k]
            if win and now - self._seen.get(h, -1e12) < win:
                return False
            ts = [t for t in self._writes.get(path, []) if now - t < 3600]
            cap = _pick(self.cfg.get("writes_per_hour"), path)
            if cap is not None and len(ts) >= cap:
                self._writes[path] = ts
                raise self._block("outbound cap", aid, "%d writes to %s in the last hour (limit %d) - held back "
                                  "so the agents cannot flood the Desk" % (len(ts), path, cap))
            ts.append(now)
            self._writes[path] = ts
            self._seen[h] = now
            return True

    def status(self):
        now = time.time()
        with self.lock:
            return {"limits": self.cfg,
                    "writes_last_hour": {p: sum(1 for t in ts if now - t < 3600) for p, ts in self._writes.items()},
                    "blocks": list(reversed(self.blocks[-20:]))}


# The run this code is working for, so hub writes know whose they are. A
# ContextVar, not a thread-local: LangGraph runs parallel (Send) branches in
# pool threads and copies the context into them, so a fan-out keeps its owner.
_ctx = contextvars.ContextVar("neos_agent_run", default=(None, None))


def set_run(aid, run):
    _ctx.set((aid, run))


def current():
    """(agent id, run id) of the agent run being worked, or (None, None) for the service itself."""
    return _ctx.get()


GUARD = Guard(os.path.join(os.environ.get("NEOS_AGENTS_DATA", "/var/lib/neos-agents"), "guard.json")
              if os.environ.get("NEOS_GUARD", "1") != "0" else None)
