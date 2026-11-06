"""Checks for guard.py - the brakes on the agents. Standard library only:

    py -3 agents/test_guard.py          (laptop)
    python3 agents/test_guard.py        (server)
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
os.environ["NEOS_GUARD"] = "0"
import guard  # noqa: E402
from guard import Guard, GuardBlocked  # noqa: E402

ok = fail = 0


def check(name, cond):
    global ok, fail
    ok, fail = ok + bool(cond), fail + (not cond)
    print(("  ok   " if cond else "  FAIL ") + name)


def blocked(fn, brake=None):
    try:
        fn()
    except GuardBlocked as e:
        return brake is None or e.brake == brake
    return False


g = Guard()
print("limits")
check("exact id wins", guard._pick({"*": 1, "broker": 2}, "broker") == 2)
check("prefix pattern fl-*", guard._pick({"*": 1, "fl-*": 3}, "fl-research") == 3)
check("falls back to *", guard._pick({"*": 1, "fl-*": 3}, "tickets") == 1)
check("GuardBlocked is a RuntimeError (LangGraph RetryPolicy will not retry it)", issubclass(GuardBlocked, RuntimeError))

print("before a run")
check("a normal start passes", not blocked(lambda: g.may_start("tickets", 2, 100_000, 500_000)))
check("run rate: 6 in an hour stops the 7th", blocked(lambda: g.may_start("tickets", 6, 0, 0), "run rate"))
check("the assistant may run often", not blocked(lambda: g.may_start("assistant", 30, 0, 0)))
check("daily budget per agent", blocked(lambda: g.may_start("tickets", 0, 1_500_000, 0), "daily budget"))
check("freelancers get a bigger day", not blocked(lambda: g.may_start("fl-research", 0, 2_000_000, 0)))
check("service-wide budget", blocked(lambda: g.may_start("memory", 0, 0, 8_000_000), "service budget"))

print("during a run")
check("under the token cap", not blocked(lambda: g.check_tokens("security", 149_000)))
check("over the token cap stops it", blocked(lambda: g.check_tokens("security", 151_000), "run token cap"))
check("a freelance research job has room for its ~300k", not blocked(lambda: g.check_tokens("fl-research", 400_000)))
c = {}
check("4 identical lines are not a loop", not blocked(lambda: [g.loop_check("x", c, "check", "rejected: too long") for _ in range(4)]))
check("the 5th identical line is", blocked(lambda: g.loop_check("x", c, "check", "rejected: too long"), "loop detector"))
c = {}
check("'done' never counts (fan-out nodes all say it)", not blocked(lambda: [g.loop_check("x", c, "investigate", "done") for _ in range(20)]))
check("different lines never count", not blocked(lambda: [g.loop_check("x", c, "draft", "draft %d" % i) for i in range(20)]))

print("outbound gate")
g = Guard()
t = 1_000_000.0
check("first alert goes", g.outbound("tickets", "/api/desk/alert", {"key": "a", "body": "x"}, now=t) is True)
check("identical alert 5 min later is dropped", g.outbound("tickets", "/api/desk/alert", {"key": "a", "body": "x"}, now=t + 300) is False)
check("identical alert after the window goes", g.outbound("tickets", "/api/desk/alert", {"key": "a", "body": "x"}, now=t + 1000) is True)
g = Guard()
sent = sum(1 for i in range(12) if g.outbound("net", "/api/desk/alert", {"n": i}, now=t + i))
check("12 different alerts in an hour go", sent == 12)
check("the 13th is held (the 80-emails-in-10-minutes story)", blocked(lambda: g.outbound("net", "/api/desk/alert", {"n": 99}, now=t + 20), "outbound cap"))
check("an hour later it may send again", g.outbound("net", "/api/desk/alert", {"n": 100}, now=t + 3700) is True)
g = Guard()
check("device blocks: 3 an hour", [g.outbound("security", "/api/security/device", {"ip": i}, now=t) for i in range(3)] == [True] * 3
      and blocked(lambda: g.outbound("security", "/api/security/device", {"ip": 9}, now=t)))
check("status reports blocks", g.status()["blocks"][0]["brake"] == "outbound cap")

print("config file")
d = tempfile.mkdtemp()
p = os.path.join(d, "guard.json")
Guard(p)
check("defaults written on first start", json.load(open(p))["run_tokens"]["*"] == 150_000)
json.dump({"run_tokens": {"tickets": 500_000}, "loop_repeats": 9}, open(p, "w"))
g = Guard(p)
check("an override is merged, the rest kept", g.limit("run_tokens", "tickets") == 500_000 and g.limit("run_tokens", "memory") == 150_000)
check("scalar override", g.cfg["loop_repeats"] == 9)
open(p, "w").write("{broken")
check("a broken file falls back to the defaults", Guard(p).limit("run_tokens", "memory") == 150_000)

print("run context")
check("the service itself is nobody", guard.current() == (None, None))
guard.set_run("tickets", "r1")
check("a run knows who it is", guard.current() == ("tickets", "r1"))

print("\n%d passed, %d failed" % (ok, fail))
sys.exit(1 if fail else 0)
