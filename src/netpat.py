"""N.E.O.S. - network PATTERNS, and the investigation they trigger.

netmon answers "is it up right now". That is the question a dashboard asks, and
it is not the question that gets a fault fixed. Nobody at an ISP has ever acted
on "the internet was down at 20:14"; they act on "it drops three times a night,
always between 19:00 and 21:30, and the loss starts at your second hop". This
module is the difference between those two sentences.

Two halves, and they are deliberately separate:

  ANALYSIS   pure functions over the history netmon already keeps - the event
             log and the hourly rollups. No probes, no network, no clock other
             than the one passed in, so it is testable and cheap enough to run
             every fifteen minutes. It finds four shapes:

               flap-storm    N up/down episodes inside a day
               loss-window   loss that recurs at the SAME hour on N days
               flap-window   flapping that recurs at the same hour
               latency-drift the last day is measurably slower than the week
               loss-trend    sustained loss over a day, at any hour

  INVESTIGATION  the expensive half. A traceroute, then a simultaneous ping
             burst at every hop, a gateway-versus-WAN comparison, the
             throughput measured during the bad window, and a speed test. It
             produces a verdict with a named hop and a paragraph that can be
             pasted into a ticket.

WHY IT RUNS ON THE MONITORING NODE. Timing is the whole point. A traceroute at
10:00 proves nothing about a fault that only exists at 20:00, so a time-of-day
finding waits and investigates INSIDE its own window - which only the machine
holding the probes can do. The hub reads the results afterwards and does the
talking (autopilot's `net-patterns` job): the node measures, the hub notifies.
That split is the same one the RAM guardian uses and for the same reason.

THREE THINGS THIS REFUSES TO DO, because each of them is a way to be confidently
wrong at an ISP:

  1. Blame a hop for its own ICMP rate limiting. A middle router that shows 40%
     loss while every hop AFTER it is clean is not dropping traffic - it is
     deprioritising the pings addressed to itself. Real path loss persists to
     the far end, so `_first_bad_hop` searches backwards from the target and
     only accepts a hop whose loss every later hop shares.
  2. Call a full line a broken one. If the bad window is also the window where
     the link sits at 80% of the subscribed rate, the finding is "the line is
     full at 20:00", not "the line is faulty at 20:00" - and the recommendation
     says so instead of opening a ticket that will be closed in one reply.
  3. Investigate a sensor that is simply down. A device that has been offline
     for two days has no pattern; it has an outage, and the panel is already
     red about it.

Stdlib only, like everything else in this folder.
"""

import concurrent.futures
import ipaddress
import time
import uuid

# --------------------------------------------------------------- settings
#
# Every one of these is a threshold somebody will want to argue with, which is
# exactly why none of them is buried in the code. The shipped values are tuned
# for a home fibre line watched by 30s ICMP sensors; the comments say what each
# one is protecting against, so tuning one does not silently break another.
DEFAULTS = {
    "enabled": True,
    "analyse_minutes": 15,      # how often the shapes below are re-derived
    "window_days": 7,           # how far back "normal" is measured from
    "min_probes_per_hour": 30,  # an hour with fewer probes is a gap, not data

    # -- flapping ---------------------------------------------------------
    # Jean's ask: three flaps in a day is a pattern, not bad luck.
    "flaps_per_day": 3,
    # A real WAN drop takes every Internet sensor down within seconds of each
    # other. Without clustering, one outage reads as four and every line trips
    # the flap threshold on its first bad minute.
    "episode_seconds": 90,

    # -- time of day ------------------------------------------------------
    "hour_loss_pct": 4.0,       # an hour this lossy is a candidate
    "hour_loss_ratio": 3.0,     # ...and must be this much worse than baseline
    "recur_days": 3,            # on this many separate days before it counts
    # The absolute floor was hiding real faults on a GOOD line. Measured here
    # 2026-09-04: both DNS sensors sit at 0.08% loss over 30 days but 0.27% at
    # 19:00-20:00 - a 3.4x elevation, every evening, on 1.2 million probes.
    # That is unmistakably a pattern and unmistakably not worth waking anyone
    # for, and with only one threshold it had to be one or the other. So a
    # window between `hour_loss_pct_min` and `hour_loss_pct` that is also
    # `hour_loss_ratio` times its own baseline is reported at INFO: visible in
    # the panel, never pushed, never investigated, never sent to an ISP.
    "hour_loss_pct_min": 0.15,
    # ...and it must be a real count, not a rounding artefact. 0.15% of a 30s
    # sensor's 120 probes an hour is 0.18 of a packet; three actual lost
    # probes is the smallest thing worth calling evidence.
    "min_lost_per_hour": 3,
    # An info finding costs nothing - no push, no traceroute, no ticket - so it
    # can afford to be reached a day sooner than one that does. Real case from
    # this line: 19:00-21:00 on 1 and 2 September lost 0.4-1.2% two evenings
    # running, which is exactly the shape of something starting, and under a
    # flat 3-day rule it would have gone unmentioned until it had happened a
    # third time. Warn and critical still require the full `recur_days`.
    "recur_days_info": 2,
    # Recurrence is a RATE, not a count. Two bad evenings is a pattern in a
    # seven-day window and noise in a thirty-day one, and a bare count cannot
    # tell those apart - it reported "lossier EVERY evening" off two days out
    # of thirty. A window must misbehave on at least this fraction of the days
    # it was actually watched.
    "recur_fraction": 0.25,
    # A "window" wider than this is not a window. A line that loses packets
    # around the clock flags every hour as hot, which leaves the baseline
    # computed from no hours at all, which makes the ratio infinite - and the
    # finding comes out as "loses packets every night, 00:00-00:00, 200x
    # worse than normal". It is a loss-trend, and the trend detector already
    # reports it correctly.
    "max_window_hours": 8,

    # -- sustained --------------------------------------------------------
    "sustained_loss_pct": 2.0,  # loss over a whole day, at no particular hour
    "latency_ratio": 1.8,       # last 24h average vs the week's
    "latency_min_ms": 15.0,     # ...and this many ms worse, so a 2ms LAN
                                # sensor doubling to 4ms is not an incident

    # -- what gets investigated -------------------------------------------
    "investigate": True,
    "investigate_severity": "warn",   # "warn" or "critical"
    "investigate_cooldown_h": 6,      # per finding key
    "max_investigations_per_day": 6,  # a hard ceiling on the expensive half
    # A time-of-day finding is investigated INSIDE its window, because that is
    # the only time the evidence exists. Off means "go now, whenever now is".
    "in_window_only": True,
    "keep_investigations": 40,

    # -- how the investigation probes -------------------------------------
    "burst_pings": 60,          # to the target and the gateway
    "burst_interval_ms": 200,   # 60 x 200ms = 12s per burst
    "hop_burst_pings": 40,      # per hop, run in parallel across hops
    "hop_limit": 12,            # hops to burst; beyond this it is transit
    "max_hops": 20,             # how far the traceroute itself walks
    "hop_loss_pct": 3.0,        # loss at a hop worth naming
    "access_hops": 4,           # hops 1..N are "your ISP's access network"
    "saturation_pct": 70,       # of the SUBSCRIBED rate = the line is full
    "speedtest": True,          # run one as part of an investigation
}

SEV_RANK = {"info": 0, "warn": 1, "critical": 2}


# ================================================================ helpers

def _cfg(cfg):
    out = dict(DEFAULTS)
    out.update(cfg or {})
    return out


def _daykey(lt):
    return "%04d-%02d-%02d" % (lt.tm_year, lt.tm_mon, lt.tm_mday)


def _hhmm(hour):
    return "%02d:00" % (hour % 24)


def _pct(part, whole):
    # Three decimals, not two: a good line's whole story happens below 0.1%,
    # and rounding it away is how "0.27% every evening" became "0.0%".
    return round(100.0 * part / whole, 3) if whole else 0.0


def _lpct(v):
    """A loss percentage printed at a precision that does not erase it.

    "%.1f%%" turns 0.27 into "0.3%" and 0.04 into "0.0%" - and "0.0% loss"
    inside a sentence explaining that this happens every evening reads as a
    broken monitor, not as a small number. Precision follows the magnitude.
    """
    if v is None:
        return "?"
    if v >= 10:
        return "%.0f%%" % v
    if v >= 1:
        return "%.1f%%" % v
    if v >= 0.1:
        return "%.2f%%" % v
    return "%.3f%%" % v


def _is_lan(ip):
    """True for an address on the house network (RFC 1918 / link-local)."""
    try:
        a = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return False
    return bool(a.is_private and not a.is_loopback)


def _span_text(hours):
    """[19, 20, 21] -> '19:00-22:00'. The end is the hour AFTER the last hot
    one, because an hourly bucket labelled 21:00 covers 21:00 to 22:00 and
    printing '19:00-21:00' would understate the window by an hour."""
    return "%s-%s" % (_hhmm(hours[0]), _hhmm(hours[-1] + 1))


def _merge_hours(hours):
    """Consecutive hours-of-day into windows, wrapping across midnight.

    Kept as explicit windows rather than a bare list because everything
    downstream - the title, the 'is it happening now' test, the decision to
    wait before investigating - is about a span of the evening, not about
    three unrelated hours that happen to be adjacent.
    """
    hours = sorted(set(int(h) % 24 for h in hours))
    if not hours:
        return []
    runs, cur = [], [hours[0]]
    for h in hours[1:]:
        if h == cur[-1] + 1:
            cur.append(h)
        else:
            runs.append(cur)
            cur = [h]
    runs.append(cur)
    # 23 and 0 are adjacent on a clock even though they are not adjacent as
    # integers - without this, a 22:00-01:00 fault reports as two findings.
    if len(runs) > 1 and runs[0][0] == 0 and runs[-1][-1] == 23:
        runs[0] = runs[-1] + runs[0]
        runs.pop()
    return runs


def _in_window(hours, now, lead_s=0):
    """Is `now` inside (or `lead_s` before) one of these hours-of-day?"""
    lt = time.localtime(now + lead_s)
    return (lt.tm_hour % 24) in set(int(h) % 24 for h in hours)


def _next_window_start(hours, now):
    """The next local timestamp at which this window opens. Used so the UI can
    say "investigates at 19:00" instead of leaving a finding looking ignored."""
    if not hours:
        return None
    start = int(hours[0]) % 24
    lt = time.localtime(now)
    for day in (0, 1):
        t = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + day,
                         start, 0, 0, 0, 0, -1))
        if t > now:
            return t
    return None


def _hour_rows(t, now, days, min_probes):
    """{hour_of_day: {day: (probes, lost)}} from a target's hourly rollups.

    Local hours, deliberately: "the evening" is a local-time idea and a UTC
    bucketing would smear the window by two hours here and by more elsewhere.

    Hours in which NOTHING answered are left out entirely. That is the thing
    being off, not the path losing packets, and including them is how a
    thirteen-hour outage on one August afternoon turned into a permanent 2%
    "packet loss" figure on a link that never dropped a packet. An outage that
    keeps to a clock is a real pattern and a serious one - it is just the
    flap-window detector's, and it reads the event log rather than this table.
    """
    floor = now - days * 86400
    table = {}
    for b in (t.get("hourly") or []):
        h = b.get("h") or 0
        if h < floor:
            continue
        n, lost = b.get("n") or 0, b.get("lost") or 0
        if n < min_probes:
            continue                      # a partial hour is not evidence
        if lost >= n:
            continue                      # down, not lossy - see the docstring
        lt = time.localtime(h)
        table.setdefault(lt.tm_hour, {})[_daykey(lt)] = (n, lost)
    return table


def _avg_rtt(buckets):
    n = sum((b.get("n") or 0) - (b.get("lost") or 0) for b in buckets)
    s = sum(b.get("sum") or 0.0 for b in buckets)
    return round(s / n, 2) if n else None


def _finding(kind, t, **kw):
    """Every finding carries the same spine, so the UI, the notifier and the
    investigation ledger can all key off it without special cases."""
    f = {"kind": kind, "id": t.get("id"), "label": t.get("label") or t.get("id"),
         "group": t.get("group") or "", "target": t.get("target") or "",
         "type": t.get("type") or "", "scope": "sensor",
         "severity": "warn", "confidence": 0.5, "investigate": True,
         "hours": [], "evidence": {}}
    f.update(kw)
    return f


# ================================================================ analysis

def _down_spans(events, ids, now, span_s):
    """[start, end] spans in which ANY of the sensors was down, merged. An UP
    event's after_s is how long the preceding DOWN state lasted, so each up
    event is one span ending at it. Merging is what makes a group scope count
    one WAN outage once: the DNS sensors notice it minutes after HTTPS does,
    and summing them reported 85 minutes as 5h26m (NEOS-214)."""
    spans = sorted([(e.get("at") or 0) - (e.get("after_s") or 0), e.get("at") or 0]
                   for e in events
                   if e.get("id") in ids and e.get("kind") == "up"
                   and now - (e.get("at") or 0) <= span_s)
    out = []
    for a, b in spans:
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def _flap_episodes(events, ids, now, span_s, episode_s):
    """Down transitions collapsed into episodes. Returns their timestamps.

    A down that lands while another sensor of the scope has been down for
    longer than episode_s is the same outage, not a new drop."""
    downs = sorted(e.get("at") or 0 for e in events
                   if e.get("id") in ids and e.get("kind") == "down"
                   and now - (e.get("at") or 0) <= span_s)
    spans = _down_spans(events, ids, now, span_s)
    eps, last = [], None
    for at in downs:
        ongoing = any(a < at - episode_s and at <= b + episode_s for a, b in spans)
        if (last is None or at - last > episode_s) and not ongoing:
            eps.append(at)
        last = at
    return eps


def _downtime(events, ids, now, span_s):
    """Seconds in the span during which any of the sensors was down."""
    return round(sum(b - a for a, b in _down_spans(events, ids, now, span_s)))


def _scopes(targets):
    """Sensors, plus one aggregate scope per group that has more than one.

    A group scope exists so that one WAN drop, which trips four Internet
    sensors at once, is reported as one flapping line rather than as four
    flapping sensors. When a group scope fires, its members are suppressed.
    """
    out = [("sensor", t.get("id"), [t], t) for t in targets if t.get("id")]
    groups = {}
    for t in targets:
        g = t.get("group") or ""
        if g:
            groups.setdefault(g, []).append(t)
    for g, members in groups.items():
        if len(members) > 1:
            head = {"id": "group:" + g, "label": g, "group": g,
                    "type": "group",
                    "target": (members[0].get("target") or "")}
            out.append(("group", "group:" + g, members, head))
    return out


def _worth_analysing(t, now):
    """Skip sensors with nothing a pattern could be found in.

    A sensor that has been solidly down all week is an outage the panel is
    already red about, and one created this morning has no baseline to be
    abnormal against. Both would otherwise generate confident nonsense.
    """
    hours = [b for b in (t.get("hourly") or []) if (b.get("h") or 0) >= now - 86400 * 2]
    n = sum((b.get("n") or 0) for b in hours)
    lost = sum((b.get("lost") or 0) for b in hours)
    if n < 60:
        return False                      # too new, or barely probed
    if lost >= n:
        return False                      # answered nothing at all: it is down
    return True


def analyse(targets, events, cfg=None, now=None):
    """Every pattern currently visible in the history. Pure; no probes.

    `targets` are netmon's raw target records (they carry `hourly`), `events`
    its transition log. Returns findings newest-evidence-first, each with a
    stable `key` so a finding seen at 15:00 and again at 15:15 is the same
    finding rather than a second alert.
    """
    cfg = _cfg(cfg)
    now = now or time.time()
    days = max(2, int(cfg["window_days"]))
    minp = int(cfg["min_probes_per_hour"])
    out = []

    live = [t for t in targets if _worth_analysing(t, now)]
    fired_groups = set()

    # -- flapping, per scope, group scopes first so they can win -----------
    for kind, sid, members, head in sorted(_scopes(live), key=lambda s: s[0]):
        ids = {m.get("id") for m in members}
        eps = _flap_episodes(events, ids, now, 86400, cfg["episode_seconds"])
        # A scope is claimed by its group as soon as the group has anything to
        # say about it, whether that is a storm or a window - otherwise one WAN
        # fault is reported once as the line and then again as each sensor.
        if kind == "sensor" and (head.get("group") or "") in fired_groups:
            continue
        if len(eps) >= int(cfg["flaps_per_day"]):
            if kind == "group":
                fired_groups.add(head.get("group") or "")
            down_s = _downtime(events, ids, now, 86400)
            sev = "critical" if len(eps) >= int(cfg["flaps_per_day"]) * 2 else "warn"
            out.append(_finding(
                "flap-storm", head, scope=kind, severity=sev,
                key="flap-storm/%s" % sid,
                confidence=min(1.0, 0.5 + 0.1 * len(eps)),
                title="%s flapped %d times today" % (head.get("label"), len(eps)),
                detail=("%d separate drops in the last 24 hours, %s of downtime. "
                        "Threshold is %d a day."
                        % (len(eps), _dur(down_s), int(cfg["flaps_per_day"]))),
                evidence={"episodes": [round(e) for e in eps],
                          "downtime_s": down_s,
                          "sensors": sorted(ids)}))

        # Do the drops land at the same time every day? Same events, a
        # different question - and deliberately NOT behind the storm threshold
        # above. One drop every evening for a week is seven flaps and never
        # three in a day, so gating this on the daily count would have made the
        # engine blind to the tidiest, most diagnosable fault there is.
        hours = {}
        for e in events:
            if e.get("id") in ids and e.get("kind") == "down" \
                    and now - (e.get("at") or 0) <= days * 86400:
                lt = time.localtime(e["at"])
                hours.setdefault(lt.tm_hour, set()).add(_daykey(lt))
        hot = [h for h, ds in hours.items() if len(ds) >= int(cfg["recur_days"])]
        if hot and kind == "group":
            fired_groups.add(head.get("group") or "")
        for run in _merge_hours(hot):
            ds = sorted(set().union(*[hours[h] for h in run]))
            out.append(_finding(
                "flap-window", head, scope=kind, severity="critical",
                key="flap-window/%s/%d" % (sid, run[0]),
                hours=run, confidence=min(1.0, 0.55 + 0.1 * len(ds)),
                title="%s drops at the same time most days (%s)"
                      % (head.get("label"), _span_text(run)),
                detail=("Drops recorded in the %s window on %d of the last %d "
                        "days (%s). A fault on a clock is an equipment or "
                        "capacity fault, not weather."
                        % (_span_text(run), len(ds), days, ", ".join(ds[-4:]))),
                evidence={"days": ds, "hours": run, "sensors": sorted(ids)}))

    # -- loss with an hour of day, per sensor ------------------------------
    for t in live:
        table = _hour_rows(t, now, days, minp)
        if len(table) < 6:
            continue                       # not enough of a day to compare
        loss_by_hour, hot = {}, []
        for hour, rows in table.items():
            n = sum(v[0] for v in rows.values())
            lost = sum(v[1] for v in rows.values())
            loss_by_hour[hour] = _pct(lost, n)
            # The LOW floor decides what is a candidate; severity is decided
            # further down once the window's real depth is known. Catching it
            # here and grading it later is what lets one detector cover both
            # "8% every evening" and "0.27% every evening", which are the same
            # shape and very different news.
            bad_days = [d for d, (dn, dl) in rows.items()
                        if _pct(dl, dn) >= cfg["hour_loss_pct_min"]
                        and dl >= int(cfg["min_lost_per_hour"])]
            # The LOWER bar admits an hour as a candidate; the grading block
            # below re-checks the full `recur_days` before it may exceed info.
            if len(bad_days) >= min(int(cfg["recur_days"]), int(cfg["recur_days_info"])):
                hot.append((hour, bad_days))
        if not hot:
            continue
        hot_hours = {h for h, _ in hot}
        if len(hot_hours) > int(cfg["max_window_hours"]):
            continue                       # all day: a trend, not an hour
        # Baseline excludes the suspect hours: comparing an hour against an
        # average that includes itself is how a 24/7 problem gets reported as
        # an evening one.
        base_n = base_lost = 0
        for hour, rows in table.items():
            if hour in hot_hours:
                continue
            base_n += sum(v[0] for v in rows.values())
            base_lost += sum(v[1] for v in rows.values())
        if base_n < minp:
            continue                       # nothing quiet enough to be normal
        baseline = _pct(base_lost, base_n)

        def _on_days(hour, day_keys):
            """That hour's loss across the days it actually misbehaved.

            The candidate filter and the grading below must use the SAME
            number or they disagree: an hour averaging 0.27% across all 22
            days but 0.9% across the two it went wrong is one fact, and
            testing the diluted figure against a threshold meant for the
            concentrated one silently drops every intermittent evening.
            """
            rs = table.get(hour) or {}
            n = sum(rs[d][0] for d in day_keys if d in rs)
            lost = sum(rs[d][1] for d in day_keys if d in rs)
            return _pct(lost, n)

        # Worse than this link's own quiet hours by the required multiple, and
        # deep enough to be worth a sentence at all. The old `max(baseline,
        # 0.2)` hard floor pre-dates the info tier and made it unreachable:
        # 0.2 x 3 = 0.6%, which is far above anything a healthy line does in
        # an evening, so every sub-threshold pattern was discarded before it
        # could be graded.
        floor = max(baseline * cfg["hour_loss_ratio"], cfg["hour_loss_pct_min"])
        keep = [(h, d) for h, d in hot if _on_days(h, d) >= floor]
        if not keep:
            continue
        days_by_hour = dict(keep)
        for run in _merge_hours([h for h, _ in keep]):
            ds = sorted(set().union(*[set(days_by_hour[h]) for h in run]))
            # Two different numbers, and conflating them is how a report gets
            # argued down. `on_bad_days` is what the fault looks like WHEN IT
            # HAPPENS - the number to quote - while the all-days average is
            # diluted by every evening that was fine, and reads as milder than
            # the thing anybody actually experienced.
            bn = sum(table[h][d][0] for h in run for d in ds if d in table[h])
            bl = sum(table[h][d][1] for h in run for d in ds if d in table[h])
            on_bad = _pct(bl, bn)
            all_days = round(max(loss_by_hour[h] for h in run), 2)
            # A baseline that rounds to zero makes any ratio meaningless -
            # "91.8x worse than 0.0%" is arithmetic, not evidence.
            # Two different jobs, and conflating them made a clean line
            # undetectable. `ratio_for_decision` divides by a FLOOR, because a
            # baseline of 0.014% is not "unmeasurable" - it is excellent, and
            # an evening twenty times worse than excellent is exactly the
            # thing worth noticing. Dividing by the raw baseline and then
            # bailing out when it was too small to divide by meant the better
            # the link, the less this could see: 0.87% against 0.014% was
            # discarded outright.
            ratio_for_decision = on_bad / max(baseline, 0.01)
            measurable = baseline >= 0.005
            ratio = round(on_bad / baseline, 1) if measurable else None
            # Graded on the DEPTH of the loss, not on the fact of it. Below
            # the absolute threshold a window is only news at all if it is
            # clearly worse than the same link's own quiet hours - otherwise
            # it is noise, and reporting it would undo the point of having a
            # threshold in the first place.
            # How many separate days this hour was WATCHED, so recurrence can
            # be stated as a share of the days it could have happened on.
            seen_days = len(set().union(*[set((table.get(h) or {}).keys())
                                          for h in run])) or 1
            share = len(ds) / float(seen_days)
            enough = (len(ds) >= int(cfg["recur_days"])
                      and share >= cfg["recur_fraction"])
            enough_info = (len(ds) >= int(cfg["recur_days_info"])
                           and share >= cfg["recur_fraction"])
            if enough and on_bad >= cfg["hour_loss_pct"] * 3:
                sev, small = "critical", False
            elif enough and on_bad >= cfg["hour_loss_pct"]:
                sev, small = "warn", False
            elif enough_info and ratio_for_decision >= cfg["hour_loss_ratio"]:
                sev, small = "info", True
            else:
                continue
            # "every evening" is a claim about frequency and has to be earned.
            # Off two days in thirty it is simply false, and a false frequency
            # is the part of a report an ISP will use to dismiss the rest.
            when = ("every %s" % _daypart(run[0]) if share >= 0.6 else
                    "on %d of the last %d %ss" % (len(ds), seen_days, _daypart(run[0])))
            head = ("%s loses packets " + when + " (%s)" if not small else
                    "%s is slightly lossier " + when + " (%s)")
            out.append(_finding(
                "loss-window", t, hours=run,
                key="loss-window/%s/%d" % (t.get("id"), run[0]),
                severity=sev,
                # An info window is a note, not a job. Sending a traceroute
                # after 0.27% would burn the daily investigation budget on the
                # one finding that cannot support a conclusion.
                investigate=not small,
                confidence=min(1.0, 0.4 + 0.5 * share),
                title=head % (t.get("label"), _span_text(run)),
                detail=("%s loss in the %s window on the %d days it happened, "
                        "against %s the rest of the day. Seen on %d of the "
                        "%d days it was watched (%s).%s"
                        % (_lpct(on_bad), _span_text(run), len(ds),
                           ("%s - %sx worse" % (_lpct(baseline), ratio)) if measurable
                           else "no measurable loss",
                           len(ds), seen_days, ", ".join(ds[-4:]),
                           (" Too small to raise with anyone - recorded because "
                            "it is consistent, and because this is what it looks "
                            "like before it is not small." if small else ""))),
                evidence={"hours": run, "days": ds,
                          "window_loss_pct": on_bad,
                          "window_loss_all_days_pct": all_days,
                          "baseline_loss_pct": baseline, "ratio": ratio,
                          "probes_in_window": bn, "lost_in_window": bl,
                          "below_threshold": small,
                          "days_seen": seen_days,
                          "share": round(share, 3),
                          "loss_by_hour": {str(h): loss_by_hour[h]
                                           for h in sorted(loss_by_hour)}}))

    # -- sustained loss and latency drift, per sensor -----------------------
    for t in live:
        hours = t.get("hourly") or []
        recent = [b for b in hours if (b.get("h") or 0) >= now - 86400]
        older = [b for b in hours if now - 86400 * days <= (b.get("h") or 0) < now - 86400]
        rn = sum((b.get("n") or 0) for b in recent)
        rl = sum((b.get("lost") or 0) for b in recent)
        on = sum((b.get("n") or 0) for b in older)
        ol = sum((b.get("lost") or 0) for b in older)
        # A trend needs two things to compare. A sensor born this afternoon
        # (an auto-discovered guest device, say) has probes for "today" and
        # none for "before", and _pct(0, 0) is 0.0 - which reads as a spotless
        # week and turns the guest going home into "started losing 86% of
        # packets today", critical, mailed as urgent (NEOS-388, 2026-11-01).
        # No baseline, no trend: the sensor's own red state already says
        # it is down, and the Network tab retires it when the device stays
        # away. _worth_analysing cannot catch this - two hours of 30 s
        # probes already clears its 60-probe floor.
        if rn >= minp * 6 and on >= minp * 6:
            rloss, oloss = _pct(rl, rn), _pct(ol, on)
            if rloss >= cfg["sustained_loss_pct"]:
                # New, or simply always. The second case is the one that gets
                # missed: a line losing 10% every hour of every day is not
                # "worse than its baseline" - it IS its baseline - so a purely
                # comparative test would stay silent about the worst fault
                # here forever. It is reported, and worded so the difference
                # between "this started" and "this never stopped" is visible.
                worse = rloss >= max(oloss, 0.2) * 2
                out.append(_finding(
                    "loss-trend", t, key="loss-trend/%s" % t.get("id"),
                    severity="critical" if rloss >= cfg["sustained_loss_pct"] * 4 else "warn",
                    confidence=0.75 if worse else 0.65,
                    title=("%s is losing %.1f%% of packets today" if worse else
                           "%s has been losing %.1f%% of packets all week")
                          % (t.get("label"), rloss),
                    detail=(("%.1f%% loss over the last 24 hours against %.1f%% "
                             "across the previous %d days - this started "
                             "recently. Not tied to an hour."
                             % (rloss, oloss, days - 1)) if worse else
                            ("%.1f%% loss over the last 24 hours and %.1f%% "
                             "across the previous %d days. Steady, at every "
                             "hour, for as long as there is history - which is "
                             "why nothing has ever alerted on it."
                             % (rloss, oloss, days - 1))),
                    evidence={"loss_24h_pct": rloss, "loss_baseline_pct": oloss,
                              "probes_24h": rn, "new": worse}))
        ravg, oavg = _avg_rtt(recent), _avg_rtt(older)
        if ravg and oavg and rn >= minp * 6:
            if ravg >= oavg * cfg["latency_ratio"] and ravg - oavg >= cfg["latency_min_ms"]:
                out.append(_finding(
                    "latency-drift", t, key="latency-drift/%s" % t.get("id"),
                    severity="warn", confidence=0.6,
                    title="%s is %.0f%% slower than its normal"
                          % (t.get("label"), 100.0 * (ravg / oavg - 1)),
                    detail=("%.1f ms average today against %.1f ms over the "
                            "previous %d days. Latency climbing before loss "
                            "appears is the usual order of events."
                            % (ravg, oavg, days - 1)),
                    evidence={"avg_24h_ms": ravg, "avg_baseline_ms": oavg}))

    out = _dedupe_group(out)
    for f in out:
        f["at"] = now
        f["active_now"] = bool(f["hours"]) and _in_window(f["hours"], now)
        f["next_window"] = _next_window_start(f["hours"], now) if f["hours"] else None
    out.sort(key=lambda f: (-SEV_RANK.get(f["severity"], 0), -f["confidence"]))
    return out


def _dedupe_group(findings):
    """One fault, one finding, even when four sensors can see it.

    n8n is watched by four sensors - failed runs, stuck executions, quiet
    workflows and the API itself - and they all probe the same process on the
    same box. When it hiccups they produce four identical findings with
    identical numbers, which is four times the noise for one event and makes
    the panel look like a cascade. The Internet group does the same with its
    four anchors.

    Same group, same kind, same hours = one fault seen from several angles.
    The deepest one is kept and the others are named on it, because *which*
    sensor showed it worst is information and the fact that they all agreed is
    corroboration - neither is worth a row of its own.
    """
    best, extra = {}, {}
    passthrough = []
    for f in findings:
        group = f.get("group") or ""
        if not group or f.get("scope") == "group":
            passthrough.append(f)
            continue
        key = (group, f["kind"], tuple(f.get("hours") or ()))
        depth = (f.get("evidence") or {}).get("window_loss_pct") or 0
        cur = best.get(key)
        if cur is None or depth > (cur.get("evidence") or {}).get("window_loss_pct", 0):
            if cur is not None:
                extra.setdefault(key, []).append(cur)
            best[key] = f
        else:
            extra.setdefault(key, []).append(f)
    for key, f in best.items():
        others = [o.get("label") or o.get("id") for o in extra.get(key) or []]
        if others:
            f["also_seen_by"] = others
            f["detail"] = (f.get("detail") or "") + (
                " The same window shows on %s - one fault, %d sensors."
                % (", ".join(others[:3]), len(others) + 1))
    return passthrough + list(best.values())


def _daypart(hour):
    hour = int(hour) % 24
    if 5 <= hour < 12:
        return "morning"
    if 12 <= hour < 17:
        return "afternoon"
    if 17 <= hour < 22:
        return "evening"
    return "night"


def _dur(seconds):
    seconds = int(seconds or 0)
    if seconds < 60:
        return "%ds" % seconds
    if seconds < 3600:
        return "%dm%02ds" % (seconds // 60, seconds % 60)
    return "%dh%02dm" % (seconds // 3600, (seconds % 3600) // 60)


# ------------------------------------------------------------- the ledger

def merge_findings(previous, current, now=None):
    """Carry `first_seen` and the investigation history across a re-analysis.

    A finding is not an event: the same "it drops every evening" is true at
    19:05 and still true at 19:20, and treating each pass as new would mean an
    alert every fifteen minutes for one fault. Keyed merge, and anything that
    has stopped being detected is marked `cleared` rather than deleted, so
    "that fixed it" is visible instead of just quiet.
    """
    now = now or time.time()
    previous = previous or {}
    out, seen = {}, set()
    for f in current:
        key = f["key"]
        seen.add(key)
        old = previous.get(key) or {}
        merged = dict(old)
        merged.update(f)
        merged["first_seen"] = old.get("first_seen") or now
        merged["last_seen"] = now
        merged["cleared"] = False
        merged["seen_count"] = (old.get("seen_count") or 0) + 1
        merged["investigations"] = old.get("investigations") or []
        merged["last_investigated"] = old.get("last_investigated") or 0
        # An escalation is news even when the finding is not. The notifier
        # keys off this rather than diffing severities itself.
        merged["escalated"] = bool(
            old and SEV_RANK.get(f["severity"], 0) > SEV_RANK.get(old.get("severity"), 0))
        out[key] = merged
    for key, old in previous.items():
        if key in seen:
            continue
        # Kept for a day after it stops showing, then dropped. Long enough for
        # the morning digest to say it recovered, short enough not to accrete.
        if now - (old.get("last_seen") or 0) > 86400:
            continue
        old = dict(old)
        old["cleared"] = True
        old["cleared_at"] = old.get("cleared_at") or now
        out[key] = old
    return out


def due_for_investigation(findings, cfg=None, now=None, done_today=0):
    """Which findings should be investigated right now, best first.

    The timing rule is the one that matters: a finding with an hour window is
    only worth probing INSIDE that window, because the evidence does not exist
    outside it. Everything else can go immediately.
    """
    cfg = _cfg(cfg)
    now = now or time.time()
    if not cfg["investigate"] or not cfg["enabled"]:
        return []
    if done_today >= int(cfg["max_investigations_per_day"]):
        return []
    floor = SEV_RANK.get(cfg["investigate_severity"], 1)
    cool = float(cfg["investigate_cooldown_h"]) * 3600
    out = []
    for f in findings.values() if hasattr(findings, "values") else findings:
        if f.get("cleared") or not f.get("investigate"):
            continue
        if SEV_RANK.get(f.get("severity"), 0) < floor:
            continue
        if now - (f.get("last_investigated") or 0) < cool:
            continue
        if f.get("hours") and cfg["in_window_only"] and not _in_window(f["hours"], now):
            continue
        out.append(f)
    out.sort(key=lambda f: (-SEV_RANK.get(f.get("severity"), 0),
                            -(f.get("confidence") or 0)))
    return out


# ========================================================== investigation

class Investigator:
    """The expensive half: go and find out WHERE.

    Constructed with a `tools` mapping rather than importing netmon, so the
    analysis module never depends on the probe module and a test can hand it
    four lambdas. Required keys:

        traceroute(host, max_hops)        -> [{"hop", "ip", "rtt_ms"}]
        burst(ip, count, interval_ms)     -> {"sent","recv","loss_pct","avg_ms",...}
        gateway()                         -> "192.168.0.1"
        speedtest()                       -> {"down_mbps","up_mbps",...} or None
        bandwidth(hours)                  -> [[ts, rx_bytes, tx_bytes], ...]
        line()                            -> {"down_mbps","up_mbps",...}
        sensors()                         -> [{"id","label","state","group"}]
    """

    def __init__(self, tools, cfg=None, log=lambda m: None):
        self.tools = tools
        self.cfg = _cfg(cfg)
        self.log = log

    # -- entry -------------------------------------------------------------

    def run(self, finding, reason="pattern"):
        cfg = self.cfg
        t0 = time.time()
        host = self._host_for(finding)
        inv = {"id": uuid.uuid4().hex[:12], "at": t0, "reason": reason,
               "key": finding.get("key", ""), "kind": finding.get("kind", ""),
               "label": finding.get("label", ""), "target": host,
               # Kept so the report can be rebuilt later against the sensor it
               # was about, and so the ticket can carry its own evidence.
               "sensor_id": finding.get("id", ""),
               "finding": {k: finding.get(k) for k in
                           ("key", "kind", "title", "detail", "severity",
                            "hours", "evidence", "label", "group")},
               "hours": finding.get("hours") or [],
               "in_window": bool(finding.get("hours")) and _in_window(finding["hours"], t0),
               "trigger": {"title": finding.get("title"),
                           "detail": finding.get("detail"),
                           "severity": finding.get("severity"),
                           "evidence": finding.get("evidence") or {}},
               "steps": [], "error": ""}
        try:
            self._context(inv)
            self._evidence(inv, finding)
            self._path(inv, host)
            self._hops(inv)
            self._ends(inv, host)
            self._saturation(inv, finding)
            self._speed(inv)
        except Exception as e:                       # never take the loop down
            inv["error"] = "%s: %s" % (type(e).__name__, e)
            self.log("netpat: investigation of %s failed (%s)" % (inv["key"], inv["error"]))
        self._verdict(inv, finding)
        inv["took_s"] = round(time.time() - t0, 1)
        return inv

    def _host_for(self, finding):
        """What to trace to. A group finding has no single target, and the
        member sensors may be local; 8.8.8.8 is the honest stand-in for 'the
        path off this network' and is already one of the watched anchors."""
        target = (finding.get("target") or "").strip()
        if finding.get("scope") == "group" or not target:
            return "8.8.8.8"
        if "://" in target:                          # an http sensor's URL
            host = target.split("://", 1)[1].split("/", 1)[0]
            return host.split(":")[0]
        return target

    def _step(self, inv, name, detail, data=None):
        inv["steps"].append({"name": name, "detail": detail, "at": time.time()})
        if data is not None:
            inv[name] = data

    # -- the steps ---------------------------------------------------------

    def _context(self, inv):
        sensors = self.tools["sensors"]() or []
        down = [s for s in sensors if s.get("state") == "down"]
        warn = [s for s in sensors if s.get("state") == "warning"]
        inv["context"] = {
            "sensors_total": len(sensors),
            "down": [{"id": s.get("id"), "label": s.get("label"),
                      "group": s.get("group")} for s in down][:12],
            "warning": [{"id": s.get("id"), "label": s.get("label")} for s in warn][:12],
        }
        # Which sensors are unhappy at the moment of the probe is the cheapest
        # discriminator there is: everything down at once is the line; one
        # thing down is that thing.
        self._step(inv, "context",
                   "%d of %d sensors down, %d degraded, at the moment of probing"
                   % (len(down), len(sensors), len(warn)))

    def _evidence(self, inv, finding):
        """Snapshot the HISTORY the finding was made from, at the moment of
        probing.

        Without this the report is only the probe: "hop 2 lost 10% just now",
        which is a single reading and is exactly what an ISP dismisses. The
        loss-by-hour profile and the sensor's own history are what turn it
        into "and here are the thirty days that made us look". Captured rather
        than recomputed at render time so the document says what was true when
        the measurement was made, even if it is opened next month.
        """
        sid = finding.get("id") or ""
        get = self.tools.get("loss_profile")
        if sid and get:
            try:
                inv["profile"] = get(sid, 30)
            except Exception as e:                     # evidence is optional
                inv["profile_error"] = str(e)[:120]
        hist = self.tools.get("history")
        if sid and hist:
            try:
                inv["history"] = hist(sid, "month")
            except Exception as e:
                inv["history_error"] = str(e)[:120]
        prof = inv.get("profile") or {}
        self._step(inv, "evidence",
                   "history captured: %s lost of %s probes over %s days"
                   % (prof.get("lost", "?"), prof.get("n", "?"), prof.get("days", "?"))
                   if prof else "no history available for this scope")

    def _path(self, inv, host):
        hops = self.tools["traceroute"](host, int(self.cfg["max_hops"])) or []
        inv["path"] = hops
        answered = [h for h in hops if h.get("ip")]
        self._step(inv, "path", "%d hops to %s, %d answered"
                   % (len(hops), host, len(answered)))

    def _hops(self, inv):
        """Ping every hop at once and measure each one's loss.

        In parallel because serially this is minutes, and because simultaneous
        bursts are also the fairer measurement: loss that appears at hop 4 in
        the same second it appears at hop 9 is one event, not two.
        """
        cfg = self.cfg
        hops = [h for h in (inv.get("path") or []) if h.get("ip")][:int(cfg["hop_limit"])]
        if not hops:
            inv["hops"] = []
            return
        n, iv = int(cfg["hop_burst_pings"]), int(cfg["burst_interval_ms"])
        out = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, len(hops))) as ex:
            futs = {ex.submit(self.tools["burst"], h["ip"], n, iv): h for h in hops}
            for fut in concurrent.futures.as_completed(futs):
                h = futs[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"error": str(e)[:80]}
                out.append(dict(h, **(res or {})))
        out.sort(key=lambda h: h.get("hop") or 0)
        inv["hops"] = out
        bad = self._first_bad_hop(out)
        inv["first_bad_hop"] = bad
        self._step(inv, "hop_loss",
                   ("loss starts at hop %d (%s), %.1f%% over %d pings"
                    % (bad["hop"], bad["ip"], bad["loss_pct"], bad.get("sent") or n))
                   if bad else
                   "no hop lost packets consistently to the far end")

    def _first_bad_hop(self, hops):
        """The earliest hop whose loss every LATER hop also shows.

        This is the whole reason a traceroute can be read wrong. A router that
        answers its own pings slowly - or not at all - while forwarding
        everything perfectly is extremely common; it shows as a spike of loss
        at one hop with clean hops behind it. Real path loss cannot heal
        itself, so the search runs from the far end backwards and stops at the
        first hop whose successors are all bad too.
        """
        floor = float(self.cfg["hop_loss_pct"])
        rows = [h for h in hops if h.get("loss_pct") is not None]
        if not rows or rows[-1].get("loss_pct", 0) < floor:
            return None                      # the far end is clean: nothing real
        bad = None
        for h in reversed(rows):
            if h.get("loss_pct", 0) >= floor * 0.6:
                bad = h
            else:
                break
        return dict(bad) if bad else None

    def _ends(self, inv, host):
        """Gateway versus the far end, measured back to back.

        The single most useful number in the whole investigation: if the
        router is clean and the internet is not, nothing inside this house is
        at fault, and that is the sentence the ISP needs to hear.
        """
        cfg = self.cfg
        n, iv = int(cfg["burst_pings"]), int(cfg["burst_interval_ms"])
        gw = self.tools["gateway"]() or ""
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            f_gw = ex.submit(self.tools["burst"], gw, n, iv) if gw else None
            f_wan = ex.submit(self.tools["burst"], host, n, iv)
            inv["lan"] = dict(f_gw.result() if f_gw else {}, ip=gw)
            inv["wan"] = dict(f_wan.result() or {}, ip=host)
        self._step(inv, "ends",
                   "gateway %s%% loss / %s %s%% loss over %d pings each"
                   % (inv["lan"].get("loss_pct", "?"), host,
                      inv["wan"].get("loss_pct", "?"), n))

    def _saturation(self, inv, finding):
        """Was the line simply FULL during the bad window?

        Skipping this check is how a monitoring system tells someone to phone
        their ISP about their own household. Averages over the finding's hours
        across the days of history available, against the subscribed rate from
        config - the router's own UPnP answer is a placeholder here and must
        not be used.
        """
        hours = finding.get("hours") or []
        line = self.tools["line"]() or {}
        plan_down = float(line.get("down_mbps") or 0)
        rows = self.tools["bandwidth"](24 * 7) or []
        want = set(int(h) % 24 for h in hours)
        peak_mbps = in_window = 0.0
        samples = 0
        for row in rows:
            if not row or len(row) < 3:
                continue
            ts, rx = row[0], (row[1] or 0)
            lt = time.localtime(ts)
            # Bandwidth rows are hourly totals here; bytes -> Mbit/s.
            mbps = (rx * 8.0) / 3600.0 / 1e6
            peak_mbps = max(peak_mbps, mbps)
            if not want or lt.tm_hour in want:
                in_window += mbps
                samples += 1
        avg = round(in_window / samples, 2) if samples else 0.0
        pct = round(100.0 * avg / plan_down, 1) if plan_down else None
        inv["saturation"] = {
            "window_avg_mbps": avg, "peak_mbps": round(peak_mbps, 2),
            "plan_down_mbps": plan_down or None, "pct_of_plan": pct,
            "full": bool(pct is not None and pct >= float(self.cfg["saturation_pct"])),
            "hours": sorted(want), "samples": samples,
        }
        self._step(inv, "saturation",
                   ("%.1f Mbit/s average in the window, %s%% of the %s Mbit/s plan"
                    % (avg, pct, plan_down)) if pct is not None else
                   "no subscribed rate configured - cannot judge saturation")

    def _speed(self, inv):
        if not self.cfg["speedtest"]:
            return
        try:
            res = self.tools["speedtest"]()
        except Exception as e:
            res = {"error": str(e)[:120]}
        inv["speedtest"] = res or {}
        self._step(inv, "speed",
                   "%s down / %s up"
                   % (inv["speedtest"].get("down_mbps", "?"),
                      inv["speedtest"].get("up_mbps", "?")))

    # -- the answer --------------------------------------------------------

    def _verdict(self, inv, finding):
        """Name a culprit, or say plainly that the evidence did not name one.

        Ordered by what would make every later conclusion wrong: a saturated
        line explains loss anywhere, a lossy gateway explains loss everywhere
        beyond it, and only once both are excluded does a hop number mean what
        it appears to mean.
        """
        cfg = self.cfg
        floor = float(cfg["hop_loss_pct"])
        lan = inv.get("lan") or {}
        wan = inv.get("wan") or {}
        sat = inv.get("saturation") or {}
        bad = inv.get("first_bad_hop") or None
        lan_loss = lan.get("loss_pct")
        wan_loss = wan.get("loss_pct")
        recommend, blame, conf = [], "inconclusive", 0.3

        if inv.get("error") and not inv.get("hops"):
            blame, conf = "error", 0.0
            verdict = "The investigation could not complete: %s" % inv["error"]

        elif sat.get("full"):
            blame, conf = "saturation", 0.75
            verdict = ("The line is FULL during this window - %.1f Mbit/s "
                       "average, %s%% of the %s Mbit/s subscribed. Loss and "
                       "latency at a saturated link are the expected result, "
                       "not a fault. Do not raise this with the ISP."
                       % (sat.get("window_avg_mbps") or 0, sat.get("pct_of_plan"),
                          sat.get("plan_down_mbps")))
            recommend = ["Find what is using the line in this window "
                         "(Network tab, Devices, during the window).",
                         "If it is expected use, the answer is a bigger plan, "
                         "not a support ticket."]

        elif lan_loss is not None and lan_loss >= floor:
            blame, conf = "local", 0.8
            verdict = ("The problem starts INSIDE the house: the router itself "
                       "lost %.1f%% of %d pings. Nothing beyond it can be "
                       "blamed while the first hop is dropping."
                       % (lan_loss, lan.get("sent") or 0))
            recommend = ["Check the cable or Wi-Fi path between this machine "
                         "and the router first.",
                         "If this box is on Wi-Fi, retest on cable before "
                         "believing any of the hop numbers above.",
                         "Reboot the router only after capturing this - it "
                         "erases the evidence."]

        elif lan_loss is not None and wan_loss is None:
            # 2026-10-13 05:47: DNS and the line were down for ~58 minutes,
            # the far end came back {"loss_pct": None, "error": "unresolved"}
            # and the old fall-through called that "clean". A far end that
            # could not be measured while the router answered is the opposite
            # of clean: nothing past the house was reachable.
            blame, conf = "outage", 0.7
            why = wan.get("error") or "no replies"
            speed = inv.get("speedtest") or {}
            verdict = ("The internet was NOT reachable at the moment of probing: "
                       "the router answered (%.1f%% loss) but %s could not be "
                       "measured at all (%s)%s. That is an outage - name "
                       "lookups or the line itself were down - not a clean result."
                       % (lan_loss, wan.get("ip") or "the far end", why,
                          ("; the speed test failed too (%s)" % str(speed["error"])[:80])
                          if speed.get("error") else ""))
            recommend = ["Check the Network tab for how long the internet was "
                         "down around this time.",
                         "An outage of more than a few minutes with a clean "
                         "router is worth raising with the ISP, quoting the times."]

        elif (_is_lan(wan.get("ip")) and wan_loss is not None
              and wan_loss >= floor):
            # A target on the house network never crosses the ISP's line, so
            # no hop count can put its loss on their side of the demarcation.
            blame, conf = "local", 0.8
            verdict = ("The router is clean (%.1f%% loss) but %s lost %.1f%% - "
                       "and %s is a device on the house network, so this "
                       "never touches the ISP. The device itself, or its "
                       "Wi-Fi or cable link, is the fault."
                       % (lan_loss or 0.0, wan.get("ip"), wan_loss, wan.get("ip")))
            recommend = ["Check that device: is it on Wi-Fi, busy, rebooting "
                         "or overheating during the window?",
                         "Do not raise this with the ISP."]

        elif bad and wan_loss is not None and wan_loss >= floor:
            hop_n = bad.get("hop") or 0
            access = hop_n <= int(cfg["access_hops"])
            blame = "isp" if access else "transit"
            conf = 0.85 if access else 0.6
            verdict = ("Clean to the router (%.1f%% loss) and lossy beyond it: "
                       "%.1f%% at hop %d (%s), and every hop after it loses "
                       "too. That is %s."
                       % (lan_loss or 0.0, bad.get("loss_pct") or 0.0, hop_n,
                          bad.get("ip"),
                          "inside the ISP's access network - their side of the "
                          "demarcation" if access else
                          "out in transit, past the ISP's own network"))
            recommend = ["Raise it with the ISP quoting the hop and the window "
                         "(the ticket text below is ready to paste)." if access
                         else "Re-run against a different destination: transit "
                              "loss to one target is often that target's route, "
                              "not your line.",
                         "Keep the pattern running - a fault the ISP cannot "
                         "reproduce at 10:00 is why the window matters."]

        elif wan_loss is not None and wan_loss >= floor:
            blame, conf = "path", 0.5
            verdict = ("The far end lost %.1f%% but no single hop owns it - "
                       "either the loss is spread thin or the hops in between "
                       "will not answer pings. Real, but not yet located."
                       % wan_loss)
            recommend = ["Re-run during the window against a second target to "
                         "see whether it follows the destination or the line."]

        elif (finding.get("hours") and not inv.get("in_window")):
            blame, conf = "out-of-window", 0.2
            verdict = ("Everything measured clean - but this ran OUTSIDE the "
                       "%s window the pattern lives in, so a clean result here "
                       "means very little."
                       % _span_text(finding["hours"]))
            recommend = ["Let the next in-window investigation run before "
                         "drawing a conclusion."]

        else:
            blame, conf = "clean", 0.4
            verdict = ("Nothing was reproducing at the moment of probing: "
                       "gateway %s%% loss, %s %s%% loss, no hop consistently "
                       "bad. The pattern is real in the history; it was not "
                       "happening during this probe."
                       % (lan_loss, wan.get("ip"), wan_loss))
            recommend = ["Intermittent by nature - the finding stays open and "
                         "will be re-probed inside its window."]

        inv["blame"] = blame
        inv["confidence"] = conf
        inv["verdict"] = verdict
        inv["recommend"] = recommend
        inv["ticket"] = self._ticket(inv, finding) if blame in ("isp", "transit") else ""

    def _ticket(self, inv, finding):
        """A paragraph an ISP can act on, with every number it will ask for.

        Written out in full rather than assembled by whoever reads the alert,
        because the parts that get left out under pressure - the window, the
        sample counts, the fact that the first hop is clean - are exactly the
        parts that stop a ticket being closed as "no fault found".
        """
        ev = finding.get("evidence") or {}
        lan, wan = inv.get("lan") or {}, inv.get("wan") or {}
        bad = inv.get("first_bad_hop") or {}
        hops = "\n".join(
            "  hop %-2s %-16s %5s%% loss  %s ms avg"
            % (h.get("hop"), h.get("ip") or "*", h.get("loss_pct", "?"),
               h.get("avg_ms", "?"))
            for h in (inv.get("hops") or []))
        when = (_span_text(finding["hours"]) if finding.get("hours")
                else "no fixed window")
        days = ev.get("days") or []
        return (
            "Recurring packet loss on my line, measured continuously from a "
            "machine on the LAN.\n\n"
            "Pattern: %s\n"
            "Window: %s local time%s\n\n"
            "Measured at %s during the window:\n"
            "  router (%s): %s%% loss over %s pings\n"
            "  %s: %s%% loss over %s pings\n\n"
            "Per-hop, simultaneous bursts:\n%s\n\n"
            "Loss first appears at hop %s (%s) and every hop beyond it is "
            "affected, while the router itself is clean - so the loss is "
            "beyond my equipment. Full per-hop data and %d days of history "
            "available on request."
            % (finding.get("title") or "recurring loss",
               when,
               (", seen on %s" % ", ".join(days[-5:])) if days else "",
               time.strftime("%Y-%m-%d %H:%M", time.localtime(inv.get("at") or time.time())),
               lan.get("ip") or "?", lan.get("loss_pct", "?"), lan.get("sent", "?"),
               wan.get("ip") or "?", wan.get("loss_pct", "?"), wan.get("sent", "?"),
               hops or "  (no hops answered)",
               bad.get("hop", "?"), bad.get("ip", "?"),
               int(self.cfg["window_days"])))
