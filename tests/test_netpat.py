"""Offline tests for the network pattern engine.

test_neos.py is an integration suite: it needs a live hub, a live agent and a
real network. This one needs none of those, and that is the point - the whole
value of netpat is a judgement made about history, so the history is
synthesised here and the judgement is checked against it. A pattern engine that
cannot be tested without waiting three evenings for a fault is a pattern engine
nobody will ever change.

Run:  py -3 test_netpat.py
"""

import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import unittest

import netpat


# --------------------------------------------------------------- fixtures

def _hour_ts(days_ago, hour):
    """A unix hour bucket at LOCAL `hour` on the day `days_ago` days back."""
    lt = time.localtime(time.time() - days_ago * 86400)
    return int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday,
                            hour, 0, 0, 0, 0, -1)))


def hourly(days=7, probes=120, base_loss=0, hot=(), hot_loss=0, hot_days=None,
           rtt=20.0, hot_rtt=None):
    """A week of hourly rollups, optionally lossy at certain local hours."""
    rows, now = [], time.time()
    hot_days = range(days + 1) if hot_days is None else hot_days
    # Down to and including today, because "the last 24 hours" is what the
    # trend and drift detectors compare against and a fixture that stops at
    # midnight leaves them with nothing to read.
    for d in range(days, -1, -1):
        for h in range(24):
            ts = _hour_ts(d, h)
            if ts > now:
                continue
            lossy = h in hot and (d in hot_days)
            lost = hot_loss if lossy else base_loss
            ms = (hot_rtt if (lossy and hot_rtt) else rtt)
            ok = probes - lost
            rows.append({"h": ts, "n": probes, "lost": lost,
                         "sum": ms * ok, "min": ms, "max": ms})
    return rows


def target(tid="internet", label="Internet (HTTPS)", group="Internet", **kw):
    t = {"id": tid, "label": label, "group": group, "type": "icmp",
         "target": "8.8.8.8", "hourly": hourly()}
    t.update(kw)
    return t


def flap_events(tid, times, gap_s=120):
    """A down/up pair at each timestamp, `gap_s` apart."""
    out = []
    for at in times:
        out.append({"at": at, "id": tid, "kind": "down", "after_s": 3600})
        out.append({"at": at + gap_s, "id": tid, "kind": "up", "after_s": gap_s})
    return out


# ------------------------------------------------------------ hour windows

class TestWindows(unittest.TestCase):

    def test_consecutive_hours_become_one_window(self):
        self.assertEqual(netpat._merge_hours([19, 20, 21]), [[19, 20, 21]])

    def test_gaps_stay_separate(self):
        self.assertEqual(netpat._merge_hours([8, 19, 20]), [[8], [19, 20]])

    def test_midnight_wraps(self):
        """23:00 and 00:00 are adjacent on a clock. Without this a late-night
        fault reports as two unrelated findings, one of them an hour long."""
        self.assertEqual(netpat._merge_hours([22, 23, 0, 1]), [[22, 23, 0, 1]])

    def test_window_text_names_the_end_of_the_last_hour(self):
        # The 21:00 bucket covers 21:00-22:00; printing "19:00-21:00" would
        # understate the window by a full hour and mislead an ISP.
        self.assertEqual(netpat._span_text([19, 20, 21]), "19:00-22:00")


# ------------------------------------------------------------- the shapes

class TestFlapping(unittest.TestCase):

    def test_three_flaps_in_a_day_is_a_finding(self):
        now = time.time()
        t = target("gateway", "Router", group="")
        events = flap_events("gateway", [now - 3600 * n for n in (2, 5, 9)])
        found = netpat.analyse([t], events, {}, now)
        storms = [f for f in found if f["kind"] == "flap-storm"]
        self.assertEqual(len(storms), 1)
        self.assertEqual(len(storms[0]["evidence"]["episodes"]), 3)

    def test_one_drop_every_evening_is_found_even_though_it_never_storms(self):
        """Seven drops over seven evenings is never three in a day. Gating the
        window check on the daily count made the engine blind to the tidiest,
        most diagnosable fault there is - and it is the one Jean described."""
        now = time.time()
        t = target("internet", "Internet (HTTPS)", group="")
        times = []
        for d in range(1, 6):
            lt = time.localtime(now - d * 86400)
            times.append(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday,
                                      20, 15, 0, 0, 0, -1)))
        found = netpat.analyse([t], flap_events("internet", times), {}, now)
        self.assertEqual([f for f in found if f["kind"] == "flap-storm"], [])
        win = [f for f in found if f["kind"] == "flap-window"]
        self.assertEqual(len(win), 1)
        self.assertEqual(win[0]["hours"], [20])
        self.assertEqual(len(win[0]["evidence"]["days"]), 5)

    def test_two_flaps_is_not(self):
        now = time.time()
        t = target("gateway", "Router", group="")
        events = flap_events("gateway", [now - 3600 * n for n in (2, 5)])
        found = netpat.analyse([t], events, {}, now)
        self.assertEqual([f for f in found if f["kind"] == "flap-storm"], [])

    def test_one_outage_seen_by_four_sensors_counts_once(self):
        """A real WAN drop takes every Internet sensor down within seconds.
        Counting each sensor would make one outage trip the threshold on its
        own - the single most likely way this feature cries wolf."""
        now = time.time()
        ids = ["internet", "dns-google", "dns-cf", "dns-lan"]
        targets = [target(i, i, group="Internet") for i in ids]
        events = []
        for i, tid in enumerate(ids):
            events += flap_events(tid, [now - 7200 + i * 3])   # 3s apart
        found = netpat.analyse(targets, events, {}, now)
        self.assertEqual([f for f in found if f["kind"] == "flap-storm"], [])

    def test_staggered_sensors_in_one_outage_are_one_drop_and_one_downtime(self):
        """NEOS-214, 13 Oct: HTTPS + router DNS went down at 04:58, the two
        ICMP DNS sensors only at 05:02 - 3 min later, past episode_seconds.
        Two outages were reported as 4 drops, and their 85 minutes as 5h26m
        because every sensor's downtime was added up."""
        now = time.time()
        ids = ["internet", "dns-lan", "dns-google", "dns-cf"]
        targets = [target(i, i, group="Internet") for i in ids]
        events = []
        for start, length in ((now - 20000, 3926), (now - 15000, 1206)):
            for i, tid in enumerate(ids):
                lag = 0 if i < 2 else 198            # ICMP notices later
                events.append({"at": start + lag, "id": tid, "kind": "down", "after_s": 9999})
                events.append({"at": start + length - (lag // 9), "id": tid,
                               "kind": "up", "after_s": length - lag - lag // 9})
        self.assertEqual(len(netpat._flap_episodes(events, set(ids), now, 86400, 90)), 2)
        self.assertEqual(netpat._downtime(events, set(ids), now, 86400), 3926 + 1206)
        found = netpat.analyse(targets, events, {}, now)
        self.assertEqual([f for f in found if f["kind"] == "flap-storm"], [],
                         "two outages is not three drops")

    def test_group_scope_reports_the_line_not_the_sensors(self):
        now = time.time()
        ids = ["internet", "dns-google", "dns-cf"]
        targets = [target(i, i, group="Internet") for i in ids]
        events = []
        for at in (now - 3600, now - 7200, now - 12000):
            for i, tid in enumerate(ids):
                events += flap_events(tid, [at + i * 2])
        found = netpat.analyse(targets, events, {}, now)
        storms = [f for f in found if f["kind"] == "flap-storm"]
        self.assertEqual(len(storms), 1, "one line, one finding")
        self.assertEqual(storms[0]["scope"], "group")
        self.assertEqual(len(storms[0]["evidence"]["episodes"]), 3)


class TestTimeOfDay(unittest.TestCase):

    def test_evening_loss_is_found_and_named(self):
        now = time.time()
        t = target(hourly=hourly(hot=(19, 20, 21), hot_loss=18))
        found = netpat.analyse([t], [], {}, now)
        win = [f for f in found if f["kind"] == "loss-window"]
        self.assertEqual(len(win), 1, [f["kind"] for f in found])
        f = win[0]
        self.assertEqual(f["hours"], [19, 20, 21])
        self.assertIn("evening", f["title"])
        self.assertGreaterEqual(len(f["evidence"]["days"]), 3)
        self.assertAlmostEqual(f["evidence"]["window_loss_pct"], 15.0, places=1)

    def test_no_measurable_baseline_means_no_ratio(self):
        """"91.8x worse than 0.0%" is arithmetic, not evidence - and it is
        what an ISP will pick apart first."""
        now = time.time()
        t = target(hourly=hourly(base_loss=0, hot=(19, 20), hot_loss=18))
        f = [x for x in netpat.analyse([t], [], {}, now)
             if x["kind"] == "loss-window"][0]
        self.assertIsNone(f["evidence"]["ratio"])
        self.assertIn("no measurable loss", f["detail"])

    def test_a_real_baseline_gives_a_real_ratio(self):
        now = time.time()
        t = target(hourly=hourly(base_loss=2, hot=(19, 20), hot_loss=18))
        f = [x for x in netpat.analyse([t], [], {}, now)
             if x["kind"] == "loss-window"][0]
        self.assertAlmostEqual(f["evidence"]["baseline_loss_pct"], 1.67, places=1)
        self.assertGreater(f["evidence"]["ratio"], 3.0)
        self.assertIn("x worse", f["detail"])

    def test_the_quoted_loss_is_what_happened_on_the_bad_days(self):
        """Averaging in the evenings that were fine understates the fault and
        makes the report read as milder than the thing anybody experienced."""
        now = time.time()
        t = target(hourly=hourly(hot=(19, 20), hot_loss=24, hot_days=[1, 2, 3]))
        f = [x for x in netpat.analyse([t], [], {}, now)
             if x["kind"] == "loss-window"][0]
        self.assertAlmostEqual(f["evidence"]["window_loss_pct"], 20.0, places=1)
        self.assertLess(f["evidence"]["window_loss_all_days_pct"],
                        f["evidence"]["window_loss_pct"])

    def test_loss_at_every_hour_is_not_a_time_of_day_pattern(self):
        """Loss that never lets up is a loss-trend, not an evening problem.
        Reporting a window here would send an investigation to the wrong hour
        and an ISP to the wrong conclusion."""
        now = time.time()
        t = target(hourly=hourly(base_loss=12))
        found = netpat.analyse([t], [], {}, now)
        self.assertEqual([f for f in found if f["kind"] == "loss-window"], [])
        trend = [f for f in found if f["kind"] == "loss-trend"]
        self.assertTrue(trend)
        # ...and it is worded as chronic, because comparing it against its own
        # baseline would otherwise leave the worst fault here silent forever.
        self.assertFalse(trend[0]["evidence"]["new"])
        self.assertIn("all week", trend[0]["title"])

    def test_loss_that_only_started_today_is_worded_as_new(self):
        now = time.time()
        rows = hourly(days=7, base_loss=0)
        for b in rows:
            if b["h"] >= now - 86400:
                b["lost"] = 14
        found = netpat.analyse([target(hourly=rows)], [], {}, now)
        trend = [f for f in found if f["kind"] == "loss-trend"]
        self.assertTrue(trend)
        self.assertTrue(trend[0]["evidence"]["new"])
        self.assertIn("today", trend[0]["title"])

    def test_a_sensor_with_no_history_cannot_have_a_trend(self):
        """NEOS-388: an auto-discovered guest device (SMB on 192.168.0.58)
        was probed for twenty minutes, went home, and two hours later was
        a critical "losing 86% of packets today against 0.0% over the
        previous 6 days". The 0.0% was six days of nothing. A comparison
        with no baseline is not a trend, in either wording."""
        now = time.time()
        rows = [b for b in hourly(days=7, base_loss=0) if b["h"] >= now - 3 * 3600]
        self.assertGreaterEqual(sum(b["n"] for b in rows), 180)
        for b in rows:
            b["lost"] = int(b["n"] * 0.85)
        found = netpat.analyse([target(hourly=rows)], [], {}, now)
        self.assertEqual([f for f in found if f["kind"] == "loss-trend"], [],
                         "a two-hour-old sensor was given a week-long trend")

    def test_one_bad_evening_is_not_a_pattern(self):
        now = time.time()
        t = target(hourly=hourly(hot=(19, 20), hot_loss=25, hot_days=[3]))
        found = netpat.analyse([t], [], {}, now)
        self.assertEqual([f for f in found if f["kind"] == "loss-window"], [])

    def test_an_outage_is_not_packet_loss(self):
        """The bug this whole tier exists because of. On 15 Aug the hub was
        OFF for thirteen hours; the panel turned that into a permanent red
        "2.03% packet loss" on a link that never dropped a packet. An hour in
        which nothing answered is the thing being down, and must not enter the
        loss maths at all."""
        now = time.time()
        rows = hourly(days=7, base_loss=0)
        killed = 0
        for b in rows:
            lt = time.localtime(b["h"])
            if lt.tm_hour in (9, 10, 11) and now - b["h"] > 4 * 86400:
                b["lost"] = b["n"]          # nothing answered for a whole hour
                killed += 1
        self.assertGreater(killed, 3)
        found = netpat.analyse([target(hourly=rows)], [], {}, now)
        self.assertEqual([f for f in found if f["kind"] in ("loss-window", "loss-trend")], [],
                         "an outage was reported as packet loss")

    def test_a_small_but_consistent_evening_elevation_is_reported_at_info(self):
        """Measured on Jean's real line: 0.37% between 18:00 and 22:00 against
        a 0.014% baseline. Far too small to raise with an ISP, far too
        consistent to leave unsaid - so it is info, and it is never
        investigated or pushed."""
        now = time.time()
        # 3600 probes an hour is the real rate of Jean's 1s ping sensors, and
        # the whole point is that this is 12 lost packets, not 10%.
        t = target(hourly=hourly(probes=3600, base_loss=0, hot=(19, 20),
                                 hot_loss=12, hot_days=[1, 2, 3]))   # 0.33%
        f = [x for x in netpat.analyse([t], [], {}, now)
             if x["kind"] == "loss-window"][0]
        self.assertEqual(f["severity"], "info")
        self.assertFalse(f["investigate"])
        self.assertTrue(f["evidence"]["below_threshold"])

    def test_an_excellent_baseline_does_not_hide_the_elevation(self):
        """A baseline of 0.014% is not 'unmeasurable', it is excellent - and
        dividing by it and then bailing out when it was too small to divide by
        meant the better the link, the less this could see."""
        now = time.time()
        rows = hourly(days=7, probes=3600, base_loss=0, hot=(19, 20),
                      hot_loss=12, hot_days=[1, 2, 3])
        # One stray loss all week: a baseline that rounds to almost nothing.
        rows[0]["lost"] = 1
        found = [x for x in netpat.analyse([target(hourly=rows)], [], {}, now)
                 if x["kind"] == "loss-window"]
        self.assertEqual(len(found), 1)

    def test_two_bad_days_in_thirty_is_not_every_evening(self):
        """Recurrence is a rate, not a count. Off a bare count this reported
        'lossier EVERY evening' from two days out of thirty."""
        now = time.time()
        t = target(hourly=hourly(days=30, hot=(19, 20), hot_loss=18, hot_days=[3, 4]))
        self.assertEqual([f for f in netpat.analyse([t], [], {"window_days": 30}, now)
                          if f["kind"] == "loss-window"], [])

    def test_the_title_only_claims_every_evening_when_it_is_most_of_them(self):
        now = time.time()
        t = target(hourly=hourly(days=7, hot=(19, 20), hot_loss=18,
                                 hot_days=[1, 2, 3]))     # 3 of 8 days
        f = [x for x in netpat.analyse([t], [], {}, now)
             if x["kind"] == "loss-window"][0]
        self.assertIn("of the last", f["title"])
        self.assertNotIn("every evening", f["title"])

    def test_one_fault_seen_by_four_sensors_is_one_finding(self):
        """n8n is watched four ways and they all probe the same process. When
        it hiccups they produced four identical findings with identical
        numbers - four times the noise for one event."""
        now = time.time()
        ts = [target("n8n-%d" % i, "n8n sensor %d" % i, group="n8n",
                     hourly=hourly(hot=(19, 20), hot_loss=18))
              for i in range(4)]
        wins = [f for f in netpat.analyse(ts, [], {}, now)
                if f["kind"] == "loss-window"]
        self.assertEqual(len(wins), 1)
        self.assertEqual(len(wins[0]["also_seen_by"]), 3)
        self.assertIn("one fault, 4 sensors", wins[0]["detail"])

    def test_a_sensor_that_is_simply_down_produces_nothing(self):
        now = time.time()
        t = target(hourly=hourly(base_loss=120))      # answered nothing at all
        self.assertEqual(netpat.analyse([t], [], {}, now), [])

    def test_a_brand_new_sensor_produces_nothing(self):
        now = time.time()
        t = target(hourly=[{"h": _hour_ts(0, 1), "n": 20, "lost": 20,
                            "sum": 0, "min": None, "max": None}])
        self.assertEqual(netpat.analyse([t], [], {}, now), [])


class TestDrift(unittest.TestCase):

    def test_latency_doubling_is_a_finding(self):
        now = time.time()
        rows = hourly(days=7, rtt=20.0)
        for b in rows:
            if b["h"] >= now - 86400:
                ok = b["n"] - b["lost"]
                b["sum"] = 55.0 * ok            # 20ms -> 55ms today
        found = netpat.analyse([target(hourly=rows)], [], {}, now)
        drift = [f for f in found if f["kind"] == "latency-drift"]
        self.assertEqual(len(drift), 1)
        self.assertAlmostEqual(drift[0]["evidence"]["avg_24h_ms"], 55.0, places=1)

    def test_a_fast_lan_sensor_wobbling_is_not(self):
        """2ms to 4ms is a doubling and means nothing. The absolute floor is
        what stops every LAN sensor in the house filing a report."""
        now = time.time()
        rows = hourly(days=7, rtt=2.0)
        for b in rows:
            if b["h"] >= now - 86400:
                b["sum"] = 4.0 * (b["n"] - b["lost"])
        found = netpat.analyse([target(hourly=rows)], [], {}, now)
        self.assertEqual([f for f in found if f["kind"] == "latency-drift"], [])


# ------------------------------------------------------------- the ledger

class TestLedger(unittest.TestCase):

    def test_the_same_finding_twice_is_one_open_item(self):
        now = time.time()
        t = target(hourly=hourly(hot=(19, 20), hot_loss=18))
        first = netpat.merge_findings({}, netpat.analyse([t], [], {}, now), now)
        second = netpat.merge_findings(first, netpat.analyse([t], [], {}, now), now + 900)
        key = list(first)[0]
        self.assertEqual(len(second), 1)
        self.assertEqual(second[key]["first_seen"], first[key]["first_seen"])
        self.assertEqual(second[key]["seen_count"], 2)

    def test_escalation_is_flagged_even_though_the_finding_is_not_new(self):
        now = time.time()
        prev = {"loss-window/internet/19": {"key": "loss-window/internet/19",
                                            "severity": "warn", "first_seen": now - 7200,
                                            "seen_count": 4}}
        cur = [{"key": "loss-window/internet/19", "severity": "critical",
                "kind": "loss-window", "hours": [19]}]
        out = netpat.merge_findings(prev, cur, now)
        self.assertTrue(out["loss-window/internet/19"]["escalated"])

    def test_a_finding_that_stops_showing_is_cleared_not_deleted(self):
        now = time.time()
        prev = {"k": {"key": "k", "severity": "warn", "last_seen": now - 60}}
        out = netpat.merge_findings(prev, [], now)
        self.assertTrue(out["k"]["cleared"])
        # ...and drops off a day later, rather than accreting forever.
        self.assertEqual(netpat.merge_findings(prev, [], now + 86401), {})


class TestScheduling(unittest.TestCase):

    def _finding(self, **kw):
        f = {"key": "k", "severity": "warn", "confidence": 0.8, "hours": [],
             "investigate": True, "cleared": False, "last_investigated": 0}
        f.update(kw)
        return f

    def test_a_time_of_day_finding_waits_for_its_window(self):
        """The whole reason investigations are scheduled rather than fired: a
        traceroute at lunchtime proves nothing about an eight o'clock fault."""
        now = time.time()
        here = time.localtime(now).tm_hour
        away = (here + 6) % 24
        self.assertEqual(
            netpat.due_for_investigation([self._finding(hours=[away])], {}, now), [])
        self.assertEqual(
            len(netpat.due_for_investigation([self._finding(hours=[here])], {}, now)), 1)

    def test_in_window_only_can_be_switched_off(self):
        now = time.time()
        away = (time.localtime(now).tm_hour + 6) % 24
        cfg = {"in_window_only": False}
        self.assertEqual(
            len(netpat.due_for_investigation([self._finding(hours=[away])], cfg, now)), 1)

    def test_the_cooldown_holds(self):
        now = time.time()
        f = self._finding(last_investigated=now - 3600)      # cooldown is 6h
        self.assertEqual(netpat.due_for_investigation([f], {}, now), [])

    def test_the_daily_cap_holds(self):
        now = time.time()
        self.assertEqual(
            netpat.due_for_investigation([self._finding()], {}, now, done_today=6), [])

    def test_critical_only_mode_ignores_warnings(self):
        now = time.time()
        cfg = {"investigate_severity": "critical"}
        self.assertEqual(netpat.due_for_investigation([self._finding()], cfg, now), [])


# ------------------------------------------------------- the investigation

def hops(*loss):
    return [{"hop": i + 1, "ip": "10.0.0.%d" % (i + 1), "rtt_ms": 5.0 * (i + 1),
             "loss_pct": l, "sent": 40, "avg_ms": 5.0 * (i + 1)}
            for i, l in enumerate(loss)]


class TestFirstBadHop(unittest.TestCase):

    def _inv(self, cfg=None):
        return netpat.Investigator({}, cfg or {})

    def test_loss_that_persists_to_the_end_names_the_first_hop_of_it(self):
        bad = self._inv()._first_bad_hop(hops(0, 0, 9.0, 11.0, 10.5))
        self.assertEqual(bad["hop"], 3)

    def test_a_hop_rate_limiting_its_own_pings_is_not_blamed(self):
        """40% loss at hop 2 with clean hops behind it is a router
        deprioritising ICMP addressed to itself while forwarding perfectly.
        This is the single most common way a traceroute is misread, and the
        reason the search runs backwards from the destination."""
        self.assertIsNone(self._inv()._first_bad_hop(hops(0, 40.0, 0, 0, 0)))

    def test_a_clean_path_names_nobody(self):
        self.assertIsNone(self._inv()._first_bad_hop(hops(0, 0, 0, 0)))


class TestVerdicts(unittest.TestCase):
    """End to end through Investigator.run with every probe stubbed."""

    def tools(self, gw_loss=0.0, wan_loss=0.0, hop_losses=(0, 0, 0, 0),
              mbps=1.0, plan=200):
        rows = []
        now = time.time()
        for d in range(3):
            for h in range(24):
                rows.append([_hour_ts(d, h), int(mbps * 1e6 * 3600 / 8), 0])
        return {
            "traceroute": lambda host, max_hops: [
                {"hop": i + 1, "ip": "10.0.0.%d" % (i + 1), "rtt_ms": 5.0}
                for i in range(len(hop_losses))],
            "burst": lambda ip, count, interval_ms: {
                "ip": ip, "sent": count, "recv": count,
                "loss_pct": (gw_loss if ip == "192.168.0.1" else
                             hop_losses[int(ip.rsplit(".", 1)[1]) - 1]
                             if ip.startswith("10.0.0.") else wan_loss),
                "avg_ms": 12.0},
            "gateway": lambda: "192.168.0.1",
            "speedtest": lambda: {"ok": True, "down_mbps": 180, "up_mbps": 90},
            "bandwidth": lambda hours: rows,
            "line": lambda: {"down_mbps": plan, "up_mbps": 100},
            "sensors": lambda: [{"id": "internet", "label": "Internet",
                                 "group": "Internet", "state": "down"}],
        }

    def finding(self, **kw):
        f = {"key": "loss-window/internet/19", "kind": "loss-window",
             "scope": "sensor", "id": "internet", "label": "Internet (HTTPS)",
             "group": "Internet", "target": "8.8.8.8",
             "title": "Internet loses packets every evening",
             "severity": "warn", "hours": [time.localtime().tm_hour],
             "evidence": {"days": ["2026-09-01", "2026-09-02", "2026-09-03"]}}
        f.update(kw)
        return f

    def test_clean_gateway_lossy_path_blames_the_isp_and_writes_a_ticket(self):
        inv = netpat.Investigator(
            self.tools(gw_loss=0.0, wan_loss=12.0, hop_losses=(0, 9, 11, 12))
        ).run(self.finding())
        self.assertEqual(inv["blame"], "isp")
        self.assertEqual(inv["first_bad_hop"]["hop"], 2)
        self.assertIn("hop 2", inv["ticket"])
        self.assertIn("10.0.0.2", inv["ticket"])
        self.assertIn("router", inv["ticket"])

    def test_a_lossy_gateway_is_blamed_before_anything_beyond_it(self):
        """Nothing past the first hop can be trusted while the first hop is
        dropping - and this is the case that must never reach an ISP."""
        inv = netpat.Investigator(
            self.tools(gw_loss=14.0, wan_loss=16.0, hop_losses=(14, 15, 16, 16))
        ).run(self.finding())
        self.assertEqual(inv["blame"], "local")
        self.assertEqual(inv["ticket"], "")

    def test_a_lossy_lan_device_is_never_blamed_on_the_isp(self):
        """NEOS-152: a sensor on 192.168.0.111 lost 85% while the router was
        clean, and the hop count alone wrote an ISP ticket for a device that
        sits on the house network."""
        inv = netpat.Investigator(
            self.tools(gw_loss=0.0, wan_loss=85.0, hop_losses=(0, 87))
        ).run(self.finding(target="192.168.0.111", label="192.168.0.111 - SSH"))
        self.assertEqual(inv["wan"]["ip"], "192.168.0.111")
        self.assertEqual(inv["blame"], "local")
        self.assertEqual(inv["ticket"], "")
        self.assertIn("never touches the ISP", inv["verdict"])

    def test_a_full_line_is_not_a_faulty_line(self):
        """150 Mbit/s average on a 200 Mbit/s plan during the bad window is a
        household, not a fault. Saturation is checked before hop numbers
        because it explains loss anywhere on the path."""
        inv = netpat.Investigator(
            self.tools(gw_loss=0.0, wan_loss=12.0, hop_losses=(0, 9, 11, 12),
                       mbps=150, plan=200)
        ).run(self.finding())
        self.assertEqual(inv["blame"], "saturation")
        self.assertEqual(inv["ticket"], "")
        self.assertTrue(inv["saturation"]["full"])
        self.assertIn("Do not raise this with the ISP", inv["verdict"])

    def test_a_clean_probe_outside_the_window_says_so(self):
        away = (time.localtime().tm_hour + 6) % 24
        inv = netpat.Investigator(self.tools()).run(self.finding(hours=[away]))
        self.assertEqual(inv["blame"], "out-of-window")
        self.assertIn("OUTSIDE", inv["verdict"])

    def test_a_clean_probe_inside_the_window_does_not_close_the_finding(self):
        inv = netpat.Investigator(self.tools()).run(self.finding())
        self.assertEqual(inv["blame"], "clean")
        self.assertIn("re-probed", " ".join(inv["recommend"]))

    def test_an_unreachable_far_end_is_an_outage_not_clean(self):
        """2026-10-13: ~58 minutes with no DNS and no route out; the far end
        came back unresolved and the verdict read "Nothing was reproducing"."""
        tools = self.tools()
        real = tools["burst"]
        tools["burst"] = lambda ip, count, interval_ms: (
            real(ip, count, interval_ms) if ip == "192.168.0.1" else
            {"sent": 0, "recv": 0, "loss_pct": None, "error": "unresolved"})
        tools["speedtest"] = lambda: {"error": "Temporary failure in name resolution"}
        inv = netpat.Investigator(tools).run(
            self.finding(target="https://www.cloudflare.com/cdn-cgi/trace"))
        self.assertEqual(inv["blame"], "outage")
        self.assertIn("NOT reachable", inv["verdict"])
        self.assertIn("unresolved", inv["verdict"])
        self.assertIn("speed test failed", inv["verdict"])
        self.assertEqual(inv["ticket"], "")

    def test_neither_end_measured_is_not_called_an_outage(self):
        """No gateway reading means this box itself may be cut off - the
        evidence cannot put the fault past the router."""
        tools = self.tools()
        tools["gateway"] = lambda: ""
        tools["burst"] = lambda ip, count, interval_ms: {
            "sent": 0, "recv": 0, "loss_pct": None, "error": "unresolved"}
        inv = netpat.Investigator(tools).run(self.finding())
        self.assertNotEqual(inv["blame"], "outage")

    def test_a_group_finding_traces_off_the_network(self):
        inv = netpat.Investigator(self.tools()).run(
            self.finding(scope="group", target="", label="Internet"))
        self.assertEqual(inv["target"], "8.8.8.8")

    def test_an_http_sensor_url_becomes_a_hostname(self):
        i = netpat.Investigator({})
        self.assertEqual(
            i._host_for({"target": "https://www.cloudflare.com/cdn-cgi/trace"}),
            "www.cloudflare.com")

    def test_a_broken_probe_does_not_take_the_investigation_down(self):
        tools = self.tools()
        tools["traceroute"] = lambda host, max_hops: 1 / 0
        inv = netpat.Investigator(tools).run(self.finding())
        self.assertTrue(inv["error"])
        self.assertEqual(inv["blame"], "error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
