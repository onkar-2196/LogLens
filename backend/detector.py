"""Signature + brute-force detection, aggregated in a single streaming pass."""
import json, re
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import unquote_plus

from geo import lookup_country
from parser import iter_log

SEV_RANK = {"low": 1, "medium": 2, "high": 3}
MAX_SAMPLE_EVENTS = 300


def load_signatures(path):
    with open(path) as f:
        cfg = json.load(f)
    sigs = [{**s, "re": re.compile(s["pattern"], re.I)} for s in cfg["signatures"]]
    return sigs, cfg["brute_force"]


def hour_key(ts: str) -> str:
    # "10/Oct/2026:13:55:36 +0000" -> "10/Oct/2026:13"  (cheap bucket, no full parse)
    return ts[:14]


def hour_iso(key: str) -> str:
    return datetime.strptime(key, "%d/%b/%Y:%H").strftime("%Y-%m-%d %H:00")


def analyze(path, sig_path, progress=None):
    sigs, bf = load_signatures(sig_path)
    total = malformed = 0
    per_hour, per_type, per_sev = Counter(), Counter(), Counter()
    ip_stats = defaultdict(lambda: {"count": 0, "types": Counter(), "max_sev": 0})
    failed_401 = defaultdict(Counter)  # ip -> hour -> count
    events = []

    for e in iter_log(path):
        if e.get("_malformed"):
            malformed += 1
            continue
        total += 1
        if progress and total % 50000 == 0:
            progress(total)

        if e["status"] == bf["status"]:
            failed_401[e["ip"]][hour_key(e["timestamp"])] += 1

        request = unquote_plus(unquote_plus(e["path"]))  # decode double-encoding
        for s in sigs:
            hay = e["user_agent"] if s["target"] == "user_agent" else request
            if s["re"].search(hay):
                _record(s["type"], s["severity"], s["id"], e, per_hour, per_type,
                        per_sev, ip_stats, events)
                break  # one tag per line: first (highest-priority) match wins

    # Brute force: IPs whose failed-auth count crosses the threshold
    for ip, hours in failed_401.items():
        if sum(hours.values()) >= bf["threshold"]:
            for h, n in hours.items():
                for _ in range(n):
                    per_hour[h] += 1
            per_type["brute_force"] += sum(hours.values())
            per_sev[bf["severity"]] += sum(hours.values())
            st = ip_stats[ip]
            st["count"] += sum(hours.values())
            st["types"]["brute_force"] += sum(hours.values())
            st["max_sev"] = max(st["max_sev"], SEV_RANK[bf["severity"]])

    sev_name = {v: k for k, v in SEV_RANK.items()}
    attackers = []
    for ip, st in sorted(ip_stats.items(), key=lambda kv: -kv[1]["count"])[:25]:
        attackers.append({"ip": ip, "country": lookup_country(ip), "attacks": st["count"],
                          "severity": sev_name.get(st["max_sev"], "low"),
                          "types": dict(st["types"])})

    countries = Counter()
    for ip, st in ip_stats.items():
        countries[lookup_country(ip)] += st["count"]

    timeline = [{"hour": hour_iso(h), "attacks": n}
                for h, n in sorted(per_hour.items(),
                                   key=lambda kv: datetime.strptime(kv[0], "%d/%b/%Y:%H"))]
    return {
        "summary": {"lines": total, "malformed": malformed,
                    "attacks": sum(per_type.values()), "unique_attackers": len(ip_stats)},
        "timeline": timeline,
        "by_type": [{"type": k, "count": v} for k, v in per_type.most_common()],
        "by_severity": dict(per_sev),
        "by_country": [{"country": k, "attacks": v} for k, v in countries.most_common(15)],
        "top_attackers": attackers,
        "events": events,
    }


def _record(typ, sev, sid, e, per_hour, per_type, per_sev, ip_stats, events):
    per_hour[hour_key(e["timestamp"])] += 1
    per_type[typ] += 1
    per_sev[sev] += 1
    st = ip_stats[e["ip"]]
    st["count"] += 1
    st["types"][typ] += 1
    st["max_sev"] = max(st["max_sev"], SEV_RANK[sev])
    if len(events) < MAX_SAMPLE_EVENTS:  # bounded sample, never the whole file
        events.append({"ip": e["ip"], "time": e["timestamp"], "method": e["method"],
                       "path": e["path"][:200], "status": e["status"],
                       "type": typ, "severity": sev, "rule": sid})
