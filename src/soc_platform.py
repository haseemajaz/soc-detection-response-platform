#!/usr/bin/env python3
"""SOC Detection & Response Platform - safe local demo.

Reads synthetic events, runs ATT&CK-mapped detection rules from rules.json,
and writes triaged alerts. Standard library only. No network, no live data.
"""
import argparse
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class RuleEngine:
    def __init__(self, rules):
        self.rules = rules

    def _matches(self, rule, event):
        rtype = rule["type"]
        if rtype == "field_contains":
            return rule["value"].lower() in str(event.get(rule["field"], "")).lower()
        if rtype == "field_equals":
            return str(event.get(rule["field"], "")) == rule["value"]
        return False

    def evaluate(self, events):
        alerts = []
        for rule in self.rules:
            if rule["type"] == "count_threshold":
                alerts.extend(self._threshold_alerts(rule, events))
            else:
                for event in events:
                    if self._matches(rule, event):
                        alerts.append(self._alert(rule, event, [event]))
        return self._dedupe(alerts)

    def _threshold_alerts(self, rule, events):
        matching = [e for e in events if e.get("event_type") == rule["event_type"]]
        groups = defaultdict(list)
        for e in matching:
            groups[e.get(rule["field"], "unknown")].append(e)
        alerts = []
        window = timedelta(minutes=rule["window_minutes"])
        for key, group in groups.items():
            group.sort(key=lambda e: parse_time(e["timestamp"]))
            for i, start in enumerate(group):
                in_window = [e for e in group[i:] if parse_time(e["timestamp"]) - parse_time(start["timestamp"]) <= window]
                if len(in_window) >= rule["threshold"]:
                    alerts.append(self._alert(rule, in_window[0], in_window, key=key))
                    break
        return alerts

    def _alert(self, rule, event, evidence, key=None):
        return {
            "id": f"ALERT-{rule['id']}-{event.get('host', 'unknown')}",
            "rule": rule["name"],
            "severity": rule["severity"],
            "host": event.get("host", "unknown"),
            "source": key or event.get("source_ip") or event.get("destination", "unknown"),
            "mitre_tactic": rule["mitre_tactic"],
            "mitre_technique": rule["mitre_technique"],
            "response": rule["response"],
            "evidence_count": len(evidence),
            "first_seen": evidence[0]["timestamp"],
            "status": "Investigate now" if rule["severity"] == "High" else "Queued",
        }

    @staticmethod
    def _dedupe(alerts):
        seen = {}
        for alert in alerts:
            seen.setdefault(alert["id"], alert)
        return list(seen.values())


def main():
    parser = argparse.ArgumentParser(description="SOC Detection & Response Platform (demo)")
    parser.add_argument("--events", default=os.path.join(HERE, "..", "demo_data", "events.json"))
    parser.add_argument("--out", default=os.path.join(HERE, "..", "out", "alerts.json"))
    args = parser.parse_args()

    events = load_json(args.events)
    rules = load_json(os.path.join(HERE, "rules.json"))
    alerts = RuleEngine(rules).evaluate(events)
    alerts.sort(key=lambda a: (a["severity"] != "High", a["rule"]))

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"generated_from": "demo_data/events.json", "alert_count": len(alerts), "alerts": alerts}, f, indent=2)

    print(f"Events scanned: {len(events)}")
    print(f"Alerts raised: {len(alerts)}  ({Counter(a['severity'] for a in alerts)})")
    for a in alerts:
        print(f" [{a['severity']}] {a['rule']} on {a['host']} - {a['mitre_technique']} - {a['status']}")
        print(f"        Response: {a['response']}")
    print(f"Alerts written to {args.out}")


if __name__ == "__main__":
    main()
