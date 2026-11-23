# Architecture - SOC Detection & Response Platform

## Data flow

```
demo_data/events.json
  -> src/soc_platform.py: load_events()      # normalise to one schema
  -> RuleEngine.evaluate()                   # each rule is a predicate + ATT&CK metadata
  -> Alert (id, rule, severity, host, evidence, mitre, response)
  -> dedupe by (rule, host, source)          # repeat events become one alert with a count
  -> triage: High -> Investigate now, Medium -> Queue, Low -> Log
  -> out/alerts.json + terminal summary
```

## Design decisions

- **Rules as data, not code.** Rules live in `src/rules.json` with a `type` field
  (`count_threshold`, `field_contains`, `field_equals`). Adding a detection
  means adding JSON, not editing the engine.
- **No external services.** No SIEM, no database, no API keys. The engine is a
  library function that can be embedded in a real pipeline later.
- **Deterministic demo data.** Every rule has at least one triggering event in
  `demo_data/events.json`, so the demo always produces the same 5 alerts.
- **Safe by construction.** The engine only reads local JSON and writes local
  JSON. It never executes commands, opens sockets, or touches real logs.

## How to extend

1. Add a rule to `src/rules.json` with `id`, `name`, `mitre_tactic`,
   `mitre_technique`, `severity`, `response`, and a `condition`.
2. Add a matching event to `demo_data/events.json`.
3. Run the tool and check `out/alerts.json`.
4. For a new rule type, add a handler in `RuleEngine._matches()`.

## Limitations (honest)

- Time windows are evaluated on the demo timestamps, not a live stream.
- No persistence: alerts are rewritten on every run.
- No authentication or multi-tenancy: this is a portfolio demo, not production SOC software.
