# Controlled Experiment Runbook

Use one record per authorized experiment. No malware, external targets, or Internet-routed traffic.

```text
Experiment ID / date-time / engineer:
Objective and expected behavior:
Target, attacker, clean checkpoint names:
Network topology and verified IP configuration:
Preconditions and approval:
Procedure:
Evidence paths and hashes:
Observed result / deviations:
Cleanup and checkpoint restoration:
Lessons, follow-up, and owner:
```

Safe initial scenarios: deliberate HTTP availability check, isolated connection-load test, process observation, benign file modification detection, controlled service start/stop, and authentication-event observation. For each, define the expected signal before execution. Capture evidence rather than relying on screenshots or memory.
