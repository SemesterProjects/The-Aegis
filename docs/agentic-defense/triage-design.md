# Deterministic Triage Design

Triage runs only after an event is persisted. It is explainable prioritization, not malware classification.

| Signal | Weight | Evidence |
| --- | ---: | --- |
| high/critical finding | 0.35 | detector severity |
| file-change burst | 0.20 | `AEGIS-FILE-*` evidence IDs |
| auth failure burst | 0.20 | `AEGIS-AUTH-*` evidence IDs |
| unusual network rate | 0.15 | `AEGIS-NET-*` evidence IDs |
| new process then network | 0.20 | `AEGIS-PROC-NET-*` evidence IDs |
| process/file/network correlation | 0.30 | only when actual PID-bearing events permit it |

Scores are capped at 1.0. `low < .30`, `medium < .60`, `high < .85`, and `critical >= .85`. A case is created at the configurable `.50` threshold. The default file burst detector emits only when the distinct-path threshold is crossed, preventing duplicate cases for one burst.

No automated response, quarantine, rollback, process termination, or network blocking exists in this layer.
