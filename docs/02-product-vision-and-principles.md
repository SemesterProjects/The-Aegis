# Product Vision and Principles

## Mission
Aegis is an autonomous AI security engineer that continuously understands software systems, observes runtime behavior, investigates attacks, identifies likely root causes, proposes secure mitigations, verifies them in controlled environments, and supports human defenders before and during production.

## Strategic intent
Aegis is not built to generate more alerts. It is built to compress the entire security lifecycle:

- observe
- understand
- investigate
- reason
- plan
- verify
- explain
- approve
- execute
- recover

## Product philosophy
### 1. Observe before acting
Every decision must be based on evidence. Partial telemetry is not enough for a high-confidence conclusion.

### 2. Reason before responding
Do not react on signatures or isolated heuristics alone. Explain the likely cause and the evidence chain.

### 3. Verify before deployment
A recommendation is not a solution until it has been validated in isolation.

### 4. Explain every decision
Operators should understand why Aegis reached a conclusion and what evidence supports it.

### 5. Humans remain the final authority
Production-facing changes require human approval.

## Architectural decomposition
### Aegis Core
The shared reasoning layer for evidence aggregation, context modeling, planning, and orchestration.

### Aegis Forge
The offensive validation environment for pre-deployment weakness discovery and patch verification.

### Aegis Shield
The runtime defense environment for monitoring, investigation, mitigation suggestion, and response support.

## Why separate Core / Forge / Shield
The same reasoning engine should be reused by both offensive and defensive workflows. This prevents duplicated logic and supports future enterprise product expansion.

## User personas
- Individual developers using Forge to harden software before release
- DevSecOps teams integrating Aegis into CI/CD
- SOC teams using Shield in production defense workflows
- Security researchers exploring novel attack patterns and mitigations

## Non-goals for the MVP
- full fleet-scale cloud orchestration
- Windows-first support
- all-language automatic patching
- autonomous production patching without approval

## Success outcomes
Aegis succeeds when it can reliably:

- observe a running Linux application
- detect suspicious runtime behavior
- explain why it thinks the behavior is malicious
- correlate runtime evidence with source structure
- propose multiple mitigation options
- verify the fix in a sandbox
- support human review before production action
