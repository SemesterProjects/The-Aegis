# Threat Model and Safety Policy

## Purpose
Aegis itself is a security-critical system. It must be designed with explicit threat awareness and strong operational guardrails.

## Threat categories
### Adversarial telemetry manipulation
Attackers may spoof process activity, tamper with logs, or inject misleading signals.

Mitigations:
- provenance tracking
- cross-source validation
- timestamp checks
- confidence thresholds on conclusions

### AI tool or prompt abuse
If tools are exposed to untrusted instructions, they can be manipulated.

Mitigations:
- strict tool schemas
- allowlists for actions
- controlled invocation paths
- human review for privileged commands

### Privilege escalation risk
Aegis may have access to sensitive systems and become a target for misuse.

Mitigations:
- least privilege
- environment isolation
- approval barriers for high-risk commands
- audit logs and access control

### Unsafe mitigation generation
The system may propose a fix that breaks functionality or creates new hazards.

Mitigations:
- isolated verification sandbox
- compile and regression checks
- rollback paths
- ranked mitigation options

## Safety policy
### Safe-read actions
Low-risk actions such as telemetry collection and read-only analysis may be automated.

### Review-required actions
Actions that trigger broader operational impact should require review before execution.

### Human-approved actions
These include patching production systems, disabling processes, blocking network flows, or deleting sensitive files.

## Default rule
If evidence is uncertain or the operation is high-risk, Aegis should recommend and wait, not act.

## Safety invariants
- no direct production mutation without approval
- no privilege escalation through an auto-generated command
- no destructive action without explicit authorization
- all high-risk actions must be logged and reversible

## Why this matters
A security product can become a major attack surface if it is not carefully governed. Safety is a product requirement, not a late-stage concern.
