# MVP Scope and Success Metrics

## MVP objective
The MVP must prove the core hypothesis: Aegis can observe a Linux application, detect abnormal behavior, reconstruct attack progression, identify likely vulnerable code, recommend candidate fixes, verify them in a sandbox, and present the reasoning to a human for approval.

## In scope
- runtime telemetry collection
- suspicious behavior detection
- attack timeline reconstruction
- probable root-cause localization
- candidate mitigation generation
- sandbox verification
- explanatory dashboard
- approval workflow before production change

## Explicitly out of scope
- broad cloud fleet orchestration
- Kubernetes-first scale operations
- Windows-first runtime coverage
- generalized cross-language automatic remediation
- autonomous production patching

## Functional requirements
- telemetry must remain trustworthy and time-ordered
- detection must work on unknown or new behavior
- reasoning must be explainable to a human engineer
- candidate fixes must be ranked and validated
- no production modification without approval

## Non-functional requirements
- safety: constrained and isolated execution
- performance: near-real-time monitoring for the target scope
- explainability: evidence trails for every conclusion
- auditability: every action logged and reviewable

## Definition of done
The MVP is complete when the system can answer the following in a live demo:

1. Can it observe a running application?
2. Can it detect suspicious behavior without using known signatures?
3. Can it explain why it believes the behavior is malicious?
4. Can it connect the behavior to probable source-level causes?
5. Can it propose multiple mitigation options?
6. Can it verify the candidate fix safely in isolation?
7. Can a human review and approve the remediation?
8. Can it recover if the mitigation is unsuccessful?

## Metrics
- time from detection to investigation summary
- time from suspicious event to root-cause hypothesis
- number of mitigation options produced
- percentage of mitigations successfully sandbox-verified
- false-positive rate in behavior detection
- approval rate for recommended actions
- rollback or recovery success rate
