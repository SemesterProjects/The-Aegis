# Validation and Test Strategy

## Purpose
Aegis is valuable only if its conclusions are trustworthy, explainable, and safe. That requires a deliberate validation strategy rather than a superficial demo pipeline.

## Test layers
### Unit tests
Check the correctness of core logic such as:

- event normalization
- timeline ordering
- evidence correlation
- scoring and ranking
- approval policies

### Integration tests
Validate interactions among subsystems:

- telemetry to detection
- detection to timeline reconstruction
- mitigation planning to verification sandbox
- approval flow to execution

### Workflow tests
Test the end-to-end product flow:

- suspicious behavior -> investigation -> likely root cause -> mitigation -> human review

### Adversarial tests
Model the conditions that attackers or bad actors would exploit:

- misleading telemetry
- malicious tool contracts
- ambiguous low-confidence alerting
- false-positive detection loops

### Safety tests
Ensure the system cannot slip past its policy boundaries.

## Verification strategy
The verification sandbox is a core product component, not a side tool.

A candidate mitigation must be validated under:

- isolated execution
- compile or build checks
- runtime behavior checks
- regression scenario validation
- explicit pass/fail criteria

## Success metrics for validation
- detection precision and recall
- root-cause localization quality
- time to investigation summary
- number of verified mitigations
- false-positive frequency
- number of blocked unsafe actions

## Demo-ready validation scenarios
- process injection or suspicious child process behavior
- file tampering in a Linux service
- network exfiltration followed by command execution
- vulnerable input processing that leads to exploitation

## Why this matters
Aegis must prove both the product and the trust model. The system is only useful if the outputs are explainable and the actions are safe.
