# AEGIS Response Agent — Architecture and Operation

## 1. Overview and Core Philosophy

The **AEGIS Response Agent** is an autonomous, policy-governed component responsible for translating completed `InvestigationResult` findings into controlled, safety-validated response decisions and actions.

```text
MonitoringEngine -> TriageEngine -> InvestigationAgent (Read-Only)
                 -> ResponseAgent -> ResponsePolicy Gate -> ExecutionAdapter -> Verification -> Audit
```

### Critical Conceptual Distinctions
- **Mitigation vs. Defence**:
  - **Mitigation** is a targeted tactical action intended to reduce immediate risk or limit ongoing damage (e.g., terminating an active reverse shell process or quarantining a dropped script).
  - **Defence** encompasses the complete, multi-layered architecture of preventive, detective, investigative, responsive, and recovery controls designed to preserve system confidentiality, integrity, and availability.
- **Planning $\neq$ Execution**: Generating a response plan does **not** mean mitigation has been performed. Actions remain proposals until explicitly authorized and dispatched.
- **Containment $\neq$ Eradication**: A successful containment action (e.g., terminating a process) does **not** prove that the underlying threat has been fully eradicated. Adversaries frequently establish secondary persistence mechanisms, alter logs, or operate through multiple compromised credentials.

---

## 2. Response Lifecycle: 6 Phases

### Phase A: Input Retrieval and Validation
- Consumes `InvestigationCase` and `InvestigationResult` directly from the durable `EvidenceStore`.
- Validates terminal status: `COMPLETE` or `PARTIAL` results are processed. `ERROR` results prohibit all containment.
- Validates identifier matching (`case_id` match) and deserialization integrity.
- Enforces plan idempotency: repeated calls for the same `case_id` return the existing plan.

### Phase B: Evidence and Risk Assessment
- Evaluates classification, investigation confidence, uncertainties, contradictory evidence, and affected assets:
  - `BENIGN`: strictly forbids containment; records audit rationale.
  - `SUSPICIOUS`: prepares proportionate monitoring and selective containment requiring human review.
  - `MALICIOUS`: prepares incident containment proposals with mandatory approval gates.
  - `UNKNOWN`: avoids definitive conclusions; proposes telemetry expansion and human review.

### Phase C: Response Planning (Playbook Engine)
- Maps findings to structured candidate actions (`ResponseAction`), specifying:
  - Action category, target, justification, supporting evidence IDs.
  - Preconditions, rollback plan, and independent verification criteria.

### Phase D: Policy and Approval Gate
- Every proposed action is evaluated by `PolicyEvaluator`:
  - **Allowlist & Default Deny**: Unknown action types are rejected.
  - **Target Scope Validation**: Target PID, file path, or IP must be verified to exist within investigation evidence.
  - **Critical Resource Protection**: Operating system PIDs (0, 4, 1), core binaries (System32, `/bin`), and loopback addresses (`127.0.0.1`) cannot be targeted.
  - **Prompt Injection Defense**: Telemetry strings (cmdlines, paths, filenames) are treated strictly as inert data parameters, never interpreted as instructions.
  - **Approval Requirement**: High-risk/disruptive operations are set to `PENDING_APPROVAL`.

### Phase E: Controlled Execution
- Dispatches eligible and approved actions to an `ExecutionAdapter`.
- **Default Mode**: `dry_run=True`. Real containment cannot occur unless live mode is explicitly enabled by configuration and accompanied by verified approval.
- Failed executions record adapter output and trigger rollback procedures where defined.

### Phase F: Post-Action Verification & Audit
- Performs independent, read-only verification of expected system state post-execution (e.g., querying the OS process table to verify the PID is absent, or verifying filesystem state).
- An adapter returning `success=True` is not accepted as proof of outcome.
- Inconclusive telemetry marks the action as failed verification.
- Persists all states, decisions, approvals, and outcomes to SQLite with full relational integrity.

---

## 3. Action Lifecycle State Machine

```text
[PROPOSED] ------------+
    |                  |
    | (requires app.)  | (info / auto-eligible)
    v                  v
[PENDING_APPROVAL]  [APPROVED]
    |                  |
    +--> [REJECTED]    | (execution handoff)
    +--> [CANCELLED]   v
                   [EXECUTING]
                     /     \
           (adapter ok)   (adapter error)
                   /         \
                  v           v
       [VERIFICATION_PENDING] [FAILED] -> [ROLLED_BACK]
                 /     \
       (verified)      (unverified / failed)
               /         \
              v           v
          [VERIFIED]   [FAILED]
```

---

## 4. Schemas and Data Models

### ResponsePlan
Stored in table `response_plans` with schema:
```json
{
  "response_id": "RSP-XXXXXXXXXX",
  "case_id": "INC-XXXXXXXXXXXX",
  "investigation_id": "INV-XXXXXXXXXXXX",
  "status": "PLANNING | PENDING_APPROVAL | APPROVED | EXECUTING | COMPLETED | FAILED | CANCELLED",
  "created_at": "ISO-8601 UTC",
  "updated_at": "ISO-8601 UTC",
  "risk_assessment": {
    "classification": "MALICIOUS",
    "confidence": 0.85,
    "business_impact": "HIGH",
    "containment_urgency": "HIGH",
    "uncertainties": [],
    "contradictory_evidence_count": 0
  },
  "decision": "Active threat detected with 85% confidence. Containment actions proposed subject to human approval.",
  "actions": [...],
  "supporting_evidence_ids": ["uuid-1", "uuid-2"],
  "uncertainties": [],
  "approval_requirements": ["Action ACT-... requires recorded human approval."],
  "policy_decisions": [...],
  "verification_plan": ["Action ACT-...: Process PID ... is no longer observed in running processes."]
}
```

### ResponseAction
Stored in table `response_actions` with schema:
```json
{
  "action_id": "ACT-XXXXXXXXXX",
  "action_type": "TERMINATE_PROCESS | QUARANTINE_FILE | BLOCK_NETWORK_IP | ISOLATE_HOST | RECORD_INCIDENT | NOTIFY_RESPONDER | REQUEST_ADDITIONAL_TELEMETRY | ACCOUNT_REVIEW",
  "target": {"pid": 5678, "name": "powershell.exe"},
  "reason": "Terminate process identified in malicious execution chain.",
  "evidence_ids": ["uuid-1"],
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "status": "PROPOSED | PENDING_APPROVAL | APPROVED | REJECTED | EXECUTING | SUCCEEDED | FAILED | VERIFICATION_PENDING | VERIFIED | ROLLED_BACK | CANCELLED | UNSUPPORTED",
  "requires_approval": true,
  "approval_status": "PENDING | APPROVED | REJECTED | EXPIRED | REVOKED | NOT_REQUIRED",
  "approval_record": {
    "approval_id": "APP-XXXXXXXX",
    "approver_id": "secops-analyst@aegis.defense",
    "status": "APPROVED",
    "rationale": "Verified malicious PowerShell execution.",
    "granted_at": "ISO-8601 UTC",
    "expires_at": null,
    "scope": {"pid": 5678, "name": "powershell.exe"}
  },
  "preconditions": ["Process PID must be currently running"],
  "rollback_or_recovery_plan": "Restart process from verified service or binary if required.",
  "verification_criteria": "Process PID 5678 is no longer observed in running processes.",
  "execution_result": {
    "success": true,
    "adapter_name": "DryRunExecutionAdapter",
    "simulated": true,
    "output": "[DRY-RUN] Simulated SIGTERM / TerminateProcess for PID 5678 (powershell.exe)",
    "execution_time_seconds": 0.001
  },
  "verification_result": {
    "verified": true,
    "method": "dry_run_simulation_check",
    "details": "Dry-run simulation verified: no host modification occurred."
  }
}
```

---

## 5. Execution Adapters

1. **`DryRunExecutionAdapter` (Default Production Adapter)**:
   - Simulates all operations.
   - Emits structured output detailing what would have occurred.
   - Modifies zero operating system resources.
   - Guarantees `simulated=True`.
2. **`MockExecutionAdapter`**:
   - Used for deterministic unit and regression testing.
   - Configurable for simulated failures, timeouts, and unsupported capabilities.
3. **`LocalLabExecutionAdapter`**:
   - Strictly bounded adapter for isolated development sandboxes.
   - Quarantines files only within designated lab directory.
   - Rejects process termination unless marked with `is_test_process=True`.

---

## 6. CLI Usage Guide

### Generate a Response Plan
```powershell
py -m aegis_core respond plan --case-id INC-023F5CADD5A6 --data-dir ./aegis-data
```

### Display an Existing Plan
```powershell
py -m aegis_core respond show --case-id INC-023F5CADD5A6 --data-dir ./aegis-data
```

### Approve an Action
```powershell
py -m aegis_core respond approve `
  --case-id INC-023F5CADD5A6 `
  --action-id ACT-C8953BE1A8 `
  --approver "analyst@aegis.defense" `
  --rationale "Verified malicious reverse shell" `
  --data-dir ./aegis-data
```

### Reject an Action
```powershell
py -m aegis_core respond reject `
  --case-id INC-023F5CADD5A6 `
  --action-id ACT-C8953BE1A8 `
  --approver "analyst@aegis.defense" `
  --rationale "Identified as legitimate administrative task" `
  --data-dir ./aegis-data
```

### Execute Approved / Eligible Actions
```powershell
# Dry-run execution (Default, Safe)
py -m aegis_core respond execute --case-id INC-023F5CADD5A6 --data-dir ./aegis-data

# Specific action execution
py -m aegis_core respond execute --case-id INC-023F5CADD5A6 --action-id ACT-C8953BE1A8 --data-dir ./aegis-data
```

### Inspect Audit Trail
```powershell
py -m aegis_core respond audit --case-id INC-023F5CADD5A6 --data-dir ./aegis-data
```

---

## 7. Testing Instructions

Run the dedicated Response Agent test suite covering all 20 safety specifications:
```powershell
py -m pytest tests/test_response_agent.py -v
```

Run the end-to-end multi-agent demonstration scenario:
```powershell
py scripts/demo_response_agent.py
```

---

## 8. Known Limitations and Future Work

1. **Operating System Specific Containment**:
   - Host isolation on Windows requires Windows Filtering Platform (WFP) or Netsh integration; Linux requires `iptables` / `nftables` / eBPF socket filters.
   - Live execution remains disabled by default; adapter implementations must be deployed within isolated network enclaves.
2. **Credential Revocation Integration**:
   - `ACCOUNT_REVIEW` actions emit notifications and tickets; direct Active Directory / Okta / Azure AD SCIM integration requires external API connectors.
3. **Distributed Coordination**:
   - Current persistence is local SQLite (`evidence.sqlite3`). Multi-node coordination would require a distributed raft or centralized SIEM/SOAR replication layer.
