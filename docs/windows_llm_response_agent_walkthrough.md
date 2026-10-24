# Windows LLM and Response Agent walkthrough

This is the operator procedure for the current checkpoint. It distinguishes a
model interpretation, a response plan, a dry-run, and a real LocalLab action.
Do not treat a plan or a simulated result as host containment.

## 1. Open the project and terminal

1. In File Explorer, open `C:\Users\Visha\OneDrive\Documents\Sem 7\Major Project`.
2. Right-click the folder background and choose **Open in Terminal**, or open
   VS Code from that folder and select **Terminal > New Terminal**.
3. Run:

```powershell
Get-Location
git branch --show-current
git rev-parse HEAD
.\.venv\Scripts\python.exe --version
```

The directory must end in `Major Project`; the branch should be
`checkpoint/response-agent-integration` or the approved committed successor.
Always invoke `.\.venv\Scripts\python.exe` so the project virtual environment
is used even if PowerShell has not been activated.

## 2. Configure the optional LLM safely

The implementation is `aegis_core\intelligence\service.py`.

- Default provider: Gemini, using `GEMINI_API_KEY`; model defaults to
  `gemini-3.5-flash-lite` unless `AEGIS_LLM_MODEL` is set.
- OpenAI-compatible provider: set `AEGIS_LLM_PROVIDER=openai-compatible`,
  `AEGIS_LLM_BASE_URL` (HTTPS only), `AEGIS_LLM_API_KEY`, and
  `AEGIS_LLM_MODEL`.
- Timeout: `AEGIS_LLM_TIMEOUT_SECONDS`, default 15 seconds.

Set a secret without displaying it:

```powershell
$secureKey = Read-Host 'Paste provider key' -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
$env:GEMINI_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
if ([string]::IsNullOrWhiteSpace($env:GEMINI_API_KEY)) { throw 'Key was not set' }
'Credential present in this PowerShell session.'
```

For the supported default, do not set `AEGIS_LLM_PROVIDER`; for an approved
OpenAI-compatible endpoint, set the three `AEGIS_LLM_*` variables above. Never
echo the key. Remove it when finished with:

```powershell
Remove-Item Env:GEMINI_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:AEGIS_LLM_API_KEY -ErrorAction SilentlyContinue
```

## 3. Prove provider connectivity

```powershell
.\.venv\Scripts\python.exe scripts\live_llm_smoke.py
```

Success prints `status=COMPLETE`, a provider/model, a nonzero grounded
reference count, and `persisted=True`. It proves a real provider received a
synthetic, bounded evidence pack; it does not prove a Windows event or a
response action.

- Missing key: `status=DISABLED`; set the appropriate variable.
- 401/403: key/account permission problem.
- 404: base URL/model/protocol mismatch.
- 429: quota/rate limit; wait or use the approved account configuration.
- 5xx/timeout: provider/network unavailable; Aegis preserves deterministic
  investigation results and reports the interpretation failure.

## 4. Run real Windows monitoring

Use a dedicated non-OneDrive directory. The file collector intentionally skips
OneDrive paths.

```powershell
$root = 'E:\AegisLab\artifacts\aegis-windows-llm-response'
.\.venv\Scripts\python.exe scripts\safe_e2e_demo.py --root $root
```

Look for nonzero process/file/network events, `chain_valid: true`, and a case
ID. `response_stage.dry_run_only: true` means no action changed the host.

Inspect the real persisted evidence:

```powershell
$data = "$root\data"
.\.venv\Scripts\python.exe -m aegis_core --analyze --data-dir $data
```

## 5. Invoke investigation with LLM and plan a response

From the safe-demo JSON, copy the `case_ids` value into `$case`.

```powershell
$case = '<INCIDENT_CASE_ID>'
.\.venv\Scripts\python.exe -m aegis_core investigate $case --data-dir $data --llm --json
.\.venv\Scripts\python.exe -m aegis_core respond plan --case-id $case --data-dir $data --json
.\.venv\Scripts\python.exe -m aegis_core respond audit --case-id $case --data-dir $data --json
```

The investigation JSON contains `llm_interpretation`. When its status is
`COMPLETE`, `respond plan` persists the same validated context as
`intelligence_context` with `authority: ADVISORY_ONLY`. The model cannot create
actions, change classification, approve anything, select a handler, or change
policy. Deterministic playbooks and `PolicyEvaluator.evaluate_action()` remain
authoritative.

If LLM status is `DISABLED`, `ERROR`, or `INVALID_OUTPUT`, planning still
works; `intelligence_context` is absent. This is the intended safe fallback.

## 6. Read plan, approval, and execution states

```powershell
.\.venv\Scripts\python.exe -m aegis_core respond show --case-id $case --data-dir $data --json
.\.venv\Scripts\python.exe -m aegis_core respond audit --case-id $case --data-dir $data --json
```

Read these literally:

- `PROPOSED` / `PENDING_APPROVAL`: not executed.
- `UNSUPPORTED` / `FAILED`: denied or unable to execute.
- `execution_result.simulated: true`: dry-run only.
- `VERIFIED` with `simulated: false`: a supported handler changed the expected
  LocalLab resource and its verifier observed that change.

The normal `respond execute` CLI uses the dry-run adapter. It is safe for
demonstrating policy/audit flow but is not live containment.

## 7. Optional bounded live LocalLab proof

Only on the controlled lab machine, run:

```powershell
.\.venv\Scripts\python.exe scripts\live_containment_demo.py
```

At each displayed prompt, type `y` then press Enter only if the target is the
script-created sandbox resource. The script may terminate only its registered
demo PID and quarantine only `aegis_sandbox\threat_payload.exe`. Verify the
final physical checks: dead PID, absent original payload, quarantine copy, and
valid audit chain. `BLOCK_NETWORK_IP` should be `UNSUPPORTED`; no firewall rule
is installed.

## 8. Clean shutdown and troubleshooting

For a foreground monitor, use a second terminal:

```powershell
.\.venv\Scripts\python.exe -m aegis_core monitor status --data-dir $data
.\.venv\Scripts\python.exe -m aegis_core monitor stop --data-dir $data
```

If telemetry is empty, confirm `$root` is outside OneDrive and exists. If
`evidence store not found` appears, pass the same `--data-dir` used by the
monitor. If no case exists, do not lower production thresholds; use the safe
demo/test fixture and label it. If an LLM response is rejected, inspect its
status and cited IDs; fabricated IDs are invalid. If an action is denied,
inspect `policy_decisions` in the audit instead of retrying with a different
case or bypassing approval.

## Final checklist

- [ ] Provider smoke test passed, or blocker recorded.
- [ ] Real Windows telemetry and persisted case observed.
- [ ] LLM interpretation status inspected.
- [ ] `intelligence_context` appears only for validated COMPLETE output.
- [ ] Response plan and policy decisions inspected.
- [ ] Dry-run is not described as live execution.
- [ ] Any LocalLab execution is independently verified.
- [ ] Audit correlates case, investigation, intelligence context, and actions.
