# AEGIS: GitHub to Ubuntu VM end-to-end guide

This guide reflects the audit. It does not assume Internet access, shared folders, or Linux parity with Windows.

## 1. Review the repository — Windows / VS Code

1. Open `C:\Users\Visha\OneDrive\Documents\Sem 7\Major Project` in VS Code and select **Terminal > New Terminal**.
2. Review work without changing it.

```powershell
git status
git diff -- aegis_core/investigation/agent.py aegis_core/response/adapters.py scripts/investigation_process_scenario.py tests
git diff -- docs
```

3. Do not use `git add .`: this checkout includes intended changes and unrelated untracked Word/report assets.
4. Verify secret and runtime exclusions.

```powershell
git check-ignore -v .env .venv e2e_data/evidence.sqlite3
git ls-files .env
```

Expected: `.env`, virtual environments, and runtime databases are ignored; `.env` must not be tracked. Never copy it to GitHub or Ubuntu.

The reviewed package declares `psutil` and `watchdog` as base runtime dependencies; use the test extra when running pytest.

In VS Code Source Control, inspect each diff and click **+** only next to intended files.

## 2. Create a safe commit — Windows terminal

After resolving the dependency blocker:

```powershell
git status
git diff --check
.\.venv\Scripts\python.exe -m pytest -q tests/test_investigation_handoff.py tests/test_response_agent.py
git add aegis_core/investigation/agent.py aegis_core/response/adapters.py scripts/investigation_process_scenario.py tests/test_investigation_agent.py tests/test_response_agent.py docs/AEGIS_END_TO_END_DEMO_RUNBOOK.md docs/AEGIS_END_TO_END_IMPLEMENTATION_REPORT.md docs/AEGIS_GITHUB_TO_VM_E2E_RUNBOOK.md
git diff --staged --check
git diff --staged
git commit -m "feat(aegis): verify controlled detection-to-response demo"
git log -1 --oneline
git status
```

If files are already staged, inspect `git diff --staged`; use `git restore --staged <file>` only for a reviewed staging mistake. Do not reset the working tree.

## 3. Push to GitHub — Windows terminal

```powershell
git branch --show-current
git remote -v
git push -u origin <branch-shown-above>
```

The audit saw `origin` at `https://github.com/SemesterProjects/The-Aegis.git`; verify owner and visibility first. Do not force-push. Inspect the GitHub commit and confirm `.env`, `.venv`, databases, VM disks, and lab artifacts are absent.

## 4. Verify Hyper-V — Windows / Hyper-V Manager

Audit-confirmed: Generation 2 VMs `aegis-attacker` and `aegis-target-ubuntu` are Off under `E:\AegisLab\vms`; `Aegis-Lab-Private` exists. Guest IPs and switch assignment are unverified.

1. Open **Hyper-V Manager**.
2. For each VM, select **Settings > Network Adapter** and record, but do not change, the assigned switch.
3. In **Virtual Switch Manager**, record the type of `Aegis-Lab-Private`.
4. Select `aegis-target-ubuntu` > **Connect** > **Start**, then log in.
5. Discover topology in Ubuntu.

```bash
ip -brief address
ip route
getent hosts github.com || true
```

A private switch does not imply Internet, host-drive sharing, or GitHub access.

## 5. Move the project to Ubuntu

Preferred only if GitHub resolves:

```bash
git clone <verified-GitHub-repository-URL> ~/aegis
cd ~/aegis
```

Otherwise use a dedicated, least-privilege transfer directory after verifying an existing SCP/SSH or share setup. Hyper-V shared folders are not assumed. Never expose a host drive, personal directories, SSH keys, or `.env`.

## 6. Install Aegis — Ubuntu terminal

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
python -m aegis_core --help
python -m aegis_core --capability-report --watch /tmp/aegis-watch
```

The capability report is authoritative. `psutil` supports rich process/network collection; `watchdog` enables native file events with polling fallback. Linux authentication may require accessible `journalctl` or `/var/log/auth.log`; eBPF is optional and kernel/privilege dependent.

## 7. Safe VM end-to-end test — Ubuntu terminal

```bash
mkdir -p /tmp/aegis-e2e
python scripts/investigation_process_scenario.py --root /tmp/aegis-e2e --count 10 --hold-seconds 30
python -c "from pathlib import Path; import json; from aegis_core.storage import EvidenceStore; s=EvidenceStore(Path('/tmp/aegis-e2e/data/evidence.sqlite3')); print(json.dumps({'events':s.count_events(),'findings':len(s.get_findings()),'cases':len(s.query_cases()),'chain_valid':s.verify_chain()},indent=2)); s.close()"
```

Expected: nonzero starts, an `AEGIS-PROC-001` finding, persisted case, pending response approval, and `chain_valid: true`. This is real local telemetry with dry-run response. If capabilities differ, record and diagnose them rather than claiming Linux success. Do not use `--live-terminate` for the default VM test.

Historical Windows live-containment failure: an earlier run reported that a registered lab process was unavailable for identity verification. The current adapter deliberately fails closed in that situation; do not weaken the creation-time and command-marker verification. This VM guide does not perform live containment.

```bash
python -m aegis_core investigate pending --data-dir /tmp/aegis-e2e/data --json
```

## 8. Panel evidence

Capture VM settings and `ip -brief address` (environment only); capability report (available collectors); scenario summary and persisted SQLite counts (collection/finding/case/chain); investigation JSON (evidence, uncertainty, stop reason); response-plan approval state; and pytest output (regression evidence, not proof of live telemetry).
