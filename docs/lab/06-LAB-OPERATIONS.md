# Lab Operations

## Startup and shutdown

Start only the VM(s) named in an approved experiment record. On this 2-core host, start the target first and confirm memory/CPU pressure before starting the attacker. Use guest graceful shutdown first; Hyper-V **Turn Off** is only for an unresponsive guest after preserving relevant evidence.

```powershell
Start-VM aegis-target-ubuntu
Get-VM aegis-target-ubuntu,aegis-attacker | Format-Table Name,State,Status
Stop-VM aegis-target-ubuntu -Shutdown
```

Expected: Hyper-V status is `Operating normally`; guest-level readiness remains unverified until inspected in the guest.

## Baselines and experiments

A clean checkpoint is a known-good, powered-off recovery point—not a backup, export, or substitute for evidence handling. Before an experiment: record baseline name, confirm private attachment, verify guest routing, define evidence destination, and use approved targets only. Afterwards: copy permitted evidence to `E:\AegisLab\artifacts`, record outcome, shut down, and restore the selected baseline.

Use explicit checkpoints: automatic checkpoints are **verified disabled** on both current VMs. New baseline only after documented updates/configuration changes and re-validation.

## Artifacts

Store artifacts outside guests under `E:\AegisLab\artifacts\YYYY-MM-DD\EXP-<id>\`. Include `metadata.md`, timestamps with timezone, hashes of collected files, logs, and later packet captures. Do not store credentials or unredacted secrets.
