# Aegis Laboratory Runbooks

This package is the operating source of truth for the local Hyper-V lab. It
documents verified current state separately from standards and recommendations.
It does not define Aegis Core, Forge, Shield, Hunter, or Guardian architecture.

## Read in this order

1. [Overview](00-LAB-OVERVIEW.md) and [architecture](01-LAB-ARCHITECTURE.md)
2. [Prerequisites](02-LAB-PREREQUISITES.md) and the [Windows/Hyper-V setup runbook](03-LAB-SETUP-WINDOWS-HYPERV.md)
3. [VM setup](04-LAB-VM-SETUP.md) and [networking](05-LAB-NETWORKING.md)
4. [Operations](06-LAB-OPERATIONS.md), [experiment runbook](07-LAB-EXPERIMENT-RUNBOOK.md), and [troubleshooting](08-LAB-TROUBLESHOOTING.md)
5. [Team handoff](09-LAB-TEAM-HANDOFF.md), [reproducibility](10-LAB-REPRODUCIBILITY.md), [security controls](11-LAB-SECURITY-CONTROLS.md), and the [validation checklist](12-LAB-VALIDATION-CHECKLIST.md)

The previous compact record remains at [../13-lab-environment.md](../13-lab-environment.md). This package supersedes it where it labels a value as **verified current**.

## Reconciliation with the earlier record

The final powered-off Hyper-V inspection found material differences from `docs/13-lab-environment.md`: both VMs are now Off (the earlier record observed the attacker running); automatic checkpoints are disabled on both VMs (the earlier record said they were enabled on the attacker); both VMs have 2 vCPUs (the earlier target value was 1); the target starts at 3 GB (not 2 GB); and the attacker maximum is 1 TB (not a safe operating default). The current active disks are `.avhdx` differencing disks, which is expected because the clean Standard checkpoints are retained. These are not changes made by this documentation task.

## Status convention

- **Verified current** — read from the local Hyper-V host on 2026-09-16.
- **Required standard** — mandatory for an Aegis experiment.
- **Recommended default** — reproducible default for a new engineer.
- **Machine-specific** — must be adapted locally.
- **Future/planned** — intentionally not implemented.
