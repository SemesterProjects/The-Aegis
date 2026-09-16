# Aegis Lab Environment

## Purpose

This record defines the isolated Hyper-V laboratory used for authorized Aegis
development and security demonstrations. It is not a production environment
and must never be used to test external or unauthorized systems.

## Host and storage

- Host: Dell Inspiron 15 3511, Windows 11 Pro, Intel i3-1115G4 (2 cores / 4
  logical processors), 16 GB RAM.
- Hypervisor: Microsoft Hyper-V.
- Lab root: `E:\AegisLab`.
- Layout: `isos\`, `vms\`, `checkpoints\`, and `artifacts\`.

## Network boundary

- Switch: `Aegis-Lab-Private`.
- Type: Hyper-V Private.
- Expected scope: VM-to-VM only; no physical-host, LAN, or Internet route.
- Internet must be attached only temporarily for operating-system patching or
  package installation, then removed before experiments.

## VM inventory and clean baselines

| Setting | Value |
| --- | --- |
| Name | `aegis-target-ubuntu` |
| Role | Ubuntu target environment |
| Generation | 2 with Secure Boot (Microsoft UEFI Certificate Authority template) |
| CPU | 1 virtual processor |
| Memory | Dynamic: 2 GB startup, 2-4 GB range |
| Disk | 40 GB dynamically expanding VHDX |
| Network | `Aegis-Lab-Private` only |

| Setting | Value |
| --- | --- |
| Name | `aegis-attacker` |
| Role | Authorized testing environment |
| Generation | 2 |
| Network | `Aegis-Lab-Private` only |

Both VMs have a standard Hyper-V checkpoint created on 2026-09-16. These are
the clean baselines for lab work. Restore the relevant checkpoint before a new
experiment, and record evidence outside the VM in `E:\AegisLab\artifacts`.

## Verification record — 2026-09-16

- Both VM adapters are attached to `Aegis-Lab-Private` and not to the Default
  Switch or an external switch.
- `Aegis-Lab-Private` is a Hyper-V **Private** switch. Windows has no
  `vEthernet (Aegis-Lab-Private)` host adapter, so it is not a host/LAN bridge.
- No lab NAT was found. The unrelated Hyper-V Default Switch remains present
  for normal Hyper-V use but is not attached to either lab VM.
- `aegis-attacker` was running and `aegis-target-ubuntu` was powered off at
  verification time; both reported normal Hyper-V status.
- `aegis-attacker` currently has automatic checkpoints enabled. Leave it as
  is for this handoff, but disable automatic checkpoints before experiments to
  avoid unexpected differencing disks and restore/merge delays.

## Operating rules

- Keep no more than one guest running during normal development on this host.
- Do not use external/bridged networking for experiments.
- Do not install malware or target external systems.
- Restore the clean checkpoint before a new experiment, and preserve evidence
  in `E:\AegisLab\artifacts` rather than in the baseline.
- A second testing VM is deferred until the target baseline is proven stable;
  it must not run concurrently with the target on this 2-core host.
