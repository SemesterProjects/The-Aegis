# Lab Validation Checklist

Use this acceptance checklist after any material lab change.

## Host

- [x] Hyper-V `vmms` running — `Get-Service vmms` — verified current.
- [x] Lab root contains `isos`, `vms`, `checkpoints`, `artifacts` — `Get-ChildItem E:\AegisLab` — verified current.

## Network

- [x] `Aegis-Lab-Private` is Private — `Get-VMSwitch` — verified current.
- [x] No host `vEthernet (Aegis-Lab-Private)` — `Get-NetAdapter -IncludeHidden` — verified current.
- [x] No lab NAT — `Get-NetNat` returned no lab mapping — verified current.
- [ ] Internet Connection Sharing does not share a lab interface — inspect `SharedAccess` and adapter sharing properties — not verified in the powered-off final inspection.
- [ ] Target static address `10.10.10.10/24` — guest `ip -br address` — unverified while off.
- [ ] Attacker static address `10.10.10.20/24` — guest `ip -br address` — unverified while off.
- [ ] No guest default route during experiment — guest `ip route` — unverified while off.

## VMs and checkpoints

- [x] Both VM definitions are Generation 2 and attach only to private switch — Hyper-V inspection — verified current.
- [x] Both have Standard clean checkpoints — `Get-VMSnapshot` — verified current.
- [x] Automatic checkpoints disabled — `Get-VM` — verified current.
- [ ] Guest OS, tools, services, and baseline cleanliness — guest-level validation — unverified while off.

## Status

**PARTIALLY READY.** Hyper-V isolation and checkpoint infrastructure are verified. Controlled security experiments require the remaining guest-level address, route, service, and baseline-cleanliness checks after an approved boot. It is ready for documentation-led development preparation, not yet verified ready for controlled experiments.
