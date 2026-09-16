# Windows and Hyper-V Setup Runbook

Run elevated PowerShell only when a step changes Hyper-V. Commands below are reproducible; review paths before executing.

| Objective | Action | Verify / expected | Failure and recovery |
| --- | --- | --- | --- |
| Verify edition | `Get-ComputerInfo | Select WindowsProductName` | Pro/Enterprise/Education | Upgrade supported edition; do not bypass edition checks. |
| Verify virtualization | `systeminfo` | Hyper-V requirements are Yes, or hypervisor detected | Enable VT-x/AMD-V and DEP in UEFI only with owner approval. |
| Enable Hyper-V | `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All` | Feature enabled; reboot requested if needed | Reboot; inspect Windows Features and firmware settings. |
| Verify service | `Get-Service vmms` | Running, Automatic | Start service; inspect Event Viewer if it fails. |
| Create lab folders | `'isos','vms','checkpoints','artifacts' \| ForEach-Object { New-Item -ItemType Directory -Path (Join-Path 'E:\AegisLab' $_) -Force }` | Four folders exist | Confirm `E:` capacity and path before retrying. |
| Create private switch | `New-VMSwitch -Name Aegis-Lab-Private -SwitchType Private` | `SwitchType : Private` | Do not substitute Internal or External. Remove only an incorrectly created empty switch with approval. |
| Verify isolation | `Get-VMSwitch -Name Aegis-Lab-Private`; `Get-NetAdapter -IncludeHidden -Name 'vEthernet (Aegis-Lab-Private)'` | Private; second command returns nothing | If a host adapter exists, stop and inspect switch type; do not attach VMs until corrected. |

GUI alternative: Hyper-V Manager → **Virtual Switch Manager** → **New virtual network switch** → **Private** → name `Aegis-Lab-Private` → Apply. ISO files belong in `E:\AegisLab\isos`; verify `Get-FileHash -Algorithm SHA256` against the publisher checksum before mounting.
