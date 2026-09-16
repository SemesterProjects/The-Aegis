# VM Setup Runbook

## Verified current definitions

| Field | Target | Attacker |
| --- | --- | --- |
| VM name / generation | `aegis-target-ubuntu` / 2 | `aegis-attacker` / 2 |
| vCPU | 2 | 2 |
| Dynamic memory | startup 3 GB; min 2 GB; max 4 GB | startup 2 GB; min 512 MB; max 1 TB |
| Active disk | 40 GB differencing VHDX | 30 GB differencing VHDX |
| Secure Boot | On; Microsoft UEFI CA | On; Microsoft UEFI CA |
| Adapter | `Aegis-Lab-Private` | `Aegis-Lab-Private` |

Active disks are differencing disks because a standard checkpoint exists. This is expected but makes manual baseline discipline essential. The attacker maximum memory is a **verified current risk**, not a recommended default: set a realistic maximum before concurrent use.

## Reproducible standard

Create Generation 2 VM → set `MicrosoftUEFICertificateAuthority` secure boot for Ubuntu → attach a SHA256-verified ISO → use dynamically expanding VHDX → attach **only** `Aegis-Lab-Private` → install a supported guest → apply guest updates while intentionally using a temporary controlled update path, then remove it → set static lab IP → create a standard manual checkpoint while powered off.

Example creation command (changes Hyper-V; adapt paths and memory):

```powershell
New-VM -Name aegis-target-ubuntu -Generation 2 -Path E:\AegisLab\vms\aegis-target-ubuntu -MemoryStartupBytes 3GB -NewVHDPath E:\AegisLab\vms\aegis-target-ubuntu\disk.vhdx -NewVHDSizeBytes 40GB -SwitchName Aegis-Lab-Private
Set-VMProcessor -VMName aegis-target-ubuntu -Count 2
Set-VMMemory -VMName aegis-target-ubuntu -DynamicMemoryEnabled $true -MinimumBytes 2GB -StartupBytes 3GB -MaximumBytes 4GB
Set-VMFirmware -VMName aegis-target-ubuntu -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
```

Validation: `Get-VM`, `Get-VMFirmware`, `Get-VMMemory`, `Get-VMHardDiskDrive`, and `Get-VMNetworkAdapter`. Guest hostname, user, installed packages, ISO version, and static address require guest-level verification while running.
