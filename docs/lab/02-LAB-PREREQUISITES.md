# Prerequisites

## Required standard checklist

| Area | Requirement | Verify |
| --- | --- | --- |
| Windows | Windows 10/11 Pro, Enterprise, or Education | `Get-ComputerInfo | Select WindowsProductName` |
| CPU | x64, VT-x/AMD-V, SLAT, VM monitor extensions | `systeminfo` → Hyper-V Requirements |
| RAM | 16 GB preferred; 8 GB minimum for one small guest | Task Manager → Performance → Memory |
| Disk | 80 GB free recommended for two guests plus checkpoints | `Get-PSDrive E` |
| Hyper-V | Hyper-V platform, management tools, `vmms` running | `Get-Service vmms` |
| Access | local administrator or Hyper-V Administrators membership | `whoami /groups` |
| Tooling | PowerShell, Git, approved Ubuntu server ISO and SHA256SUMS | `git --version`; `Get-FileHash` |
| Repository | read access to team repository; write only for approved changes | `git remote -v` |

## Recommended configurations

For two concurrently running lightweight guests: 16 GB RAM, 4+ physical cores, and 100 GB free storage. On a constrained host, retain the same private-network semantics but use one guest at a time and smaller startup memory. Do not assume the current laptop settings apply to another engineer.

Administrative rights can change Hyper-V and host networking; use them only through reviewed runbooks. Never place ISO checksums, credentials, or private keys in source control.
