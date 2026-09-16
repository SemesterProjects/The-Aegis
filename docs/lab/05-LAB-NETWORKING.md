# Networking Runbook

## Required standard, not verified current guest state

Use `10.10.10.0/24`: target `10.10.10.10/24`, attacker `10.10.10.20/24`; no gateway, no DNS, no DHCP, and no default route during experiments. Static addresses make evidence timelines repeatable and avoid a DHCP service becoming a hidden dependency.

Private switch behavior provides Layer-2 VM-to-VM connectivity only. It does not establish IP configuration or a TCP service. Validate each layer separately after booting approved VMs:

```powershell
# Host: verify attachment, not guest reachability
Get-VMNetworkAdapter -VMName aegis-target-ubuntu | Format-Table VMName,SwitchName,Status
Get-VMNetworkAdapter -VMName aegis-attacker | Format-Table VMName,SwitchName,Status
Get-NetNat
Get-Service SharedAccess
```

```bash
# Guest: address and route
ip -br address; ip route
# Guest-to-guest IP, then a deliberate TCP listener/service test
ping -c 3 10.10.10.20
nc -vz 10.10.10.20 8080
# Internet absence must be explicit
ip route | grep default && echo 'unexpected default route'
```

`ping` proves neither a service nor complete isolation. `nc` proves a chosen TCP port is reachable only when a deliberately enabled listener exists. Verify host isolation by confirming no `vEthernet (Aegis-Lab-Private)` adapter; verify Internet isolation by absence of a guest default route and failed external route checks. `Get-NetNat` must not show a lab NAT, and Windows Internet Connection Sharing (`SharedAccess`) must not provide connectivity for the lab switch. Do not add a gateway or bridge for experiments.
