# Lab Architecture

## Verified current topology

```text
Windows 11 Pro developer host
  └─ Hyper-V boundary
       └─ Aegis-Lab-Private (Private switch; no host vEthernet adapter)
            ├─ aegis-target-ubuntu   [static IP planned: 10.10.10.10]
            └─ aegis-attacker        [static IP planned: 10.10.10.20]
```

**Verified current:** the switch is Hyper-V `Private`; both adapters attach only to it; no lab NAT exists; no `vEthernet (Aegis-Lab-Private)` host adapter exists. Private switch semantics permit VM-to-VM Layer-2 traffic but not host, physical LAN, or Internet routing.

**Unverified while powered off:** guest IP configuration, subnet, DNS, routes, and target/attacker connectivity. Therefore `10.10.10.0/24` and the addresses shown above are **required standard**, not verified current values.

## Lab versus product

The host, switch, VMs, checkpoints, and artifacts directory are lab components. Platform adapters, normalized evidence, investigation, policy, and execution controls belong to Aegis. Future Windows, macOS, service, or sensor VMs fit on additional isolated segments; they do not change Aegis Core’s OS-independent design.

## Resource boundary

**Machine-specific:** current host is Windows 11 Pro, Intel i3-1115G4 (2 physical cores/4 logical processors), 16 GB RAM. Both current VMs have 2 vCPUs. Run one guest by default; run both only for a time-bounded connectivity experiment after confirming host responsiveness.
