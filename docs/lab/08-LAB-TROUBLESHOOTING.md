# Troubleshooting

## Hyper-V

### VM will not start / insufficient RAM

**Likely cause:** host pressure or an invalid memory configuration. **Verify:** `Get-VM`, `Get-VMMemory`, Task Manager memory. **Fix:** power off the other guest; reduce a *newly planned* configuration; do not alter a clean baseline without recording it. **Verify again:** VM reports `Operating normally`. **Rollback:** restore the documented VM memory settings.

### Permission, VMMS, disk, or checkpoint failure

**Verify:** `Get-Service vmms`, `whoami /groups`, `Get-VMHardDiskDrive`, `Get-VMSnapshot`. **Fix:** ensure Hyper-V Administrators membership, start `vmms`, free storage, or wait for a merge. Never delete `.avhdx` files manually. **Rollback:** stop and seek review if merge state is unclear.

## Networking

### No address / attacker cannot reach target

**Likely cause:** missing guest static configuration or wrong switch. **Verify:** `Get-VMNetworkAdapter`, then guest `ip -br address` and `ip route`. **Fix:** correct guest netplan/static settings or reconnect only to `Aegis-Lab-Private`. **Verify again:** IP and selected TCP test. **Rollback:** restore guest baseline.

### Refused TCP connection / service unavailable

**Verify:** `ss -lntp`, guest firewall state, service status. **Fix:** start only the intended lab service and document it. **Rollback:** stop service or restore checkpoint.

### Unexpected Internet connectivity

**Verify:** guest `ip route`; Hyper-V adapter attachment. **Fix:** stop the experiment, remove default route in guest, and reconnect only to private switch. **Verify again:** no default route and no host private adapter. **Rollback:** restore clean checkpoint.

## Ubuntu and resources

Missing commands/packages require an approved, temporary update path; record it and return to isolation. For netplan syntax, run `sudo netplan try` before `sudo netplan apply`. If both guests burden the host, shut down one and use staged evidence/replay instead.
