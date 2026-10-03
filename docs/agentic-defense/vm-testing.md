# VM Testing Status and Procedure

Verified laboratory facts from the final Hyper-V record: `aegis-target-ubuntu` and `aegis-attacker` are Generation 2 VMs on the Private `Aegis-Lab-Private` switch with clean Standard checkpoints. No NAT or host vEthernet interface is present. Guest IP configuration, credentials, OS package state, and VM connectivity were not verified while powered off; do not invent them.

The host test is verified on Windows. Linux VM and macOS testing are **NOT VERIFIED by this task**. After a maintainer intentionally boots the target VM and confirms its private IP/credentials, run the same clean-install and safe E2E commands in the VM. Verify the private switch attachment first using the lab runbooks, then use only a dedicated VM test directory. Do not attach an external switch or bridge it for this test.

| Test | Windows host | Linux VM | Expected |
| --- | --- | --- | --- |
| Process lifecycle | verified | not verified | canonical process event |
| File lifecycle | verified | not verified | canonical file event |
| Loopback network | verified | not verified | canonical network event |
| Multi-signal case | verified | not verified | persistent `NEW` case |
