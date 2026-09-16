# Team Handoff

Git transfers documentation and automation—not running VMs, checkpoints, or this laptop’s `E:` drive. Canonical workflow is reproducible setup on each engineer’s machine; VM export/import is an optional convenience only after security review.

Use a protected GitHub repository with pull requests, required review, and CI that checks Markdown links and any future PowerShell scripts. Keep the runbooks, non-secret manifests, ISO checksums, and guest-configuration templates in Git. Do not use Git or Git LFS for VHDX/AVHDX files, checkpoints, artifacts containing sensitive evidence, passwords, or private keys: they are large, machine-bound, potentially sensitive, and checkpoint chains are easy to corrupt when copied independently.

## New engineer day-1 checklist

1. Clone the repository and read this package.
2. Meet [prerequisites](02-LAB-PREREQUISITES.md); obtain Hyper-V and repository access.
3. Create an equivalent local lab root; adapt machine-specific paths, CPU, and RAM.
4. Create `Aegis-Lab-Private`; verify no host adapter and no external attachment.
5. Reproduce target and attacker from [VM setup](04-LAB-VM-SETUP.md).
6. Configure the required static private addresses; validate all network layers.
7. Create manual clean checkpoints and register the local details in the team’s approved tracker.

Do not depend on the original laptop being online. Preserve standard names and private-network semantics, but never copy passwords, private keys, ISO files without hashes, or machine-specific secrets through Git.
