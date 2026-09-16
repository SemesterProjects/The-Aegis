# Reproducibility and Automation Direction

## Canonical approach

Version documentation, PowerShell templates, non-secret manifests, guest configuration templates, ISO URLs/checksums, and validation commands. Never commit VM disks, checkpoint chains, passwords, private keys, tokens, API keys, or unapproved host-identifying data.

## Practical evolution

Start with reviewed `scripts/lab/` PowerShell commands only after the current manual runbook has been proven on a second machine. Each script must state purpose, inputs, prerequisites, changes, idempotency, verification, and failure behavior. Suitable first automations: directory creation, switch creation with type check, VM definition creation, and read-only validation. Do not automate guest credentials or destructive disk operations without explicit review.

An environment manifest should capture standardized VM names, intended topology, ISO checksum, and resource *ranges*, while keeping local paths and credentials outside Git. Terraform/Packer are deferred: they add no current benefit over PowerShell plus documented guest configuration.
