# Security Controls

The primary control is the Hyper-V Private switch: no host, LAN, or Internet route. Keep experiments authorized, bounded to named lab guests, and never bridge networking for convenience. Use least privilege in guests and restrict Hyper-V administration to trusted engineers.

Treat VM credentials, keys, and collected evidence as sensitive. Store secrets outside Git; preserve evidence with timestamps and hashes; redact before sharing. Use clean checkpoints before experiments, but understand they cannot undo host-side effects or recover evidence stored only in a guest.

The lab can safely test benign fixtures and controlled signals on isolated guests. It cannot justify testing real malware, external systems, production endpoints, or attacks that require Internet exposure. Host Windows protections remain enabled; no experiment may require disabling them without explicit separate authorization.
