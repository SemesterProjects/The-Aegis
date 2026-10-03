# Safe Ransomware-Like Behavior Simulation

Use only `scripts/safe_e2e_demo.py` and its caller-provided dedicated root. It creates test files, changes their content, renames one, deletes one, and produces a local HTTP request. It does not encrypt files, alter user documents, use external infrastructure, or perform rollback.

The expected triage wording is **unusual burst of file changes** / **ransomware-like behavior requiring investigation**, not confirmed ransomware. The case records exact event IDs for the Investigation Agent.
