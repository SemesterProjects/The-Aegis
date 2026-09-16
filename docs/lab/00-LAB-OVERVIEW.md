# Lab Overview

## Purpose and scope

The Aegis laboratory is isolated development and authorized security-testing infrastructure. It supports reproducible host and network observations, benign application fixtures, controlled security experiments, evidence capture, and checkpoint-based recovery.

It is not a production environment, a general penetration-testing environment, an Internet-facing service, or the Aegis product architecture. It must never be used against systems without explicit authorization.

## Current scope — verified current

| VM | Role | State at inspection | Switch | Clean baseline |
| --- | --- | --- | --- | --- |
| `aegis-target-ubuntu` | target | Off | `Aegis-Lab-Private` | Standard checkpoint, 2026-09-16 18:24 |
| `aegis-attacker` | authorized testing source | Off | `Aegis-Lab-Private` | Standard checkpoint, 2026-09-16 18:23 |

The lifecycle is: establish clean baseline → validate isolation → run one authorized experiment → save evidence externally → restore baseline → record outcome. The engineer running an experiment owns the baseline selection, evidence, and cleanup.

## Product boundary

Forge/Hunter/Guardian may later use the lab to validate pre-deployment security work. Shield may later use lab scenarios to validate runtime observation and response. The lab provides test hosts and isolation only; it must not force Linux-specific Core contracts or limit Aegis’s Windows/macOS design.

See [architecture](01-LAB-ARCHITECTURE.md) and [operations](06-LAB-OPERATIONS.md).
