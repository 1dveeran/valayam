# ADR-004: Provenance & Audit Trail

**Status:** Accepted (2026-07-26)  
**Deciders:** Valayam Engineering Team  
**Tags:** audit, HMAC, provenance, tamper-proof

## Context

Security scanning results must be trustworthy. Without an audit trail, findings could be silently modified, deleted, or fabricated. Compliance requirements (SOC 2, FedRAMP) demand tamper-evident logs.

## Decision

1. **JSONL audit log** (`valayam-core/src/audit.rs`): Every scan event (start, plugin execution, finding, completion) written as a newline-delimited JSON record.
2. **HMAC hash chain**: Each audit record includes `prev_hash` (SHA-256 of previous record) and `hmac` (keyed-HMAC of current record). Per-session UUID key prevents replay across sessions. Tampering breaks the chain — detectable by re-computing hashes.
3. **Scan session UUID**: `scan_id: Uuid` threaded through the entire MPSC pipeline — from `ScanContext` to `FindingOwned`. Enables grouping findings by scan session.
4. **Plugin coverage validation**: At startup, warns if template sections have zero applicable plugins registered. Prevents silent gaps in scan coverage.
5. **SafePluginFuture**: `panic::catch_unwind` wrapper around plugin execution. Plugin panics captured as audit events rather than crashing the scanner.

## Consequences

**Positive:** Full tamper-evident chain-of-custody for all scan findings. Session UUID enables cross-referencing findings with telemetry. Plugin coverage warnings prevent silent scanning gaps.  
**Negative:** HMAC computation adds ~0.5ms per audit record. Audit log grows linearly with scan duration. Session UUID adds field to every event struct.  
**Risks:** Clock skew between distributed components could affect audit ordering. Mitigated by using monotonic scan sequence numbers alongside wall-clock timestamps.