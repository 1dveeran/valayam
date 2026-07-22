// TODO: Implement Attack Surface Drift Detection (Phase 15).
// - State storage in SQLite/Redis to persist scan baselines.
// - Baseline comparison across recurring scans to detect new ports/endpoints.
// - Generate drift alerts for continuous monitoring pipelines.

pub mod executor;
pub mod state;
