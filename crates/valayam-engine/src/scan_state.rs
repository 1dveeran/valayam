//! ScanState — Tracks the pause/resume status of a scan execution.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanState {
    Running,
    Paused,
}
