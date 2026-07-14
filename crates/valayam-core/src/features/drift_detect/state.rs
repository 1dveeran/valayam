use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanState {
    pub ports_open: Vec<u16>,
    pub endpoints_discovered: Vec<String>,
}

pub fn save_state(_id: &str, _state: &ScanState, _backend: &Option<String>) {
    // MVP: Save to .valayam-state/ as JSON
}

pub fn load_state(_id: &str, _backend: &Option<String>) -> Option<ScanState> {
    // MVP: Load from .valayam-state/ as JSON
    None
}
