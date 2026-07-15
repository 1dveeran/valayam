use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ScanSnapshot {
    pub id: String,
    pub pending_targets: Vec<String>,
    pub completed_targets: Vec<String>,
    pub timestamp: u64,
}

pub struct StateDB {
    base_dir: PathBuf,
}

impl StateDB {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> std::io::Result<Self> {
        let path = base_dir.as_ref().to_path_buf();
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        Ok(Self { base_dir: path })
    }

    pub fn save_state(&self, state_id: &str, pending: &[String], completed: &[String]) -> std::io::Result<()> {
        let snapshot = ScanSnapshot {
            id: state_id.to_string(),
            pending_targets: pending.to_vec(),
            completed_targets: completed.to_vec(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let file_path = self.base_dir.join(format!("{}.json", state_id));
        let tmp_path = self.base_dir.join(format!("{}.json.tmp", state_id));
        
        let data = serde_json::to_string_pretty(&snapshot)?;
        
        // Atomic write: write to temp file first, then rename over the real file
        fs::write(&tmp_path, data)?;
        fs::rename(&tmp_path, &file_path)?;
        
        Ok(())
    }

    pub fn load_state(&self, state_id: &str) -> std::io::Result<Option<(Vec<String>, Vec<String>)>> {
        let file_path = self.base_dir.join(format!("{}.json", state_id));
        
        if !file_path.exists() {
            return Ok(None);
        }

        let data = fs::read_to_string(file_path)?;
        let snapshot: ScanSnapshot = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(Some((snapshot.pending_targets, snapshot.completed_targets)))
    }
}
