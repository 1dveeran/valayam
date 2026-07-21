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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_snapshot_serde() {
        let snapshot = ScanSnapshot {
            id: "test-scan-001".into(),
            pending_targets: vec!["https://example.com".into(), "https://test.com".into()],
            completed_targets: vec!["https://done.com".into()],
            timestamp: 1700000000,
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let back: ScanSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "test-scan-001");
        assert_eq!(back.pending_targets.len(), 2);
        assert_eq!(back.timestamp, 1700000000);
    }

    #[test]
    fn test_scan_snapshot_empty_lists() {
        let snapshot = ScanSnapshot {
            id: "empty-scan".into(),
            pending_targets: vec![],
            completed_targets: vec![],
            timestamp: 1700000000,
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("empty-scan"));
    }

    #[test]
    fn test_state_db_creates_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("sub").join("state");
        let db = StateDB::new(&nested).unwrap();
        assert!(nested.exists());
        drop(db);
    }

    #[test]
    fn test_state_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDB::new(dir.path()).unwrap();
        db.save_state("scan-1", &["https://target.com".into()], &[]).unwrap();
        let loaded = db.load_state("scan-1").unwrap();
        assert!(loaded.is_some());
        let (pending, completed) = loaded.unwrap();
        assert_eq!(pending, vec!["https://target.com"]);
        assert!(completed.is_empty());
    }

    #[test]
    fn test_state_load_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDB::new(dir.path()).unwrap();
        let loaded = db.load_state("nonexistent").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_state_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDB::new(dir.path()).unwrap();
        db.save_state("s", &["https://old.com".into()], &[]).unwrap();
        db.save_state("s", &["https://new.com".into()], &["https://old.com".into()]).unwrap();
        let (p, c) = db.load_state("s").unwrap().unwrap();
        assert_eq!(p, vec!["https://new.com"]);
        assert_eq!(c, vec!["https://old.com"]);
    }
}
