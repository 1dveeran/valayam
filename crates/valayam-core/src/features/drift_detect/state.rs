use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::core::error::ScannerError;

/// Represents the discovered state of a target during a scan.
/// Persisted between scans for drift detection.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanState {
    /// TCP/UDP ports found open on the target
    pub ports_open: Vec<u16>,
    /// HTTP endpoints discovered during crawling
    pub endpoints_discovered: Vec<String>,
    /// Optional MD5 hash of the response body for content drift detection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body_hash: Option<String>,
    /// Optional MD5 hash of response headers structure for header drift detection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_headers_hash: Option<String>,
    /// Optional HTTP response status code for status drift detection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
}

/// Default directory for persisting scan state between runs.
const DEFAULT_STATE_DIR: &str = ".valayam-state";

/// Acquire a process-wide lock for state file operations.
/// This ensures threads within the same process don't concurrently write state files.
fn state_lock() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

/// Get the state file path for a given ID.
fn state_path(state_dir: &Path, id: &str) -> PathBuf {
    state_dir.join(format!("{}.json", id))
}

/// Get the temporary file path used during atomic writes.
fn temp_state_path(state_dir: &Path, id: &str) -> PathBuf {
    state_dir.join(format!("{}.json.tmp", id))
}

/// Get the backup file path for a given state ID.
fn backup_state_path(state_dir: &Path, id: &str) -> PathBuf {
    state_dir.join(format!("{}.json.backup", id))
}

/// Resolve the state directory from the backend parameter, falling back to `.valayam-state/`.
fn resolve_state_dir(backend: &Option<String>) -> PathBuf {
    match backend {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(DEFAULT_STATE_DIR),
    }
}

/// Ensure the state directory exists, creating it (and all parents) if necessary.
fn ensure_state_dir(state_dir: &Path) -> Result<(), ScannerError> {
    if !state_dir.exists() {
        fs::create_dir_all(state_dir).map_err(|e| {
            ScannerError::ConfigurationError(format!(
                "Failed to create state directory '{}': {}",
                state_dir.display(),
                e
            ))
        })?;
        info!(directory = %state_dir.display(), "Created state directory");
    }
    Ok(())
}

/// Save scan state to a JSON file using atomic write semantics.
///
/// # Atomicity
/// 1. Serialize state to pretty-printed JSON.
/// 2. Write to a temporary file in the same directory (`{id}.json.tmp`).
/// 3. If the state file already exists, rename it to a backup (`{id}.json.backup`).
/// 4. Rename the temporary file to the final path (`{id}.json`).
///
/// This ensures that a crash during writing will never leave a partially-written state file.
/// On the next load, the backup will be used if the primary file is missing or corrupted.
///
/// # Arguments
/// * `id` - Unique identifier for this state (e.g., baseline_id)
/// * `state` - The scan state to persist
/// * `backend` - Optional custom state directory path. Uses `.valayam-state/` if None.
pub fn save_state(id: &str, state: &ScanState, backend: &Option<String>) -> Result<(), ScannerError> {
    let _lock = state_lock().lock().map_err(|e| {
        ScannerError::ConfigurationError(format!("Failed to acquire state lock: {}", e))
    })?;

    let state_dir = resolve_state_dir(backend);
    ensure_state_dir(&state_dir)?;

    // Serialize to pretty-printed JSON
    let json = serde_json::to_string_pretty(state).map_err(|e| {
        ScannerError::ParseError(format!("Failed to serialize state for '{}': {}", id, e))
    })?;

    // Write to a temporary file in the same directory
    let temp_path = temp_state_path(&state_dir, id);
    {
        let mut file = fs::File::create(&temp_path).map_err(|e| {
            ScannerError::ConfigurationError(format!(
                "Failed to create temporary state file '{}': {}",
                temp_path.display(),
                e
            ))
        })?;

        file.write_all(json.as_bytes()).map_err(|e| {
            ScannerError::ConfigurationError(format!(
                "Failed to write to temporary state file '{}': {}",
                temp_path.display(),
                e
            ))
        })?;

        // Force flush to disk for crash safety
        file.sync_all().map_err(|e| {
            ScannerError::ConfigurationError(format!(
                "Failed to sync temporary state file '{}': {}",
                temp_path.display(),
                e
            ))
        })?;
    }

    let final_path = state_path(&state_dir, id);
    let backup_path = backup_state_path(&state_dir, id);

    // Create a backup of the existing state file before overwriting
    if final_path.exists() {
        // Remove old backup if it exists
        if backup_path.exists() {
            fs::remove_file(&backup_path).map_err(|e| {
                ScannerError::ConfigurationError(format!(
                    "Failed to remove old backup '{}': {}",
                    backup_path.display(),
                    e
                ))
            })?;
        }

        fs::rename(&final_path, &backup_path).map_err(|e| {
            ScannerError::ConfigurationError(format!(
                "Failed to rename state file to backup '{}': {}",
                backup_path.display(),
                e
            ))
        })?;

        debug!(backup = %backup_path.display(), "Created state backup before overwrite");
    }

    // Atomic rename: temporary file -> final path
    // On Unix this is an atomic replace; on Windows, remove destination first.
    #[cfg(target_os = "windows")]
    {
        let _ = fs::remove_file(&final_path);
    }
    fs::rename(&temp_path, &final_path).map_err(|e| {
        ScannerError::ConfigurationError(format!(
            "Failed to rename temporary state file to '{}': {}",
            final_path.display(),
            e
        ))
    })?;

    info!(id = %id, path = %final_path.display(), "State saved successfully");
    Ok(())
}

/// Load scan state from a JSON file.
///
/// # Corruption Handling
/// If the primary state file is corrupted (invalid JSON or I/O error), the function
/// attempts to recover from the backup file (`{id}.json.backup`). If the backup is also
/// corrupted, `Ok(None)` is returned and an error is logged.
///
/// # Arguments
/// * `id` - Unique identifier for this state
/// * `backend` - Optional custom state directory path
///
/// # Returns
/// * `Ok(Some(state))` - State loaded successfully
/// * `Ok(None)` - No state file exists or all copies are corrupted
/// * `Err(e)` - Unexpected error
pub fn load_state(id: &str, backend: &Option<String>) -> Result<Option<ScanState>, ScannerError> {
    let _lock = state_lock().lock().map_err(|e| {
        ScannerError::ConfigurationError(format!("Failed to acquire state lock: {}", e))
    })?;

    let state_dir = resolve_state_dir(backend);
    let final_path = state_path(&state_dir, id);

    if !final_path.exists() {
        debug!(id = %id, "No state file found at '{}'", final_path.display());
        return Ok(None);
    }

    // Attempt to read and parse the primary state file
    match fs::read_to_string(&final_path) {
        Ok(contents) => {
            match serde_json::from_str::<ScanState>(&contents) {
                Ok(state) => {
                    debug!(id = %id, "State loaded from '{}'", final_path.display());
                    return Ok(Some(state));
                }
                Err(parse_err) => {
                    warn!(
                        id = %id,
                        error = %parse_err,
                        "State file '{}' is corrupted, attempting backup recovery",
                        final_path.display()
                    );
                }
            }
        }
        Err(io_err) => {
            warn!(
                id = %id,
                error = %io_err,
                "Failed to read state file '{}', attempting backup recovery",
                final_path.display()
            );
        }
    }

    // Fallback: try loading from backup
    let backup_path = backup_state_path(&state_dir, id);
    if backup_path.exists() {
        match fs::read_to_string(&backup_path) {
            Ok(contents) => {
                match serde_json::from_str::<ScanState>(&contents) {
                    Ok(state) => {
                        info!(
                            id = %id,
                            backup = %backup_path.display(),
                            "State successfully recovered from backup"
                        );
                        // Restore backup to primary location for next load
                        let _ = fs::copy(&backup_path, &final_path);
                        return Ok(Some(state));
                    }
                    Err(parse_err) => {
                        error!(
                            id = %id,
                            error = %parse_err,
                            "Backup file '{}' is also corrupted",
                            backup_path.display()
                        );
                    }
                }
            }
            Err(io_err) => {
                error!(
                    id = %id,
                    error = %io_err,
                    "Failed to read backup file '{}'",
                    backup_path.display()
                );
            }
        }
    }

    error!(
        id = %id,
        "State file and backup are both missing or corrupted for '{}'",
        final_path.display()
    );
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_state() -> ScanState {
        ScanState {
            ports_open: vec![80, 443],
            endpoints_discovered: vec![
                "/api/v1/users".to_string(),
                "/api/v1/admin".to_string(),
            ],
            response_body_hash: Some("abc123def456".to_string()),
            response_headers_hash: None,
            response_status: Some(200),
        }
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let backend = Some(dir.path().to_str().unwrap().to_string());
        let state = test_state();

        save_state("test-target", &state, &backend).unwrap();

        let loaded = load_state("test-target", &backend)
            .unwrap()
            .expect("State should exist after save");

        assert_eq!(loaded.ports_open, vec![80, 443]);
        assert_eq!(loaded.endpoints_discovered.len(), 2);
        assert_eq!(loaded.response_body_hash, Some("abc123def456".to_string()));
        assert_eq!(loaded.response_status, Some(200));
        assert!(loaded.response_headers_hash.is_none());
    }

    #[test]
    fn test_load_nonexistent_returns_none() {
        let dir = TempDir::new().unwrap();
        let backend = Some(dir.path().to_str().unwrap().to_string());

        let result = load_state("nonexistent", &backend).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_backup_recovery_on_corruption() {
        let dir = TempDir::new().unwrap();
        let backend = Some(dir.path().to_str().unwrap().to_string());
        let state = test_state();

        // Save twice — the second call creates a backup of the first save
        save_state("test-target", &state, &backend).unwrap();
        // Modify state slightly so second save is distinct from first
        let mut state_v2 = test_state();
        state_v2.ports_open.push(8080);
        save_state("test-target", &state_v2, &backend).unwrap();

        // Corrupt the main state file with invalid JSON
        let state_path = dir.path().join("test-target.json");
        fs::write(&state_path, "this is not valid json{}").unwrap();

        // Load should recover from backup (contains first save data: [80, 443])
        let loaded = load_state("test-target", &backend)
            .unwrap()
            .expect("State should be recovered from backup");
        assert_eq!(loaded.ports_open, vec![80, 443]);

        // Verify the backup was restored to the primary location
        let contents = fs::read_to_string(&state_path).unwrap();
        let restored: ScanState = serde_json::from_str(&contents).unwrap();
        assert_eq!(restored.ports_open, vec![80, 443]);
    }

    #[test]
    fn test_save_creates_state_directory() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("nested").join("state");
        let backend = Some(nested.to_str().unwrap().to_string());
        let state = test_state();

        save_state("test-target", &state, &backend).unwrap();
        assert!(nested.exists(), "State directory should be created");

        let loaded = load_state("test-target", &backend)
            .unwrap()
            .expect("State should load from nested directory");
        assert_eq!(loaded.ports_open, vec![80, 443]);
    }

    #[test]
    fn test_save_multiple_ids_independently() {
        let dir = TempDir::new().unwrap();
        let backend = Some(dir.path().to_str().unwrap().to_string());

        let state_a = ScanState {
            ports_open: vec![80],
            endpoints_discovered: vec![],
            response_body_hash: None,
            response_headers_hash: None,
            response_status: None,
        };

        let state_b = ScanState {
            ports_open: vec![443],
            endpoints_discovered: vec!["/api".to_string()],
            response_body_hash: Some("hash_b".to_string()),
            response_headers_hash: None,
            response_status: Some(404),
        };

        save_state("target-a", &state_a, &backend).unwrap();
        save_state("target-b", &state_b, &backend).unwrap();

        let loaded_a = load_state("target-a", &backend)
            .unwrap()
            .expect("State A should exist");
        let loaded_b = load_state("target-b", &backend)
            .unwrap()
            .expect("State B should exist");

        assert_eq!(loaded_a.ports_open, vec![80]);
        assert!(loaded_a.response_status.is_none());

        assert_eq!(loaded_b.ports_open, vec![443]);
        assert_eq!(loaded_b.response_status, Some(404));
        assert_eq!(loaded_b.endpoints_discovered, vec!["/api".to_string()]);
    }

    #[test]
    fn test_backup_not_created_on_first_save() {
        let dir = TempDir::new().unwrap();
        let backend = Some(dir.path().to_str().unwrap().to_string());
        let state = test_state();

        save_state("new-target", &state, &backend).unwrap();

        // No backup should exist on first save
        let backup_path = dir.path().join("new-target.json.backup");
        assert!(!backup_path.exists(), "Backup should not exist on first save");
    }

    #[test]
    fn test_backup_created_on_overwrite() {
        let dir = TempDir::new().unwrap();
        let backend = Some(dir.path().to_str().unwrap().to_string());
        let state = test_state();

        save_state("target", &state, &backend).unwrap();
        save_state("target", &state, &backend).unwrap();

        // Backup should exist after second save
        let backup_path = dir.path().join("target.json.backup");
        assert!(backup_path.exists(), "Backup should exist after overwrite");
    }
}