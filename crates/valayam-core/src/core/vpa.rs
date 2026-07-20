use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub author: Option<String>,
    pub runtime: String, // "grpc", "wasm"
    pub language: String,
    pub entrypoint: String,
    pub capabilities: Option<Vec<String>>,
}

#[derive(Debug)]
pub enum VpaError {
    IoError(std::io::Error),
    ZipError(zip::result::ZipError),
    YamlError(serde_yaml::Error),
    InvalidManifest(String),
    ExtractionError(String),
}

impl From<std::io::Error> for VpaError {
    fn from(e: std::io::Error) -> Self { VpaError::IoError(e) }
}
impl From<zip::result::ZipError> for VpaError {
    fn from(e: zip::result::ZipError) -> Self { VpaError::ZipError(e) }
}
impl From<serde_yaml::Error> for VpaError {
    fn from(e: serde_yaml::Error) -> Self { VpaError::YamlError(e) }
}

/// Extract a VPA archive securely to the given cache directory, and return the loaded Manifest and extraction path.
/// If `pub_key` is provided, it enforces that `signature.sig` exists and is valid.
pub fn extract_vpa(archive_path: &Path, cache_base_dir: &Path, pub_key: Option<&[u8; 32]>) -> Result<(PluginManifest, PathBuf), VpaError> {
    let file = fs::File::open(archive_path)?;
    let mut archive = ZipArchive::new(file)?;
    
    // Create a unique extraction directory for this VPA
    let file_stem = archive_path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("plugin");
    let extract_dir = cache_base_dir.join(format!("{}_{}", file_stem, &uuid::Uuid::new_v4().to_string().replace("-", "")[..8]));
    
    fs::create_dir_all(&extract_dir)?;

    let mut manifest: Option<PluginManifest> = None;
    let mut signature_bytes: Option<Vec<u8>> = None;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => path.to_owned(),
            None => continue, // Skip suspicious paths
        };

        // Prevent ZipSlip (enclosed_name already does this securely in `zip` crate, but we are explicit)
        let out_full_path = extract_dir.join(&outpath);

        if (*file.name()).ends_with('/') {
            fs::create_dir_all(&out_full_path)?;
        } else {
            if let Some(p) = out_full_path.parent() {
                if !p.exists() {
                    fs::create_dir_all(p)?;
                }
            }
            
            let mut outfile = fs::File::create(&out_full_path)?;
            std::io::copy(&mut file, &mut outfile)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    fs::set_permissions(&out_full_path, fs::Permissions::from_mode(mode))?;
                }
            }

            if outpath.to_string_lossy() == "plugin.yaml" {
                let content = fs::read_to_string(&out_full_path)?;
                manifest = Some(serde_yaml::from_str(&content)?);
            } else if outpath.to_string_lossy() == "signature.sig" {
                signature_bytes = Some(fs::read(&out_full_path)?);
            }
        }
    }

    let manifest = manifest.ok_or_else(|| VpaError::InvalidManifest("plugin.yaml is missing from the VPA archive".to_string()))?;
    
    if let Some(pk) = pub_key {
        let sig = signature_bytes.ok_or_else(|| VpaError::ExtractionError("VPA requires a signature.sig but none was found".to_string()))?;
        if sig.len() != 64 {
            return Err(VpaError::ExtractionError("Invalid signature length".to_string()));
        }
        
        // We verify the signature against the raw bytes of plugin.yaml
        let manifest_content = fs::read(extract_dir.join("plugin.yaml"))?;
        let sig_array: [u8; 64] = sig.try_into().unwrap();
        
        let is_valid = crate::core::crypto::PluginCrypto::verify(pk, &manifest_content, &sig_array)
            .map_err(|e| VpaError::ExtractionError(format!("Signature verification failed: {}", e)))?;
            
        if !is_valid {
            return Err(VpaError::ExtractionError("Signature validation failed: untrusted plugin".to_string()));
        }
    }

    Ok((manifest, extract_dir))
}
