use anyhow::{Context, Result};
use std::path::Path;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use super::oci_client::{OciClient, OciManifest, OciDescriptor};

pub struct PluginPublisher {
    client: OciClient,
}

impl PluginPublisher {
    pub fn new(registry: &str, username: Option<&str>, password: Option<&str>) -> Result<Self> {
        let client = OciClient::new(registry, username, password)?;
        Ok(Self { client })
    }

    /// Push a local .vpa plugin file to an OCI registry
    pub async fn push(&self, repo: &str, tag: &str, vpa_path: &Path, signature: Option<&str>) -> Result<()> {
        if !vpa_path.exists() {
            anyhow::bail!("Plugin archive {} does not exist", vpa_path.display());
        }

        let blob = std::fs::read(vpa_path)?;
        
        // Calculate SHA256 digest
        let mut hasher = Sha256::new();
        hasher.update(&blob);
        let hash = hasher.finalize();
        let digest_str = format!("sha256:{:x}", hash);
        let size = blob.len() as u64;

        tracing::info!(repo = %repo, tag = %tag, digest = %digest_str, size = %size, "Pushing plugin blob to OCI registry");

        // Push the blob
        self.client.push_blob(repo, &blob, &digest_str).await.context("Failed to push plugin blob")?;

        // Prepare annotations
        let mut annotations = HashMap::new();
        annotations.insert("org.valayam.plugin.version".to_string(), "1.0.0".to_string());
        
        if let Some(sig) = signature {
            annotations.insert("org.valayam.plugin.signature".to_string(), sig.to_string());
        }

        // Create OCI Manifest
        let manifest = OciManifest {
            schema_version: 2,
            media_type: Some("application/vnd.oci.image.manifest.v1+json".to_string()),
            config: OciDescriptor {
                media_type: "application/vnd.valayam.plugin.config.v1+json".to_string(),
                digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a".to_string(), // Dummy config digest for now
                size: 2, // "{}"
                annotations: None,
            },
            layers: vec![OciDescriptor {
                media_type: "application/vnd.valayam.plugin.layer.v1+zip".to_string(),
                digest: digest_str.clone(),
                size,
                annotations: Some(annotations),
            }],
            annotations: None,
        };

        // We also need to push the dummy config blob to be fully compliant
        tracing::info!("Pushing dummy config blob to OCI registry");
        let config_data = b"{}";
        let mut config_hasher = Sha256::new();
        config_hasher.update(config_data);
        let config_digest_str = format!("sha256:{:x}", config_hasher.finalize());
        self.client.push_blob(repo, config_data, &config_digest_str).await.context("Failed to push config blob")?;


        tracing::info!("Pushing manifest to OCI registry");
        self.client.push_manifest(repo, tag, &manifest).await.context("Failed to push manifest")?;

        tracing::info!(repo = %repo, tag = %tag, "Successfully pushed Valayam plugin to OCI registry");

        Ok(())
    }
}
