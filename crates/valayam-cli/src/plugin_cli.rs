use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use walkdir::WalkDir;
use zip::write::FileOptions;

pub fn package_plugin(dir: &str, output: Option<&str>, sign: Option<&str>) -> anyhow::Result<()> {
    let dir_path = Path::new(dir);
    if !dir_path.exists() || !dir_path.is_dir() {
        anyhow::bail!("Directory '{}' does not exist or is not a directory.", dir);
    }

    let manifest_path = dir_path.join("plugin.yaml");
    if !manifest_path.exists() {
        anyhow::bail!("Missing plugin.yaml in '{}'. A valid Valayam plugin requires a manifest.", dir);
    }

    // Read manifest to determine default output name
    let manifest_content = std::fs::read_to_string(&manifest_path)?;
    let manifest: valayam_engine::vpa::PluginManifest = serde_yaml::from_str(&manifest_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse plugin.yaml: {}", e))?;

    let out_file_path = match output {
        Some(o) => std::path::PathBuf::from(o),
        None => Path::new(".").join(format!("{}.vpa", manifest.name)),
    };

    println!("Packaging plugin '{}' (v{}) into {}...", manifest.name, manifest.version, out_file_path.display());

    let file = File::create(&out_file_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);

    let mut buffer = Vec::new();
    for entry in WalkDir::new(dir_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let name = path.strip_prefix(dir_path).unwrap();

        // Skip the root dir itself, the output file, and any existing signature.sig
        if name.as_os_str().is_empty() || path == out_file_path || name.to_string_lossy() == "signature.sig" {
            continue;
        }

        #[allow(deprecated)]
        if path.is_file() {
            zip.start_file_from_path(name, options)?;
            let mut f = File::open(path)?;
            f.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
            buffer.clear();
        } else if !name.as_os_str().is_empty() {
            zip.add_directory_from_path(name, options)?;
        }
    }

    if let Some(priv_key_path) = sign {
        println!("Signing plugin with key: {}", priv_key_path);
        let priv_key_bytes = std::fs::read(priv_key_path)?;
        if priv_key_bytes.len() != 32 {
            anyhow::bail!("Invalid private key length (expected 32 bytes)");
        }
        let mut priv_key = [0u8; 32];
        priv_key.copy_from_slice(&priv_key_bytes[0..32]);
        let manifest_bytes = std::fs::read(&manifest_path)?;
        let signature = valayam_engine::crypto::PluginCrypto::sign(&priv_key, &manifest_bytes)?;
        
        zip.start_file("signature.sig", options)?;
        zip.write_all(&signature)?;
    }

    zip.finish()?;
    println!("Successfully created {}", out_file_path.display());

    Ok(())
}

pub fn init_plugin(name: &str, lang: &str, runtime: &str) -> anyhow::Result<()> {
    let dir_path = Path::new(name);
    if dir_path.exists() {
        anyhow::bail!("Directory '{}' already exists.", name);
    }
    
    std::fs::create_dir_all(dir_path)?;
    println!("\nCreating Valayam Plugin '{}'...", name);
    
    // Create plugin.yaml
    let manifest = format!(
        "name: \"{}\"\nversion: \"1.0.0\"\nauthor: \"SecurityTeam\"\nruntime: \"{}\"\nlanguage: \"{}\"\nentrypoint: \"run.bat\"\ncapabilities:\n  - \"network_scan\"\n",
        name, runtime, lang
    );
    std::fs::write(dir_path.join("plugin.yaml"), manifest)?;
    println!("- Created plugin.yaml");

    if lang == "python" {
        let py_content = format!(
            "from valayam_sdk import PluginServer, ScannerPlugin, Finding\n\n\
            class {}Scanner(ScannerPlugin):\n\
                def execute(self, template, context):\n\
                    target = context.get(\"target_url\", \"\")\n\
                    return [\n\
                        Finding(title=\"Sample Finding\", severity=\"INFO\", description=f\"Scanned {{target}}\")\n\
                    ]\n\n\
            if __name__ == \"__main__\":\n\
                PluginServer({}Scanner()).serve()\n",
            name.replace("-", "").capitalize_first_letter(),
            name.replace("-", "").capitalize_first_letter()
        );
        std::fs::write(dir_path.join("plugin.py"), py_content)?;
        println!("- Created plugin.py");
        
        let req_content = "valayam-sdk\n";
        std::fs::write(dir_path.join("requirements.txt"), req_content)?;
        println!("- Created requirements.txt");
        
        let bat_content = "@echo off\npython plugin.py\n";
        std::fs::write(dir_path.join("run.bat"), bat_content)?;
        println!("- Created run.bat");
    } else {
        println!("- Note: Boilerplate generation for language '{}' is currently minimal.", lang);
    }

    println!("\nRun `valayam plugin package {}` to package your plugin into {}.vpa!", name, name);
    Ok(())
}

trait Capitalize {
    fn capitalize_first_letter(&self) -> String;
}
impl Capitalize for String {
    fn capitalize_first_letter(&self) -> String {
        let mut c = self.chars();
        match c.next() {
            None => String::new(),
            Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_init_plugin_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let plugin_dir = dir.path().join("test-plugin");
        let name = plugin_dir.to_str().unwrap();

        let result = init_plugin(name, "python", "grpc");
        assert!(result.is_ok(), "init_plugin should succeed: {:?}", result.err());
        assert!(plugin_dir.exists());
        assert!(plugin_dir.join("plugin.yaml").exists());
        assert!(plugin_dir.join("plugin.py").exists());

        let _ = std::fs::remove_dir_all(&plugin_dir);
    }

    #[test]
    fn test_init_plugin_existing_dir_fails() {
        // Use a path that already exists on disk
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        // Temp dir already exists, so init should fail
        let result = init_plugin(path, "python", "grpc");
        assert!(result.is_err(), "init on existing dir should fail");
        let err = format!("{}", result.err().unwrap());
        assert!(err.contains("already exists"), "Error should mention 'already exists': {}", err);
    }

    #[test]
    fn test_package_nonexistent_dir_fails() {
        let result = package_plugin("/nonexistent/plugin_dir", None, None);
        assert!(result.is_err());
        let err = format!("{}", result.err().unwrap());
        assert!(err.contains("does not exist") || err.contains("exist"));
    }

    #[test]
    fn test_generate_key_creates_files() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("test_key");
        let prefix_str = prefix.to_str().unwrap();
        let result = generate_key(prefix_str);
        assert!(result.is_ok());
        assert!(Path::new(&format!("{}.pem", prefix_str)).exists());
        assert!(Path::new(&format!("{}.pub", prefix_str)).exists());
        // Cleanup
        let _ = std::fs::remove_file(format!("{}.pem", prefix_str));
        let _ = std::fs::remove_file(format!("{}.pub", prefix_str));
    }

    #[test]
    fn test_capitalize_empty_string() {
        let s = String::new();
        assert_eq!(s.capitalize_first_letter(), "");
    }

    #[test]
    fn test_capitalize_lowercase() {
        let s = "hello".to_string();
        assert_eq!(s.capitalize_first_letter(), "Hello");
    }

    #[test]
    fn test_capitalize_already_capitalized() {
        let s = "Hello".to_string();
        assert_eq!(s.capitalize_first_letter(), "Hello");
    }

    #[test]
    fn test_capitalize_single_char() {
        let s = "a".to_string();
        assert_eq!(s.capitalize_first_letter(), "A");
    }

    #[test]
    fn test_capitalize_hyphenated_name() {
        // The trait capitalizes only the first letter, not after hyphens
        let s = "my-plugin".to_string();
        assert_eq!(s.capitalize_first_letter(), "My-plugin");
    }
}

pub fn generate_key(output_prefix: &str) -> anyhow::Result<()> {
    let (priv_key, pub_key) = valayam_engine::crypto::PluginCrypto::generate_keypair();
    let priv_path = format!("{}.pem", output_prefix);
    let pub_path = format!("{}.pub", output_prefix);
    std::fs::write(&priv_path, priv_key)?;
    std::fs::write(&pub_path, pub_key)?;
    println!("Generated ED25519 keypair:\n- Private key (Keep Secret!): {}\n- Public key (Distribute!): {}", priv_path, pub_path);
    Ok(())
}
