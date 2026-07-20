use std::fs::File;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

pub struct AppBinary {
    archive: ZipArchive<File>,
}

impl AppBinary {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
        let archive = ZipArchive::new(file).map_err(|e| format!("Failed to parse zip archive: {}", e))?;
        Ok(Self { archive })
    }

    pub fn extract_file(&mut self, file_name: &str) -> Result<Vec<u8>, String> {
        let mut file = self.archive.by_name(file_name)
            .map_err(|e| format!("File {} not found in archive: {}", file_name, e))?;
        
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).map_err(|e| format!("Failed to read file {}: {}", file_name, e))?;
        
        Ok(buffer)
    }

    pub fn extract_android_manifest(&mut self) -> Result<Vec<u8>, String> {
        self.extract_file("AndroidManifest.xml")
    }

    pub fn extract_ios_info_plist(&mut self) -> Result<Vec<u8>, String> {
        // Find Info.plist inside the Payload/*.app/ directory
        for i in 0..self.archive.len() {
            let name = {
                if let Ok(file) = self.archive.by_index(i) {
                    if file.name().contains("Payload/") && file.name().ends_with(".app/Info.plist") {
                        Some(file.name().to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some(file_name) = name {
                return self.extract_file(&file_name);
            }
        }
        Err("Info.plist not found in IPA".to_string())
    }
}
