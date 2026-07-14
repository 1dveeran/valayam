use valayam_core::core::result::ScanResult;
use std::fs::File;
use std::io::Write;

/// Generates a Markdown report from scan results.
pub struct MarkdownReporter;

impl MarkdownReporter {
    pub fn generate(results: &[ScanResult], output_path: &str) -> Result<(), String> {
        let mut md = String::from("# Valayam Vulnerability Scan Report\n\n");
        md.push_str("| Timestamp | Template | Severity | Target | Payload |\n");
        md.push_str("| --- | --- | --- | --- | --- |\n");
        
        for result in results {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                result.timestamp, result.template_name, result.template_severity, result.target, result.payload
            ));
        }
        
        let mut file = File::create(output_path).map_err(|e| e.to_string())?;
        file.write_all(md.as_bytes()).map_err(|e| e.to_string())?;
        
        Ok(())
    }
}
