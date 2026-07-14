use valayam_core::core::result::ScanResult;
use std::fs::File;
use std::io::Write;

/// Generates an HTML report from scan results.
pub struct HtmlReporter;

impl HtmlReporter {
    pub fn generate(results: &[ScanResult], output_path: &str) -> Result<(), String> {
        let mut html = String::from("<html><head><title>Valayam Scan Report</title></head><body>");
        html.push_str("<h1>Valayam Vulnerability Scan Report</h1>");
        html.push_str("<table border='1'><tr><th>Timestamp</th><th>Template</th><th>Severity</th><th>Target</th><th>Payload</th></tr>");
        
        for result in results {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                result.timestamp, result.template_name, result.template_severity, result.target, result.payload
            ));
        }
        
        html.push_str("</table></body></html>");
        
        let mut file = File::create(output_path).map_err(|e| e.to_string())?;
        file.write_all(html.as_bytes()).map_err(|e| e.to_string())?;
        
        Ok(())
    }
}
