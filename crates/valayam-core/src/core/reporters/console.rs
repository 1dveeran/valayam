use crate::core::traits::{Reporter, FindingOwned};

pub struct ConsoleReporter;

#[async_trait::async_trait]
impl Reporter for ConsoleReporter {
    async fn process_finding(&self, finding: &FindingOwned) -> Result<(), std::io::Error> {
        println!("\n[🚨 VULNERABILITY DETECTED]");
        println!(" ├─ Target:   {}", finding.target);
        println!(" ├─ Template: {} ({})", finding.template_name, finding.template_id);
        println!(" ├─ Severity: {}", finding.severity);
        if let Some(ref data) = finding.extracted_data {
            println!(" ├─ Data:     {}", data);
        }
        println!(" └─ Match:    {}", finding.matched_at);
        Ok(())
    }
}
