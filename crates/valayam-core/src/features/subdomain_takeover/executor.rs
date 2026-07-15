use crate::core::result::ScanResult;
use crate::network::dns;
use crate::template::schema::TemplateInfo;
use chrono::Utc;
use super::parser::SubdomainTakeoverTemplate;

const VULNERABLE_CNAMES: &[&str] = &[
    "github.io",
    "s3.amazonaws.com",
    "herokuapp.com",
    "azurewebsites.net",
    "elasticbeanstalk.com",
    "cloudfront.net",
];

pub async fn execute(
    target_host: &str,
    templates: &[SubdomainTakeoverTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let domain = template.target.replace("{{Hostname}}", target_host);
        
        let cnames = dns::resolve(&domain, "CNAME").await;
        
        for cname in cnames {
            for &vuln in VULNERABLE_CNAMES {
                if cname.contains(vuln) {
                    return Some(ScanResult {
                        timestamp: Utc::now(),
                        template_id: template_id.to_string(),
                        template_name: template_info.name.clone(),
                        template_severity: template_info.severity.clone(),
                        target: domain.clone(),
                        payload: format!("Dangling CNAME record detected pointing to {}. Vulnerable to subdomain takeover.", cname),
                        compliance: Default::default(),
                    });
                }
            }
        }
    }
    None
}
