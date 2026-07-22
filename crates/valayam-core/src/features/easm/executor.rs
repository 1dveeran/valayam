use crate::core::result::ScanResult;
use valayam_models::templates::schema::TemplateInfo;
use valayam_models::templates::easm::EasmTemplate;
use reqwest::Client;
use super::{crtsh, alienvault};
use std::collections::HashSet;

pub async fn execute(
    client: &Client,
    target_url: &str,
    target_host: &str,
    templates: &[EasmTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    let mut discovered_subdomains = HashSet::new();

    for easm in templates {
        let domain = if easm.domain == "{{Hostname}}" {
            target_host
        } else {
            &easm.domain
        };

        for source in &easm.sources {
            match source.to_lowercase().as_str() {
                "crtsh" => {
                    if let Ok(subs) = crtsh::enumerate_subdomains(client, domain, easm.max_results).await {
                        for sub in subs {
                            discovered_subdomains.insert(sub);
                        }
                    }
                }
                "alienvault" => {
                    if let Ok(subs) = alienvault::enumerate_subdomains(client, domain, easm.max_results).await {
                        for sub in subs {
                            discovered_subdomains.insert(sub);
                        }
                    }
                }
                _ => {
                    // Unsupported source
                }
            }
        }
    }

    if !discovered_subdomains.is_empty() {
        let mut results = discovered_subdomains.into_iter().collect::<Vec<_>>();
        results.sort();
        
        // In a real implementation we would dynamically route these back 
        // into the execution pipeline. For now we record them as a finding.
        let mut result = ScanResult::new(template_id, template_info, target_url);
        result.set_extracted("discovered_subdomains", results.join(", "));
        return Some(result);
    }

    None
}
