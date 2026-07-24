use valayam_models::finding::FindingOwned;
use crate::network::dns;
use valayam_models::TemplateMetadata;
use valayam_models::templates::subdomain_takeover::SubdomainTakeoverTemplate;

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
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    for template in templates {
        let domain = template.target.replace("{{Hostname}}", target_host);

        let cnames = dns::resolve(&domain, "CNAME").await.unwrap_or_default();

        for cname in &cnames {
            for &vuln in VULNERABLE_CNAMES {
                if cname.contains(vuln) {
                    return Some(FindingOwned::from_template_and_info(
                        template_id,
                        template_meta,
                        domain.clone(),
                        format!("Dangling CNAME record detected pointing to {}. Vulnerable to subdomain takeover.", cname),
                    ));
                }
            }
        }
    }
    None
}