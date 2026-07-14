use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdpAuditTemplate {
    pub target: String,
    pub provider: String, // "azure_ad", "okta", "saml_generic"
}
