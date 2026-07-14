use serde::{Deserialize, Serialize};
use crate::core::matcher::ResponseMatcher;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OauthAuditTemplate {
    pub target: String,
    pub flow_type: String, // "authorization_code", "implicit", "client_credentials"
    pub jwt_mutations: Vec<String>, // e.g. "none_alg", "key_confusion"
    pub matchers: Vec<ResponseMatcher>,
}
