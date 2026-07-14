use serde::{Deserialize, Serialize};
use crate::core::matcher::ResponseMatcher;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientSecretAuditTemplate {
    pub target: String,
    pub matchers: Vec<ResponseMatcher>,
}
