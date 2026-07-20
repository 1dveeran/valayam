use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiProxyTemplate {
    pub enabled: bool,
    pub port: Option<u16>,
    pub allow_modification: Option<bool>,
}
