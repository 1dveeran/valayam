pub mod template_info;
pub mod result;
pub mod finding;
pub mod bridge;
pub mod error;
pub mod templates;

pub use result::ScanResult;
pub use finding::{FindingOwned, PluginOutcomeKind, PluginMetrics, PluginHealth};
pub use template_info::TemplateInfo;
