//! Core data models for the Valayam scanner.
//!
//! Defines ScanResult, FindingOwned, PluginOutcomeKind, PluginMetrics,
//! PluginHealth, TemplateInfo, TemplateMetadata, and the template section
//! schemas. All scanner crates depend on these type definitions.

pub mod template_info;
pub mod result;
pub mod finding;
pub mod bridge;
pub mod error;
pub mod templates;

pub use result::ScanResult;
pub use finding::{FindingOwned, PluginOutcomeKind, PluginMetrics, PluginHealth};
pub use template_info::{TemplateInfo, TemplateMetadata};