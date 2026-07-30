//! Scan report generators — multi-format output for scan results.
//!
//! Supports HTML, Markdown, compliance (PDF), SARIF, and PDF report generation.
//! Each format provides structured presentation of findings and metrics.

pub mod html;
pub mod markdown;
pub mod compliance;
pub mod sarif;
pub mod pdf;