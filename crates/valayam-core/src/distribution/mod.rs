//! Distribution and publishing — OCI container registry client, publisher, and puller.
//!
//! Manages packaging and distribution of scan plugins, templates, and
//! configuration via OCI-compatible registries.

pub mod oci_client;
pub mod publisher;
pub mod puller;