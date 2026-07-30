//! Exploitation handlers — interactive bind and reverse shell listeners.
//!
//! For RCE verification during red-team operations. Spawns async tasks
//! to manage TCP streams transparently. Integrates with the Valayam CLI
//! for interactive PTY shell access.

pub mod handler;