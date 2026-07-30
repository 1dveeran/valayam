//! Crawler parsers — JS route extraction, OpenAPI parsing, and WASM decompilation.
//!
//! Each submodule handles a specific content type or format encountered
//! during crawling, extracting routes, endpoints, and metadata.

pub mod javascript;
pub mod openapi;
pub mod openapi_generator;
pub mod wasm;