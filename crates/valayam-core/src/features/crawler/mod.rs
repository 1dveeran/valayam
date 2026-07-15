// TODO: Implement Enterprise Web Crawler (Phase 5).
// - spider.rs: Build async crawling loop with rate limiting and domain bounds.
// - parsers.rs: Implement JS/SPA route extraction, WASM decompilation, and OpenAPI parsing.
// - Inject custom auth headers dynamically during the crawling process.
pub mod spider;
pub mod parsers;
pub mod wordlists;

pub use spider::Crawler;
