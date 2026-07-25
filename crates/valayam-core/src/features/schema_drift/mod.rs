// Schema drift detection natively parses OpenAPI documents, crawls the target application,
// and cross-references active endpoints against the specification to flag undocumented
// (Shadow API) and abandoned (Zombie API) routes.
// - Highlight undocumented shadow APIs and deprecated endpoints still active.
// - Generate diff reports for developer feedback loops.

pub mod executor;
