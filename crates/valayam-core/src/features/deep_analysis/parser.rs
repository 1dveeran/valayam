use serde::{Deserialize, Serialize};

// TODO: Deep Analysis Template Parser — Full Implementation Plan
// ===============================================================
// Goal: Expand the flat `analysis_type` string discriminator into a
//       structured enum with per-type configuration fields and template
//       validation. Support YAML-based template loading with nested
//       module-specific configs.
//
// Required Crates:
//   - serde / serde_yaml (template loading)
//   - serde_json (JSON parsing for response processing)
//   - schemars (JSON Schema generation for template autocomplete)
//   - thiserror (ergonomic error derive)
//   - url (URL pattern validation in template targets)
//   - globset (path pattern matching for artifact recovery targets)
//
// Data Structures Needed:
//   - DeepAnalysisType enum (instead of raw String):
//       LlmMutation(LlmConfig),          // see llm_mutator.rs
//       WasmDecompile(WasmConfig),       // future
//       SourceMapReconstruct(SourceMapConfig), // future
//       ArtifactRecovery(ArtifactConfig), // see artifact_recovery.rs
//       Custom(String)
//   - LlmConfig { mutation_strategy: String, max_variants: u32,
//     send_to_fuzzer: bool }
//   - WasmConfig { decompile: bool, export_symbols: bool,
//     extract_strings: bool }
//   - SourceMapConfig { reconstruct: bool, resolve_original: bool,
//     download_missing: bool }
//   - ArtifactConfig { probe_paths: Vec<String>, max_size_bytes: u64,
//     extract_archives: bool, secret_scan: bool, pattern_file: Option<String> }
//   - DeepAnalysisTemplate (extend current):
//       - add analysis_config: Option<serde_json::Value> (flex per-type
//         config parsed at runtime based on analysis_type)
//       - add severity_override: Option<String>
//       - add tags: Option<Vec<String>>
//       - add conditions: Option<Vec<AnalysisCondition>>
//   - AnalysisCondition { metric: String (e.g., "confidence"),
//     operator: String (">", "<", "==", "contains"),
//     value: serde_json::Value }
//
// Error Handling:
//   - TemplateValidationError enum:
//       UnknownAnalysisType(type: String),
//       MissingConfigForType { analysis_type: String,
//         required_fields: Vec<String> },
//       InvalidUrlPattern(url: String),
//       InvalidCondition { condition: String, reason: String },
//       ConfigConversionError { from_type: String, to_type: String,
//         inner: serde_json::Error }
//   - Deserialization with try_from: DeepAnalysisTemplate may implement
//     TryFrom<RawTemplate> to validate and convert
//
// Integration Points:
//   - Template registry: DeepAnalysisTemplate loaded alongside all
//     other templates via the common ScanTemplate trait
//   - Executor modules (llm_mutator, wasm, source_map, artifact):
//     each receives the typed config extracted from analysis_config
//   - Schema generation: schemars derive for IDE autocomplete when
//     editing template YAML files
//
// Template YAML Example (future):
//   ```yaml
//   id: deep-analysis-llm-001
//   info:
//     name: LLM WAF Bypass for SQLi
//     severity: critical
//     tags: [waf-bypass, sqli, ai-assisted]
//   deep_analysis:
//     type: llm_mutation
//     config:
//       mutation_strategy: sql_injection
//       max_variants: 5
//       send_to_fuzzer: true
//       provider: ollama
//       model: codellama
//     conditions:
//       - metric: response_time
//         operator: "<"
//         value: 5000
//   ```
//
// Implementation Phases:
//   1. Phase 1 (Current): Simple struct with String-based discriminator.
//      analysis_type can be "llm_mutation", "wasm_decompile",
//      "source_map", or "artifact_recovery". Single optional prompt field.
//   2. Phase 2: Introduce flexible serde_json::Value config field.
//      Each executor module validates its own config at runtime.
//   3. Phase 3: Full typed enum with per-variant config structs.
//      Deserialize with adjacently-tagged enum representation.
//   4. Phase 4: Template validation on load — report missing fields,
//      invalid combinations, and unsupported analysis types before
//      any scan begins.
// =======================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeepAnalysisTemplate {
    pub target: String,
    pub analysis_type: String, // "llm_mutation", "wasm_decompile", "source_map", "artifact_recovery"
    pub prompt: Option<String>,
}
