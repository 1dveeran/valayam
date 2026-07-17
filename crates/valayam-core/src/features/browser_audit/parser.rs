use serde::{Deserialize, Serialize};
use crate::core::matcher::ResponseMatcher;

// TODO: Browser Audit Template Parser — Full Implementation Plan
// ===============================================================
// Goal: Expand the template format to support headless browser scenarios
//       — DOM interaction, click/scroll actions, form filling, JS execution
//       verification, and screenshot capture.
//
// Required Crates:
//   - serde / serde_yaml (template loading from YAML)
//   - jsonpath-rust (evaluate JSONPath on page DOM state)
//   - regex (match console output patterns)
//
// Data Structures Needed:
//   - BrowserAction enum:
//       - Navigate(url: String)
//       - Click(selector: String)
//       - FillForm { selector: String, value: String }
//       - ExecuteJs(code: String)
//       - WaitForSelector(selector: String, timeout_ms: u64)
//       - Screenshot(path: Option<String>)
//       - EvaluateAndMatch { js: String, matchers: Vec<ResponseMatcher> }
//   - BrowserAuditTemplate (extend current):
//       - add actions: Vec<BrowserAction>
//       - add expected_console: Vec<String> (patterns to find in console)
//       - add dom_conditions: Vec<DomCondition>
//   - DomCondition { selector: String, attribute: Option<String>,
//     exists: bool, text_contains: Option<String> }
//
// Error Handling:
//   - TemplateParseError (invalid YAML, unknown action type)
//   - MissingFieldError (e.g., selector missing for Click action)
//   - Validation: ensure at least Navigate action is first
//
// Integration Points:
//   - Template registry: BrowserAuditTemplate loaded via template loading
//     pipeline (currently uses ScanTemplate trait)
//   - Executor: actions get consumed sequentially by the headless browser
//   - Output: matched conditions produce ScanResult with evidence (screenshot
//     path, console logs, DOM snapshot)
//
// Format is extendable from the current:
//   target, script (Python worker identifier), matchers
// To a full:
//   target, actions: [{action: navigate, url: ...}, {action: click, selector: ...}],
//   script (optional), expected_console, matchers
// ===============================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BrowserAuditTemplate {
    pub target: String,
    pub script: String, // Python worker script identifier
    pub matchers: Vec<ResponseMatcher>,
}
