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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_audit_template_deser() {
        let json = r#"{"target": "https://example.com", "script": "login.py", "matchers": []}"#;
        let tmpl: BrowserAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.target, "https://example.com");
        assert_eq!(tmpl.script, "login.py");
        assert!(tmpl.matchers.is_empty());
    }

    #[test]
    fn test_browser_audit_with_matchers() {
        let json = r#"{"target": "https://app.com", "script": "check.py", "matchers": [{"type": "word", "part": "body", "words": ["success"]}]}"#;
        let tmpl: BrowserAuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.matchers.len(), 1);
        assert_eq!(tmpl.matchers[0].words, vec!["success"]);
    }

    #[test]
    fn test_browser_audit_serde_roundtrip() {
        let tmpl = BrowserAuditTemplate {
            target: "https://site.com".into(),
            script: "script.py".into(),
            matchers: vec![],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: BrowserAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.script, "script.py");
    }
}
