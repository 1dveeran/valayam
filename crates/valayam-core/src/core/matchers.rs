//! Concrete Matcher implementations operating on zero-copy &[u8] buffers.

use super::traits::Matcher;

/// Regex matcher on raw bytes — no UTF-8 conversion.
pub struct RegexMatcher {
    patterns: Vec<regex::bytes::Regex>,
    label: String,
}

impl RegexMatcher {
    /// Create from pattern strings. Invalid patterns are logged and skipped.
    pub fn new(patterns: &[String]) -> Self {
        let compiled: Vec<_> = patterns
            .iter()
            .filter_map(|p| {
                regex::bytes::Regex::new(p)
                    .inspect_err(|e| tracing::warn!(pattern = %p, error = %e, "invalid regex, skipping"))
                    .ok()
            })
            .collect();
        Self { patterns: compiled, label: "regex".to_string() }
    }
}

impl Matcher for RegexMatcher {
    fn evaluate(&self, buf: &[u8]) -> bool {
        self.patterns.iter().any(|re| re.is_match(buf))
    }
    fn name(&self) -> &str { &self.label }
}

/// HTTP status code matcher.
pub struct StatusMatcher {
    allowed: Vec<u16>,
}

impl StatusMatcher {
    pub fn new(statuses: Vec<u16>) -> Self { Self { allowed: statuses } }
    pub fn matches_status(&self, status: u16) -> bool { self.allowed.contains(&status) }
}

impl Matcher for StatusMatcher {
    fn evaluate(&self, _buf: &[u8]) -> bool { false } // Use matches_status() directly
    fn name(&self) -> &str { "status" }
}

/// Fast byte-level substring search.
pub struct WordMatcher {
    words: Vec<Vec<u8>>,
}

impl WordMatcher {
    pub fn new(words: Vec<String>) -> Self {
        Self { words: words.into_iter().map(|w| w.into_bytes()).collect() }
    }
}

impl Matcher for WordMatcher {
    fn evaluate(&self, buf: &[u8]) -> bool {
        self.words.iter().any(|w| buf.windows(w.len()).any(|win| win == w.as_slice()))
    }
    fn name(&self) -> &str { "word" }
}

/// AND/OR combinator.
pub enum MatchCondition { And, Or }

pub struct CompositeMatcher {
    matchers: Vec<Box<dyn Matcher>>,
    condition: MatchCondition,
}

impl CompositeMatcher {
    pub fn new(matchers: Vec<Box<dyn Matcher>>, condition: MatchCondition) -> Self {
        Self { matchers, condition }
    }
}

impl Matcher for CompositeMatcher {
    fn evaluate(&self, buf: &[u8]) -> bool {
        match self.condition {
            MatchCondition::And => self.matchers.iter().all(|m| m.evaluate(buf)),
            MatchCondition::Or  => self.matchers.iter().any(|m| m.evaluate(buf)),
        }
    }
    fn name(&self) -> &str { "composite" }
}
