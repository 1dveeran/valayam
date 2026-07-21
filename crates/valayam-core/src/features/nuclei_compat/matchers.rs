pub fn evaluate_words_stream(stream: &[u8], words: &[String]) -> bool {
    // Basic fast substring matcher for Nuclei word types
    // For large streams/many words, Aho-Corasick would be ideal, but standard windows work for now.

    // We convert stream to a lossy string for simple word matching.
    // Zero-copy would involve memchr or similar byte matching.
    let text = String::from_utf8_lossy(stream);

    for word in words {
        if text.contains(word) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_words_stream_finds_word() {
        let stream = b"Hello World, this is a test response";
        let words = vec!["World".to_string(), "missing".to_string()];
        assert!(evaluate_words_stream(stream, &words));
    }

    #[test]
    fn test_evaluate_words_stream_no_match() {
        let stream = b"Hello World";
        let words = vec!["goodbye".to_string()];
        assert!(!evaluate_words_stream(stream, &words));
    }

    #[test]
    fn test_evaluate_words_stream_empty_words() {
        let stream = b"Hello World";
        let words: Vec<String> = vec![];
        assert!(!evaluate_words_stream(stream, &words));
    }

    #[test]
    fn test_evaluate_words_stream_empty_stream() {
        let stream = b"";
        let words = vec!["test".to_string()];
        assert!(!evaluate_words_stream(stream, &words));
    }

    #[test]
    fn test_evaluate_words_stream_multiple_words_any_match() {
        let stream = b"admin password root";
        let words = vec!["root".to_string(), "admin".to_string(), "nobody".to_string()];
        assert!(evaluate_words_stream(stream, &words));
    }

    #[test]
    fn test_evaluate_words_stream_case_sensitive() {
        let stream = b"Hello World";
        let words = vec!["world".to_string()];
        // Nuclei word matching is case-sensitive by default
        assert!(!evaluate_words_stream(stream, &words));
    }

    #[test]
    fn test_evaluate_words_stream_partial_word() {
        let stream = b"authentication token";
        let words = vec!["token".to_string()];
        assert!(evaluate_words_stream(stream, &words));
    }
}
