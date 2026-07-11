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
