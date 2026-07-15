use urlencoding::encode;

pub struct WafPermutator;

impl WafPermutator {
    /// Takes a blocked payload and returns a list of evasive permutations
    pub fn generate_permutations(payload: &str) -> Vec<String> {
        let mut permutations = Vec::new();

        // 1. URL Encoding (Standard)
        permutations.push(encode(payload).into_owned());

        // 2. Double URL Encoding
        permutations.push(encode(&encode(payload)).into_owned());

        // 3. Unicode Normalization (e.g. Fullwidth characters bypassing simple regex)
        // For scaffold, we simulate replacing standard quotes with fullwidth quote
        if payload.contains('\'') {
            permutations.push(payload.replace('\'', "％u0027")); // Evades naive ' detection
        }

        if payload.contains('<') {
            permutations.push(payload.replace('<', "％u003c")); // Evades naive XSS detection
        }

        // 4. Case mutation (e.g. SeLeCt)
        // Simplistic toggling for letters
        let toggled = payload.chars().enumerate().map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        }).collect::<String>();
        permutations.push(toggled);
        
        permutations
    }

    /// Generates HTTP Parameter Pollution (HPP) URLs
    pub fn generate_hpp_urls(base_url: &str, param: &str, payload: &str) -> Vec<String> {
        vec![
            // Standard HPP: Supply parameter twice, waf might check first, backend uses second
            format!("{}?{}=safe&{}={}", base_url, param, param, encode(payload)),
            
            // Reordered HPP
            format!("{}?{}={}&{}=safe", base_url, param, encode(payload), param),
        ]
    }
}
