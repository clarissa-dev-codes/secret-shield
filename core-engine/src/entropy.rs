use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

/// Matches assignments like: api_secret = "9f82a7c1e4b30d92a8f7c6e5d4b3a210"
static ASSIGNMENT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b[a-z0-9_]*(?:secret|token|password|passwd|pwd|api_?key|auth|credential)[a-z0-9_]*\b\s*[:=]\s*["']([^"'\s]{16,})["']"#
    ).unwrap()
});

/// Calculates Shannon entropy H = -sum(p(x) * log2(p(x)))
pub fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut frequencies: HashMap<char, usize> = HashMap::new();
    let mut total_chars = 0usize;

    for ch in input.chars() {
        *frequencies.entry(ch).or_insert(0) += 1;
        total_chars += 1;
    }

    let len = total_chars as f64;
    frequencies.values().fold(0.0, |acc, &count| {
        let probability = (count as f64) / len;
        acc - probability * probability.log2()
    })
}

/// Returns a list of (byte_start, byte_end, matched_secret) for high-entropy assignments.
pub fn find_high_entropy_assignments(line: &str, threshold: f64) -> Vec<(usize, usize, String)> {
    let mut matches = Vec::new();

    for cap in ASSIGNMENT_REGEX.captures_iter(line) {
        if let Some(secret_match) = cap.get(1) {
            let val = secret_match.as_str();
            if val.to_lowercase().contains("example")
                || val.to_lowercase().contains("placeholder")
                || val.to_lowercase().contains("your_")
            {
                continue;
            }

            if shannon_entropy(val) >= threshold {
                matches.push((
                    secret_match.start(),
                    secret_match.end(),
                    val.to_string(),
                ));
            }
        }
    }

    matches
}
