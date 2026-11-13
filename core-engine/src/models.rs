use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Warning,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub file_path: String,
    pub line_number: usize,
    pub column_start: usize,
    pub column_end: usize,
    pub rule_id: String,
    pub description: String,
    pub severity: Severity,
    pub redacted_preview: String,
}

/// Masks the middle of a detected secret so logs and UIs never expose raw keys.
pub fn redact_secret(raw: &str) -> String {
    let char_count = raw.chars().count();
    if char_count <= 8 {
        return "*".repeat(char_count);
    }
    let prefix: String = raw.chars().take(4).collect();
    let suffix: String = raw.chars().skip(char_count - 4).collect();
    format!("{}********{}", prefix, suffix)
}
