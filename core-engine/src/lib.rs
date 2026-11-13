pub mod entropy;
pub mod models;
pub mod rules;
pub mod scanner;

pub use models::{Finding, Severity};
pub use scanner::{check_env_gitignore, scan_file, scan_path, scan_text};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_provider_keys() {
        let sample_code = r#"
            const openai = "sk-proj-abc123def456ghi789jkl012mno345";
            const aws = "AKIAIOSFODNN7EXAMPLE";
            const github = "ghp_1234567890abcdef1234567890abcdef1234";
        "#;

        let findings = scan_text("app.ts", sample_code);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].rule_id, "OPENAI_API_KEY");
        assert_eq!(findings[1].rule_id, "AWS_ACCESS_KEY_ID");
        assert_eq!(findings[2].rule_id, "GITHUB_TOKEN");
        assert!(!findings[0].redacted_preview.contains("ghi789"));
    }

    #[test]
    fn detects_high_entropy_custom_secret() {
        let sample_code = r#"
            const webhook_secret = "9f82a7c1e4b30d92a8f7c6e5d4b3a210xZ9q";
            const normal_url = "https://example.com";
        "#;

        let findings = scan_text("config.js", sample_code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "HIGH_ENTROPY_SECRET");
    }

    #[test]
    fn respects_inline_ignore_comment() {
        let sample_code = r#"
            const test_key = "AKIAIOSFODNN7EXAMPLE"; // secret-shield:ignore
        "#;

        let findings = scan_text("test.ts", sample_code);
        assert!(findings.is_empty());
    }
}
