use crate::models::Severity;
use once_cell::sync::Lazy;
use regex::Regex;

pub struct SecretRule {
    pub id: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub pattern: Regex,
}

pub static SECRET_RULES: Lazy<Vec<SecretRule>> = Lazy::new(|| {
    vec![
        SecretRule {
            id: "OPENAI_API_KEY",
            description: "Hardcoded OpenAI API Key detected",
            severity: Severity::Critical,
            pattern: Regex::new(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b").unwrap(),
        },
        SecretRule {
            id: "AWS_ACCESS_KEY_ID",
            description: "Hardcoded AWS Access Key ID detected",
            severity: Severity::Critical,
            pattern: Regex::new(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b").unwrap(),
        },
        SecretRule {
            id: "GITHUB_TOKEN",
            description: "Hardcoded GitHub Personal Access Token detected",
            severity: Severity::Critical,
            pattern: Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b").unwrap(),
        },
        SecretRule {
            id: "STRIPE_LIVE_KEY",
            description: "Hardcoded Stripe Live Secret Key detected",
            severity: Severity::Critical,
            pattern: Regex::new(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b").unwrap(),
        },
        SecretRule {
            id: "GOOGLE_API_KEY",
            description: "Hardcoded Google Cloud / Firebase API Key detected",
            severity: Severity::High,
            pattern: Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").unwrap(),
        },
        SecretRule {
            id: "SLACK_TOKEN",
            description: "Hardcoded Slack Bot or User Token detected",
            severity: Severity::High,
            pattern: Regex::new(r"\bxox[baprs]-[0-9a-zA-Z-]{10,48}\b").unwrap(),
        },
        SecretRule {
            id: "PRIVATE_KEY_HEADER",
            description: "Hardcoded Private Key block detected",
            severity: Severity::Critical,
            pattern: Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
        },
    ]
});
