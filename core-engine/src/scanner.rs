use crate::entropy::find_high_entropy_assignments;
use crate::models::{redact_secret, Finding, Severity};
use crate::rules::SECRET_RULES;
use ignore::WalkBuilder;
use std::fs;
use std::path::Path;

const ENTROPY_THRESHOLD: f64 = 4.0;

/// Scans a single string of text (useful for unit tests and live IDE buffers).
pub fn scan_text(file_path: &str, content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        let line_number = line_idx + 1;

        // Allow developers to explicitly suppress intentional test fixtures
        if line.contains("secret-shield:ignore") {
            continue;
        }

        // 1. Check known regex signatures
        for rule in SECRET_RULES.iter() {
            for mat in rule.pattern.find_iter(line) {
                findings.push(Finding {
                    file_path: file_path.to_string(),
                    line_number,
                    column_start: mat.start() + 1,
                    column_end: mat.end() + 1,
                    rule_id: rule.id.to_string(),
                    description: rule.description.to_string(),
                    severity: rule.severity.clone(),
                    redacted_preview: redact_secret(mat.as_str()),
                });
            }
        }

        // 2. Check high-entropy variable assignments not already caught by regex
        for (start, end, secret_val) in find_high_entropy_assignments(line, ENTROPY_THRESHOLD) {
            let col_start = start + 1;
            let already_flagged = findings.iter().any(|f| {
                f.line_number == line_number && f.column_start <= col_start && f.column_end >= col_start
            });

            if !already_flagged {
                findings.push(Finding {
                    file_path: file_path.to_string(),
                    line_number,
                    column_start: col_start,
                    column_end: end + 1,
                    rule_id: "HIGH_ENTROPY_SECRET".to_string(),
                    description: "High-entropy string assigned to a sensitive variable name".to_string(),
                    severity: Severity::High,
                    redacted_preview: redact_secret(&secret_val),
                });
            }
        }
    }

    findings
}

/// Scans a single file on disk, safely skipping binary files.
pub fn scan_file(path: &Path) -> Vec<Finding> {
    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };

    // Skip binary files (NUL byte heuristic)
    if bytes.iter().take(8000).any(|&b| b == 0) {
        return Vec::new();
    }

    let content = String::from_utf8_lossy(&bytes);
    let path_str = path.to_string_lossy().to_string();
    scan_text(&path_str, &content)
}

/// Checks if a project directory has a .env file that is missing from .gitignore.
pub fn check_env_gitignore(dir: &Path) -> Option<Finding> {
    let env_path = dir.join(".env");
    if !env_path.exists() {
        return None;
    }

    let gitignore_path = dir.join(".gitignore");
    let is_ignored = if let Ok(gitignore_content) = fs::read_to_string(&gitignore_path) {
        gitignore_content.lines().any(|line| {
            let trimmed = line.trim();
            trimmed == ".env" || trimmed == ".env*" || trimmed == "*.env" || trimmed == "/.env"
        })
    } else {
        false
    };

    if !is_ignored {
        Some(Finding {
            file_path: env_path.to_string_lossy().to_string(),
            line_number: 1,
            column_start: 1,
            column_end: 1,
            rule_id: "UNIGNORED_ENV_FILE".to_string(),
            description: ".env file exists in project root without a matching rule in .gitignore".to_string(),
            severity: Severity::Warning,
            redacted_preview: ".env (exposed to Git)".to_string(),
        })
    } else {
        None
    }
}

/// Scans either a single file or recursively walks a directory respecting .gitignore.
pub fn scan_path(target: &Path) -> Vec<Finding> {
    if target.is_file() {
        return scan_file(target);
    }

    let mut all_findings = Vec::new();

    if let Some(env_warning) = check_env_gitignore(target) {
        all_findings.push(env_warning);
    }

    let walker = WalkBuilder::new(target)
        .hidden(false) // Allow scanning dotfiles like .env.local if not gitignored
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            name != ".git" && name != "node_modules" && name != "target"
        })
        .build();

    for result in walker.flatten() {
        let path = result.path();
        if path.is_file() {
            // Avoid scanning .env itself for secrets if it IS properly gitignored
            if path.file_name().and_then(|n| n.to_str()) == Some(".env") {
                continue;
            }
            all_findings.extend(scan_file(path));
        }
    }

    all_findings
}
