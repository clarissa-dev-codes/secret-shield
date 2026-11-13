use clap::{Parser, Subcommand, ValueEnum};
use core_engine::{scan_path, Severity};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "secret-shield")]
#[command(about = "High-speed static secret scanner for developers and AI-assisted workflows", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file or directory for hardcoded secrets
    Scan {
        /// File or directory path to scan
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format (pretty for humans, json for IDE integrations)
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
        format: OutputFormat,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, format } => {
            if !path.exists() {
                eprintln!("Error: Path '{}' does not exist.", path.display());
                process::exit(2);
            }

            let findings = scan_path(&path);

            match format {
                OutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&findings)
                        .expect("Failed to serialize findings to JSON");
                    println!("{}", json);
                }
                OutputFormat::Pretty => {
                    if findings.is_empty() {
                        println!("SecretShield: No hardcoded secrets detected in '{}'.", path.display());
                    } else {
                        println!(
                            "SecretShield found {} potential secret(s) in '{}':\n",
                            findings.len(),
                            path.display()
                        );
                        for f in &findings {
                            let badge = match f.severity {
                                Severity::Critical => "[CRITICAL]",
                                Severity::High => "[HIGH]    ",
                                Severity::Medium => "[MEDIUM]  ",
                                Severity::Warning => "[WARNING] ",
                            };
                            println!(
                                "{} {} ({}:{}:{}) -> {} [{}]",
                                badge,
                                f.rule_id,
                                f.file_path,
                                f.line_number,
                                f.column_start,
                                f.description,
                                f.redacted_preview
                            );
                        }
                    }
                }
            }

            // Exit with code 1 if secrets were found (standard for CI/CD & pre-commit hooks)
            if !findings.is_empty() {
                process::exit(1);
            }
        }
    }
}
