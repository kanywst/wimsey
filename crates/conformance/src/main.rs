//! The `wimsey-conformance` command: generate the vectors, or run them.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use wimsey_conformance::{generate, run};

#[derive(Parser)]
#[command(
    name = "wimsey-conformance",
    about = "Generate and run the WIMSE cross-implementation conformance vectors"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write the vectors and their manifest. Deterministic: rerunning on an
    /// unchanged implementation produces no diff.
    Generate {
        /// The directory to write into.
        #[arg(long, default_value = "conformance")]
        out: PathBuf,
    },
    /// Run the vectors against this implementation. Exits non-zero on any
    /// failed check.
    Run {
        /// The directory holding `manifest.json`.
        #[arg(long, default_value = "conformance")]
        dir: PathBuf,
        /// How to report the result.
        #[arg(long, value_enum, default_value_t = Format::Human)]
        format: Format,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    /// One line per check, plus a summary.
    Human,
    /// The whole report as JSON, for a CI job to consume.
    Json,
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut json = serde_json::to_string_pretty(value).expect("vectors serialize");
    json.push('\n');
    std::fs::write(path, json)
}

fn write_vectors(out: &Path) -> std::io::Result<()> {
    write_json(&out.join("manifest.json"), &generate::manifest())?;
    write_json(
        &out.join("identifier/parse-basic.json"),
        &generate::identifier_vector(),
    )?;
    write_json(&out.join("wit/issue-basic.json"), &generate::wit_vector())?;
    write_json(&out.join("wpt/proof-basic.json"), &generate::wpt_vector())?;
    write_json(
        &out.join("httpsig/sign-basic.json"),
        &generate::httpsig_vector(),
    )
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Generate { out } => {
            if let Err(e) = write_vectors(&out) {
                eprintln!("error: writing vectors to {}: {e}", out.display());
                return ExitCode::FAILURE;
            }
            eprintln!("wrote the conformance vectors to {}", out.display());
            ExitCode::SUCCESS
        }
        Command::Run { dir, format } => {
            let report = match run::run_dir(&dir) {
                Ok(report) => report,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };

            let mut stdout = std::io::stdout().lock();
            match format {
                Format::Json => {
                    let json = serde_json::to_string_pretty(&report).expect("report serializes");
                    let _ = writeln!(stdout, "{json}");
                }
                Format::Human => {
                    for check in &report.checks {
                        let mark = if check.passed { "ok  " } else { "FAIL" };
                        let _ = writeln!(stdout, "{mark} {} {}", check.vector, check.name);
                        if let Some(detail) = &check.detail {
                            let _ = writeln!(stdout, "       {detail}");
                        }
                    }
                    let _ = writeln!(
                        stdout,
                        "\n{} passed, {} failed",
                        report.passed(),
                        report.failed()
                    );
                }
            }

            if report.is_green() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
