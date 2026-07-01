//! `wimsey` — a command-line tool for WIMSE workload credentials.
//!
//! Issues, verifies and inspects Workload Identity Tokens and Workload Proof
//! Tokens using Ed25519 keys stored as OKP JSON Web Keys.

mod key;

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use serde_json::json;
use wimsey_identifier::WorkloadIdentifier;
use wimsey_wit::{Confirmation, Jwk, WitClaims};
use wimsey_wpt::WptClaims;

use crate::key::JwkKey;

/// A fallible result carrying a boxed error.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser)]
#[command(
    name = "wimsey",
    version,
    about = "A vendor-neutral WIMSE reference implementation"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Ed25519 key management.
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Workload Identity Token (WIT) operations.
    Wit {
        #[command(subcommand)]
        cmd: WitCmd,
    },
    /// Workload Proof Token (WPT) operations.
    Wpt {
        #[command(subcommand)]
        cmd: WptCmd,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Generate a new Ed25519 private key as an OKP JWK.
    Generate {
        /// Optional 32-byte seed (Base64url) for a reproducible key. For testing
        /// only: a seed on the command line is visible to other processes.
        #[arg(long)]
        seed: Option<String>,
        /// Write to this file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the public JWK for a private key file.
    Public {
        /// The private key file.
        #[arg(long, value_name = "FILE")]
        r#in: PathBuf,
        /// Write to this file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum WitCmd {
    /// Issue a WIT signed by the issuer key.
    Issue {
        /// The issuer's private key file.
        #[arg(long, value_name = "FILE")]
        issuer_key: PathBuf,
        /// The workload identifier, e.g. `spiffe://example.org/api`.
        #[arg(long)]
        sub: String,
        /// The issuer identifier.
        #[arg(long)]
        iss: String,
        /// The confirmation (proof-of-possession) key file; its public half
        /// goes in the `cnf` claim.
        #[arg(long, value_name = "FILE")]
        cnf_key: PathBuf,
        /// Lifetime in seconds.
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
        /// Optional JOSE `kid` header.
        #[arg(long)]
        kid: Option<String>,
        /// Optional token id; a random 128-bit value is used if omitted.
        #[arg(long)]
        jti: Option<String>,
        /// Override the current time (Unix seconds).
        #[arg(long)]
        now: Option<u64>,
    },
    /// Verify a WIT against the issuer's public key.
    Verify {
        /// The issuer's public (or private) key file.
        #[arg(long, value_name = "FILE")]
        issuer_jwk: PathBuf,
        /// The token value.
        #[arg(long, conflicts_with = "token_file")]
        token: Option<String>,
        /// A file containing the token.
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Require this issuer.
        #[arg(long)]
        expected_iss: Option<String>,
        /// Override the current time (Unix seconds). For testing only; pinning
        /// this defeats expiry checks.
        #[arg(long)]
        now: Option<u64>,
    },
    /// Decode a WIT's header and claims without verifying.
    Inspect {
        /// The token value.
        #[arg(long, conflicts_with = "token_file")]
        token: Option<String>,
        /// A file containing the token.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum WptCmd {
    /// Create a WPT bound to a WIT, signed by the proof-of-possession key.
    New {
        /// The proof-of-possession private key file.
        #[arg(long, value_name = "FILE")]
        pop_key: PathBuf,
        /// The WIT this proof is bound to.
        #[arg(long)]
        wit: String,
        /// The audience (request target URI).
        #[arg(long)]
        aud: String,
        /// Lifetime in seconds.
        #[arg(long, default_value_t = 120)]
        ttl: u64,
        /// Optional proof id; a random 128-bit value is used if omitted.
        #[arg(long)]
        jti: Option<String>,
        /// Override the current time (Unix seconds).
        #[arg(long)]
        now: Option<u64>,
    },
    /// Verify a WPT: verify the WIT with the issuer key, then check the proof
    /// against the WIT's confirmation key.
    Verify {
        /// The issuer's public key file, used to verify the bound WIT.
        #[arg(long, value_name = "FILE")]
        issuer_jwk: PathBuf,
        /// The WIT the proof is bound to.
        #[arg(long)]
        wit: String,
        /// The audience the proof must be addressed to.
        #[arg(long)]
        aud: String,
        /// The proof value.
        #[arg(long)]
        proof: String,
        /// Require this issuer on the WIT.
        #[arg(long)]
        expected_iss: Option<String>,
        /// Override the current time (Unix seconds). For testing only.
        #[arg(long)]
        now: Option<u64>,
    },
}

fn main() {
    if let Err(err) = run(Cli::parse()) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Key { cmd } => run_key(cmd),
        Command::Wit { cmd } => run_wit(cmd),
        Command::Wpt { cmd } => run_wpt(cmd),
    }
}

fn run_key(cmd: KeyCmd) -> Result<()> {
    match cmd {
        KeyCmd::Generate { seed, out } => {
            let signing_key = if let Some(seed) = seed {
                let bytes = URL_SAFE_NO_PAD.decode(seed)?;
                let seed: [u8; 32] = bytes.try_into().map_err(|_| "seed is not 32 bytes")?;
                SigningKey::from_bytes(&seed)
            } else {
                let mut seed = [0u8; 32];
                getrandom::getrandom(&mut seed).map_err(|e| format!("getrandom: {e}"))?;
                SigningKey::from_bytes(&seed)
            };
            emit(
                &key::to_json(&JwkKey::from_signing_key(&signing_key))?,
                out.as_deref(),
            )
        }
        KeyCmd::Public { r#in, out } => {
            let jwk = key::load(&r#in)?;
            // Validate before exporting: with a private seed, re-derive the
            // public key so a mismatched `x` is rejected; otherwise confirm the
            // advertised public key is a valid Ed25519 key.
            let public = if jwk.d.is_some() {
                JwkKey::from_signing_key(&jwk.signing_key()?).to_public()
            } else {
                jwk.verifying_key()?;
                jwk.to_public()
            };
            emit(&key::to_json(&public)?, out.as_deref())
        }
    }
}

fn run_wit(cmd: WitCmd) -> Result<()> {
    match cmd {
        WitCmd::Issue {
            issuer_key,
            sub,
            iss,
            cnf_key,
            ttl,
            kid,
            jti,
            now,
        } => {
            let issuer = key::load(&issuer_key)?.signing_key()?;
            let cnf = key::load(&cnf_key)?.verifying_key()?;
            let iat = now.unwrap_or_else(wimsey_wit::now_unix);
            let exp = iat
                .checked_add(ttl)
                .ok_or("ttl overflows the expiry time")?;
            let claims = WitClaims {
                iss: iss.trim().to_owned(),
                sub: WorkloadIdentifier::parse(sub.trim())?,
                iat,
                exp,
                jti: jti.map_or_else(random_id, Ok)?,
                cnf: Confirmation {
                    jwk: Jwk::from_ed25519(&cnf),
                },
            };
            let token = wimsey_wit::issue(&claims, kid.as_deref(), &issuer)?;
            println!("{token}");
            Ok(())
        }
        WitCmd::Verify {
            issuer_jwk,
            token,
            token_file,
            expected_iss,
            now,
        } => {
            let key = key::load(&issuer_jwk)?.verifying_key()?;
            let token = read_token(token, token_file)?;
            let mut validation =
                wimsey_wit::Validation::at(now.unwrap_or_else(wimsey_wit::now_unix));
            if let Some(iss) = expected_iss {
                validation = validation.expect_issuer(iss);
            }
            let verified = wimsey_wit::verify(&token, &key, &validation)?;
            let out = json!({ "kid": verified.kid, "claims": verified.claims });
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
        WitCmd::Inspect { token, token_file } => {
            let token = read_token(token, token_file)?;
            let header: serde_json::Value = serde_json::from_slice(&decode_part(&token, 0)?)?;
            let claims: serde_json::Value = serde_json::from_slice(&decode_part(&token, 1)?)?;
            let out = json!({ "header": header, "claims": claims });
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
    }
}

fn run_wpt(cmd: WptCmd) -> Result<()> {
    match cmd {
        WptCmd::New {
            pop_key,
            wit,
            aud,
            ttl,
            jti,
            now,
        } => {
            let pop = key::load(&pop_key)?.signing_key()?;
            let iat = now.unwrap_or_else(wimsey_wit::now_unix);
            let exp = iat
                .checked_add(ttl)
                .ok_or("ttl overflows the expiry time")?;
            let claims = WptClaims {
                aud: aud.trim().to_owned(),
                exp,
                jti: jti.map_or_else(random_id, Ok)?,
                wth: wimsey_wpt::wit_thumbprint(wit.trim()),
                ath: None,
            };
            let proof = wimsey_wpt::issue(&claims, &pop)?;
            println!("{proof}");
            Ok(())
        }
        WptCmd::Verify {
            issuer_jwk,
            wit,
            aud,
            proof,
            expected_iss,
            now,
        } => {
            let wit = wit.trim();
            let now = now.unwrap_or_else(wimsey_wit::now_unix);

            // First establish trust in the WIT via the issuer key, then take the
            // confirmation key from the *verified* WIT.
            let issuer = key::load(&issuer_jwk)?.verifying_key()?;
            let mut wit_validation = wimsey_wit::Validation::at(now);
            if let Some(iss) = expected_iss {
                wit_validation = wit_validation.expect_issuer(iss);
            }
            let verified_wit = wimsey_wit::verify(wit, &issuer, &wit_validation)?;

            let validation = wimsey_wpt::Validation::new(now, aud.trim(), wit);
            let verified = wimsey_wpt::verify(proof.trim(), &verified_wit.pop_key, &validation)?;

            let out = json!({ "sub": verified_wit.claims.sub, "wpt": verified.claims });
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
    }
}

fn decode_part(token: &str, index: usize) -> Result<Vec<u8>> {
    let part = token
        .split('.')
        .nth(index)
        .ok_or("token does not have the expected number of parts")?;
    Ok(URL_SAFE_NO_PAD.decode(part)?)
}

fn read_token(token: Option<String>, token_file: Option<PathBuf>) -> Result<String> {
    match (token, token_file) {
        (Some(token), _) => Ok(token.trim().to_owned()),
        (None, Some(path)) => Ok(std::fs::read_to_string(path)?.trim().to_owned()),
        (None, None) => Err("provide --token or --token-file".into()),
    }
}

fn random_id() -> Result<String> {
    use std::fmt::Write as _;

    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("getrandom: {e}"))?;
    let mut id = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(id, "{b:02x}");
    }
    Ok(id)
}

fn emit(content: &str, out: Option<&Path>) -> Result<()> {
    match out {
        Some(path) => write_owner_only(path, content)?,
        None => println!("{content}"),
    }
    Ok(())
}

/// Writes `content` to `path`, restricting it to the owner (mode 0600 on unix)
/// since these files may contain private key material.
fn write_owner_only(path: &Path, content: &str) -> Result<()> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    // `mode` only applies when creating the file; force 0600 on an existing one
    // too, so key material never lands with looser permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600);
        file.set_permissions(perms)?;
    }
    file.write_all(content.as_bytes())?;
    Ok(())
}
