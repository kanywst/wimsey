//! `wimsey httpsig` — RFC 9421 HTTP Message Signatures over the WIMSE profile.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde_json::json;
use wimsey_httpsig::{
    content_digest_sha256, sign, verify, verify_content_digest, Component, HttpRequest,
    SignatureParams, VerifyConfig, ALG,
};

use crate::key;
use crate::Result;

#[derive(Subcommand)]
pub(crate) enum HttpsigCmd {
    /// Sign an HTTP request with the workload's proof-of-possession key.
    Sign(SignArgs),
    /// Verify a signed HTTP request: verify the WIT, then the signature.
    Verify(VerifyArgs),
}

#[derive(Args)]
pub(crate) struct SignArgs {
    /// The proof-of-possession private key file.
    #[arg(long, value_name = "FILE")]
    pop_key: PathBuf,
    /// The request method.
    #[arg(long, default_value = "POST")]
    method: String,
    /// The request authority (host[:port]).
    #[arg(long)]
    authority: String,
    /// The absolute request path.
    #[arg(long)]
    path: String,
    /// The query string, without the leading `?`.
    #[arg(long)]
    query: Option<String>,
    /// An extra header, `Name: Value`; repeatable.
    #[arg(long = "header", value_name = "NAME: VALUE")]
    header: Vec<String>,
    /// A WIT to carry in a `Workload-Identity-Token` header and cover.
    #[arg(long)]
    wit: Option<String>,
    /// A body file; its SHA-256 `Content-Digest` header is added and covered.
    #[arg(long, value_name = "FILE")]
    body_file: Option<PathBuf>,
    /// Comma-separated covered components (overrides the default set).
    #[arg(long)]
    cover: Option<String>,
    /// The `keyid` signature parameter.
    #[arg(long)]
    keyid: String,
    /// The `created` time (Unix seconds); defaults to now.
    #[arg(long)]
    created: Option<u64>,
    /// The signature label.
    #[arg(long, default_value = "wimse")]
    label: String,
}

#[derive(Args)]
pub(crate) struct VerifyArgs {
    /// The issuer's public key file, used to verify the WIT.
    #[arg(long, value_name = "FILE")]
    issuer_jwk: PathBuf,
    /// The WIT carried in the request.
    #[arg(long)]
    wit: String,
    /// The request method.
    #[arg(long, default_value = "POST")]
    method: String,
    /// The request authority (host[:port]).
    #[arg(long)]
    authority: String,
    /// The absolute request path.
    #[arg(long)]
    path: String,
    /// The query string, without the leading `?`.
    #[arg(long)]
    query: Option<String>,
    /// An extra header, `Name: Value`; repeatable.
    #[arg(long = "header", value_name = "NAME: VALUE")]
    header: Vec<String>,
    /// A body file to bind against the covered `Content-Digest` header.
    #[arg(long, value_name = "FILE")]
    body_file: Option<PathBuf>,
    /// The `Signature-Input` field value.
    #[arg(long)]
    signature_input: String,
    /// The `Signature` field value.
    #[arg(long)]
    signature: String,
    /// Comma-separated components that must be covered (overrides the default).
    #[arg(long)]
    require: Option<String>,
    /// Require this issuer on the WIT.
    #[arg(long)]
    expected_iss: Option<String>,
    /// Override the current time (Unix seconds). For testing only.
    #[arg(long)]
    now: Option<u64>,
}

pub(crate) fn run(cmd: HttpsigCmd) -> Result<()> {
    match cmd {
        HttpsigCmd::Sign(args) => run_sign(args),
        HttpsigCmd::Verify(args) => run_verify(args),
    }
}

fn parse_header(spec: &str) -> Result<(String, String)> {
    let (name, value) = spec
        .split_once(':')
        .ok_or("header must be in `Name: Value` form")?;
    let name = name.trim();
    if name.is_empty() {
        return Err("header name cannot be empty".into());
    }
    Ok((name.to_owned(), value.trim().to_owned()))
}

/// Validates and normalizes a request path: RFC 9421 requires `@path` to begin
/// with `/`.
fn checked_path(raw: &str) -> Result<String> {
    let path = raw.trim();
    if !path.starts_with('/') {
        return Err("path must start with `/`".into());
    }
    Ok(path.to_owned())
}

fn parse_component(token: &str) -> Result<Component> {
    let token = token.trim();
    if let Some(derived) = token.strip_prefix('@') {
        match derived {
            "method" => Ok(Component::Method),
            "authority" => Ok(Component::Authority),
            "path" => Ok(Component::Path),
            "query" => Ok(Component::Query),
            other => Err(format!("unsupported derived component `@{other}`").into()),
        }
    } else {
        Ok(Component::header(token))
    }
}

fn parse_components(list: &str) -> Result<Vec<Component>> {
    list.split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(parse_component)
        .collect()
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
}

fn run_sign(args: SignArgs) -> Result<()> {
    let pop = key::load(&args.pop_key)?.signing_key()?;

    let mut headers = Vec::new();
    for spec in &args.header {
        headers.push(parse_header(spec)?);
    }
    if let Some(body_file) = &args.body_file {
        if has_header(&headers, "content-digest") {
            return Err("do not pass a Content-Digest header together with --body-file".into());
        }
        let body = std::fs::read(body_file)?;
        headers.push(("Content-Digest".to_owned(), content_digest_sha256(&body)));
    }
    if let Some(wit) = &args.wit {
        if has_header(&headers, "workload-identity-token") {
            return Err("do not pass a Workload-Identity-Token header together with --wit".into());
        }
        headers.push(("Workload-Identity-Token".to_owned(), wit.trim().to_owned()));
    }

    let request = HttpRequest {
        method: args.method.trim().to_owned(),
        authority: args.authority.trim().to_owned(),
        path: checked_path(&args.path)?,
        query: args.query.map(|q| q.trim().to_owned()),
        headers,
    };

    let components = if let Some(list) = args.cover {
        parse_components(&list)?
    } else {
        let mut components = vec![Component::Method, Component::Authority, Component::Path];
        if args.body_file.is_some() {
            components.push(Component::header("content-digest"));
        }
        if args.wit.is_some() {
            components.push(Component::header("workload-identity-token"));
        }
        components
    };

    let params = SignatureParams {
        created: Some(args.created.unwrap_or_else(wimsey_wit::now_unix)),
        keyid: Some(args.keyid),
        alg: Some(ALG.to_owned()),
        ..SignatureParams::default()
    };

    let signed = sign(&request, &components, &params, args.label.trim(), &pop)?;
    println!("Signature-Input: {}", signed.signature_input);
    println!("Signature: {}", signed.signature);
    Ok(())
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    let issuer = key::load(&args.issuer_jwk)?.verifying_key()?;
    let wit = args.wit.trim();
    let now = args.now.unwrap_or_else(wimsey_wit::now_unix);

    let mut wit_validation = wimsey_wit::Validation::at(now);
    if let Some(iss) = args.expected_iss {
        wit_validation = wit_validation.expect_issuer(iss.trim().to_owned());
    }
    let verified_wit = wimsey_wit::verify(wit, &issuer, &wit_validation)?;

    let mut headers = Vec::new();
    for spec in &args.header {
        headers.push(parse_header(spec)?);
    }
    // The signature covered the WIT header. If the caller supplied one, it must
    // match the verified WIT, otherwise the reported subject would describe a
    // different token than the request actually carries.
    if let Some((_, existing)) = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("workload-identity-token"))
    {
        if existing.trim() != wit {
            return Err("the supplied Workload-Identity-Token header does not match --wit".into());
        }
    } else {
        headers.push(("Workload-Identity-Token".to_owned(), wit.to_owned()));
    }
    let body = match &args.body_file {
        Some(path) => Some(std::fs::read(path)?),
        None => None,
    };
    if let Some(body) = &body {
        if !has_header(&headers, "content-digest") {
            headers.push(("Content-Digest".to_owned(), content_digest_sha256(body)));
        }
    }

    let request = HttpRequest {
        method: args.method.trim().to_owned(),
        authority: args.authority.trim().to_owned(),
        path: checked_path(&args.path)?,
        query: args.query.map(|q| q.trim().to_owned()),
        headers,
    };

    let required = if let Some(list) = args.require {
        parse_components(&list)?
    } else {
        let mut required = vec![
            Component::Method,
            Component::Authority,
            Component::Path,
            Component::header("workload-identity-token"),
        ];
        if body.is_some() {
            required.push(Component::header("content-digest"));
        }
        required
    };

    let config = VerifyConfig {
        now: Some(now),
        required_components: required,
        ..VerifyConfig::default()
    };
    let verified = verify(
        &request,
        args.signature_input.trim(),
        args.signature.trim(),
        &verified_wit.pop_key,
        &config,
    )?;

    // Bind the body, if provided, to the covered content-digest header.
    if let Some(body) = &body {
        let digest = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-digest"))
            .map(|(_, value)| value.as_str())
            .ok_or("content-digest header is missing")?;
        if !verify_content_digest(digest, body) {
            return Err("content-digest does not match the body".into());
        }
    }

    let out = json!({ "sub": verified_wit.claims.sub, "label": verified.label });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
