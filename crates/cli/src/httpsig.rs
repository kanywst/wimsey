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
    /// Reject a signature whose `created` is older than this many seconds.
    #[arg(long)]
    max_age: Option<u64>,
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

/// Whether `name` is a valid HTTP field name — a non-empty run of RFC 9110
/// `tchar`s. This keeps stray characters (including CR/LF or `:`) out of the
/// signature base's component identifiers.
fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '.'
                        | '^'
                        | '_'
                        | '`'
                        | '|'
                        | '~'
                )
        })
}

fn parse_header(spec: &str) -> Result<(String, String)> {
    let (name, value) = spec
        .split_once(':')
        .ok_or("header must be in `Name: Value` form")?;
    let name = name.trim();
    if !is_valid_header_name(name) {
        return Err(format!("invalid header name `{name}`").into());
    }
    Ok((name.to_owned(), value.trim().to_owned()))
}

/// Validates a request path: RFC 9421's `@path` is the absolute path only, so it
/// must begin with `/` and carry no query (`?`) or fragment (`#`).
fn checked_path(raw: &str) -> Result<String> {
    let path = raw.trim();
    if !path.starts_with('/') {
        return Err("path must start with `/`".into());
    }
    if path.contains(['?', '#']) {
        return Err("path must not contain a query (`?`) or fragment (`#`)".into());
    }
    Ok(path.to_owned())
}

/// Validates an HTTP method: a non-empty RFC 9110 token, taken as-is (RFC 9421
/// Section 2.2.1 performs no case transformation).
fn checked_method(raw: &str) -> Result<String> {
    let method = raw.trim();
    if !is_valid_header_name(method) {
        return Err("method must be a non-empty HTTP token".into());
    }
    Ok(method.to_owned())
}

fn parse_component(token: &str) -> Result<Component> {
    let token = token.trim();
    if let Some(derived) = token.strip_prefix('@') {
        match derived.to_ascii_lowercase().as_str() {
            "method" => Ok(Component::Method),
            "authority" => Ok(Component::Authority),
            "path" => Ok(Component::Path),
            "query" => Ok(Component::Query),
            other => Err(format!("unsupported derived component `@{other}`").into()),
        }
    } else {
        if !is_valid_header_name(token) {
            return Err(format!("invalid header component `{token}`").into());
        }
        // `Component::header` lowercases the name (RFC 9421 Section 2.1).
        Ok(Component::header(token))
    }
}

fn parse_components(list: &str) -> Result<Vec<Component>> {
    let components: Vec<Component> = list
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(parse_component)
        .collect::<Result<_>>()?;
    if components.is_empty() {
        return Err("the component list must not be empty".into());
    }
    Ok(components)
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
}

/// Builds and normalizes an [`HttpRequest`] the same way for signing and
/// verification: `@method` is a validated token taken as-is, `@authority` is
/// lowercased (RFC 9421 Section 2.2.2), and a leading `?` is stripped from the
/// query (which is stored without it).
fn build_request(
    method: &str,
    authority: &str,
    path: &str,
    query: Option<&str>,
    headers: Vec<(String, String)>,
) -> Result<HttpRequest> {
    Ok(HttpRequest {
        method: checked_method(method)?,
        authority: authority.trim().to_ascii_lowercase(),
        path: checked_path(path)?,
        query: query.map(|q| q.trim().trim_start_matches('?').to_owned()),
        headers,
    })
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

    let request = build_request(
        &args.method,
        &args.authority,
        &args.path,
        args.query.as_deref(),
        headers,
    )?;

    let components = if let Some(list) = args.cover {
        let components = parse_components(&list)?;
        if args.wit.is_some() && !components.contains(&Component::header("workload-identity-token"))
        {
            return Err("--cover must include workload-identity-token when --wit is set".into());
        }
        if args.body_file.is_some() && !components.contains(&Component::header("content-digest")) {
            return Err("--cover must include content-digest when --body-file is set".into());
        }
        components
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

    let keyid = args.keyid.trim();
    if keyid.is_empty() {
        return Err("keyid must not be empty".into());
    }
    let params = SignatureParams {
        created: Some(args.created.unwrap_or_else(wimsey_wit::now_unix)),
        keyid: Some(keyid.to_owned()),
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
    if !has_header(&headers, "workload-identity-token") {
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

    let request = build_request(
        &args.method,
        &args.authority,
        &args.path,
        args.query.as_deref(),
        headers,
    )?;

    // Validate the WIT against the exact value the signature covers: RFC 9421
    // joins multiple same-named headers, so checking the joined component value
    // (not just the first header) prevents smuggling a second, unverified token.
    let covered_wit = request
        .component_value(&Component::header("workload-identity-token"))
        .map_err(|_| "workload-identity-token header is missing")?;
    if covered_wit != wit {
        return Err("the supplied Workload-Identity-Token header does not match --wit".into());
    }

    let required = if let Some(list) = args.require {
        let required = parse_components(&list)?;
        // The WIMSE profile always binds the WIT, and the body when present.
        if !required.contains(&Component::header("workload-identity-token")) {
            return Err("--require must include workload-identity-token".into());
        }
        if body.is_some() && !required.contains(&Component::header("content-digest")) {
            return Err("--require must include content-digest when --body-file is set".into());
        }
        required
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
        max_age: args.max_age,
        ..VerifyConfig::default()
    };
    let verified = verify(
        &request,
        args.signature_input.trim(),
        args.signature.trim(),
        &verified_wit.pop_key,
        &config,
    )?;

    // Bind the body to the exact content-digest value the signature covers
    // (the joined component value, not just the first matching header).
    if let Some(body) = &body {
        let digest = request
            .component_value(&Component::header("content-digest"))
            .map_err(|_| "content-digest header is missing")?;
        if !verify_content_digest(&digest, body) {
            return Err("content-digest does not match the body".into());
        }
    }

    let out = json!({ "sub": verified_wit.claims.sub, "label": verified.label });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
