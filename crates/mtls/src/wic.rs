//! Workload Identity Certificate (WIC): an X.509 certificate carrying the
//! workload identifier in a URI subjectAltName, signed by a workload CA.

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    PublicKeyData, SanType, SignatureAlgorithm, SigningKey as RcgenSigningKey,
    SubjectPublicKeyInfo, PKCS_ECDSA_P256_SHA256, PKCS_ED25519,
};
use wimsey_identifier::WorkloadIdentifier;
use wimsey_jose::{Algorithm, SigningKey, VerifyingKey};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::{
    OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ED25519,
};
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;

use crate::error::MtlsError;

/// A workload certificate authority: it holds the CA certificate and its
/// signing key, and certifies public keys that workloads generated themselves.
pub struct WorkloadCa {
    issuer: Issuer<'static, CaKey>,
    der: Vec<u8>,
}

/// The CA's signing key, presented to rcgen.
///
/// rcgen signs ECDSA through `ring`, which draws a random nonce, so a P-256 CA
/// built that way would emit a different certificate for the same key and
/// inputs every run. Signing goes through `wimsey-jose` instead, whose ES256 is
/// RFC 6979 deterministic, which is what lets a certificate be a recorded
/// conformance vector at all.
struct CaKey {
    key: SigningKey,
    public_key: Vec<u8>,
}

impl CaKey {
    fn new(key: SigningKey) -> Self {
        let public_key = key.verifying_key().to_raw_bytes();
        Self { key, public_key }
    }
}

impl PublicKeyData for CaKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        match self.key.algorithm() {
            Algorithm::Es256 => &PKCS_ECDSA_P256_SHA256,
            _ => &PKCS_ED25519,
        }
    }
}

impl RcgenSigningKey for CaKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let raw = self.key.sign(message);
        Ok(match self.key.algorithm() {
            Algorithm::Es256 => ecdsa_signature_to_der(&raw),
            _ => raw.to_vec(),
        })
    }
}

/// Re-encodes a fixed-width ECDSA signature as the DER X.509 carries.
///
/// JOSE writes `r` and `s` as two fixed-width integers; X.509 writes a SEQUENCE
/// of two DER INTEGERs, which are signed, minimally encoded, and so a different
/// length nearly every time.
fn ecdsa_signature_to_der(raw: &[u8; 64]) -> Vec<u8> {
    fn integer(value: &[u8]) -> Vec<u8> {
        // Minimal encoding: drop leading zero octets, but keep one if the
        // first remaining bit is set, or the value would read as negative.
        let start = value
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(value.len() - 1);
        let value = &value[start..];
        let mut out = vec![0x02];
        if value[0] & 0x80 == 0 {
            out.push(u8::try_from(value.len()).expect("half a signature is 32 bytes"));
        } else {
            out.push(u8::try_from(value.len() + 1).expect("half a signature is 32 bytes"));
            out.push(0x00);
        }
        out.extend_from_slice(value);
        out
    }

    let (r, s) = raw.split_at(32);
    let body: Vec<u8> = integer(r).into_iter().chain(integer(s)).collect();
    // At most 2 + 33 + 2 + 33 = 70 bytes, so the length is always one octet.
    let mut der = vec![0x30, u8::try_from(body.len()).expect("at most 70 bytes")];
    der.extend_from_slice(&body);
    der
}

/// Recovers the fixed-width form from the DER a certificate carries.
fn ecdsa_signature_from_der(der: &[u8]) -> Result<[u8; 64], MtlsError> {
    fn integer<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], MtlsError> {
        let [0x02, len, rest @ ..] = input else {
            return Err(MtlsError::InvalidSignature);
        };
        let len = usize::from(*len);
        let value = rest.get(..len).ok_or(MtlsError::InvalidSignature)?;
        *input = &rest[len..];
        // A leading zero is only legal as the encoding of zero itself, or to
        // keep a value whose top bit is set from reading as negative.
        let value = match value {
            [0x00] => value,
            [0x00, tail @ ..] if tail[0] & 0x80 != 0 => tail,
            [0x00, ..] => return Err(MtlsError::InvalidSignature),
            value => value,
        };
        if value.len() > 32 || value.is_empty() {
            return Err(MtlsError::InvalidSignature);
        }
        Ok(value)
    }

    let (&[0x30, len], rest) = der.split_at_checked(2).ok_or(MtlsError::InvalidSignature)? else {
        return Err(MtlsError::InvalidSignature);
    };
    if rest.len() != usize::from(len) {
        return Err(MtlsError::InvalidSignature);
    }
    let mut body = rest;
    let r = integer(&mut body)?;
    let s = integer(&mut body)?;
    if !body.is_empty() {
        return Err(MtlsError::InvalidSignature);
    }

    let mut raw = [0u8; 64];
    raw[32 - r.len()..32].copy_from_slice(r);
    raw[64 - s.len()..].copy_from_slice(s);
    Ok(raw)
}

/// `prime256v1` (1.2.840.10045.3.1.7), the only curve `Algorithm::Es256` names.
const OID_EC_P256: x509_parser::der_parser::oid::Oid<'static> =
    x509_parser::der_parser::oid!(1.2.840 .10045 .3 .1 .7);

/// The DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410 Section 4).
///
/// A full SPKI is this prefix followed by the 32-byte public key: a SEQUENCE
/// wrapping the `id-Ed25519` OID (1.3.101.112) and a BIT STRING with no unused
/// bits.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, // SEQUENCE, 42 bytes
    0x30, 0x05, // SEQUENCE, 5 bytes (AlgorithmIdentifier)
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
    0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused
];

/// The DER prefix of a P-256 `SubjectPublicKeyInfo` (RFC 5480 Section 2).
///
/// A full SPKI is this prefix followed by the 65-byte uncompressed point: a
/// SEQUENCE wrapping `id-ecPublicKey` (1.2.840.10045.2.1) with the named curve
/// `prime256v1` (1.2.840.10045.3.1.7), and a BIT STRING with no unused bits.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, // SEQUENCE, 89 bytes
    0x30, 0x13, // SEQUENCE, 19 bytes (AlgorithmIdentifier)
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7
    0x03, 0x42, 0x00, // BIT STRING, 66 bytes, 0 unused
];

/// What follows the version INTEGER in an Ed25519 PKCS#8 key, in either version.
const ED25519_PKCS8_INNER: [u8; 11] = [
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier: 1.3.101.112
    0x04, 0x22, 0x04, 0x20, // OCTET STRING wrapping a 32-byte OCTET STRING
];

/// Reads the seed out of a PKCS#8 Ed25519 private key.
///
/// v1 (RFC 5208) and v2 (RFC 5958) differ in the version INTEGER and in whether
/// the public key is appended, but both put the same header at the same offset
/// with the seed straight after it. Accepting only v1 would turn away the keys
/// rcgen itself emits, which are v2.
fn ed25519_seed_from_pkcs8(der: &[u8]) -> Result<[u8; 32], MtlsError> {
    let header = der.get(..5).ok_or(MtlsError::InvalidKey)?;
    if !matches!(header, [0x30, _, 0x02, 0x01, 0x00 | 0x01]) {
        return Err(MtlsError::InvalidKey);
    }
    der.get(5..)
        .and_then(|rest| rest.strip_prefix(ED25519_PKCS8_INNER.as_slice()))
        .ok_or(MtlsError::UnsupportedAlgorithm)?
        .get(..32)
        .and_then(|seed| seed.try_into().ok())
        .ok_or(MtlsError::InvalidKey)
}

/// Wraps a public key as the `SubjectPublicKeyInfo` rcgen certifies.
fn spki(public_key: &VerifyingKey) -> Result<SubjectPublicKeyInfo, MtlsError> {
    let raw = public_key.to_raw_bytes();
    let prefix: &[u8] = match public_key.algorithm() {
        Algorithm::Es256 => &P256_SPKI_PREFIX,
        _ => &ED25519_SPKI_PREFIX,
    };
    let mut der = Vec::with_capacity(prefix.len() + raw.len());
    der.extend_from_slice(prefix);
    der.extend_from_slice(&raw);
    SubjectPublicKeyInfo::from_der(&der).map_err(|_| MtlsError::InvalidKey)
}

impl WorkloadCa {
    /// Generates a new Ed25519 workload CA valid between the two Unix
    /// timestamps.
    ///
    /// The window is explicit because the underlying default is a certificate
    /// valid until the year 4096, which is not a lifetime anyone would choose
    /// for a CA on purpose.
    ///
    /// The key exists only for the lifetime of the returned value. To run a CA
    /// that outlives one process — which is to say, any real one — keep the key
    /// yourself and use [`WorkloadCa::from_pkcs8_der`].
    ///
    /// # Errors
    ///
    /// Returns [`MtlsError::Generate`] if key or certificate generation fails,
    /// or [`MtlsError::Time`] if a timestamp is out of range.
    pub fn generate(not_before: u64, not_after: u64) -> Result<Self, MtlsError> {
        let pkcs8 = KeyPair::generate_for(&PKCS_ED25519)?.serialize_der();
        Self::from_pkcs8_der(&pkcs8, not_before, not_after)
    }

    /// Builds a workload CA from a signing key of either supported algorithm.
    ///
    /// The general form of the constructors below. An `ES256` CA signs through
    /// RFC 6979, so the same key and window always produce the same CA
    /// certificate, exactly as an Ed25519 one does.
    ///
    /// # Errors
    ///
    /// Returns [`MtlsError::Generate`] if certificate generation fails, or
    /// [`MtlsError::Time`] if a timestamp is out of range.
    pub fn from_signing_key(
        signing_key: &SigningKey,
        not_before: u64,
        not_after: u64,
    ) -> Result<Self, MtlsError> {
        Self::from_key(CaKey::new(signing_key.clone()), not_before, not_after)
    }

    /// Loads a workload CA from an existing PKCS#8-encoded Ed25519 private key.
    ///
    /// This is how a CA survives a restart: the same key yields the same CA
    /// certificate, so peers that already trust it keep trusting it.
    ///
    /// # Errors
    ///
    /// Returns [`MtlsError::InvalidKey`] if `pkcs8_der` is not a PKCS#8 Ed25519
    /// private key, [`MtlsError::Generate`] if certificate generation fails, or
    /// [`MtlsError::Time`] if a timestamp is out of range.
    pub fn from_pkcs8_der(
        pkcs8_der: &[u8],
        not_before: u64,
        not_after: u64,
    ) -> Result<Self, MtlsError> {
        // PKCS#8 loading stays Ed25519-only: an ES256 CA is built from a
        // `wimsey-jose` key through `from_signing_key`, which is the form the
        // rest of this workspace already passes around.
        let seed = ed25519_seed_from_pkcs8(pkcs8_der)?;
        Self::from_signing_key(&SigningKey::from_ed25519_seed(&seed), not_before, not_after)
    }

    /// Loads a workload CA from an Ed25519 signing key.
    ///
    /// The convenient form of [`WorkloadCa::from_pkcs8_der`] for callers already
    /// holding an `ed25519-dalek` key — for example one unsealed from a KMS or
    /// read from a key file. The same key always yields the same CA
    /// certificate.
    ///
    /// # Errors
    ///
    /// Returns [`MtlsError::Generate`] if certificate generation fails, or
    /// [`MtlsError::Time`] if a timestamp is out of range.
    pub fn from_ed25519(
        signing_key: &SigningKey,
        not_before: u64,
        not_after: u64,
    ) -> Result<Self, MtlsError> {
        if signing_key.algorithm() != Algorithm::EdDsa {
            return Err(MtlsError::UnsupportedAlgorithm);
        }
        Self::from_signing_key(signing_key, not_before, not_after)
    }

    fn from_key(key: CaKey, not_before: u64, not_after: u64) -> Result<Self, MtlsError> {
        let mut params = CertificateParams::new(Vec::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = to_time(not_before)?;
        params.not_after = to_time(not_after)?;
        let cert = params.self_signed(&key)?;
        let der = cert.der().to_vec();
        Ok(Self {
            issuer: Issuer::new(params, key),
            der,
        })
    }

    /// The CA certificate, DER-encoded; used as the trust anchor by [`verify`].
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.der
    }

    /// Issues a WIC binding `identifier` to `public_key`, valid between the two
    /// Unix timestamps. Returns the certificate, DER-encoded.
    ///
    /// Only the workload's *public* key is passed in. The workload generates its
    /// own key pair and never hands the private half to the CA, so a compromised
    /// CA cannot impersonate a workload it has already certified — it can only
    /// mint new certificates. This is the same custody model SPIFFE uses, and
    /// the reason this crate has no way to ask a CA for a private key.
    ///
    /// # Errors
    ///
    /// Returns [`MtlsError::MissingIdentifier`] if the identifier cannot be
    /// encoded as a URI SAN, [`MtlsError::InvalidKey`] if `public_key` cannot be
    /// encoded, [`MtlsError::Time`] if a timestamp is out of range, or
    /// [`MtlsError::Generate`] if signing fails.
    pub fn issue(
        &self,
        identifier: &WorkloadIdentifier,
        public_key: &VerifyingKey,
        not_before: u64,
        not_after: u64,
    ) -> Result<Vec<u8>, MtlsError> {
        let mut params = CertificateParams::new(Vec::new())?;
        params.subject_alt_names = vec![SanType::URI(
            identifier
                .as_str()
                .try_into()
                .map_err(|_| MtlsError::MissingIdentifier)?,
        )];
        params.not_before = to_time(not_before)?;
        params.not_after = to_time(not_after)?;
        // Section 3 of `draft-ietf-wimse-mutual-tls`: a WIC used by a TLS client
        // SHOULD carry `id-kp-clientAuth`, and one used by a TLS server
        // `id-kp-serverAuth`. A workload is routinely both, and the draft allows
        // a certificate to carry both, so issuance sets the pair.
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];

        let cert = params.signed_by(&spki(public_key)?, &self.issuer)?;
        Ok(cert.der().to_vec())
    }
}

fn to_time(unix: u64) -> Result<::time::OffsetDateTime, MtlsError> {
    let secs = i64::try_from(unix).map_err(|_| MtlsError::Time)?;
    ::time::OffsetDateTime::from_unix_timestamp(secs).map_err(|_| MtlsError::Time)
}

/// Extracts the workload identifier from a WIC without verifying it.
///
/// # Errors
///
/// Returns [`MtlsError::Parse`] if the certificate cannot be parsed, or
/// [`MtlsError::MissingIdentifier`] if it has no URI SAN.
pub fn workload_identifier(wic_der: &[u8]) -> Result<WorkloadIdentifier, MtlsError> {
    let (rest, cert) = X509Certificate::from_der(wic_der).map_err(|_| MtlsError::Parse)?;
    if !rest.is_empty() {
        return Err(MtlsError::Parse);
    }
    uri_san(&cert)
}

/// Verifies a WIC against a CA certificate at time `now` (Unix seconds) and
/// returns the workload identifier.
///
/// Checks that both the certificate signature and the CA key are Ed25519, the
/// CA signature over the tbsCertificate, that both the CA and leaf are within
/// their validity windows, and that the leaf carries exactly one URI SAN.
///
/// # Errors
///
/// Returns the corresponding [`MtlsError`] for a parse failure, a wrong
/// algorithm or key, a bad signature, an out-of-window certificate, or a
/// missing / invalid identifier.
pub fn verify(wic_der: &[u8], ca_der: &[u8], now: u64) -> Result<WorkloadIdentifier, MtlsError> {
    let (rest_wic, leaf) = X509Certificate::from_der(wic_der).map_err(|_| MtlsError::Parse)?;
    let (rest_ca, ca) = X509Certificate::from_der(ca_der).map_err(|_| MtlsError::Parse)?;
    if !rest_wic.is_empty() || !rest_ca.is_empty() {
        return Err(MtlsError::Parse);
    }

    // The outer signatureAlgorithm and the inner tbsCertificate.signature
    // (RFC 5280 Section 4.1.1.2) must agree, and both must be the algorithm the
    // CA's own key can actually produce. Deciding from the CA key rather than
    // from the certificate's own claim is what stops a certificate naming one
    // algorithm and being checked under another.
    let algorithm = match ca.public_key().algorithm.algorithm {
        ref oid if *oid == OID_SIG_ED25519 => Algorithm::EdDsa,
        ref oid if *oid == OID_KEY_TYPE_EC_PUBLIC_KEY => Algorithm::Es256,
        _ => return Err(MtlsError::UnsupportedAlgorithm),
    };
    let expected_signature_oid = match algorithm {
        Algorithm::Es256 => OID_SIG_ECDSA_WITH_SHA256,
        _ => OID_SIG_ED25519,
    };
    if leaf.signature_algorithm.algorithm != expected_signature_oid
        || leaf.tbs_certificate.signature.algorithm != expected_signature_oid
    {
        return Err(MtlsError::UnsupportedAlgorithm);
    }
    // An EC key names its curve in the AlgorithmIdentifier parameters, and
    // `Algorithm::Es256` is P-256 only.
    if algorithm == Algorithm::Es256 {
        let curve = ca
            .public_key()
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok());
        if curve != Some(OID_EC_P256) {
            return Err(MtlsError::UnsupportedAlgorithm);
        }
    }

    // The CA public key BIT STRING must be a whole number of octets.
    if ca.public_key().subject_public_key.unused_bits != 0 {
        return Err(MtlsError::InvalidKey);
    }
    let ca_key =
        VerifyingKey::from_raw_bytes(algorithm, ca.public_key().subject_public_key.data.as_ref())
            .map_err(|_| MtlsError::InvalidKey)?;

    // The signature BIT STRING must be a whole number of octets.
    if leaf.signature_value.unused_bits != 0 {
        return Err(MtlsError::InvalidSignature);
    }
    // X.509 carries ECDSA as DER; the key verifies the fixed-width form.
    let signature = match algorithm {
        Algorithm::Es256 => ecdsa_signature_from_der(leaf.signature_value.data.as_ref())?.to_vec(),
        _ => leaf.signature_value.data.to_vec(),
    };
    ca_key
        .verify(leaf.tbs_certificate.as_ref(), &signature)
        .map_err(|_| MtlsError::InvalidSignature)?;

    // Both the leaf and the CA must be within their validity windows.
    let secs = i64::try_from(now).map_err(|_| MtlsError::Time)?;
    let at = ASN1Time::from_timestamp(secs).map_err(|_| MtlsError::Time)?;
    if !ca.validity().is_valid_at(at) || !leaf.validity().is_valid_at(at) {
        return Err(MtlsError::NotValid);
    }

    uri_san(&leaf)
}

fn uri_san(cert: &X509Certificate) -> Result<WorkloadIdentifier, MtlsError> {
    let san = cert
        .subject_alternative_name()
        .map_err(|_| MtlsError::Parse)?
        .ok_or(MtlsError::MissingIdentifier)?;

    // A SPIFFE X.509-SVID carries exactly one URI SAN; other SAN types (e.g.
    // DNS names) are permitted and ignored.
    let mut uris = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        });
    let uri = uris.next().ok_or(MtlsError::MissingIdentifier)?;
    if uris.next().is_some() {
        return Err(MtlsError::MultipleIdentifiers);
    }
    Ok(WorkloadIdentifier::parse(uri)?)
}

#[cfg(test)]
mod tests {
    use wimsey_identifier::WorkloadIdentifier;

    use wimsey_jose::SigningKey;

    use super::{verify, workload_identifier, WorkloadCa};
    use crate::error::MtlsError;

    const NBF: u64 = 1_700_000_000;
    const NAF: u64 = 1_700_086_400;
    /// The CA's validity, which outlives the certificates it issues.
    const CA_NBF: u64 = 1_600_000_000;
    const CA_NAF: u64 = 1_900_000_000;

    fn id() -> WorkloadIdentifier {
        WorkloadIdentifier::parse("spiffe://example.org/workload/api").unwrap()
    }

    fn ca() -> WorkloadCa {
        WorkloadCa::generate(CA_NBF, CA_NAF).unwrap()
    }

    /// Encodes an Ed25519 signing key as PKCS#8 v1, the older of the two forms
    /// `from_pkcs8_der` reads. rcgen itself emits v2.
    fn ed25519_pkcs8(signing_key: &SigningKey) -> Vec<u8> {
        const V1_PREFIX: [u8; 5] = [
            0x30, 0x2e, // SEQUENCE, 46 bytes
            0x02, 0x01, 0x00, // INTEGER version 0
        ];
        let mut der = Vec::with_capacity(48);
        der.extend_from_slice(&V1_PREFIX);
        der.extend_from_slice(&super::ED25519_PKCS8_INNER);
        der.extend_from_slice(&signing_key.to_bytes());
        der
    }

    /// A key pair the *workload* owns. Only its public half reaches the CA.
    fn workload_key() -> SigningKey {
        SigningKey::from_ed25519_seed(&[7u8; 32])
    }

    fn issue(ca: &WorkloadCa) -> Vec<u8> {
        ca.issue(&id(), &workload_key().verifying_key(), NBF, NAF)
            .unwrap()
    }

    #[test]
    fn issue_verify_round_trip() {
        let ca = ca();
        let wic = issue(&ca);

        let verified = verify(&wic, ca.certificate_der(), NBF + 100).unwrap();
        assert_eq!(verified, id());
    }

    #[test]
    fn issues_with_both_extended_key_usages() {
        use x509_parser::certificate::X509Certificate;
        use x509_parser::prelude::FromDer;

        let ca = ca();
        let wic = issue(&ca);

        let (_, cert) = X509Certificate::from_der(&wic).unwrap();
        let eku = cert
            .extended_key_usage()
            .unwrap()
            .expect("the WIC carries an extendedKeyUsage extension")
            .value;
        assert!(eku.client_auth, "id-kp-clientAuth must be set");
        assert!(eku.server_auth, "id-kp-serverAuth must be set");
    }

    // A CA that cannot outlive its process is not a CA. Reloading the same key
    // must reproduce the same certificate, or every restart silently breaks
    // every peer that already trusts it.
    #[test]
    fn a_reloaded_ca_is_the_same_ca() {
        let key = SigningKey::from_ed25519_seed(&[3u8; 32]);
        let first = WorkloadCa::from_ed25519(&key, CA_NBF, CA_NAF).unwrap();
        let restarted = WorkloadCa::from_ed25519(&key, CA_NBF, CA_NAF).unwrap();
        assert_eq!(first.certificate_der(), restarted.certificate_der());

        // And a certificate issued before the restart still verifies after it.
        let wic = issue(&first);
        assert_eq!(
            verify(&wic, restarted.certificate_der(), NBF + 100).unwrap(),
            id()
        );
    }

    /// The four combinations of CA algorithm and workload key algorithm.
    ///
    /// A workload whose proof-of-possession key is ES256 has to be able to get
    /// a certificate too, whatever the CA signs with, or the token path and the
    /// certificate path disagree about which algorithms a workload may use.
    #[test]
    fn issues_and_verifies_across_both_algorithms() {
        let cas = [
            ("EdDSA", SigningKey::from_ed25519_seed(&[3u8; 32])),
            ("ES256", SigningKey::from_p256_scalar(&[4u8; 32]).unwrap()),
        ];
        let workloads = [
            ("EdDSA", SigningKey::from_ed25519_seed(&[5u8; 32])),
            ("ES256", SigningKey::from_p256_scalar(&[6u8; 32]).unwrap()),
        ];
        for (ca_alg, ca_key) in &cas {
            let ca = WorkloadCa::from_signing_key(ca_key, CA_NBF, CA_NAF).unwrap();
            for (wl_alg, wl_key) in &workloads {
                let wic = ca
                    .issue(&id(), &wl_key.verifying_key(), NBF, NAF)
                    .unwrap_or_else(|e| panic!("{ca_alg} CA, {wl_alg} workload: {e}"));
                let subject = verify(&wic, ca.certificate_der(), NBF + 1)
                    .unwrap_or_else(|e| panic!("{ca_alg} CA, {wl_alg} workload: {e}"));
                assert_eq!(subject, id());
            }
        }
    }

    /// An ES256 CA has to be as reproducible as an Ed25519 one, or a
    /// certificate cannot be a recorded conformance vector.
    #[test]
    fn an_es256_ca_is_deterministic() {
        let key = SigningKey::from_p256_scalar(&[4u8; 32]).unwrap();
        let workload = SigningKey::from_p256_scalar(&[6u8; 32]).unwrap();
        let issue = || {
            let ca = WorkloadCa::from_signing_key(&key, CA_NBF, CA_NAF).unwrap();
            let wic = ca
                .issue(&id(), &workload.verifying_key(), NBF, NAF)
                .unwrap();
            (ca.certificate_der().to_vec(), wic)
        };
        assert_eq!(issue(), issue());
    }

    /// The CA's key decides which signature algorithm is acceptable, so a
    /// certificate cannot name one algorithm and be checked under another.
    #[test]
    fn rejects_a_certificate_signed_by_the_other_algorithm() {
        let ed = WorkloadCa::from_signing_key(
            &SigningKey::from_ed25519_seed(&[3u8; 32]),
            CA_NBF,
            CA_NAF,
        )
        .unwrap();
        let ec = WorkloadCa::from_signing_key(
            &SigningKey::from_p256_scalar(&[4u8; 32]).unwrap(),
            CA_NBF,
            CA_NAF,
        )
        .unwrap();
        let wic = ed
            .issue(&id(), &workload_key().verifying_key(), NBF, NAF)
            .unwrap();
        let err = verify(&wic, ec.certificate_der(), NBF + 1);
        assert!(
            matches!(err, Err(MtlsError::UnsupportedAlgorithm)),
            "{err:?}"
        );
    }

    #[test]
    fn round_trips_an_ecdsa_signature_through_der() {
        // A leading zero on either half is the case a hand-rolled encoder gets
        // wrong: DER INTEGERs are signed and minimally encoded.
        for raw in [[0u8; 64], [0xffu8; 64], {
            let mut v = [0x7fu8; 64];
            v[0] = 0x00;
            v[32] = 0x80;
            v
        }] {
            let der = super::ecdsa_signature_to_der(&raw);
            assert_eq!(
                super::ecdsa_signature_from_der(&der).unwrap(),
                raw,
                "{raw:02x?}"
            );
        }
    }

    #[test]
    fn rejects_malformed_ecdsa_der() {
        for bad in [
            &b""[..],
            &[0x30, 0x00][..],
            &[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01][..],
            // A non-minimal leading zero.
            &[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01][..],
        ] {
            assert!(super::ecdsa_signature_from_der(bad).is_err(), "{bad:02x?}");
        }
    }

    #[test]
    fn loads_a_ca_from_pkcs8() {
        let key = SigningKey::from_ed25519_seed(&[3u8; 32]);
        let from_key = WorkloadCa::from_ed25519(&key, CA_NBF, CA_NAF).unwrap();
        let from_der = WorkloadCa::from_pkcs8_der(&ed25519_pkcs8(&key), CA_NBF, CA_NAF).unwrap();
        assert_eq!(from_key.certificate_der(), from_der.certificate_der());
    }

    #[test]
    fn rejects_a_ca_key_that_is_not_ed25519() {
        let err = WorkloadCa::from_pkcs8_der(b"not a key at all", CA_NBF, CA_NAF);
        assert!(matches!(err, Err(MtlsError::InvalidKey)));
    }

    // Issuance takes only the workload's public key, so the same inputs must
    // produce the same certificate — there is no per-issuance secret to vary.
    #[test]
    fn issuance_is_reproducible() {
        let ca =
            WorkloadCa::from_ed25519(&SigningKey::from_ed25519_seed(&[3u8; 32]), CA_NBF, CA_NAF)
                .unwrap();
        assert_eq!(issue(&ca), issue(&ca));
    }

    // The certificate must bind the key the workload actually holds. A WIC
    // issued for one key must not be usable by the holder of another.
    #[test]
    fn certifies_the_public_key_it_was_given() {
        use x509_parser::certificate::X509Certificate;
        use x509_parser::prelude::FromDer;

        let ca = ca();
        let wic = issue(&ca);
        let (_, cert) = X509Certificate::from_der(&wic).unwrap();
        assert_eq!(
            cert.public_key().subject_public_key.data.as_ref(),
            &workload_key().verifying_key().to_raw_bytes()[..],
            "the WIC must carry the workload's own public key"
        );
    }

    #[test]
    fn extracts_identifier_without_verifying() {
        let ca = ca();
        let wic = issue(&ca);
        assert_eq!(workload_identifier(&wic).unwrap(), id());
    }

    #[test]
    fn rejects_a_different_ca() {
        let ca = ca();
        let wic = issue(&ca);
        let other = WorkloadCa::generate(CA_NBF, CA_NAF).unwrap();

        let err = verify(&wic, other.certificate_der(), NBF + 100);
        assert!(matches!(err, Err(MtlsError::InvalidSignature)));
    }

    #[test]
    fn rejects_an_expired_certificate() {
        let ca = ca();
        let wic = issue(&ca);

        let err = verify(&wic, ca.certificate_der(), NAF + 1);
        assert!(matches!(err, Err(MtlsError::NotValid)));
    }

    #[test]
    fn rejects_a_certificate_without_a_uri_san() {
        // The CA certificate carries no subjectAltName.
        let ca = ca();
        let err = workload_identifier(ca.certificate_der());
        assert!(matches!(err, Err(MtlsError::MissingIdentifier)));
    }

    #[test]
    fn rejects_multiple_uri_sans() {
        use rcgen::{CertificateParams, KeyPair, SanType, PKCS_ED25519};

        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.subject_alt_names = vec![
            SanType::URI("spiffe://example.org/a".try_into().unwrap()),
            SanType::URI("spiffe://example.org/b".try_into().unwrap()),
        ];
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let cert = params.self_signed(&key).unwrap();

        let err = workload_identifier(cert.der().as_ref());
        assert!(matches!(err, Err(MtlsError::MultipleIdentifiers)));
    }

    #[test]
    fn accepts_a_uri_san_alongside_other_san_types() {
        use rcgen::{CertificateParams, KeyPair, SanType, PKCS_ED25519};

        // SPIFFE permits a single URI SAN together with other SAN types.
        let identifier = id();
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.subject_alt_names = vec![
            SanType::URI(identifier.as_str().try_into().unwrap()),
            SanType::DnsName("example.org".try_into().unwrap()),
        ];
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let cert = params.self_signed(&key).unwrap();

        assert_eq!(
            workload_identifier(cert.der().as_ref()).unwrap(),
            identifier
        );
    }
}
