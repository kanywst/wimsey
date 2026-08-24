//! Workload Identity Certificate (WIC): an X.509 certificate carrying the
//! workload identifier in a URI subjectAltName, signed by a workload CA.

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType,
    SubjectPublicKeyInfo, PKCS_ED25519,
};
use wimsey_identifier::WorkloadIdentifier;
use wimsey_jose::{Algorithm, SigningKey, VerifyingKey};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::OID_SIG_ED25519;
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;

use crate::error::MtlsError;

/// A workload certificate authority: it holds the CA certificate and its
/// signing key, and certifies public keys that workloads generated themselves.
pub struct WorkloadCa {
    issuer: Issuer<'static, KeyPair>,
    der: Vec<u8>,
}

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

/// The DER prefix of a PKCS#8 v1 Ed25519 private key (RFC 8410 Section 7).
///
/// A full PKCS#8 key is this prefix followed by the 32-byte seed.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, // SEQUENCE, 46 bytes
    0x02, 0x01, 0x00, // INTEGER version 0
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier: 1.3.101.112
    0x04, 0x22, 0x04, 0x20, // OCTET STRING wrapping a 32-byte OCTET STRING
];

/// Encodes an Ed25519 signing key as PKCS#8, the form rcgen loads.
fn ed25519_pkcs8(signing_key: &SigningKey) -> Vec<u8> {
    let mut der = Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + 32);
    der.extend_from_slice(&ED25519_PKCS8_PREFIX);
    der.extend_from_slice(&signing_key.to_bytes());
    der
}

/// Wraps an Ed25519 public key as the `SubjectPublicKeyInfo` rcgen certifies.
fn spki(public_key: &VerifyingKey) -> Result<SubjectPublicKeyInfo, MtlsError> {
    // Certificates are Ed25519-only for now. The mutual-TLS draft does not
    // require ES256 the way workload-creds does for the token path, so a P-256
    // key is refused here rather than silently certified under the wrong
    // algorithm identifier.
    if public_key.algorithm() != Algorithm::EdDsa {
        return Err(MtlsError::UnsupportedAlgorithm);
    }
    let mut der = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
    der.extend_from_slice(&ED25519_SPKI_PREFIX);
    der.extend_from_slice(&public_key.to_raw_bytes());
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
        Self::from_key(KeyPair::generate_for(&PKCS_ED25519)?, not_before, not_after)
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
        let key = KeyPair::try_from(pkcs8_der).map_err(|_| MtlsError::InvalidKey)?;
        // This crate signs with Ed25519 only, and `verify` rejects anything else
        // anyway. Refusing here means a caller finds out when it loads the key,
        // not when the first peer turns its certificate away.
        if key.algorithm() != &PKCS_ED25519 {
            return Err(MtlsError::UnsupportedAlgorithm);
        }
        Self::from_key(key, not_before, not_after)
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
        Self::from_pkcs8_der(&ed25519_pkcs8(signing_key), not_before, not_after)
    }

    fn from_key(key: KeyPair, not_before: u64, not_after: u64) -> Result<Self, MtlsError> {
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

    // The outer signatureAlgorithm, the inner tbsCertificate.signature (RFC 5280
    // Section 4.1.1.2) and the CA's own key must all be Ed25519.
    if leaf.signature_algorithm.algorithm != OID_SIG_ED25519
        || leaf.tbs_certificate.signature.algorithm != OID_SIG_ED25519
        || ca.public_key().algorithm.algorithm != OID_SIG_ED25519
    {
        return Err(MtlsError::UnsupportedAlgorithm);
    }

    // The CA public key BIT STRING must be a whole number of octets.
    if ca.public_key().subject_public_key.unused_bits != 0 {
        return Err(MtlsError::InvalidKey);
    }
    let ca_key: [u8; 32] = ca
        .public_key()
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| MtlsError::InvalidKey)?;
    let ca_key = VerifyingKey::from_raw_bytes(Algorithm::EdDsa, &ca_key)
        .map_err(|_| MtlsError::InvalidKey)?;

    // The signature BIT STRING must be a whole number of octets.
    if leaf.signature_value.unused_bits != 0 {
        return Err(MtlsError::InvalidSignature);
    }
    ca_key
        .verify(
            leaf.tbs_certificate.as_ref(),
            leaf.signature_value.data.as_ref(),
        )
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

    #[test]
    fn loads_a_ca_from_pkcs8() {
        let key = SigningKey::from_ed25519_seed(&[3u8; 32]);
        let from_key = WorkloadCa::from_ed25519(&key, CA_NBF, CA_NAF).unwrap();
        let from_der =
            WorkloadCa::from_pkcs8_der(&super::ed25519_pkcs8(&key), CA_NBF, CA_NAF).unwrap();
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
