//! Workload Identity Certificate (WIC): an X.509 certificate carrying the
//! workload identifier in a URI subjectAltName, signed by a workload CA.

use ed25519_dalek::{Signature, VerifyingKey};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType, PKCS_ED25519};
use wimsey_identifier::WorkloadIdentifier;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::OID_SIG_ED25519;
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;

use crate::error::MtlsError;

/// A workload certificate authority: it holds the CA certificate and its
/// signing key, and issues WICs.
pub struct WorkloadCa {
    issuer: Issuer<'static, KeyPair>,
    der: Vec<u8>,
}

/// A freshly issued WIC and the private key the workload keeps.
pub struct IssuedWic {
    /// The certificate, DER-encoded.
    pub certificate_der: Vec<u8>,
    /// The workload's private key, PKCS#8 DER-encoded.
    pub private_key_pkcs8_der: Vec<u8>,
}

impl WorkloadCa {
    /// Generates a new Ed25519 workload CA.
    ///
    /// # Errors
    ///
    /// Returns [`MtlsError::Generate`] if key or certificate generation fails.
    pub fn generate() -> Result<Self, MtlsError> {
        let mut params = CertificateParams::new(Vec::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate_for(&PKCS_ED25519)?;
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

    /// Issues a WIC for `identifier`, valid between the two Unix timestamps.
    ///
    /// # Errors
    ///
    /// Returns [`MtlsError`] if the identifier cannot be encoded, the validity
    /// times are out of range, or signing fails.
    pub fn issue_wic(
        &self,
        identifier: &WorkloadIdentifier,
        not_before: u64,
        not_after: u64,
    ) -> Result<IssuedWic, MtlsError> {
        let mut params = CertificateParams::new(Vec::new())?;
        params.subject_alt_names = vec![SanType::URI(
            identifier
                .as_str()
                .try_into()
                .map_err(|_| MtlsError::MissingIdentifier)?,
        )];
        params.not_before = to_time(not_before)?;
        params.not_after = to_time(not_after)?;

        let leaf_key = KeyPair::generate_for(&PKCS_ED25519)?;
        let cert = params.signed_by(&leaf_key, &self.issuer)?;
        Ok(IssuedWic {
            certificate_der: cert.der().to_vec(),
            private_key_pkcs8_der: leaf_key.serialize_der(),
        })
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
    let (_, cert) = X509Certificate::from_der(wic_der).map_err(|_| MtlsError::Parse)?;
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
    let (_, leaf) = X509Certificate::from_der(wic_der).map_err(|_| MtlsError::Parse)?;
    let (_, ca) = X509Certificate::from_der(ca_der).map_err(|_| MtlsError::Parse)?;

    // Both the certificate signature and the CA's own key must be Ed25519.
    if leaf.signature_algorithm.algorithm != OID_SIG_ED25519
        || ca.public_key().algorithm.algorithm != OID_SIG_ED25519
    {
        return Err(MtlsError::UnsupportedAlgorithm);
    }

    let ca_key: [u8; 32] = ca
        .public_key()
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| MtlsError::InvalidKey)?;
    let ca_key = VerifyingKey::from_bytes(&ca_key).map_err(|_| MtlsError::InvalidKey)?;

    // The signature BIT STRING must be a whole number of octets.
    if leaf.signature_value.unused_bits != 0 {
        return Err(MtlsError::InvalidSignature);
    }
    let signature: [u8; 64] = leaf
        .signature_value
        .data
        .as_ref()
        .try_into()
        .map_err(|_| MtlsError::InvalidSignature)?;
    ca_key
        .verify_strict(
            leaf.tbs_certificate.as_ref(),
            &Signature::from_bytes(&signature),
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

    // An X.509-SVID carries exactly one URI SAN (SPIFFE X509-SVID Section 4.2).
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

    use super::{verify, workload_identifier, WorkloadCa};
    use crate::error::MtlsError;

    const NBF: u64 = 1_700_000_000;
    const NAF: u64 = 1_700_086_400;

    fn id() -> WorkloadIdentifier {
        WorkloadIdentifier::parse("spiffe://example.org/workload/api").unwrap()
    }

    #[test]
    fn issue_verify_round_trip() {
        let ca = WorkloadCa::generate().unwrap();
        let wic = ca.issue_wic(&id(), NBF, NAF).unwrap();

        let verified = verify(&wic.certificate_der, ca.certificate_der(), NBF + 100).unwrap();
        assert_eq!(verified, id());
    }

    #[test]
    fn extracts_identifier_without_verifying() {
        let ca = WorkloadCa::generate().unwrap();
        let wic = ca.issue_wic(&id(), NBF, NAF).unwrap();
        assert_eq!(workload_identifier(&wic.certificate_der).unwrap(), id());
    }

    #[test]
    fn rejects_a_different_ca() {
        let ca = WorkloadCa::generate().unwrap();
        let other = WorkloadCa::generate().unwrap();
        let wic = ca.issue_wic(&id(), NBF, NAF).unwrap();

        let err = verify(&wic.certificate_der, other.certificate_der(), NBF + 100);
        assert!(matches!(err, Err(MtlsError::InvalidSignature)));
    }

    #[test]
    fn rejects_an_expired_certificate() {
        let ca = WorkloadCa::generate().unwrap();
        let wic = ca.issue_wic(&id(), NBF, NAF).unwrap();

        let err = verify(&wic.certificate_der, ca.certificate_der(), NAF + 1);
        assert!(matches!(err, Err(MtlsError::NotValid)));
    }

    #[test]
    fn rejects_a_certificate_without_a_uri_san() {
        // The CA certificate carries no subjectAltName.
        let ca = WorkloadCa::generate().unwrap();
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
}
