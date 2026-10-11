//! Real, retained local provider TLS identities; no listener or trust-store mutation.

use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose,
};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier as _},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    sign::CertifiedKey,
};
use std::{sync::Arc, time::Duration};

pub(super) const CA_CERT: &str = "provider-ca.der";
pub(super) const CA_KEY: &str = "provider-ca.key.der";
pub(super) const LEAF_CERT: &str = "provider-tls.der";
pub(super) const LEAF_KEY: &str = "provider-tls.key.der";
pub(super) const FILES: [&str; 4] = [CA_CERT, CA_KEY, LEAF_CERT, LEAF_KEY];
pub(super) const MAX_DER: usize = 16 * 1024;

pub(super) struct PublicIdentity {
    pub(super) root: Vec<u8>,
    pub(super) leaf: Vec<u8>,
}

pub(super) fn generate(
    directory: &Path,
    host: &str,
    not_before: u64,
    not_after: u64,
    unique: &mut BTreeSet<Hash>,
) -> Result<PublicIdentity> {
    ensure!(not_before < not_after, "invalid provider TLS interval");
    let start = time::OffsetDateTime::from_unix_timestamp(i64::try_from(not_before)?)?;
    let end = time::OffsetDateTime::from_unix_timestamp(i64::try_from(not_after)?)?;
    let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut root_params = CertificateParams::new(Vec::<String>::new())?;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    root_params.not_before = start;
    root_params.not_after = end;
    let root = root_params.self_signed(&root_key)?;
    let root_secret = Zeroizing::new(root_key.serialize_der());
    let issuer = Issuer::from_params(&root_params, root_key);
    let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut leaf_params = CertificateParams::new(vec![host.to_owned()])?;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.not_before = start;
    leaf_params.not_after = end;
    let leaf = leaf_params.signed_by(&leaf_key, &issuer)?;
    let leaf_secret = Zeroizing::new(leaf_key.serialize_der());
    let public = PublicIdentity {
        root: root.der().as_ref().to_vec(),
        leaf: leaf.der().as_ref().to_vec(),
    };
    for bytes in [&public.root, &public.leaf, &*root_secret, &*leaf_secret] {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_DER,
            "provider TLS identity exceeds bound"
        );
    }
    verify(&public.root, &public.leaf, host, not_before)?;
    for (certificate, secret) in [(&public.root, &*root_secret), (&public.leaf, &*leaf_secret)] {
        ensure!(
            unique.insert(validate_key(certificate, secret)?),
            "provider TLS keys must be distinct"
        );
    }
    for (name, bytes) in [
        (CA_CERT, public.root.as_slice()),
        (CA_KEY, root_secret.as_slice()),
        (LEAF_CERT, public.leaf.as_slice()),
        (LEAF_KEY, leaf_secret.as_slice()),
    ] {
        custody::write_private_file_atomic(&directory.join(name), bytes)?;
    }
    Ok(public)
}

pub(super) fn validate_key(certificate: &[u8], secret: &[u8]) -> Result<Hash> {
    let key = PrivateKeyDer::try_from(secret.to_vec())
        .map_err(|_| eyre!("invalid retained provider TLS private key"))?;
    let provider = rustls::crypto::ring::default_provider();
    let certified = CertifiedKey::from_der(
        vec![CertificateDer::from(certificate.to_vec())],
        key,
        &provider,
    )
    .map_err(|_| eyre!("retained provider TLS key does not match its certificate"))?;
    certified
        .keys_match()
        .map_err(|_| eyre!("retained provider TLS key does not match its certificate"))?;
    let public = certified
        .key
        .public_key()
        .ok_or_else(|| eyre!("retained provider TLS public key is unavailable"))?;
    Ok(Hash::new(public.as_ref()))
}

pub(super) fn verify(root: &[u8], leaf: &[u8], host: &str, at: u64) -> Result<()> {
    ensure!(
        !root.is_empty() && root.len() <= MAX_DER && !leaf.is_empty() && leaf.len() <= MAX_DER,
        "provider TLS certificate exceeds bound"
    );
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root.to_vec()))
        .map_err(|_| eyre!("invalid retained provider TLS root"))?;
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|_| eyre!("invalid retained provider TLS verifier"))?;
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| eyre!("invalid retained provider TLS name"))?;
    verifier
        .verify_server_cert(
            &CertificateDer::from(leaf),
            &[],
            &name,
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(at)),
        )
        .map_err(|_| eyre!("retained provider TLS certificate verification failed"))?;
    Ok(())
}

pub(super) fn validate_retained(
    directory: &capture::CapturedDirectory,
    root: &[u8],
    leaf: &[u8],
    host: &str,
    original_time: u64,
    unique: &mut BTreeSet<Hash>,
) -> Result<()> {
    // Reopen checks original identity at its original time. This is not a current-validity
    // grant; the actual future TLS connection must verify its current clock as usual.
    let retained_root = directory.read(CA_CERT, MAX_DER)?;
    let retained_leaf = directory.read(LEAF_CERT, MAX_DER)?;
    ensure!(
        retained_root == root && retained_leaf == leaf,
        "retained provider TLS identity changed"
    );
    verify(root, leaf, host, original_time)?;
    for (name, certificate) in [(CA_KEY, root), (LEAF_KEY, leaf)] {
        let secret = directory.read(name, MAX_DER)?;
        ensure!(
            unique.insert(validate_key(certificate, &secret)?),
            "retained provider TLS key is not distinct"
        );
    }
    directory.revalidate()?;
    Ok(())
}
