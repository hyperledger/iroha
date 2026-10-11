/// Default (G1 pubkey, G2 signature) BLS suite.
pub use normal::NormalBls as BlsNormal;
/// Default BLS private key (G2 signature, G1 public key).
pub use normal::NormalPrivateKey as BlsNormalPrivateKey;
/// Default BLS public key (G2 signature, G1 public key).
pub use normal::NormalPublicKey as BlsNormalPublicKey;
/// Compact BLS suite (smaller signatures, slower ops).
///
/// Raw-key same-message aggregate verification is intentionally not part of
/// the public API because it is unsafe without verified proofs of possession.
/// Use [`crate::bls_small_verify_aggregate_same_message`] instead.
///
/// ```compile_fail
/// use iroha_crypto::BlsSmall;
///
/// let signature = [0_u8; 48];
/// let public_key = [0_u8; 96];
/// let signatures: [&[u8]; 1] = [&signature];
/// let public_keys: [&[u8]; 1] = [&public_key];
/// let _ = BlsSmall::verify_aggregate_same_message(
///     b"same message",
///     &signatures,
///     &public_keys,
/// );
/// ```
///
/// Pre-aggregated same-message verification has the same requirement and is
/// deliberately not exposed for BLS-small. Pass the individual signatures and
/// `PoPs` to [`crate::bls_small_verify_aggregate_same_message`] instead.
///
/// ```compile_fail
/// use iroha_crypto::BlsSmall;
///
/// let aggregate_signature = [0_u8; 48];
/// let public_key = [0_u8; 96];
/// let public_keys: [&[u8]; 1] = [&public_key];
/// let _ = BlsSmall::verify_preaggregated_same_message(
///     b"same message",
///     &aggregate_signature,
///     &public_keys,
/// );
/// ```
pub use small::SmallBls as BlsSmall;
/// Compact BLS private key (smaller signatures).
pub use small::SmallPrivateKey as BlsSmallPrivateKey;
/// Compact BLS public key (smaller signatures).
pub use small::SmallPublicKey as BlsSmallPublicKey;
pub(crate) mod aggregate_custody;
pub(crate) mod canonical;
pub mod consensus;
#[cfg(test)]
mod consolidation_tests;
mod ethereum;
mod implementation;
pub(crate) mod signing;
pub use signing::BlsSigningError;
pub(crate) mod uncached;
pub use ethereum::{
    ETHEREUM_BLS_POP_DST, ethereum_bls_pop_fast_aggregate_verify,
    ethereum_bls_pop_validate_public_key,
};
/// This version is the "normal" BLS signature scheme with the public key group in G1 and signature
/// group in G2. Canonical compressed signatures are 96 bytes and public keys are 48 bytes.
mod normal {
    use super::{implementation, implementation::BlsConfiguration};
    use crate::Algorithm;
    #[derive(Debug, Clone, Copy)]
    pub struct NormalConfiguration;
    impl BlsConfiguration for NormalConfiguration {
        const ALGORITHM: Algorithm = Algorithm::BlsNormal;
        type Engine = w3f_bls::ZBLS;
    }
    /// Default (non-compact) BLS signature suite.
    pub type NormalBls = implementation::BlsImpl<NormalConfiguration>;
    /// Public key type for the default BLS suite.
    pub type NormalPublicKey =
        w3f_bls::PublicKey<<NormalConfiguration as BlsConfiguration>::Engine>;
    /// Private key type for the default BLS suite.
    pub type NormalPrivateKey = implementation::ManagedSecretKey<NormalConfiguration>;
}
/// Small BLS signature scheme results in smaller signatures but slower
/// operations and bigger public key.
///
/// This is good for situations where space is a consideration and verification is infrequent.
mod small {
    use super::implementation::{self, BlsConfiguration};
    use crate::Algorithm;
    #[derive(Debug, Clone, Copy)]
    pub struct SmallConfiguration;
    impl BlsConfiguration for SmallConfiguration {
        const ALGORITHM: Algorithm = Algorithm::BlsSmall;
        type Engine = w3f_bls::TinyBLS381;
    }
    /// Compact BLS signature suite with smaller signatures.
    pub type SmallBls = implementation::BlsImpl<SmallConfiguration>;
    /// Public key type for the compact BLS suite.
    pub type SmallPublicKey = w3f_bls::PublicKey<<SmallConfiguration as BlsConfiguration>::Engine>;
    /// Private key type for the compact BLS suite.
    pub type SmallPrivateKey = implementation::ManagedSecretKey<SmallConfiguration>;
}
#[cfg(test)]
mod tests;
/// Parse the already PoP-verified normal key without allocating a diagnostic.
pub(crate) fn parsed_normal_key_borrowed(
    payload: &[u8],
) -> Result<blstrs::G1Affine, uncached::Rejection> {
    match uncached::public_key(uncached::Orientation::Normal, payload)? {
        uncached::PublicKey::Normal(key) => Ok(key),
        uncached::PublicKey::Small(_) => Err(uncached::Rejection::Verification),
    }
}

/// Retain the original parsed normal key after the typed canonical relation.
pub(crate) fn verified_normal_key_borrowed(
    payload: &[u8],
    proof: &[u8],
    message: &[u8],
) -> Result<blstrs::G1Affine, uncached::Rejection> {
    let key = uncached::public_key(uncached::Orientation::Normal, payload)?;
    let proof = uncached::signature(uncached::Orientation::Normal, proof)?;
    uncached::verify_parsed(&key, &proof, message)?;
    match key {
        uncached::PublicKey::Normal(key) => Ok(key),
        uncached::PublicKey::Small(_) => Err(uncached::Rejection::Verification),
    }
}

// Crate-local helpers let the PoP-enforcing public wrappers share the
// aggregate implementations without exposing raw-key same-message checks.
pub(crate) fn verify_aggregate_same_message_normal(
    message: &[u8],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
) -> Result<(), crate::Error> {
    implementation::BlsImpl::<normal::NormalConfiguration>::verify_aggregate_same_message(
        message,
        signatures,
        public_keys,
    )
}
pub(crate) fn verify_aggregate_same_message_small(
    message: &[u8],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
) -> Result<(), crate::Error> {
    implementation::BlsImpl::<small::SmallConfiguration>::verify_aggregate_same_message(
        message,
        signatures,
        public_keys,
    )
}
/// Exact per-signature verification across distinct messages, normal variant.
///
/// Success proves every signature is valid for the public key and message at the same index.
pub fn verify_aggregate_multi_message_normal(
    messages: &[&[u8]],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
) -> Result<(), crate::Error> {
    implementation::BlsImpl::<normal::NormalConfiguration>::verify_aggregate_multi_message(
        messages,
        signatures,
        public_keys,
    )
}
/// Exact per-signature verification across distinct messages, small variant.
///
/// Success proves every signature is valid for the public key and message at the same index.
pub fn verify_aggregate_multi_message_small(
    messages: &[&[u8]],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
) -> Result<(), crate::Error> {
    implementation::BlsImpl::<small::SmallConfiguration>::verify_aggregate_multi_message(
        messages,
        signatures,
        public_keys,
    )
}
/// Aggregate (sum) signatures for the same-message case (normal variant: pk in G1, sig in G2).
/// Returns aggregated signature bytes.
#[cfg(feature = "bls")]
pub fn aggregate_same_message_normal(signatures: &[&[u8]]) -> Result<Vec<u8>, crate::Error> {
    implementation::BlsImpl::<normal::NormalConfiguration>::aggregate_signatures(signatures)
}
/// Verify one pre-aggregated signature over distinct messages signed by groups of parsed keys
/// (normal variant). The caller has verified every key's proof of possession, the distinctness
/// of the messages and the uniqueness of the keys inside each group.
#[cfg(test)]
pub(crate) fn verify_preaggregated_multi_message_normal(
    groups: &[(&[&BlsNormalPublicKey], &[u8])],
    aggregated_signature: &[u8],
) -> Result<(), crate::Error> {
    implementation::BlsImpl::<normal::NormalConfiguration>::verify_preaggregated_multi_message(
        groups,
        aggregated_signature,
    )
}
/// Verify a pre-aggregated signature for the same-message case (normal variant).
#[cfg(feature = "bls")]
pub(crate) fn verify_preaggregated_same_message_normal(
    message: &[u8],
    aggregated_signature: &[u8],
    public_keys: &[&[u8]],
) -> Result<(), crate::Error> {
    implementation::BlsImpl::<normal::NormalConfiguration>::verify_preaggregated_same_message(
        message,
        aggregated_signature,
        public_keys,
    )
}

/// Use the ordinary exact positive cache around the sole single-signature relation.
pub(crate) fn verify_signature_bytes(
    algorithm: crate::Algorithm,
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), crate::Error> {
    match algorithm {
        crate::Algorithm::BlsNormal => BlsNormal::verify_bytes(message, signature, public_key),
        crate::Algorithm::BlsSmall => BlsSmall::verify_bytes(message, signature, public_key),
        _ => Err(crate::Error::BadSignature),
    }
}
