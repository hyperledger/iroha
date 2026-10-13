//! Exact production qualification boundary for Soracloud runtime mutations.
//!
//! The daemon receives only a stable public binding through configuration and
//! resolves the corresponding deployment-owned signer through runtime
//! injection. Private keys, credentials, tokens, and vendor connection
//! material never cross this boundary. A qualified signer is re-probed
//! immediately before and after every operation, and every returned signature
//! is verified against the exact requested transaction or provenance payload.
use iroha_config::parameters::validate_production_runtime_handle;
use iroha_crypto::{Algorithm, PublicKey, Signature};
pub use iroha_data_model::soracloud::SoracloudRuntimeProvenancePurposeV1;
use iroha_data_model::{
    account::AccountId,
    soracloud::validate_soracloud_runtime_provenance_preimage_v1,
    transaction::{SignedTransaction, TransactionPayload},
};
use std::sync::Arc;
const MAX_SORACLOUD_RUNTIME_PROVENANCE_PREIMAGE_BYTES_V1: usize = 16 * 1024 * 1024;
/// Public liveness and policy identity reported by the runtime signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoracloudRuntimeSignerQualificationV1 {
    revision: u64,
    policy_digest: [u8; 32],
    active: bool,
    test_only: bool,
}
impl SoracloudRuntimeSignerQualificationV1 {
    /// Construct a qualification report.
    ///
    /// Call [`Self::validate`] before trusting a report received from an
    /// external provider.
    #[must_use]
    pub const fn new(
        revision: u64,
        policy_digest: [u8; 32],
        active: bool,
        test_only: bool,
    ) -> Self {
        Self {
            revision,
            policy_digest,
            active,
            test_only,
        }
    }
    /// Return the exact adapter and public-policy revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }
    /// Return the exact public-policy digest.
    #[must_use]
    pub const fn policy_digest(self) -> [u8; 32] {
        self.policy_digest
    }
    /// Return whether the provider reports an active, non-revoked posture.
    #[must_use]
    pub const fn active(self) -> bool {
        self.active
    }
    /// Return whether the provider reports a test-only implementation.
    #[must_use]
    pub const fn test_only(self) -> bool {
        self.test_only
    }
    /// Reject zero, inactive, revoked, or test-only qualification.
    ///
    /// # Errors
    ///
    /// Returns the exact invalid public posture.
    pub fn validate(self) -> Result<(), SoracloudRuntimeSignerQualificationValueErrorV1> {
        if self.revision == 0 {
            return Err(SoracloudRuntimeSignerQualificationValueErrorV1::ZeroRevision);
        }
        if self.policy_digest == [0; 32] {
            return Err(SoracloudRuntimeSignerQualificationValueErrorV1::ZeroPolicyDigest);
        }
        if !self.active {
            return Err(SoracloudRuntimeSignerQualificationValueErrorV1::Inactive);
        }
        if self.test_only {
            return Err(SoracloudRuntimeSignerQualificationValueErrorV1::TestOnly);
        }
        Ok(())
    }
}
/// Invalid public signer qualification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoracloudRuntimeSignerQualificationValueErrorV1 {
    /// Adapter or public-policy revision is zero.
    ZeroRevision,
    /// Public-policy digest is all zeroes.
    ZeroPolicyDigest,
    /// Provider reports an inactive or revoked posture.
    Inactive,
    /// Provider reports a test-only implementation.
    TestOnly,
}
/// Exact non-secret identity expected from the deployment-owned signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoracloudRuntimeSignerBindingV1 {
    handle: String,
    authority: AccountId,
    public_key: PublicKey,
    qualification: SoracloudRuntimeSignerQualificationV1,
}
impl SoracloudRuntimeSignerBindingV1 {
    /// Project and validate one parsed public signer binding.
    ///
    /// # Errors
    ///
    /// Rejects an algorithm label that differs from the algorithm embedded in
    /// the public key, in addition to every invariant enforced by
    /// [`Self::try_new`].
    pub fn try_from_config(
        binding: &iroha_config::parameters::actual::SoracloudRuntimeMutationSignerBinding,
    ) -> Result<Self, SoracloudRuntimeSignerBindingErrorV1> {
        if binding.public_key.try_algorithm() != Ok(binding.algorithm) {
            return Err(SoracloudRuntimeSignerBindingErrorV1::AlgorithmKeyMismatch);
        }
        Self::try_new(
            binding.handle.clone(),
            binding.authority.clone(),
            binding.public_key.clone(),
            SoracloudRuntimeSignerQualificationV1::new(
                binding.revision,
                binding.policy_digest,
                true,
                false,
            ),
        )
    }
    /// Validate and construct an expected production signer binding.
    ///
    /// # Errors
    ///
    /// Rejects non-production handles, invalid qualification, unsupported key
    /// algorithms, and authority/key mismatches.
    pub fn try_new(
        handle: impl Into<String>,
        authority: AccountId,
        public_key: PublicKey,
        qualification: SoracloudRuntimeSignerQualificationV1,
    ) -> Result<Self, SoracloudRuntimeSignerBindingErrorV1> {
        let handle = handle.into();
        validate_production_runtime_handle(&handle)
            .map_err(|_| SoracloudRuntimeSignerBindingErrorV1::InvalidHandle)?;
        qualification
            .validate()
            .map_err(|_| SoracloudRuntimeSignerBindingErrorV1::InvalidQualification)?;
        validate_public_key_algorithm(&public_key)
            .map_err(|()| SoracloudRuntimeSignerBindingErrorV1::UnsupportedKeyAlgorithm)?;
        if AccountId::new(public_key.clone()) != authority {
            return Err(SoracloudRuntimeSignerBindingErrorV1::AuthorityKeyMismatch);
        }
        Ok(Self {
            handle,
            authority,
            public_key,
            qualification,
        })
    }
    /// Return the stable opaque provider handle.
    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }
    /// Return the exact transaction authority.
    #[must_use]
    pub const fn authority(&self) -> &AccountId {
        &self.authority
    }
    /// Return the exact public key.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    /// Return the expected active, non-test qualification.
    #[must_use]
    pub const fn qualification(&self) -> SoracloudRuntimeSignerQualificationV1 {
        self.qualification
    }
}
/// Invalid expected signer binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoracloudRuntimeSignerBindingErrorV1 {
    /// Handle is malformed, credential-bearing, or test-marked.
    InvalidHandle,
    /// Revision, digest, active posture, or test posture is invalid.
    InvalidQualification,
    /// Public-key algorithm is not Ed25519 or ML-DSA.
    UnsupportedKeyAlgorithm,
    /// Configured algorithm label differs from the public-key algorithm.
    AlgorithmKeyMismatch,
    /// Public key does not derive the configured authority.
    AuthorityKeyMismatch,
}
/// Payload-free failure while probing the deployment-owned signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoracloudRuntimeSignerProbeErrorV1 {
    /// Provider or backing signing service is unavailable.
    Unavailable,
    /// Provider refused or could not answer the public probe.
    Refused,
}
/// Payload-free failure while asking the deployment-owned signer to sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoracloudRuntimeSigningErrorV1 {
    /// Provider or backing signing service is unavailable.
    Unavailable,
    /// Provider refused or could not sign the supplied input.
    Refused,
    /// Transaction payload belongs to another authority.
    InputAuthorityMismatch,
    /// Provider returned another payload, authority, or an invalid signature.
    SubstitutedTransaction,
    /// Provider returned a signature that does not verify over the exact preimage.
    InvalidProvenanceSignature,
    /// Provenance preimage is malformed or bound to another purpose.
    InvalidProvenancePreimage,
    /// Provider identity, key, revision, or posture changed around the request.
    QualificationChanged,
}
/// Runtime-only mutation and purpose-separated provenance signer.
///
/// Implementations keep credentials and private keys inside the deployment
/// adapter. A bare [`iroha_crypto::KeyPair`] deliberately does not implement
/// this trait.
pub trait SoracloudRuntimeMutationSignerV1: Send + Sync {
    /// Return the stable opaque production-provider handle.
    fn handle(&self) -> &str;
    /// Return the transaction authority controlled by this provider.
    fn authority(&self) -> AccountId;
    /// Probe the exact public key controlled by this provider.
    ///
    /// # Errors
    ///
    /// Returns a redacted probe failure when the provider key is unavailable.
    fn public_key(&self) -> Result<PublicKey, SoracloudRuntimeSignerProbeErrorV1>;
    /// Probe the active revision, policy digest, and non-test posture.
    ///
    /// # Errors
    ///
    /// Returns a redacted probe failure when qualification cannot be read.
    fn qualification(
        &self,
    ) -> Result<SoracloudRuntimeSignerQualificationV1, SoracloudRuntimeSignerProbeErrorV1>;
    /// Sign one exact fee-quoted Soracloud transaction payload.
    ///
    /// # Errors
    ///
    /// Returns a redacted signing failure when the exact payload cannot be signed.
    fn sign_transaction(
        &self,
        payload: TransactionPayload,
    ) -> Result<SignedTransaction, SoracloudRuntimeSigningErrorV1>;
    /// Sign one exact canonical, purpose-bound provenance preimage.
    ///
    /// # Errors
    ///
    /// Returns a redacted signing failure when the exact preimage cannot be signed.
    fn sign_provenance(
        &self,
        purpose: SoracloudRuntimeProvenancePurposeV1,
        preimage: &[u8],
    ) -> Result<Signature, SoracloudRuntimeSigningErrorV1>;
}
/// Startup or operation-bound exact qualification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoracloudRuntimeSignerQualificationErrorV1 {
    /// A public provider probe was unavailable or refused.
    ProviderUnavailable,
    /// Provider handle is noncanonical or test-marked.
    InvalidProviderHandle,
    /// Provider returned a zero revision or zero policy digest.
    InvalidProviderQualification,
    /// Provider reports an inactive or revoked posture.
    ProviderInactive,
    /// Provider reports a test-only implementation.
    TestProviderRejected,
    /// Provider returned a key algorithm outside Ed25519 and ML-DSA.
    UnsupportedProviderKeyAlgorithm,
    /// Provider handle differs from configuration.
    HandleMismatch,
    /// Provider authority differs from configuration.
    AuthorityMismatch,
    /// Provider public key differs from configuration.
    PublicKeyMismatch,
    /// Provider public key does not derive its reported authority.
    ProviderAuthorityKeyMismatch,
    /// Provider revision differs from configuration.
    RevisionMismatch,
    /// Provider public-policy digest differs from configuration.
    PolicyDigestMismatch,
    /// Provider identity changed between adjacent probes.
    ProviderDrift,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProviderSnapshotV1 {
    handle: String,
    authority: AccountId,
    public_key: PublicKey,
    qualification: SoracloudRuntimeSignerQualificationV1,
}
fn validate_public_key_algorithm(public_key: &PublicKey) -> Result<(), ()> {
    if matches!(
        public_key.try_algorithm(),
        Ok(Algorithm::Ed25519 | Algorithm::MlDsa)
    ) {
        Ok(())
    } else {
        Err(())
    }
}
fn probe_provider(
    provider: &(impl SoracloudRuntimeMutationSignerV1 + ?Sized),
) -> Result<ProviderSnapshotV1, SoracloudRuntimeSignerQualificationErrorV1> {
    let handle_before = provider.handle().to_owned();
    validate_production_runtime_handle(&handle_before)
        .map_err(|_| SoracloudRuntimeSignerQualificationErrorV1::InvalidProviderHandle)?;
    let authority = provider.authority();
    let public_key = provider
        .public_key()
        .map_err(|_| SoracloudRuntimeSignerQualificationErrorV1::ProviderUnavailable)?;
    validate_public_key_algorithm(&public_key).map_err(|()| {
        SoracloudRuntimeSignerQualificationErrorV1::UnsupportedProviderKeyAlgorithm
    })?;
    let qualification = provider
        .qualification()
        .map_err(|_| SoracloudRuntimeSignerQualificationErrorV1::ProviderUnavailable)?;
    qualification.validate().map_err(|error| match error {
        SoracloudRuntimeSignerQualificationValueErrorV1::Inactive => {
            SoracloudRuntimeSignerQualificationErrorV1::ProviderInactive
        }
        SoracloudRuntimeSignerQualificationValueErrorV1::TestOnly => {
            SoracloudRuntimeSignerQualificationErrorV1::TestProviderRejected
        }
        SoracloudRuntimeSignerQualificationValueErrorV1::ZeroRevision
        | SoracloudRuntimeSignerQualificationValueErrorV1::ZeroPolicyDigest => {
            SoracloudRuntimeSignerQualificationErrorV1::InvalidProviderQualification
        }
    })?;
    if provider.handle() != handle_before {
        return Err(SoracloudRuntimeSignerQualificationErrorV1::ProviderDrift);
    }
    Ok(ProviderSnapshotV1 {
        handle: handle_before,
        authority,
        public_key,
        qualification,
    })
}
fn validate_snapshot(
    binding: &SoracloudRuntimeSignerBindingV1,
    snapshot: &ProviderSnapshotV1,
) -> Result<(), SoracloudRuntimeSignerQualificationErrorV1> {
    if snapshot.handle != binding.handle {
        return Err(SoracloudRuntimeSignerQualificationErrorV1::HandleMismatch);
    }
    if snapshot.authority != binding.authority {
        return Err(SoracloudRuntimeSignerQualificationErrorV1::AuthorityMismatch);
    }
    if snapshot.public_key != binding.public_key {
        return Err(SoracloudRuntimeSignerQualificationErrorV1::PublicKeyMismatch);
    }
    if AccountId::new(snapshot.public_key.clone()) != snapshot.authority {
        return Err(SoracloudRuntimeSignerQualificationErrorV1::ProviderAuthorityKeyMismatch);
    }
    if snapshot.qualification.revision != binding.qualification.revision {
        return Err(SoracloudRuntimeSignerQualificationErrorV1::RevisionMismatch);
    }
    if snapshot.qualification.policy_digest != binding.qualification.policy_digest {
        return Err(SoracloudRuntimeSignerQualificationErrorV1::PolicyDigestMismatch);
    }
    Ok(())
}
fn qualification_probe_error(
    error: SoracloudRuntimeSignerQualificationErrorV1,
) -> SoracloudRuntimeSignerProbeErrorV1 {
    if error == SoracloudRuntimeSignerQualificationErrorV1::ProviderUnavailable {
        SoracloudRuntimeSignerProbeErrorV1::Unavailable
    } else {
        SoracloudRuntimeSignerProbeErrorV1::Refused
    }
}
struct QualifiedSoracloudRuntimeMutationSignerV1 {
    binding: SoracloudRuntimeSignerBindingV1,
    provider: Arc<dyn SoracloudRuntimeMutationSignerV1>,
}
impl QualifiedSoracloudRuntimeMutationSignerV1 {
    fn try_new(
        binding: SoracloudRuntimeSignerBindingV1,
        provider: Arc<dyn SoracloudRuntimeMutationSignerV1>,
    ) -> Result<Self, SoracloudRuntimeSignerQualificationErrorV1> {
        let first = probe_provider(provider.as_ref())?;
        let second = probe_provider(provider.as_ref())?;
        if first != second {
            return Err(SoracloudRuntimeSignerQualificationErrorV1::ProviderDrift);
        }
        validate_snapshot(&binding, &first)?;
        Ok(Self { binding, provider })
    }
    fn revalidate(&self) -> Result<(), SoracloudRuntimeSignerQualificationErrorV1> {
        validate_snapshot(&self.binding, &probe_provider(self.provider.as_ref())?)
    }
}
impl SoracloudRuntimeMutationSignerV1 for QualifiedSoracloudRuntimeMutationSignerV1 {
    fn handle(&self) -> &str {
        self.binding.handle()
    }
    fn authority(&self) -> AccountId {
        self.binding.authority().clone()
    }
    fn public_key(&self) -> Result<PublicKey, SoracloudRuntimeSignerProbeErrorV1> {
        self.revalidate().map_err(qualification_probe_error)?;
        Ok(self.binding.public_key().clone())
    }
    fn qualification(
        &self,
    ) -> Result<SoracloudRuntimeSignerQualificationV1, SoracloudRuntimeSignerProbeErrorV1> {
        self.revalidate().map_err(qualification_probe_error)?;
        Ok(self.binding.qualification())
    }
    fn sign_transaction(
        &self,
        payload: TransactionPayload,
    ) -> Result<SignedTransaction, SoracloudRuntimeSigningErrorV1> {
        if payload.authority() != self.binding.authority() {
            return Err(SoracloudRuntimeSigningErrorV1::InputAuthorityMismatch);
        }
        self.revalidate()
            .map_err(|_| SoracloudRuntimeSigningErrorV1::QualificationChanged)?;
        let expected_payload = payload.clone();
        let transaction = self.provider.sign_transaction(payload)?;
        self.revalidate()
            .map_err(|_| SoracloudRuntimeSigningErrorV1::QualificationChanged)?;
        if transaction.payload() != &expected_payload
            || transaction.authority() != self.binding.authority()
            || transaction.attachments().is_some()
            || transaction.multisig_signatures().is_some()
            || transaction.verify_signature().is_err()
        {
            return Err(SoracloudRuntimeSigningErrorV1::SubstitutedTransaction);
        }
        Ok(transaction)
    }
    fn sign_provenance(
        &self,
        purpose: SoracloudRuntimeProvenancePurposeV1,
        preimage: &[u8],
    ) -> Result<Signature, SoracloudRuntimeSigningErrorV1> {
        if preimage.is_empty()
            || preimage.len() > MAX_SORACLOUD_RUNTIME_PROVENANCE_PREIMAGE_BYTES_V1
        {
            return Err(SoracloudRuntimeSigningErrorV1::InvalidProvenancePreimage);
        }
        validate_soracloud_runtime_provenance_preimage_v1(purpose, preimage)
            .map_err(|_| SoracloudRuntimeSigningErrorV1::InvalidProvenancePreimage)?;
        self.revalidate()
            .map_err(|_| SoracloudRuntimeSigningErrorV1::QualificationChanged)?;
        let signature = self.provider.sign_provenance(purpose, preimage)?;
        self.revalidate()
            .map_err(|_| SoracloudRuntimeSigningErrorV1::QualificationChanged)?;
        signature
            .verify(self.binding.public_key(), preimage)
            .map_err(|_| SoracloudRuntimeSigningErrorV1::InvalidProvenanceSignature)?;
        Ok(signature)
    }
}
/// Qualify an injected Soracloud signer against one exact expected binding.
///
/// The provider is probed twice before this function returns. The returned
/// facade revalidates the binding before and after every signing request and
/// verifies every result locally.
///
/// # Errors
///
/// Returns a payload-free error when the binding or provider is missing,
/// substituted, stale, revoked, test-marked, or unstable.
pub fn qualify_soracloud_runtime_mutation_signer_v1(
    binding: SoracloudRuntimeSignerBindingV1,
    provider: Arc<dyn SoracloudRuntimeMutationSignerV1>,
) -> Result<Arc<dyn SoracloudRuntimeMutationSignerV1>, SoracloudRuntimeSignerQualificationErrorV1> {
    let provider = QualifiedSoracloudRuntimeMutationSignerV1::try_new(binding, provider)?;
    let provider: Arc<dyn SoracloudRuntimeMutationSignerV1> = Arc::new(provider);
    Ok(provider)
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Hash, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId,
        block::BlockHeader,
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
        soracloud::encode_soracloud_runtime_provenance_preimage_v1,
        transaction::signed::{MultisigSignature, MultisigSignatures},
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use std::sync::Mutex;
    const QUALIFICATION: SoracloudRuntimeSignerQualificationV1 =
        SoracloudRuntimeSignerQualificationV1::new(9, [0xA9; 32], true, false);
    #[derive(Clone, Copy)]
    enum TestTransactionMutation {
        Attachments,
        Multisig,
    }
    struct TestSigner {
        handle: String,
        key_pair: KeyPair,
        qualification: Mutex<SoracloudRuntimeSignerQualificationV1>,
        transaction_mutation: Mutex<Option<TestTransactionMutation>>,
        forge_provenance: bool,
    }
    impl SoracloudRuntimeMutationSignerV1 for TestSigner {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn authority(&self) -> AccountId {
            AccountId::new(self.key_pair.public_key().clone())
        }
        fn public_key(&self) -> Result<PublicKey, SoracloudRuntimeSignerProbeErrorV1> {
            Ok(self.key_pair.public_key().clone())
        }
        fn qualification(
            &self,
        ) -> Result<SoracloudRuntimeSignerQualificationV1, SoracloudRuntimeSignerProbeErrorV1>
        {
            Ok(*self.qualification.lock().expect("qualification lock"))
        }
        fn sign_transaction(
            &self,
            payload: TransactionPayload,
        ) -> Result<SignedTransaction, SoracloudRuntimeSigningErrorV1> {
            let mutation = *self
                .transaction_mutation
                .lock()
                .expect("transaction mutation lock");
            let mut builder = TransactionBuilder::from_payload(payload).expect("valid payload");
            if matches!(mutation, Some(TestTransactionMutation::Attachments)) {
                let backend = "halo2/ipa".into();
                builder = builder
                    .with_proof_attachments(vec![ProofAttachment::new_ref(
                        backend,
                        ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
                        VerifyingKeyId::new("halo2/ipa", "test-vk"),
                    )])
                    .expect("valid proof carriers");
            }
            let mut signed = builder
                .try_sign(self.key_pair.private_key())
                .map_err(|_| SoracloudRuntimeSigningErrorV1::Refused)?;
            if matches!(mutation, Some(TestTransactionMutation::Multisig)) {
                let payload_signature = signed.signature().0.clone();
                signed.set_multisig_signatures(MultisigSignatures::new(vec![
                    MultisigSignature::new(self.key_pair.public_key().clone(), payload_signature),
                ]));
            }
            Ok(signed)
        }
        fn sign_provenance(
            &self,
            _purpose: SoracloudRuntimeProvenancePurposeV1,
            preimage: &[u8],
        ) -> Result<Signature, SoracloudRuntimeSigningErrorV1> {
            let key_pair = if self.forge_provenance {
                KeyPair::random()
            } else {
                self.key_pair.clone()
            };
            Signature::try_new(key_pair.private_key(), preimage)
                .map_err(|_| SoracloudRuntimeSigningErrorV1::Refused)
        }
    }
    fn fixture(
        forge_provenance: bool,
    ) -> (
        SoracloudRuntimeSignerBindingV1,
        Arc<TestSigner>,
        TransactionPayload,
    ) {
        let key_pair = KeyPair::random();
        let authority = AccountId::new(key_pair.public_key().clone());
        let binding = SoracloudRuntimeSignerBindingV1::try_new(
            "provider://soracloud/runtime-primary",
            authority.clone(),
            key_pair.public_key().clone(),
            QUALIFICATION,
        )
        .expect("valid binding");
        let provider = Arc::new(TestSigner {
            handle: binding.handle().to_owned(),
            key_pair,
            qualification: Mutex::new(QUALIFICATION),
            transaction_mutation: Mutex::new(None),
            forge_provenance,
        });
        let payload = TransactionBuilder::new(
            NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
                Hash::prehashed([0x15; Hash::LENGTH]),
            )),
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .into_payload()
        .expect("valid payload");
        (binding, provider, payload)
    }
    #[test]
    fn qualified_signer_reverifies_exact_transaction_and_provenance() {
        let (binding, provider, payload) = fixture(false);
        let signer = qualify_soracloud_runtime_mutation_signer_v1(binding, provider)
            .expect("provider qualifies");
        let transaction = signer
            .sign_transaction(payload.clone())
            .expect("transaction signs");
        assert_eq!(transaction.payload(), &payload);
        let provenance_payload = encode_soracloud_runtime_provenance_preimage_v1(
            SoracloudRuntimeProvenancePurposeV1::InrouHostAdvert,
            b"canonical provenance payload",
        )
        .expect("encode provenance preimage");
        let signature = signer
            .sign_provenance(
                SoracloudRuntimeProvenancePurposeV1::InrouHostAdvert,
                &provenance_payload,
            )
            .expect("provenance signs");
        signature
            .verify(
                &signer.public_key().expect("qualified key"),
                &provenance_payload,
            )
            .expect("signature verifies");
    }
    #[test]
    fn qualification_rejects_inactive_and_test_only_providers() {
        for (qualification, expected) in [
            (
                SoracloudRuntimeSignerQualificationV1::new(9, [0xA9; 32], false, false),
                SoracloudRuntimeSignerQualificationErrorV1::ProviderInactive,
            ),
            (
                SoracloudRuntimeSignerQualificationV1::new(9, [0xA9; 32], true, true),
                SoracloudRuntimeSignerQualificationErrorV1::TestProviderRejected,
            ),
        ] {
            let (binding, provider, _) = fixture(false);
            *provider.qualification.lock().expect("qualification lock") = qualification;
            assert_eq!(
                qualify_soracloud_runtime_mutation_signer_v1(binding, provider).err(),
                Some(expected)
            );
        }
    }
    #[test]
    fn qualification_rejects_substituted_handle_and_stale_revision() {
        let (binding, mut provider, _) = fixture(false);
        Arc::get_mut(&mut provider)
            .expect("sole provider reference")
            .handle = "provider://soracloud/runtime-substituted".to_owned();
        assert_eq!(
            qualify_soracloud_runtime_mutation_signer_v1(binding, provider).err(),
            Some(SoracloudRuntimeSignerQualificationErrorV1::HandleMismatch)
        );
        let (binding, provider, _) = fixture(false);
        *provider.qualification.lock().expect("qualification lock") =
            SoracloudRuntimeSignerQualificationV1::new(10, [0xA9; 32], true, false);
        assert_eq!(
            qualify_soracloud_runtime_mutation_signer_v1(binding, provider).err(),
            Some(SoracloudRuntimeSignerQualificationErrorV1::RevisionMismatch)
        );
    }
    #[test]
    fn qualified_signer_rejects_forged_provenance_signature() {
        let (binding, provider, _) = fixture(true);
        let signer = qualify_soracloud_runtime_mutation_signer_v1(binding, provider)
            .expect("provider qualifies");
        let preimage = encode_soracloud_runtime_provenance_preimage_v1(
            SoracloudRuntimeProvenancePurposeV1::InrouHostAdvert,
            b"exact payload",
        )
        .expect("encode provenance preimage");
        assert_eq!(
            signer.sign_provenance(
                SoracloudRuntimeProvenancePurposeV1::InrouHostAdvert,
                &preimage,
            ),
            Err(SoracloudRuntimeSigningErrorV1::InvalidProvenanceSignature)
        );
    }
    #[test]
    fn qualified_signer_rejects_explicit_purpose_mismatch() {
        let (binding, provider, _) = fixture(false);
        let signer = qualify_soracloud_runtime_mutation_signer_v1(binding, provider)
            .expect("provider qualifies");
        let inrou_preimage = encode_soracloud_runtime_provenance_preimage_v1(
            SoracloudRuntimeProvenancePurposeV1::InrouHostAdvert,
            b"same semantic bytes",
        )
        .expect("encode provenance preimage");
        assert_eq!(
            signer.sign_provenance(
                SoracloudRuntimeProvenancePurposeV1::InrouHostWithdraw,
                &inrou_preimage,
            ),
            Err(SoracloudRuntimeSigningErrorV1::InvalidProvenancePreimage)
        );
    }
    fn assert_transaction_sidecar_is_rejected(mutation: TestTransactionMutation) {
        let (binding, provider, payload) = fixture(false);
        *provider
            .transaction_mutation
            .lock()
            .expect("transaction mutation lock") = Some(mutation);
        let signer = qualify_soracloud_runtime_mutation_signer_v1(binding, provider)
            .expect("provider qualifies");
        assert_eq!(
            signer.sign_transaction(payload),
            Err(SoracloudRuntimeSigningErrorV1::SubstitutedTransaction)
        );
    }
    #[test]
    fn qualified_signer_rejects_provider_injected_proof_attachments() {
        assert_transaction_sidecar_is_rejected(TestTransactionMutation::Attachments);
    }
    #[test]
    fn qualified_signer_rejects_provider_injected_multisig_sidecar() {
        assert_transaction_sidecar_is_rejected(TestTransactionMutation::Multisig);
    }
    #[test]
    fn qualified_public_probes_do_not_mask_later_revocation() {
        let (binding, provider, _) = fixture(false);
        let signer = qualify_soracloud_runtime_mutation_signer_v1(binding, provider.clone())
            .expect("provider qualifies");
        *provider.qualification.lock().expect("qualification lock") =
            SoracloudRuntimeSignerQualificationV1::new(9, [0xA9; 32], false, false);
        assert_eq!(
            signer.public_key(),
            Err(SoracloudRuntimeSignerProbeErrorV1::Refused)
        );
        assert_eq!(
            signer.qualification(),
            Err(SoracloudRuntimeSignerProbeErrorV1::Refused)
        );
    }
}
