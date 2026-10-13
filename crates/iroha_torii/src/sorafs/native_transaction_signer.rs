//! Production qualification boundary for native SoraFS transaction signers.
//!
//! Runtime credentials and private keys remain outside configuration and Torii. This module binds
//! each injected signer to one immutable non-secret expected identity, probes that identity twice
//! before accepting the provider, and revalidates it immediately before and after every signing
//! operation. The facade also rejects an input owned by another authority and verifies that the
//! provider returned the exact payload, authority, and a valid signature. Each signing request
//! must contain exactly one direct instruction owned by its role before any request-time probe.
use iroha_config::parameters::validate_production_runtime_handle;
use iroha_crypto::{Algorithm, PublicKey};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    transaction::{SignedTransaction, TransactionPayload},
};
use std::sync::Arc;

mod payload_authorization;
pub use payload_authorization::sorafs_native_transaction_payload_matches_role_v1;
/// One isolated native SoraFS transaction-signing role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SorafsNativeTransactionSignerRoleV1 {
    /// Finalized proof-outcome recording transactions.
    ProofOutcome = 0,
    /// Native repair transactions.
    Repair = 1,
    /// Native reserve and rent transactions.
    Reserve = 2,
    /// Native orderbook transactions.
    Orderbook = 3,
}
impl SorafsNativeTransactionSignerRoleV1 {
    /// Return the stable public role label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProofOutcome => "proof_outcome",
            Self::Repair => "repair",
            Self::Reserve => "reserve",
            Self::Orderbook => "orderbook",
        }
    }
}
/// Public revision and policy identity reported by one runtime signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SorafsNativeTransactionSignerQualificationV1 {
    revision: u64,
    policy_digest: [u8; 32],
}
impl SorafsNativeTransactionSignerQualificationV1 {
    /// Construct a qualification value.
    ///
    /// Call [`Self::validate`] before trusting values returned by an external provider. Keeping
    /// construction infallible lets Torii reject malformed provider probes explicitly rather than
    /// making them unrepresentable in adversarial tests.
    #[must_use]
    pub const fn new(revision: u64, policy_digest: [u8; 32]) -> Self {
        Self {
            revision,
            policy_digest,
        }
    }
    /// Return the exact adapter and public-policy revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }
    /// Return the exact digest of the provider's public policy.
    #[must_use]
    pub const fn policy_digest(self) -> [u8; 32] {
        self.policy_digest
    }
    /// Reject a zero revision or zero policy digest.
    ///
    /// # Errors
    ///
    /// Returns the precise invalid field.
    pub fn validate(self) -> Result<(), SorafsNativeTransactionSignerQualificationValueErrorV1> {
        if self.revision == 0 {
            return Err(SorafsNativeTransactionSignerQualificationValueErrorV1::ZeroRevision);
        }
        if self.policy_digest == [0; 32] {
            return Err(SorafsNativeTransactionSignerQualificationValueErrorV1::ZeroPolicyDigest);
        }
        Ok(())
    }
}
/// Invalid public qualification value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SorafsNativeTransactionSignerQualificationValueErrorV1 {
    /// Adapter or public-policy revision is zero.
    ZeroRevision,
    /// Public-policy digest is all zeroes.
    ZeroPolicyDigest,
}
/// Non-secret expected identity of one native transaction signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SorafsNativeTransactionSignerBindingV1 {
    role: SorafsNativeTransactionSignerRoleV1,
    handle: String,
    authority: AccountId,
    public_key: PublicKey,
    qualification: SorafsNativeTransactionSignerQualificationV1,
}
impl SorafsNativeTransactionSignerBindingV1 {
    /// Validate and construct an expected production signer binding.
    ///
    /// # Errors
    ///
    /// Rejects non-production handles, zero qualification fields, unsupported
    /// key algorithms, and authority/key mismatches.
    pub fn try_new(
        role: SorafsNativeTransactionSignerRoleV1,
        handle: impl Into<String>,
        authority: AccountId,
        public_key: PublicKey,
        qualification: SorafsNativeTransactionSignerQualificationV1,
    ) -> Result<Self, SorafsNativeTransactionSignerBindingErrorV1> {
        let handle = handle.into();
        validate_production_runtime_handle(&handle)
            .map_err(|_| SorafsNativeTransactionSignerBindingErrorV1::InvalidHandle)?;
        qualification
            .validate()
            .map_err(|_| SorafsNativeTransactionSignerBindingErrorV1::InvalidQualification)?;
        validate_public_key_algorithm(&public_key)
            .map_err(|_| SorafsNativeTransactionSignerBindingErrorV1::UnsupportedKeyAlgorithm)?;
        if AccountId::new(public_key.clone()) != authority {
            return Err(SorafsNativeTransactionSignerBindingErrorV1::AuthorityKeyMismatch);
        }
        Ok(Self {
            role,
            handle,
            authority,
            public_key,
            qualification,
        })
    }
    /// Return the isolated signer role.
    #[must_use]
    pub const fn role(&self) -> SorafsNativeTransactionSignerRoleV1 {
        self.role
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
    /// Return the exact provider public key.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    /// Return the exact expected provider qualification.
    #[must_use]
    ///
    /// # Errors
    ///
    /// Returns an error if the signing provider is unavailable or refuses the
    /// public qualification probe.
    pub const fn qualification(&self) -> SorafsNativeTransactionSignerQualificationV1 {
        self.qualification
    }
}
/// Invalid expected signer binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SorafsNativeTransactionSignerBindingErrorV1 {
    /// Handle is empty, unbounded, noncanonical, or test-marked.
    InvalidHandle,
    /// Revision or policy digest is zero.
    InvalidQualification,
    /// Public key algorithm is not Ed25519 or ML-DSA.
    UnsupportedKeyAlgorithm,
    /// Public key does not derive the configured transaction authority.
    AuthorityKeyMismatch,
}
/// Payload-free failure while probing an external signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SorafsNativeTransactionSignerProbeErrorV1 {
    /// The configured signing provider is temporarily unavailable.
    Unavailable,
    /// The provider refused or could not answer the public probe.
    Refused,
}
/// Shared identity contract implemented by every native transaction signer.
///
/// Implementations must return public identity only. Credentials, private keys, tokens, vendor
/// diagnostics, and payload material are never valid probe outputs.
///
/// A bare local [`iroha_crypto::KeyPair`] intentionally does not implement this
/// contract or any role-specific signer trait:
///
/// ```compile_fail
/// fn assert_production_provider<T: iroha_torii::SoraFsProofOutcomeTransactionSigner>() {}
/// assert_production_provider::<iroha_crypto::KeyPair>();
/// ```
pub trait SorafsNativeTransactionSignerProviderV1: Send + Sync {
    /// Return the one isolated role served by this provider.
    fn role(&self) -> SorafsNativeTransactionSignerRoleV1;
    /// Return the stable opaque provider handle.
    fn handle(&self) -> &str;
    /// Return the transaction authority controlled by this provider.
    fn authority(&self) -> AccountId;
    /// Probe the exact public key controlled by this provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing provider is unavailable or refuses the
    /// public-key probe.
    fn public_key(&self) -> Result<PublicKey, SorafsNativeTransactionSignerProbeErrorV1>;
    /// Probe the active adapter revision and public-policy digest.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider is unavailable or refuses the qualification probe.
    fn qualification(
        &self,
    ) -> Result<
        SorafsNativeTransactionSignerQualificationV1,
        SorafsNativeTransactionSignerProbeErrorV1,
    >;
}
/// Runtime-only signer used by the durable SoraFS proof-outcome forwarder.
///
/// Implementations use qualified deployment-owned signing infrastructure. The signer is
/// intentionally given only a fully constructed payload and no transaction queue capability,
/// which makes an interrupted
/// signing claim safe to replay. Before claiming an outbox entry, the worker checks finalized state
/// for the exact provider-scoped `CanRecordSorafsProofOutcome` permission on
/// [`SorafsNativeTransactionSignerProviderV1::authority`], including permissions inherited through
/// roles.
pub trait SoraFsProofOutcomeTransactionSigner:
    SorafsNativeTransactionSignerProviderV1 + Send + Sync
{
    /// Sign the exact fee-quoted transaction payload.
    ///
    /// # Errors
    ///
    /// Returns an error for provider unavailability or refusal, an input authority
    /// mismatch, a substituted or invalid signed transaction, or qualification drift.
    fn sign(
        &self,
        payload: TransactionPayload,
    ) -> Result<SignedTransaction, SoraFsProofOutcomeSigningError>;
}
/// Payload-free proof-outcome signing failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoraFsProofOutcomeSigningError {
    /// The runtime signing provider is temporarily unavailable.
    Unavailable,
    /// The signer refused or could not sign the supplied payload.
    Refused,
    /// The supplied payload is not owned by the signer's immutable authority.
    InputAuthorityMismatch,
    /// The provider returned another payload, authority, or an invalid signature.
    SubstitutedTransaction,
    /// Provider identity, key, revision, or policy changed around signing.
    QualificationChanged,
}
/// Runtime-only signer used by the durable native SoraFS repair forwarder.
///
/// Implementations receive only a fully constructed fee-quoted payload and cannot submit it. Before
/// a signing claim is consumed, the worker reconciles finalized repair state and checks the exact
/// provider permission or provider-owner binding required by the native instruction.
pub trait SoraFsRepairTransactionSigner:
    SorafsNativeTransactionSignerProviderV1 + Send + Sync
{
    /// Sign the exact fee-quoted transaction payload.
    ///
    /// # Errors
    ///
    /// Returns an error for provider unavailability or refusal, an input authority
    /// mismatch, a substituted or invalid signed transaction, or qualification drift.
    fn sign(
        &self,
        payload: TransactionPayload,
    ) -> Result<SignedTransaction, SoraFsRepairTransactionSigningError>;
}
/// Payload-free native repair transaction signing failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoraFsRepairTransactionSigningError {
    /// The runtime signing provider is temporarily unavailable.
    Unavailable,
    /// The signer refused or could not sign the supplied payload.
    Refused,
    /// The supplied payload is not owned by the signer's immutable authority.
    InputAuthorityMismatch,
    /// The provider returned another payload, authority, or an invalid signature.
    SubstitutedTransaction,
    /// Provider identity, key, revision, or policy changed around signing.
    QualificationChanged,
}
/// Runtime-only signer used by the durable native SoraFS reserve/rent forwarder.
///
/// The signer receives only a fully constructed fee-quoted payload and has no
/// access to Torii ingress or the durable outbox. The worker first reconciles
/// the retained operation against one finalized ledger view and requires this
/// provider's authority to equal the exact governed or provider authority.
pub trait SoraFsReserveTransactionSigner:
    SorafsNativeTransactionSignerProviderV1 + Send + Sync
{
    /// Sign the exact fee-quoted transaction payload.
    ///
    /// # Errors
    ///
    /// Returns an error for provider unavailability or refusal, an input authority
    /// mismatch, a substituted or invalid signed transaction, or qualification drift.
    fn sign(
        &self,
        payload: TransactionPayload,
    ) -> Result<SignedTransaction, SoraFsReserveTransactionSigningError>;
}
/// Payload-free native reserve/rent transaction signing failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoraFsReserveTransactionSigningError {
    /// The runtime signing provider is temporarily unavailable.
    Unavailable,
    /// The signer refused or could not sign the supplied payload.
    Refused,
    /// The supplied payload is not owned by the signer's immutable authority.
    InputAuthorityMismatch,
    /// The provider returned another payload, authority, or an invalid signature.
    SubstitutedTransaction,
    /// Provider identity, key, revision, or policy changed around signing.
    QualificationChanged,
}
/// Runtime-only signer used by the durable native SoraFS orderbook forwarder.
///
/// The signer receives only a fully constructed fee-quoted payload and has no
/// access to Torii ingress or the durable outbox. The supervised worker
/// reconciles every retained operation against one finalized ledger view.
pub trait SoraFsOrderbookTransactionSigner:
    SorafsNativeTransactionSignerProviderV1 + Send + Sync
{
    /// Sign the exact fee-quoted transaction payload.
    ///
    /// # Errors
    ///
    /// Returns an error for provider unavailability or refusal, an input authority
    /// mismatch, a substituted or invalid signed transaction, or qualification drift.
    fn sign(
        &self,
        payload: TransactionPayload,
    ) -> Result<SignedTransaction, SoraFsOrderbookTransactionSigningError>;
}
/// Payload-free native orderbook transaction signing failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoraFsOrderbookTransactionSigningError {
    /// The runtime signing provider is temporarily unavailable.
    Unavailable,
    /// The signer refused or could not sign the supplied payload.
    Refused,
    /// The supplied payload is not owned by the signer's immutable authority.
    InputAuthorityMismatch,
    /// The provider returned another payload, authority, or an invalid signature.
    SubstitutedTransaction,
    /// Provider identity, key, revision, or policy changed around signing.
    QualificationChanged,
}
/// Startup or request-bound signer qualification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SorafsNativeTransactionSignerQualificationErrorV1 {
    /// The binding was supplied to a constructor for another role.
    BindingRoleMismatch,
    /// The provider reports another role.
    ProviderRoleMismatch,
    /// A public provider probe was unavailable or refused.
    ProviderUnavailable,
    /// Provider handle is noncanonical or test-marked.
    InvalidProviderHandle,
    /// Provider returned a zero revision or policy digest.
    InvalidProviderQualification,
    /// Provider returned a public key algorithm outside Ed25519 and ML-DSA.
    UnsupportedProviderKeyAlgorithm,
    /// Provider handle does not match the expected binding.
    HandleMismatch,
    /// Provider authority does not match the expected binding.
    AuthorityMismatch,
    /// Provider public key does not match the expected binding.
    PublicKeyMismatch,
    /// Provider public key does not derive its reported authority.
    ProviderAuthorityKeyMismatch,
    /// Provider revision does not match the expected binding.
    RevisionMismatch,
    /// Provider public-policy digest does not match the expected binding.
    PolicyDigestMismatch,
    /// Provider identity changed between adjacent probes.
    ProviderDrift,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderSnapshotV1 {
    role: SorafsNativeTransactionSignerRoleV1,
    handle: String,
    authority: AccountId,
    public_key: PublicKey,
    qualification: SorafsNativeTransactionSignerQualificationV1,
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
    provider: &(impl SorafsNativeTransactionSignerProviderV1 + ?Sized),
) -> Result<ProviderSnapshotV1, SorafsNativeTransactionSignerQualificationErrorV1> {
    let handle_before = provider.handle().to_owned();
    validate_production_runtime_handle(&handle_before)
        .map_err(|_| SorafsNativeTransactionSignerQualificationErrorV1::InvalidProviderHandle)?;
    let role = provider.role();
    let authority = provider.authority();
    let public_key = provider
        .public_key()
        .map_err(|_| SorafsNativeTransactionSignerQualificationErrorV1::ProviderUnavailable)?;
    validate_public_key_algorithm(&public_key).map_err(|()| {
        SorafsNativeTransactionSignerQualificationErrorV1::UnsupportedProviderKeyAlgorithm
    })?;
    let qualification = provider
        .qualification()
        .map_err(|_| SorafsNativeTransactionSignerQualificationErrorV1::ProviderUnavailable)?;
    qualification.validate().map_err(|_| {
        SorafsNativeTransactionSignerQualificationErrorV1::InvalidProviderQualification
    })?;
    if provider.handle() != handle_before {
        return Err(SorafsNativeTransactionSignerQualificationErrorV1::ProviderDrift);
    }
    Ok(ProviderSnapshotV1 {
        role,
        handle: handle_before,
        authority,
        public_key,
        qualification,
    })
}
fn validate_snapshot(
    expected_role: SorafsNativeTransactionSignerRoleV1,
    binding: &SorafsNativeTransactionSignerBindingV1,
    snapshot: &ProviderSnapshotV1,
) -> Result<(), SorafsNativeTransactionSignerQualificationErrorV1> {
    if binding.role != expected_role {
        return Err(SorafsNativeTransactionSignerQualificationErrorV1::BindingRoleMismatch);
    }
    if snapshot.role != expected_role {
        return Err(SorafsNativeTransactionSignerQualificationErrorV1::ProviderRoleMismatch);
    }
    if snapshot.handle != binding.handle {
        return Err(SorafsNativeTransactionSignerQualificationErrorV1::HandleMismatch);
    }
    if snapshot.public_key != binding.public_key {
        return Err(SorafsNativeTransactionSignerQualificationErrorV1::PublicKeyMismatch);
    }
    if snapshot.authority != binding.authority {
        return Err(SorafsNativeTransactionSignerQualificationErrorV1::AuthorityMismatch);
    }
    if AccountId::new(snapshot.public_key.clone()) != snapshot.authority {
        return Err(
            SorafsNativeTransactionSignerQualificationErrorV1::ProviderAuthorityKeyMismatch,
        );
    }
    if snapshot.qualification.revision != binding.qualification.revision {
        return Err(SorafsNativeTransactionSignerQualificationErrorV1::RevisionMismatch);
    }
    if snapshot.qualification.policy_digest != binding.qualification.policy_digest {
        return Err(SorafsNativeTransactionSignerQualificationErrorV1::PolicyDigestMismatch);
    }
    Ok(())
}
struct QualifiedNativeTransactionSignerV1<S: ?Sized> {
    network_id: NetworkId,
    expected_role: SorafsNativeTransactionSignerRoleV1,
    binding: SorafsNativeTransactionSignerBindingV1,
    provider: Arc<S>,
}
impl<S> QualifiedNativeTransactionSignerV1<S>
where
    S: SorafsNativeTransactionSignerProviderV1 + ?Sized,
{
    fn try_new(
        network_id: NetworkId,
        expected_role: SorafsNativeTransactionSignerRoleV1,
        binding: SorafsNativeTransactionSignerBindingV1,
        provider: Arc<S>,
    ) -> Result<Self, SorafsNativeTransactionSignerQualificationErrorV1> {
        if binding.role != expected_role {
            return Err(SorafsNativeTransactionSignerQualificationErrorV1::BindingRoleMismatch);
        }
        let first = probe_provider(provider.as_ref())?;
        let second = probe_provider(provider.as_ref())?;
        if first != second {
            return Err(SorafsNativeTransactionSignerQualificationErrorV1::ProviderDrift);
        }
        validate_snapshot(expected_role, &binding, &first)?;
        Ok(Self {
            network_id,
            expected_role,
            binding,
            provider,
        })
    }
    fn revalidate(&self) -> Result<(), SorafsNativeTransactionSignerQualificationErrorV1> {
        let snapshot = probe_provider(self.provider.as_ref())?;
        validate_snapshot(self.expected_role, &self.binding, &snapshot)
    }
    fn accepts_transaction(
        &self,
        transaction: &SignedTransaction,
        expected_payload: &TransactionPayload,
    ) -> bool {
        transaction.payload() == expected_payload
            && transaction.authority() == self.binding.authority()
            && transaction.attachments().is_none()
            && transaction.multisig_signatures().is_none()
            && transaction.verify_signature().is_ok()
    }
}
macro_rules! define_qualified_signer {
    (
        $wrapper:ident,
        $trait_name:ident,
        $signing_error:ident,
        $role:expr,
        $constructor:ident,
        $constructor_doc:literal
    ) => {
        struct $wrapper {
            inner: QualifiedNativeTransactionSignerV1<dyn $trait_name>,
        }
        impl SorafsNativeTransactionSignerProviderV1 for $wrapper {
            fn role(&self) -> SorafsNativeTransactionSignerRoleV1 {
                self.inner.binding.role()
            }
            fn handle(&self) -> &str {
                self.inner.binding.handle()
            }
            fn authority(&self) -> AccountId {
                self.inner.binding.authority().clone()
            }
            fn public_key(&self) -> Result<PublicKey, SorafsNativeTransactionSignerProbeErrorV1> {
                self.inner
                    .revalidate()
                    .map_err(|_| SorafsNativeTransactionSignerProbeErrorV1::Unavailable)?;
                Ok(self.inner.binding.public_key().clone())
            }
            fn qualification(
                &self,
            ) -> Result<
                SorafsNativeTransactionSignerQualificationV1,
                SorafsNativeTransactionSignerProbeErrorV1,
            > {
                self.inner
                    .revalidate()
                    .map_err(|_| SorafsNativeTransactionSignerProbeErrorV1::Unavailable)?;
                Ok(self.inner.binding.qualification())
            }
        }
        impl $trait_name for $wrapper {
            fn sign(
                &self,
                payload: TransactionPayload,
            ) -> Result<SignedTransaction, $signing_error> {
                if payload.authority() != self.inner.binding.authority() {
                    return Err($signing_error::InputAuthorityMismatch);
                }
                if payload.network_id() != Some(&self.inner.network_id)
                    || !sorafs_native_transaction_payload_matches_role_v1(
                        self.inner.expected_role,
                        &payload,
                    )
                {
                    return Err($signing_error::Refused);
                }
                self.inner
                    .revalidate()
                    .map_err(|_| $signing_error::QualificationChanged)?;
                let expected_payload = payload.clone();
                let result = self.inner.provider.sign(payload);
                self.inner
                    .revalidate()
                    .map_err(|_| $signing_error::QualificationChanged)?;
                let transaction = result?;
                if !self
                    .inner
                    .accepts_transaction(&transaction, &expected_payload)
                {
                    return Err($signing_error::SubstitutedTransaction);
                }
                Ok(transaction)
            }
        }
        #[doc = $constructor_doc]
        ///
        /// The provider is probed twice before this function returns. The returned trait object
        /// revalidates the same binding before every fallible public-identity probe and immediately
        /// before and after every signing request. Wrong-authority, cross-role, wrapped or
        /// multi-instruction inputs are rejected before request-time provider probes. The network
        /// is retained independently from native runtime construction, never from a request.
        ///
        /// # Errors
        ///
        /// Returns a payload-free error when the binding or provider identity
        /// is invalid, unavailable, substituted, stale, or unstable.
        pub fn $constructor(
            network_id: NetworkId,
            binding: SorafsNativeTransactionSignerBindingV1,
            provider: Arc<dyn $trait_name>,
        ) -> Result<Arc<dyn $trait_name>, SorafsNativeTransactionSignerQualificationErrorV1> {
            let inner =
                QualifiedNativeTransactionSignerV1::try_new(network_id, $role, binding, provider)?;
            Ok(Arc::new($wrapper { inner }))
        }
    };
}
define_qualified_signer!(
    QualifiedProofOutcomeTransactionSignerV1,
    SoraFsProofOutcomeTransactionSigner,
    SoraFsProofOutcomeSigningError,
    SorafsNativeTransactionSignerRoleV1::ProofOutcome,
    qualify_sorafs_proof_outcome_transaction_signer_v1,
    "Qualify one proof-outcome signer against its exact expected binding."
);
define_qualified_signer!(
    QualifiedRepairTransactionSignerV1,
    SoraFsRepairTransactionSigner,
    SoraFsRepairTransactionSigningError,
    SorafsNativeTransactionSignerRoleV1::Repair,
    qualify_sorafs_repair_transaction_signer_v1,
    "Qualify one native repair signer against its exact expected binding."
);
define_qualified_signer!(
    QualifiedReserveTransactionSignerV1,
    SoraFsReserveTransactionSigner,
    SoraFsReserveTransactionSigningError,
    SorafsNativeTransactionSignerRoleV1::Reserve,
    qualify_sorafs_reserve_transaction_signer_v1,
    "Qualify one native reserve/rent signer against its exact expected binding."
);
define_qualified_signer!(
    QualifiedOrderbookTransactionSignerV1,
    SoraFsOrderbookTransactionSigner,
    SoraFsOrderbookTransactionSigningError,
    SorafsNativeTransactionSignerRoleV1::Orderbook,
    qualify_sorafs_orderbook_transaction_signer_v1,
    "Qualify one native orderbook signer against its exact expected binding."
);
#[cfg(test)]
/// Native signer fixtures and adversarial qualification tests.
pub(crate) mod tests {
    mod payload_authorization;

    use super::*;
    use iroha_crypto::KeyPair;
    use iroha_data_model::{
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
        transaction::{FeePaymentIntent, TransactionBuilder, signed::MultisigSignatures},
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    const EXPECTED_QUALIFICATION: SorafsNativeTransactionSignerQualificationV1 =
        SorafsNativeTransactionSignerQualificationV1::new(7, [0xA7; 32]);
    enum TestSignOutput {
        Exact,
        SubstitutePayload(Box<TransactionPayload>),
        ForgeSignature(KeyPair),
        AttachProofSidecar,
        AttachEmptyMultisigSidecar,
    }
    /// Deterministic role-bound signer shared by complete Torii runtime fixtures.
    pub struct TestProvider {
        role: SorafsNativeTransactionSignerRoleV1,
        handle: String,
        keypair: KeyPair,
        authority: Mutex<AccountId>,
        public_key: Mutex<Result<PublicKey, SorafsNativeTransactionSignerProbeErrorV1>>,
        qualification: Mutex<
            Result<
                SorafsNativeTransactionSignerQualificationV1,
                SorafsNativeTransactionSignerProbeErrorV1,
            >,
        >,
        qualification_after_probe: Mutex<
            Option<
                Result<
                    SorafsNativeTransactionSignerQualificationV1,
                    SorafsNativeTransactionSignerProbeErrorV1,
                >,
            >,
        >,
        qualification_after_sign: Mutex<
            Option<
                Result<
                    SorafsNativeTransactionSignerQualificationV1,
                    SorafsNativeTransactionSignerProbeErrorV1,
                >,
            >,
        >,
        sign_output: Mutex<TestSignOutput>,
        sign_calls: AtomicUsize,
        probe_calls: AtomicUsize,
    }
    impl TestProvider {
        /// Construct one exact signing role with deterministic fixture custody.
        pub(crate) fn new(
            role: SorafsNativeTransactionSignerRoleV1,
            handle: impl Into<String>,
            seed: u8,
        ) -> Self {
            let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .expect("derive native signer fixture");
            Self::with_keypair(role, handle, keypair)
        }
        fn with_keypair(
            role: SorafsNativeTransactionSignerRoleV1,
            handle: impl Into<String>,
            keypair: KeyPair,
        ) -> Self {
            let public_key = keypair.public_key().clone();
            Self {
                role,
                handle: handle.into(),
                keypair,
                authority: Mutex::new(AccountId::new(public_key.clone())),
                public_key: Mutex::new(Ok(public_key)),
                qualification: Mutex::new(Ok(EXPECTED_QUALIFICATION)),
                qualification_after_probe: Mutex::new(None),
                qualification_after_sign: Mutex::new(None),
                sign_output: Mutex::new(TestSignOutput::Exact),
                sign_calls: AtomicUsize::new(0),
                probe_calls: AtomicUsize::new(0),
            }
        }
        /// Return the exact public configuration expected by startup qualification.
        pub(crate) fn expected_binding(&self) -> SorafsNativeTransactionSignerBindingV1 {
            SorafsNativeTransactionSignerBindingV1::try_new(
                self.role,
                self.handle.clone(),
                self.authority(),
                self.public_key().expect("fixture public key"),
                self.qualification().expect("fixture qualification"),
            )
            .expect("valid native signer fixture binding")
        }
        fn set_qualification(
            &self,
            value: Result<
                SorafsNativeTransactionSignerQualificationV1,
                SorafsNativeTransactionSignerProbeErrorV1,
            >,
        ) {
            *self
                .qualification
                .lock()
                .expect("qualification fixture lock") = value;
        }
        fn drift_qualification_after_probe(
            &self,
            value: Result<
                SorafsNativeTransactionSignerQualificationV1,
                SorafsNativeTransactionSignerProbeErrorV1,
            >,
        ) {
            *self
                .qualification_after_probe
                .lock()
                .expect("post-probe qualification fixture lock") = Some(value);
        }
        fn drift_qualification_after_sign(
            &self,
            value: Result<
                SorafsNativeTransactionSignerQualificationV1,
                SorafsNativeTransactionSignerProbeErrorV1,
            >,
        ) {
            *self
                .qualification_after_sign
                .lock()
                .expect("post-sign qualification fixture lock") = Some(value);
        }
        fn substitute_payload_once(&self, payload: TransactionPayload) {
            *self.sign_output.lock().expect("sign-output fixture lock") =
                TestSignOutput::SubstitutePayload(Box::new(payload));
        }
        fn forge_signature_once(&self, signer: KeyPair) {
            *self.sign_output.lock().expect("sign-output fixture lock") =
                TestSignOutput::ForgeSignature(signer);
        }
        fn attach_proof_sidecar_once(&self) {
            *self.sign_output.lock().expect("sign-output fixture lock") =
                TestSignOutput::AttachProofSidecar;
        }
        fn attach_empty_multisig_sidecar_once(&self) {
            *self.sign_output.lock().expect("sign-output fixture lock") =
                TestSignOutput::AttachEmptyMultisigSidecar;
        }
        fn sign_payload(&self, payload: TransactionPayload) -> Result<SignedTransaction, ()> {
            self.sign_calls.fetch_add(1, Ordering::SeqCst);
            let output = std::mem::replace(
                &mut *self.sign_output.lock().expect("sign-output fixture lock"),
                TestSignOutput::Exact,
            );
            let transaction = match output {
                TestSignOutput::Exact => TransactionBuilder::from_payload(payload)
                    .and_then(|builder| builder.try_sign(self.keypair.private_key()))
                    .map_err(|_| ())?,
                TestSignOutput::SubstitutePayload(substituted) => {
                    TransactionBuilder::from_payload(*substituted)
                        .and_then(|builder| builder.try_sign(self.keypair.private_key()))
                        .map_err(|_| ())?
                }
                TestSignOutput::ForgeSignature(signer) => {
                    let builder = TransactionBuilder::from_payload(payload).map_err(|_| ())?;
                    let signature = iroha_crypto::Signature::try_new(
                        signer.private_key(),
                        &builder.payload_hash_bytes(),
                    )
                    .map_err(|_| ())?;
                    builder.build_with_signature(signature)
                }
                TestSignOutput::AttachProofSidecar => {
                    let attachments = vec![ProofAttachment::new_ref(
                        "halo2/ipa".into(),
                        ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
                        VerifyingKeyId::new("halo2/ipa", "native-signer-sidecar-vk"),
                    )];
                    TransactionBuilder::from_payload(payload)
                        .map_err(|_| ())?
                        .with_proof_attachments(attachments)
                        .expect("valid proof carriers")
                        .try_sign(self.keypair.private_key())
                        .map_err(|_| ())?
                }
                TestSignOutput::AttachEmptyMultisigSidecar => {
                    let mut transaction = TransactionBuilder::from_payload(payload)
                        .and_then(|builder| builder.try_sign(self.keypair.private_key()))
                        .map_err(|_| ())?;
                    transaction.set_multisig_signatures(MultisigSignatures::new(Vec::new()));
                    transaction
                }
            };
            if let Some(qualification) = self
                .qualification_after_sign
                .lock()
                .expect("post-sign qualification fixture lock")
                .take()
            {
                self.set_qualification(qualification);
            }
            Ok(transaction)
        }
    }
    impl SorafsNativeTransactionSignerProviderV1 for TestProvider {
        fn role(&self) -> SorafsNativeTransactionSignerRoleV1 {
            self.probe_calls.fetch_add(1, Ordering::SeqCst);
            self.role
        }
        fn handle(&self) -> &str {
            self.probe_calls.fetch_add(1, Ordering::SeqCst);
            &self.handle
        }
        fn authority(&self) -> AccountId {
            self.probe_calls.fetch_add(1, Ordering::SeqCst);
            self.authority
                .lock()
                .expect("authority fixture lock")
                .clone()
        }
        fn public_key(&self) -> Result<PublicKey, SorafsNativeTransactionSignerProbeErrorV1> {
            self.probe_calls.fetch_add(1, Ordering::SeqCst);
            self.public_key
                .lock()
                .expect("public-key fixture lock")
                .clone()
        }
        fn qualification(
            &self,
        ) -> Result<
            SorafsNativeTransactionSignerQualificationV1,
            SorafsNativeTransactionSignerProbeErrorV1,
        > {
            self.probe_calls.fetch_add(1, Ordering::SeqCst);
            let current = *self
                .qualification
                .lock()
                .expect("qualification fixture lock");
            if let Some(next) = self
                .qualification_after_probe
                .lock()
                .expect("post-probe qualification fixture lock")
                .take()
            {
                self.set_qualification(next);
            }
            current
        }
    }
    macro_rules! impl_test_role_signer {
        ($trait_name:ident, $error:ident) => {
            impl $trait_name for TestProvider {
                fn sign(&self, payload: TransactionPayload) -> Result<SignedTransaction, $error> {
                    self.sign_payload(payload).map_err(|()| $error::Refused)
                }
            }
        };
    }
    impl_test_role_signer!(
        SoraFsProofOutcomeTransactionSigner,
        SoraFsProofOutcomeSigningError
    );
    impl_test_role_signer!(
        SoraFsRepairTransactionSigner,
        SoraFsRepairTransactionSigningError
    );
    impl_test_role_signer!(
        SoraFsReserveTransactionSigner,
        SoraFsReserveTransactionSigningError
    );
    impl_test_role_signer!(
        SoraFsOrderbookTransactionSigner,
        SoraFsOrderbookTransactionSigningError
    );
    fn payload(authority: AccountId) -> TransactionPayload {
        TransactionBuilder::new(
            crate::signed_query_test_network_id(),
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([payload_authorization::proof_instruction()])
        .into_payload()
        .expect("valid native signer fixture payload")
    }
    #[test]
    fn all_role_constructors_accept_exact_production_bindings() {
        let proof = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/primary",
            0x11,
        ));
        qualify_sorafs_proof_outcome_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            proof.expected_binding(),
            proof.clone(),
        )
        .expect("qualify proof-outcome signer");
        let repair = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::Repair,
            "provider://sorafs/repair/primary",
            0x12,
        ));
        qualify_sorafs_repair_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            repair.expected_binding(),
            repair.clone(),
        )
        .expect("qualify repair signer");
        let reserve = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::Reserve,
            "provider://sorafs/reserve/primary",
            0x13,
        ));
        qualify_sorafs_reserve_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            reserve.expected_binding(),
            reserve.clone(),
        )
        .expect("qualify reserve signer");
        let orderbook = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::Orderbook,
            "provider://sorafs/orderbook/primary",
            0x14,
        ));
        qualify_sorafs_orderbook_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            orderbook.expected_binding(),
            orderbook,
        )
        .expect("qualify orderbook signer");
    }
    #[test]
    fn expected_bindings_enforce_handle_grammar_qualification_and_key_identity() {
        let provider = TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/primary",
            0x21,
        );
        let authority = provider.authority();
        let public_key = provider.public_key().expect("fixture public key");
        for handle in [
            "provider://sorafs/proof-outcome/primary",
            "provider:prod/native_signer.v1-slot_a",
        ] {
            SorafsNativeTransactionSignerBindingV1::try_new(
                SorafsNativeTransactionSignerRoleV1::ProofOutcome,
                handle,
                authority.clone(),
                public_key.clone(),
                EXPECTED_QUALIFICATION,
            )
            .expect("central production runtime-handle grammar must accept the fixture");
        }
        for handle in [
            "",
            "mock://sorafs/proof-outcome",
            "provider://sorafs/test/primary",
            "provider://sorafs/proof outcome",
            "https://operator:secret@signer",
            "https://signer/path?credential=secret",
            "https://signer/path#fragment",
            "provider://sorafs/%70roof-outcome/primary",
            "provider:\\sorafs\\proof-outcome\\primary",
        ] {
            assert_eq!(
                SorafsNativeTransactionSignerBindingV1::try_new(
                    SorafsNativeTransactionSignerRoleV1::ProofOutcome,
                    handle,
                    authority.clone(),
                    public_key.clone(),
                    EXPECTED_QUALIFICATION,
                ),
                Err(SorafsNativeTransactionSignerBindingErrorV1::InvalidHandle)
            );
        }
        for invalid in [
            SorafsNativeTransactionSignerQualificationV1::new(0, [0xA7; 32]),
            SorafsNativeTransactionSignerQualificationV1::new(7, [0; 32]),
        ] {
            assert_eq!(
                SorafsNativeTransactionSignerBindingV1::try_new(
                    SorafsNativeTransactionSignerRoleV1::ProofOutcome,
                    "provider://sorafs/proof-outcome/primary",
                    authority.clone(),
                    public_key.clone(),
                    invalid,
                ),
                Err(SorafsNativeTransactionSignerBindingErrorV1::InvalidQualification)
            );
        }
        let secp = KeyPair::try_from_seed(vec![0x22; 32], Algorithm::Secp256k1)
            .expect("derive unsupported signer fixture");
        assert_eq!(
            SorafsNativeTransactionSignerBindingV1::try_new(
                SorafsNativeTransactionSignerRoleV1::ProofOutcome,
                "provider://sorafs/proof-outcome/primary",
                AccountId::new(secp.public_key().clone()),
                secp.public_key().clone(),
                EXPECTED_QUALIFICATION,
            ),
            Err(SorafsNativeTransactionSignerBindingErrorV1::UnsupportedKeyAlgorithm)
        );
        assert_eq!(
            SorafsNativeTransactionSignerBindingV1::try_new(
                SorafsNativeTransactionSignerRoleV1::ProofOutcome,
                "provider://sorafs/proof-outcome/primary",
                AccountId::new(secp.public_key().clone()),
                public_key,
                EXPECTED_QUALIFICATION,
            ),
            Err(SorafsNativeTransactionSignerBindingErrorV1::AuthorityKeyMismatch)
        );
    }
    #[test]
    fn startup_rejects_each_stable_provider_substitution() {
        let provider = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/primary",
            0x31,
        ));
        let expected = provider.expected_binding();
        let wrong_handle = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/secondary",
            0x31,
        ));
        assert!(matches!(
            qualify_sorafs_proof_outcome_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                expected.clone(),
                wrong_handle
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::HandleMismatch)
        ));
        let wrong_key = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/primary",
            0x32,
        ));
        assert!(matches!(
            qualify_sorafs_proof_outcome_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                expected.clone(),
                wrong_key
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::PublicKeyMismatch)
        ));
        let wrong_authority_key = KeyPair::try_from_seed(vec![0x33; 32], Algorithm::Ed25519)
            .expect("derive authority substitution fixture");
        *provider.authority.lock().expect("authority fixture lock") =
            AccountId::new(wrong_authority_key.public_key().clone());
        assert!(matches!(
            qualify_sorafs_proof_outcome_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                expected.clone(),
                provider.clone()
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::AuthorityMismatch)
        ));
        *provider.authority.lock().expect("authority fixture lock") = expected.authority().clone();
        provider.set_qualification(Ok(SorafsNativeTransactionSignerQualificationV1::new(
            expected.qualification().revision() + 1,
            expected.qualification().policy_digest(),
        )));
        assert!(matches!(
            qualify_sorafs_proof_outcome_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                expected.clone(),
                provider.clone()
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::RevisionMismatch)
        ));
        provider.set_qualification(Ok(SorafsNativeTransactionSignerQualificationV1::new(
            expected.qualification().revision(),
            [0xB7; 32],
        )));
        assert!(matches!(
            qualify_sorafs_proof_outcome_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                expected,
                provider
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::PolicyDigestMismatch)
        ));
    }
    #[test]
    fn startup_rejects_invalid_or_unavailable_provider_probes() {
        let provider = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/primary",
            0x41,
        ));
        let binding = provider.expected_binding();
        provider.set_qualification(Ok(SorafsNativeTransactionSignerQualificationV1::new(
            0, [0xA7; 32],
        )));
        assert!(matches!(
            qualify_sorafs_proof_outcome_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                binding.clone(),
                provider.clone()
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::InvalidProviderQualification)
        ));
        provider.set_qualification(Err(SorafsNativeTransactionSignerProbeErrorV1::Unavailable));
        assert!(matches!(
            qualify_sorafs_proof_outcome_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                binding,
                provider.clone()
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::ProviderUnavailable)
        ));
    }
    #[test]
    fn startup_rejects_unavailable_key_invalid_handle_algorithm_and_probe_drift() {
        let expected_provider = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/primary",
            0x45,
        ));
        let binding = expected_provider.expected_binding();
        *expected_provider
            .public_key
            .lock()
            .expect("public-key fixture lock") =
            Err(SorafsNativeTransactionSignerProbeErrorV1::Unavailable);
        assert!(matches!(
            qualify_sorafs_proof_outcome_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                binding.clone(),
                expected_provider
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::ProviderUnavailable)
        ));
        for handle in [
            "mock://sorafs/proof-outcome/primary",
            "https://operator:secret@signer",
            "https://signer/path?credential=secret",
            "https://signer/path#fragment",
            "provider://sorafs/%70roof-outcome/primary",
            "provider:\\sorafs\\proof-outcome\\primary",
        ] {
            let invalid_handle = Arc::new(TestProvider::new(
                SorafsNativeTransactionSignerRoleV1::ProofOutcome,
                handle,
                0x45,
            ));
            assert!(matches!(
                qualify_sorafs_proof_outcome_transaction_signer_v1(
                    crate::signed_query_test_network_id(),
                    binding.clone(),
                    invalid_handle
                ),
                Err(SorafsNativeTransactionSignerQualificationErrorV1::InvalidProviderHandle)
            ));
        }
        let secp = KeyPair::try_from_seed(vec![0x46; 32], Algorithm::Secp256k1)
            .expect("derive unsupported provider fixture");
        let unsupported_algorithm = Arc::new(TestProvider::with_keypair(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/primary",
            secp,
        ));
        assert!(matches!(
            qualify_sorafs_proof_outcome_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                binding.clone(),
                unsupported_algorithm
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::UnsupportedProviderKeyAlgorithm)
        ));
        let drifting = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/primary",
            0x45,
        ));
        drifting.drift_qualification_after_probe(Ok(
            SorafsNativeTransactionSignerQualificationV1::new(8, [0xA7; 32]),
        ));
        assert!(matches!(
            qualify_sorafs_proof_outcome_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                binding,
                drifting
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::ProviderDrift)
        ));
    }
    #[test]
    fn constructors_reject_binding_and_provider_role_confusion() {
        let proof = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/primary",
            0x51,
        ));
        assert!(matches!(
            qualify_sorafs_repair_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                proof.expected_binding(),
                proof.clone()
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::BindingRoleMismatch)
        ));
        let repair_binding = SorafsNativeTransactionSignerBindingV1::try_new(
            SorafsNativeTransactionSignerRoleV1::Repair,
            proof.handle.clone(),
            proof.authority(),
            proof.public_key().expect("fixture public key"),
            EXPECTED_QUALIFICATION,
        )
        .expect("valid repair-role binding shape");
        assert!(matches!(
            qualify_sorafs_repair_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                repair_binding,
                proof
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::ProviderRoleMismatch)
        ));
    }
    #[test]
    fn qualified_signer_revalidates_before_and_after_signing() {
        let pre_drift = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/pre-drift",
            0x61,
        ));
        let pre_binding = pre_drift.expected_binding();
        let pre_qualified = qualify_sorafs_proof_outcome_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            pre_binding,
            pre_drift.clone(),
        )
        .expect("qualify pre-sign drift fixture");
        pre_drift.set_qualification(Ok(SorafsNativeTransactionSignerQualificationV1::new(
            8, [0xA7; 32],
        )));
        assert_eq!(
            pre_qualified.sign(payload(pre_drift.authority())),
            Err(SoraFsProofOutcomeSigningError::QualificationChanged)
        );
        assert_eq!(pre_drift.sign_calls.load(Ordering::SeqCst), 0);
        let post_drift = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/post-drift",
            0x62,
        ));
        let post_binding = post_drift.expected_binding();
        let post_qualified = qualify_sorafs_proof_outcome_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            post_binding,
            post_drift.clone(),
        )
        .expect("qualify post-sign drift fixture");
        post_drift.drift_qualification_after_sign(Ok(
            SorafsNativeTransactionSignerQualificationV1::new(8, [0xA7; 32]),
        ));
        assert_eq!(
            post_qualified.sign(payload(post_drift.authority())),
            Err(SoraFsProofOutcomeSigningError::QualificationChanged)
        );
        assert_eq!(post_drift.sign_calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn qualified_signer_maps_probe_failure_to_qualification_changed() {
        let provider = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/probe-failure",
            0x71,
        ));
        let qualified = qualify_sorafs_proof_outcome_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            provider.expected_binding(),
            provider.clone(),
        )
        .expect("qualify unavailable-probe fixture");
        provider.set_qualification(Err(SorafsNativeTransactionSignerProbeErrorV1::Unavailable));
        assert_eq!(
            qualified.sign(payload(provider.authority())),
            Err(SoraFsProofOutcomeSigningError::QualificationChanged)
        );
        assert_eq!(provider.sign_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn double_qualification_rejects_live_provider_drift() {
        let provider = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/double-qualification-drift",
            0x72,
        ));
        let binding = provider.expected_binding();
        let qualified = qualify_sorafs_proof_outcome_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            binding.clone(),
            provider.clone(),
        )
        .expect("qualify double-qualification drift fixture");
        provider.set_qualification(Ok(SorafsNativeTransactionSignerQualificationV1::new(
            binding.qualification().revision() + 1,
            binding.qualification().policy_digest(),
        )));
        assert_eq!(
            qualified.public_key(),
            Err(SorafsNativeTransactionSignerProbeErrorV1::Unavailable)
        );
        assert_eq!(
            qualified.qualification(),
            Err(SorafsNativeTransactionSignerProbeErrorV1::Unavailable)
        );
        assert!(matches!(
            qualify_sorafs_proof_outcome_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                binding,
                qualified
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::ProviderUnavailable)
        ));
    }
    #[test]
    fn double_qualification_rejects_unavailable_live_provider() {
        let provider = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/double-qualification-unavailable",
            0x73,
        ));
        let binding = provider.expected_binding();
        let qualified = qualify_sorafs_proof_outcome_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            binding.clone(),
            provider.clone(),
        )
        .expect("qualify double-qualification unavailable fixture");
        provider.set_qualification(Err(SorafsNativeTransactionSignerProbeErrorV1::Unavailable));
        assert_eq!(
            qualified.public_key(),
            Err(SorafsNativeTransactionSignerProbeErrorV1::Unavailable)
        );
        assert_eq!(
            qualified.qualification(),
            Err(SorafsNativeTransactionSignerProbeErrorV1::Unavailable)
        );
        assert!(matches!(
            qualify_sorafs_proof_outcome_transaction_signer_v1(
                crate::signed_query_test_network_id(),
                binding,
                qualified
            ),
            Err(SorafsNativeTransactionSignerQualificationErrorV1::ProviderUnavailable)
        ));
    }
    #[test]
    fn qualified_facade_keeps_immutable_infallible_identity_and_rejects_stale_public_probes() {
        let provider = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/immutable-facade",
            0x81,
        ));
        let binding = provider.expected_binding();
        let qualified = qualify_sorafs_proof_outcome_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            binding.clone(),
            provider.clone(),
        )
        .expect("qualify immutable-facade fixture");
        let substituted = KeyPair::try_from_seed(vec![0x82; 32], Algorithm::Ed25519)
            .expect("derive accessor-substitution fixture");
        *provider.authority.lock().expect("authority fixture lock") =
            AccountId::new(substituted.public_key().clone());
        *provider.public_key.lock().expect("public-key fixture lock") =
            Ok(substituted.public_key().clone());
        provider.set_qualification(Ok(SorafsNativeTransactionSignerQualificationV1::new(
            binding.qualification().revision() + 1,
            [0xB8; 32],
        )));
        assert_eq!(qualified.role(), binding.role());
        assert_eq!(qualified.handle(), binding.handle());
        assert_eq!(qualified.authority(), binding.authority().clone());
        assert_eq!(
            qualified.public_key(),
            Err(SorafsNativeTransactionSignerProbeErrorV1::Unavailable)
        );
        assert_eq!(
            qualified.qualification(),
            Err(SorafsNativeTransactionSignerProbeErrorV1::Unavailable)
        );
        let worker_payload = payload(qualified.authority());
        assert_eq!(worker_payload.authority(), binding.authority());
        assert_eq!(
            qualified.sign(worker_payload),
            Err(SoraFsProofOutcomeSigningError::QualificationChanged)
        );
        assert_eq!(provider.sign_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn qualified_signer_rejects_unbound_input_authority_before_provider_call() {
        let provider = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/input-authority",
            0x83,
        ));
        let qualified = qualify_sorafs_proof_outcome_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            provider.expected_binding(),
            provider.clone(),
        )
        .expect("qualify input-authority fixture");
        let unbound = KeyPair::try_from_seed(vec![0x84; 32], Algorithm::Ed25519)
            .expect("derive unbound-authority fixture");
        assert_eq!(
            qualified.sign(payload(AccountId::new(unbound.public_key().clone()))),
            Err(SoraFsProofOutcomeSigningError::InputAuthorityMismatch)
        );
        assert_eq!(provider.sign_calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn qualified_signer_rejects_provider_substituted_payload() {
        let provider = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/substituted-payload",
            0x85,
        ));
        let qualified = qualify_sorafs_proof_outcome_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            provider.expected_binding(),
            provider.clone(),
        )
        .expect("qualify substituted-payload fixture");
        let exact_payload = payload(qualified.authority());
        let mut substituted_payload = exact_payload.clone();
        substituted_payload.creation_time_ms = substituted_payload
            .creation_time_ms
            .checked_add(1)
            .expect("fixture creation time has headroom");
        provider.substitute_payload_once(substituted_payload);
        assert_eq!(
            qualified.sign(exact_payload),
            Err(SoraFsProofOutcomeSigningError::SubstitutedTransaction)
        );
        assert_eq!(provider.sign_calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn qualified_signer_rejects_provider_forged_signature() {
        let provider = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/forged-signature",
            0x86,
        ));
        let qualified = qualify_sorafs_proof_outcome_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            provider.expected_binding(),
            provider.clone(),
        )
        .expect("qualify forged-signature fixture");
        let forger = KeyPair::try_from_seed(vec![0x87; 32], Algorithm::Ed25519)
            .expect("derive forged-signature fixture");
        provider.forge_signature_once(forger);
        assert_eq!(
            qualified.sign(payload(qualified.authority())),
            Err(SoraFsProofOutcomeSigningError::SubstitutedTransaction)
        );
        assert_eq!(provider.sign_calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn qualified_signer_accepts_exact_envelope_and_rejects_provider_sidecars() {
        let exact_provider = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/exact-envelope",
            0x88,
        ));
        let exact = qualify_sorafs_proof_outcome_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            exact_provider.expected_binding(),
            exact_provider.clone(),
        )
        .expect("qualify exact-envelope fixture")
        .sign(payload(exact_provider.authority()))
        .expect("accept exact sidecar-free signed transaction");
        assert!(exact.attachments().is_none());
        assert!(exact.multisig_signatures().is_none());
        assert_eq!(exact_provider.sign_calls.load(Ordering::SeqCst), 1);
        let attached_provider = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/proof-sidecar",
            0x89,
        ));
        let attached = qualify_sorafs_proof_outcome_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            attached_provider.expected_binding(),
            attached_provider.clone(),
        )
        .expect("qualify proof-sidecar fixture");
        attached_provider.attach_proof_sidecar_once();
        assert_eq!(
            attached.sign(payload(attached_provider.authority())),
            Err(SoraFsProofOutcomeSigningError::SubstitutedTransaction)
        );
        assert_eq!(attached_provider.sign_calls.load(Ordering::SeqCst), 1);
        let multisig_provider = Arc::new(TestProvider::new(
            SorafsNativeTransactionSignerRoleV1::ProofOutcome,
            "provider://sorafs/proof-outcome/empty-multisig-sidecar",
            0x8A,
        ));
        let multisig = qualify_sorafs_proof_outcome_transaction_signer_v1(
            crate::signed_query_test_network_id(),
            multisig_provider.expected_binding(),
            multisig_provider.clone(),
        )
        .expect("qualify empty-multisig-sidecar fixture");
        multisig_provider.attach_empty_multisig_sidecar_once();
        assert_eq!(
            multisig.sign(payload(multisig_provider.authority())),
            Err(SoraFsProofOutcomeSigningError::SubstitutedTransaction)
        );
        assert_eq!(multisig_provider.sign_calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn keypair_has_no_blanket_production_signer_impl_in_source() {
        let source = include_str!("../lib.rs");
        for role_trait in [
            "impl SoraFsProofOutcomeTransactionSigner for KeyPair",
            "impl SoraFsRepairTransactionSigner for KeyPair",
            "impl SoraFsReserveTransactionSigner for KeyPair",
            "impl SoraFsOrderbookTransactionSigner for KeyPair",
        ] {
            assert!(
                !source.contains(role_trait),
                "blanket local-key fallback must stay removed: {role_trait}"
            );
        }
    }
}
