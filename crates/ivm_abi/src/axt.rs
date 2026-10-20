//! Atomic cross-transaction (AXT) helper types.
//!
//! VM-facing descriptor, touch, and proof helpers adapt the canonical data-model
//! AXT wire to pointer-ABI TLVs. Remote-spend staging carries the exact
//! `AxtAnchoredSpendV1` model value. Staging checks public structural binding;
//! finalized-source and issuer authority remain State-owned admission work.
use crate::{
    codec::{decode_canonical_norito, encode_canonical_norito},
    error::VMError,
};
use iroha_crypto::Hash;
#[cfg(test)]
use iroha_crypto::Signature;
#[cfg(test)]
use iroha_data_model::nexus::AxtAssetIncarnationV1;
#[cfg(test)]
use iroha_data_model::nexus::SpendOp as ModelSpendOp;
use iroha_data_model::nexus::{
    AssetHandle as ModelAssetHandle, AxtAnchoredSpendReplayKeyV1, AxtAnchoredSpendV1, AxtBinding,
    AxtDescriptor as ModelAxtDescriptor, AxtHandleReplayKey,
    AxtPolicySnapshot as ModelAxtPolicySnapshot,
    AxtPolicySnapshotValidationError as ModelAxtPolicySnapshotValidationError,
    AxtProofEnvelope as ModelAxtProofEnvelope, AxtTouchSpec as ModelAxtTouchSpec,
    MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES, ProofBlob as ModelProofBlob,
    RemoteSpendIntent as ModelRemoteSpendIntent, TouchManifest as ModelTouchManifest,
    compute_descriptor_binding, compute_remote_spend_intent_commitment_v1,
    validate_descriptor as validate_model_descriptor,
};
#[cfg(test)]
use iroha_data_model::nexus::{
    AxtHandleBudgetKey as ModelAxtHandleBudgetKey, AxtHandleIssuerContextV1,
    GroupBinding as ModelGroupBinding, HandleBudget as ModelHandleBudget,
    HandleSubject as ModelHandleSubject,
};
#[cfg(test)]
use iroha_data_model::prelude::AssetDefinitionId;
use iroha_data_model::{
    asset::AssetBalanceScope,
    prelude::{AccountId, Quantity},
};
use iroha_model_base::topology::DataSpaceId;
#[cfg(test)]
use iroha_model_base::topology::LaneId;
use norito::codec::{Decode, Encode};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
};
/// Alias for the Norito proof envelope used in AXT proof verification.
pub type AxtProofEnvelope = ModelAxtProofEnvelope;
const AMOUNT_COMMITMENT_DOMAIN_SEPARATOR: &[u8] = b"iroha.axt.amount-commitment.v1";
/// Effective handle amount resolved from the intent/proof pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHandleAmount {
    /// Non-zero amount used for budget checks and settlement.
    pub amount: Quantity,
    /// Optional amount commitment retained in block fragments.
    pub amount_commitment: Option<[u8; 32]>,
}
/// Dynamic AXT handle-use facts extracted from one canonically decoded and
/// cryptographically verified proof envelope.
///
/// Constructing this value does not itself verify the FASTPQ proof. Callers
/// must only build it after successful proof verification. The compact facts
/// let repeated handles enforce amount and intent membership without decoding
/// or scanning the full proof payload again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AxtProofUseFacts {
    dsid: DataSpaceId,
    committed_amount: Option<u128>,
    supplied_amount_commitment: Option<[u8; 32]>,
    fixed_amount_commitment: Option<[u8; 32]>,
    variable_amount_commitment_payload: Option<Vec<u8>>,
    remote_spend_intent_commitments: Vec<[u8; 32]>,
}
impl AxtProofUseFacts {
    /// Extract reusable handle-use facts from an already verified canonical envelope.
    ///
    /// This consumes the decoded envelope so its potentially large remote-intent
    /// commitment vector can be retained without cloning it.
    #[must_use]
    pub fn from_verified_envelope(envelope: AxtProofEnvelope) -> Self {
        Self::from_canonical_envelope(envelope)
    }
    fn from_canonical_envelope(mut envelope: AxtProofEnvelope) -> Self {
        let dsid = envelope.dsid;
        let committed_amount = envelope.committed_amount;
        let supplied_amount_commitment = envelope.amount_commitment;
        let normalized_payload =
            (committed_amount.is_some() || supplied_amount_commitment.is_some()).then(|| {
                envelope.amount_commitment = None;
                encode_canonical_norito(&envelope)
                    .expect("a decoded canonical AXT proof envelope always re-encodes")
            });
        let fixed_amount_commitment = committed_amount.map(|amount| {
            derive_amount_commitment_from_normalized_payload(
                dsid,
                &proof_scalar_to_quantity(amount),
                normalized_payload.as_deref(),
            )
        });
        let variable_amount_commitment_payload =
            if committed_amount.is_none() && supplied_amount_commitment.is_some() {
                normalized_payload
            } else {
                None
            };
        let remote_spend_intent_commitments = envelope
            .fastpq_binding
            .take()
            .map_or_else(Vec::new, |binding| binding.remote_spend_intent_commitments);
        Self {
            dsid,
            committed_amount,
            supplied_amount_commitment,
            fixed_amount_commitment,
            variable_amount_commitment_payload,
            remote_spend_intent_commitments,
        }
    }

    /// Return the proof-bound, canonically ordered remote-spend commitments.
    #[must_use]
    pub fn remote_spend_intent_commitments(&self) -> &[[u8; 32]] {
        &self.remote_spend_intent_commitments
    }

    /// Require exact one-time consumption of every proof-bound remote-spend claim.
    ///
    /// The input may arrive in handle execution order. It is sorted without
    /// deduplication, so duplicate handle consumption and unconsumed proof
    /// claims both fail the exact comparison.
    ///
    /// # Errors
    ///
    /// Returns [`VMError::PermissionDenied`] unless the consumed commitment
    /// multiset exactly equals the proof's canonical commitment set.
    pub fn validate_remote_spend_consumption(
        &self,
        consumed_commitments: &[[u8; 32]],
    ) -> Result<(), VMError> {
        let mut consumed = consumed_commitments.to_vec();
        consumed.sort_unstable();
        if consumed == self.remote_spend_intent_commitments {
            Ok(())
        } else {
            Err(VMError::PermissionDenied)
        }
    }
}
/// Errors returned by [`resolve_handle_amount_components`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleAmountResolutionError {
    /// No cleartext amount was provided; a public proof scalar cannot authorize a private amount.
    MissingAmount,
    /// The supplied proof payload is not a canonical AXT proof envelope.
    InvalidProofEnvelope,
    /// Cleartext and committed amounts disagree.
    Mismatch,
    /// Resolved amount is zero and therefore invalid for handle usage.
    ZeroAmount,
    /// A business quantity cannot be represented exactly by the V1 proof scalar.
    InvalidProofScalar,
    /// Proof-supplied amount commitment does not bind the canonical proof statement.
    CommitmentMismatch,
}
impl HandleAmountResolutionError {
    /// Convert the resolver error to the syscall-level VM error used by hosts.
    #[must_use]
    pub const fn to_vm_error(self) -> VMError {
        match self {
            Self::MissingAmount | Self::InvalidProofEnvelope => VMError::NoritoInvalid,
            Self::Mismatch
            | Self::ZeroAmount
            | Self::InvalidProofScalar
            | Self::CommitmentMismatch => VMError::PermissionDenied,
        }
    }
}
fn quantity_to_proof_scalar(amount: &Quantity) -> Result<u128, HandleAmountResolutionError> {
    if amount.scale() != 0 {
        return Err(HandleAmountResolutionError::InvalidProofScalar);
    }
    amount
        .as_numeric()
        .try_mantissa_u128()
        .ok_or(HandleAmountResolutionError::InvalidProofScalar)
}
fn proof_scalar_to_quantity(amount: u128) -> Quantity {
    amount
        .to_string()
        .parse()
        .expect("every u128 is an exact scale-zero Quantity")
}
/// Build a deterministic amount commitment over an AXT envelope and amount.
///
/// This digest links the envelope and fragment copies for consistency; it does
/// not authenticate the amount. Amount authenticity comes from the
/// proof-bound FASTPQ batch metadata checked by the AXT proof verifier.
///
/// Canonical AXT proof envelopes are hashed with their `amount_commitment`
/// field cleared. This makes the commitment non-circular and lets validators
/// recompute it from an envelope that already carries the claimed value.
#[must_use]
pub fn derive_amount_commitment(
    dsid: DataSpaceId,
    amount: &Quantity,
    proof_payload: Option<&[u8]>,
) -> [u8; 32] {
    let normalized_proof_payload = proof_payload.map(|payload| {
        if payload.len() > MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES {
            return Cow::Borrowed(payload);
        }
        decode_canonical_norito::<AxtProofEnvelope>(payload).map_or_else(
            |_| Cow::Borrowed(payload),
            |mut envelope| {
                envelope.amount_commitment = None;
                Cow::Owned(
                    encode_canonical_norito(&envelope)
                        .expect("a decoded canonical AXT proof envelope always re-encodes"),
                )
            },
        )
    });
    derive_amount_commitment_from_normalized_payload(
        dsid,
        amount,
        normalized_proof_payload.as_deref(),
    )
}
fn derive_amount_commitment_from_normalized_payload(
    dsid: DataSpaceId,
    amount: &Quantity,
    proof_payload: Option<&[u8]>,
) -> [u8; 32] {
    let amount_text = amount.to_string();
    let amount_len =
        u16::try_from(amount_text.len()).expect("bounded Quantity text length always fits in u16");
    let dsid_bytes = dsid.as_u64().to_be_bytes();
    let amount_len_bytes = amount_len.to_be_bytes();
    let fixed_chunks = [
        AMOUNT_COMMITMENT_DOMAIN_SEPARATOR,
        dsid_bytes.as_slice(),
        amount_len_bytes.as_slice(),
        amount_text.as_bytes(),
    ];
    proof_payload.map_or_else(
        || Hash::new_from_chunks(&fixed_chunks).into(),
        |payload| {
            Hash::new_from_chunks(&[
                fixed_chunks[0],
                fixed_chunks[1],
                fixed_chunks[2],
                fixed_chunks[3],
                payload,
            ])
            .into()
        },
    )
}
/// Resolve an effective amount from the canonical model components shared by
/// VM-host and block-admission validation.
///
/// Keeping this conversion in one place prevents the two consensus-critical
/// validation layers from disagreeing about fractional quantities, proof
/// scalar bounds, redacted-amount rejection, or commitment derivation.
///
/// # Errors
///
/// Returns [`HandleAmountResolutionError`] when the amount is absent, zero, inconsistent with the
/// proof statement, or cannot be represented exactly by the V1 proof scalar.
pub fn resolve_handle_amount_components(
    asset_dsid: DataSpaceId,
    intent_amount: Option<&Quantity>,
    proof_payload: Option<&[u8]>,
) -> Result<ResolvedHandleAmount, HandleAmountResolutionError> {
    // TODO: Admit private amounts only after a proof-bound confidential value,
    // conservation relation, and budget comparison replace this public scalar.
    let intent_amount = intent_amount.ok_or(HandleAmountResolutionError::MissingAmount)?;
    let Some(proof_payload) = proof_payload else {
        let amount = intent_amount.clone();
        if amount.is_zero() {
            return Err(HandleAmountResolutionError::ZeroAmount);
        }
        return Ok(ResolvedHandleAmount {
            amount,
            amount_commitment: None,
        });
    };
    if proof_payload.len() > MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES {
        return Err(HandleAmountResolutionError::InvalidProofEnvelope);
    }
    let envelope = decode_canonical_norito::<AxtProofEnvelope>(proof_payload)
        .map_err(|_| HandleAmountResolutionError::InvalidProofEnvelope)?;
    let facts = AxtProofUseFacts::from_canonical_envelope(envelope);
    resolve_handle_amount_components_from_proof_facts(asset_dsid, Some(intent_amount), &facts)
}
/// Resolve an effective handle amount from cached, verified proof facts.
///
/// Unlike [`resolve_handle_amount_components`], this path performs no proof
/// decoding or full-payload scan and is suitable for repeated use of one proof.
///
/// # Errors
///
/// Returns [`HandleAmountResolutionError`] when the dataspace or amount does
/// not match the verified proof facts, or when the intent amount is absent,
/// zero, or not exactly representable by the V1 proof scalar.
pub fn resolve_handle_amount_components_from_proof_facts(
    asset_dsid: DataSpaceId,
    intent_amount: Option<&Quantity>,
    facts: &AxtProofUseFacts,
) -> Result<ResolvedHandleAmount, HandleAmountResolutionError> {
    if facts.dsid != asset_dsid {
        return Err(HandleAmountResolutionError::InvalidProofEnvelope);
    }
    let intent_amount = intent_amount.ok_or(HandleAmountResolutionError::MissingAmount)?;
    let committed_amount = facts.committed_amount;
    let amount = match committed_amount {
        Some(committed_amount) => {
            if quantity_to_proof_scalar(intent_amount)? != committed_amount {
                return Err(HandleAmountResolutionError::Mismatch);
            }
            intent_amount.clone()
        }
        None => intent_amount.clone(),
    };
    if amount.is_zero() {
        return Err(HandleAmountResolutionError::ZeroAmount);
    }
    let supplied_commitment = facts.supplied_amount_commitment;
    let commitment_required = committed_amount.is_some() || supplied_commitment.is_some();
    let amount_commitment = commitment_required.then(|| {
        facts.fixed_amount_commitment.unwrap_or_else(|| {
            derive_amount_commitment_from_normalized_payload(
                asset_dsid,
                &amount,
                facts.variable_amount_commitment_payload.as_deref(),
            )
        })
    });
    if supplied_commitment.is_some() && supplied_commitment != amount_commitment {
        return Err(HandleAmountResolutionError::CommitmentMismatch);
    }
    Ok(ResolvedHandleAmount {
        amount,
        amount_commitment,
    })
}
/// Canonical descriptor for an AXT envelope.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    norito::json::Serialize,
    norito::json::Deserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "ivm_abi::axt::AxtDescriptor")]
pub struct AxtDescriptor {
    /// List of dataspace identifiers touched by the transaction.
    pub dsids: Vec<DataSpaceId>,
    /// Fine-grained access declarations for each DS.
    pub touches: Vec<AxtTouchSpec>,
}
impl AxtDescriptor {
    /// Start a deterministic descriptor builder.
    #[must_use]
    pub fn builder() -> AxtDescriptorBuilder {
        AxtDescriptorBuilder::default()
    }
    /// Collect the dataspace identifiers declared in the descriptor.
    #[must_use]
    pub fn dsid_set(&self) -> BTreeSet<DataSpaceId> {
        self.dsids.iter().copied().collect()
    }
    /// Locate the declared touch specification for a dataspace.
    #[must_use]
    pub fn touch_for(&self, dsid: &DataSpaceId) -> Option<&AxtTouchSpec> {
        self.touches.iter().find(|touch| &touch.dsid == dsid)
    }
}
/// Deterministic builder for [`AxtDescriptor`].
#[derive(Debug, Default)]
pub struct AxtDescriptorBuilder {
    dsids: BTreeSet<DataSpaceId>,
    touches: BTreeMap<DataSpaceId, AxtTouchSpec>,
}
impl AxtDescriptorBuilder {
    /// Declare that the descriptor touches the provided dataspace id.
    #[must_use]
    pub fn dataspace(mut self, dsid: DataSpaceId) -> Self {
        self.dsids.insert(dsid);
        self
    }
    /// Add or replace the touch specification for a dataspace.
    ///
    /// Paths are trimmed, sorted, and deduplicated for deterministic output.
    #[must_use]
    pub fn touch<R, W>(mut self, dsid: DataSpaceId, read: R, write: W) -> Self
    where
        R: IntoIterator,
        R::Item: Into<String>,
        W: IntoIterator,
        W::Item: Into<String>,
    {
        self.dsids.insert(dsid);
        self.touches.insert(
            dsid,
            AxtTouchSpec {
                dsid,
                read: canonicalize_paths(read),
                write: canonicalize_paths(write),
            },
        );
        self
    }
    /// Finalise the descriptor and validate pointer-ABI invariants.
    ///
    /// # Errors
    /// Returns an error if the descriptor is empty or contains mismatched
    /// dataspace/touch declarations.
    pub fn build(self) -> Result<AxtDescriptor, VMError> {
        let mut dsids = self.dsids;
        dsids.extend(self.touches.keys().copied());
        let descriptor = AxtDescriptor {
            dsids: dsids.into_iter().collect(),
            touches: self.touches.into_values().collect(),
        };
        validate_descriptor(&descriptor)?;
        Ok(descriptor)
    }
    /// Finalise the descriptor and compute its canonical binding.
    ///
    /// # Errors
    /// Returns an error when validation fails or the descriptor cannot be
    /// encoded to Norito bytes for hashing.
    pub fn build_with_binding(self) -> Result<(AxtDescriptor, [u8; 32]), VMError> {
        let descriptor = self.build()?;
        let binding = compute_binding(&descriptor).map_err(|_| VMError::NoritoInvalid)?;
        Ok((descriptor, binding))
    }
}
fn canonicalize_paths<I, S>(paths: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut paths: Vec<String> = paths
        .into_iter()
        .map(|p| p.into().trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect();
    paths.sort();
    paths.dedup();
    paths
}
/// Validate basic invariants of an AXT descriptor.
pub fn validate_descriptor(descriptor: &AxtDescriptor) -> Result<(), VMError> {
    validate_model_descriptor(&model_descriptor(descriptor)).map_err(|_| VMError::PermissionDenied)
}
fn model_descriptor(descriptor: &AxtDescriptor) -> ModelAxtDescriptor {
    ModelAxtDescriptor {
        dsids: descriptor.dsids.clone(),
        touches: descriptor
            .touches
            .iter()
            .map(|touch| ModelAxtTouchSpec {
                dsid: touch.dsid,
                read: touch.read.clone(),
                write: touch.write.clone(),
            })
            .collect(),
    }
}
/// Compute the expiry slot after applying a wall-clock skew allowance.
#[must_use]
pub fn expiry_slot_with_skew(
    expiry_slot: u64,
    slot_length_ms: NonZeroU64,
    max_clock_skew_ms: u64,
    override_ms: Option<u32>,
) -> u64 {
    let effective_ms = override_ms
        .map(u64::from)
        .unwrap_or(max_clock_skew_ms)
        .min(max_clock_skew_ms);
    if effective_ms == 0 {
        return expiry_slot;
    }
    let slot_ms = slot_length_ms.get();
    let skew_slots = effective_ms.div_ceil(slot_ms);
    expiry_slot.saturating_add(skew_slots)
}
/// Policy hook for gating AXT touches.
pub trait AxtPolicy: Send + Sync {
    /// Decide whether a touch manifest is allowed for the given dataspace.
    fn allow_touch(&self, dsid: DataSpaceId, manifest: &TouchManifest) -> Result<(), VMError>;
}
/// Default AXT policy that allows all operations.
pub struct AllowAllAxtPolicy;
impl AxtPolicy for AllowAllAxtPolicy {
    fn allow_touch(&self, _dsid: DataSpaceId, _manifest: &TouchManifest) -> Result<(), VMError> {
        Ok(())
    }
}
/// Simple policy implementation backed by an AXT policy snapshot.
#[derive(Clone, Debug)]
pub struct SnapshotAxtPolicy;
impl SnapshotAxtPolicy {
    /// Construct a policy from a snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ModelAxtPolicySnapshotValidationError`] when the snapshot is
    /// not canonically ordered or its version does not bind its exact entries.
    pub fn new(
        snapshot: &ModelAxtPolicySnapshot,
    ) -> Result<Self, ModelAxtPolicySnapshotValidationError> {
        Self::new_with_timing(
            snapshot,
            NonZeroU64::new(1).expect("slot length must be non-zero"),
            0,
        )
    }
    /// Construct a policy from a snapshot and explicit timing parameters.
    ///
    /// # Errors
    ///
    /// Returns [`ModelAxtPolicySnapshotValidationError`] when the snapshot is
    /// not canonically ordered or its version does not bind its exact entries.
    pub fn new_with_timing(
        snapshot: &ModelAxtPolicySnapshot,
        _slot_length_ms: NonZeroU64,
        _max_clock_skew_ms: u64,
    ) -> Result<Self, ModelAxtPolicySnapshotValidationError> {
        snapshot.validate()?;
        Ok(Self)
    }
}
impl AxtPolicy for SnapshotAxtPolicy {
    fn allow_touch(&self, _dsid: DataSpaceId, _manifest: &TouchManifest) -> Result<(), VMError> {
        Ok(())
    }
}
/// Declared access set for a dataspace touched by an AXT envelope.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    norito::json::Serialize,
    norito::json::Deserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "ivm_abi::axt::AxtTouchSpec")]
pub struct AxtTouchSpec {
    /// Dataspace identifier.
    pub dsid: DataSpaceId,
    /// Logical read-set expressed as application key prefixes.
    pub read: Vec<String>,
    /// Logical write-set expressed as application key prefixes.
    pub write: Vec<String>,
}
/// Runtime manifest supplied via `AXT_TOUCH`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    norito::json::Serialize,
    norito::json::Deserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "ivm_abi::axt::TouchManifest")]
pub struct TouchManifest {
    /// Keys read within the dataspace during execution.
    pub read: Vec<String>,
    /// Keys written within the dataspace during execution.
    pub write: Vec<String>,
}
/// Validate the semantic canonical form of an AXT touch manifest.
///
/// Empty read/write sets are valid, but every present key must be non-empty,
/// trimmed, strictly sorted, and unique. In particular, an empty prefix is
/// forbidden because every key starts with it.
///
/// # Errors
///
/// Returns [`VMError::NoritoInvalid`] when a key list is not canonical.
pub fn validate_touch_manifest(manifest: &TouchManifest) -> Result<(), VMError> {
    if !canonical_nonempty_strings(&manifest.read) || !canonical_nonempty_strings(&manifest.write) {
        return Err(VMError::NoritoInvalid);
    }
    Ok(())
}
/// Validate a persisted data-model touch manifest with the runtime invariants.
///
/// # Errors
///
/// Returns [`VMError::NoritoInvalid`] when a key list is not canonical.
pub fn validate_model_touch_manifest(manifest: &ModelTouchManifest) -> Result<(), VMError> {
    validate_touch_manifest(&TouchManifest {
        read: manifest.read.clone(),
        write: manifest.write.clone(),
    })
}
fn canonical_nonempty_strings(values: &[String]) -> bool {
    values
        .iter()
        .all(|value| !value.is_empty() && value.trim() == value)
        && values.windows(2).all(|pair| pair[0] < pair[1])
}
/// Validate the context-free shape and value invariants of a signed model handle.
///
/// Current issuer authority, descriptor identity, freshness, and cumulative
/// budgets require authenticated State context. The signed model value is the
/// only V1 handle wire; there is no pointer-only handle representation.
///
/// # Errors
///
/// Returns [`VMError::NoritoInvalid`] for noncanonical strings or account IDs
/// and [`VMError::PermissionDenied`] for unusable capability values.
pub fn validate_model_asset_handle(handle: &ModelAssetHandle) -> Result<(), VMError> {
    if handle.group_binding.composability_group_id.is_empty()
        || !canonical_nonempty_strings(&handle.scope)
        || (!handle.subject.account.is_empty()
            && canonical_account_id(&handle.subject.account).is_none())
    {
        return Err(VMError::NoritoInvalid);
    }
    if handle.scope.is_empty()
        || handle.subject.account.is_empty()
        || handle.budget.remaining.is_zero()
        || handle
            .budget
            .per_use
            .as_ref()
            .is_some_and(Quantity::is_zero)
        || handle.handle_era == 0
        || handle.sub_nonce == 0
        || handle.group_binding.epoch_id == 0
        || handle.expiry_slot == 0
        || handle
            .issuer_context
            .issuer_manifest_root
            .iter()
            .all(|byte| *byte == 0)
        || handle.issuer_context.validate().is_err()
        || handle.issuer_context.abi_version != 1
        || handle.issuer_context.abi_hash.iter().all(|byte| *byte == 0)
    {
        return Err(VMError::PermissionDenied);
    }
    Ok(())
}
/// Validate a signed model remote-spend intent's context-free invariants.
///
/// # Errors
///
/// Returns [`VMError::NoritoInvalid`] for non-transfer operations or
/// noncanonical accounts and [`VMError::PermissionDenied`] for an absent or zero amount.
pub fn validate_model_remote_spend_intent(intent: &ModelRemoteSpendIntent) -> Result<(), VMError> {
    if intent.op.kind != "transfer" {
        return Err(VMError::NoritoInvalid);
    }
    for account in [&intent.op.from, &intent.op.to] {
        if canonical_account_id(account).is_none() {
            return Err(VMError::NoritoInvalid);
        }
    }
    // TODO: Admit private amounts only with a proof-bound confidential value,
    // conservation relation, and budget comparison; a public scalar is not private.
    if intent.op.amount.as_ref().is_none_or(Quantity::is_zero) {
        return Err(VMError::PermissionDenied);
    }
    Ok(())
}
fn canonical_account_id(value: &str) -> Option<AccountId> {
    let parsed = AccountId::parse_encoded(value).ok()?;
    (parsed.to_string() == value).then_some(parsed)
}
/// Require a registered asset policy's balance scope to match the intent dataspace.
///
/// Globally scoped assets belong to the universal dataspace. A
/// dataspace-restricted definition selects the exact signed intent/proof
/// dataspace bucket. Callers must first establish that the asset definition is
/// registered in committed state and derive `resolved_scope` from its balance
/// policy; the opaque asset-definition identifier carries no routing meaning.
///
/// # Errors
///
/// Returns [`VMError::PermissionDenied`] when the policy-derived scope does not
/// match `asset_dsid`.
pub fn validate_remote_spend_asset_scope(
    asset_dsid: DataSpaceId,
    resolved_scope: AssetBalanceScope,
) -> Result<(), VMError> {
    let matches = match resolved_scope {
        AssetBalanceScope::Global => asset_dsid == DataSpaceId::UNIVERSAL,
        AssetBalanceScope::Dataspace(dataspace) => asset_dsid == dataspace,
    };
    matches.then_some(()).ok_or(VMError::PermissionDenied)
}
/// Require a proof-bound commitment for a persisted data-model remote spend.
///
/// The caller must first verify the FASTPQ proof cryptographically.
///
/// # Errors
///
/// Returns [`VMError::PermissionDenied`] for a mismatched asset or absent
/// proof-bound commitment, and [`VMError::NoritoInvalid`] for malformed proof bytes.
pub fn validate_model_remote_spend_intent_commitment(
    handle: &ModelAssetHandle,
    intent: &ModelRemoteSpendIntent,
    effective_amount: &Quantity,
    proof: &ModelProofBlob,
) -> Result<(), VMError> {
    if intent.op.amount.as_ref() != Some(effective_amount)
        || handle.asset_definition_id != intent.op.asset_definition_id
    {
        return Err(VMError::PermissionDenied);
    }
    validate_remote_spend_intent_commitment_components(
        expected_model_remote_spend_intent_commitment_v1(handle, intent, effective_amount),
        &proof.payload,
    )
}
/// Require an exact persisted remote-spend commitment from cached, verified proof facts.
///
/// This performs the same semantic membership check as
/// [`validate_model_remote_spend_intent_commitment`] without decoding or
/// scanning the proof payload again.
///
/// # Errors
///
/// Returns [`VMError::PermissionDenied`] when the proof facts do not contain
/// the exact handle identity/asset/operation/account/amount commitment.
pub fn validate_model_remote_spend_intent_commitment_from_proof_facts(
    handle: &ModelAssetHandle,
    intent: &ModelRemoteSpendIntent,
    effective_amount: &Quantity,
    facts: &AxtProofUseFacts,
) -> Result<(), VMError> {
    if intent.op.amount.as_ref() != Some(effective_amount)
        || facts.dsid != intent.asset_dsid
        || handle.asset_definition_id != intent.op.asset_definition_id
    {
        return Err(VMError::PermissionDenied);
    }
    validate_remote_spend_intent_commitment_components_from_commitments(
        expected_model_remote_spend_intent_commitment_v1(handle, intent, effective_amount),
        &facts.remote_spend_intent_commitments,
    )
}

/// Derive the commitment expected for one concrete persisted handle use.
#[must_use]
pub fn expected_model_remote_spend_intent_commitment_v1(
    handle: &ModelAssetHandle,
    intent: &ModelRemoteSpendIntent,
    effective_amount: &Quantity,
) -> [u8; 32] {
    compute_remote_spend_intent_commitment_v1(
        AxtHandleReplayKey::from_handle(intent.asset_dsid, handle),
        &handle.asset_definition_id,
        &intent.op.kind,
        &intent.op.from,
        &intent.op.to,
        effective_amount,
    )
}
fn validate_remote_spend_intent_commitment_components(
    expected: [u8; 32],
    proof_payload: &[u8],
) -> Result<(), VMError> {
    if proof_payload.len() > MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES {
        return Err(VMError::NoritoInvalid);
    }
    let envelope = decode_canonical_norito::<ModelAxtProofEnvelope>(proof_payload)
        .map_err(|_| VMError::NoritoInvalid)?;
    let binding = envelope
        .fastpq_binding
        .as_ref()
        .ok_or(VMError::PermissionDenied)?;
    validate_remote_spend_intent_commitment_components_from_commitments(
        expected,
        &binding.remote_spend_intent_commitments,
    )
}
fn validate_remote_spend_intent_commitment_components_from_commitments(
    expected: [u8; 32],
    remote_spend_intent_commitments: &[[u8; 32]],
) -> Result<(), VMError> {
    remote_spend_intent_commitments
        .binary_search(&expected)
        .map(|_| ())
        .map_err(|_| VMError::PermissionDenied)
}
/// Wrapper around proof artifacts provided by dataspace verifiers.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::axt::ProofBlob")]
pub struct ProofBlob {
    /// Raw proof bytes, bounded by the shared AXT proof-envelope payload limit.
    pub payload: Vec<u8>,
    /// Outer mirror of the proof-bound optional expiry slot.
    ///
    /// `None` is an authenticated no-expiry sentinel. Proof-aware hosts must
    /// exact-compare this value with the proof metadata before applying the
    /// current AXT policy slot's freshness check.
    #[norito(required)]
    pub expiry_slot: Option<u64>,
}
/// Validate context-free proof-blob invariants.
///
/// Proof schema, dataspace binding, manifest binding, freshness relative to a
/// current slot, and cryptographic validity require host context.
///
/// # Errors
///
/// Returns [`VMError::NoritoInvalid`] when proof bytes are empty or oversized,
/// or an explicit expiry uses the forbidden zero sentinel.
pub fn validate_proof_blob(proof: &ProofBlob) -> Result<(), VMError> {
    if proof.payload.is_empty()
        || proof.payload.len() > MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES
        || proof.expiry_slot == Some(0)
    {
        return Err(VMError::NoritoInvalid);
    }
    Ok(())
}
/// Preflight the structural FastPQ V1 binding carried by an AXT proof envelope.
///
/// This checks only envelope routing and metadata. It does not verify FastPQ
/// proof contents and must never be treated as proof acceptance.
///
/// # Errors
///
/// Returns [`VMError::PermissionDenied`] when the envelope does not bind to the
/// expected dataspace/manifest or does not advertise FastPQ V1 proof material.
pub fn preflight_fastpq_v1_proof_envelope_for_manifest(
    envelope: &AxtProofEnvelope,
    dsid: DataSpaceId,
    manifest_root: [u8; 32],
) -> Result<(), VMError> {
    preflight_fastpq_v1_proof_envelope(envelope, dsid)?;
    if envelope.manifest_root != manifest_root {
        return Err(VMError::PermissionDenied);
    }
    Ok(())
}
/// Preflight an AXT proof envelope as FastPQ V1 material without pinning a manifest root.
///
/// This is diagnostic routing/metadata validation only. A host must still call
/// a real FastPQ verifier before accepting the envelope as proof material.
///
/// # Errors
///
/// Returns [`VMError::PermissionDenied`] when the envelope does not bind to the
/// expected dataspace or does not advertise FastPQ V1 proof material.
pub fn preflight_fastpq_v1_proof_envelope(
    envelope: &AxtProofEnvelope,
    dsid: DataSpaceId,
) -> Result<(), VMError> {
    let Some(binding) = envelope.fastpq_binding.as_ref() else {
        return Err(VMError::PermissionDenied);
    };
    if envelope.dsid != dsid
        || envelope.manifest_root.iter().all(|byte| *byte == 0)
        || envelope.proof.is_empty()
        || binding.source_dsid != dsid.as_u64()
        || binding.verifier_id != "fastpq"
        || binding.verifier_version != "v1"
        || !fastpq_binding_shape_is_concrete(binding)
    {
        return Err(VMError::PermissionDenied);
    }
    Ok(())
}
fn fastpq_binding_shape_is_concrete(binding: &iroha_data_model::nexus::AxtFastpqBinding) -> bool {
    binding_string_is_present(&binding.parameter)
        && binding_string_is_present(&binding.source_dataspace)
        && binding_string_is_present(&binding.source_receipt_id)
        && binding_hex_digest_is_present(&binding.source_tx_commitment)
        && fastpq_claim_type_is_supported(&binding.claim_type)
        && binding_hex_digest_is_present(&binding.claim_digest)
        && binding_hex_digest_is_present(&binding.witness_commitment)
        && binding_hex_digest_is_present(&binding.policy_commitment)
        && binding_string_is_present(&binding.verified_effect_type)
        && binding_string_is_present(&binding.corridor)
        && !binding.target_dsids.is_empty()
        && binding
            .target_dsids
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        && binding.effect_binding.as_ref().is_none_or(|effect| {
            [
                &effect.destination_domain,
                &effect.destination_account_id,
                &effect.vault_account_id,
                &effect.issuance_account_id,
                &effect.source_asset_definition_id,
                &effect.destination_asset_definition_id,
            ]
            .into_iter()
            .all(|value| value.as_deref().is_none_or(binding_string_is_present))
        })
        && binding.remote_spend_intent_commitments.len()
            <= iroha_data_model::nexus::MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1
        && binding
            .remote_spend_intent_commitments
            .windows(2)
            .all(|pair| pair[0] < pair[1])
}
fn binding_string_is_present(value: &str) -> bool {
    !value.is_empty() && value.trim() == value
}
fn binding_hex_digest_is_present(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
fn fastpq_claim_type_is_supported(value: &str) -> bool {
    matches!(
        value,
        "authorization" | "compliance" | "tx_predicate" | "value_conservation"
    )
}
/// Compute the canonical descriptor binding used by asset handles.
///
/// The current implementation prefixes the descriptor bytes with a stable domain separator and
/// hashes the concatenation using the original BN254 Poseidon sponge (rate 2, capacity 1). Byte packing appends
/// a `0x01` delimiter and zero-pads to an eight-byte boundary before the sponge's field-level +1
/// padding. This matches the normative definition documented in `nexus.md`.
pub fn compute_binding(descriptor: &AxtDescriptor) -> Result<[u8; 32], norito::Error> {
    compute_descriptor_binding(&model_descriptor(descriptor))
}
/// Shared helper used by hosts to track in-flight AXT state.
#[derive(Clone, Debug)]
pub struct HostAxtState {
    descriptor: AxtDescriptor,
    binding: [u8; 32],
    expected_dsids: BTreeSet<DataSpaceId>,
    touches: BTreeMap<DataSpaceId, TouchManifest>,
    proofs: BTreeMap<DataSpaceId, ProofBlob>,
    spends: Vec<AxtAnchoredSpendV1>,
}
impl HostAxtState {
    #[must_use]
    pub fn new(descriptor: AxtDescriptor, binding: [u8; 32]) -> Self {
        let expected_dsids = descriptor.dsid_set();
        Self {
            descriptor,
            binding,
            expected_dsids,
            touches: BTreeMap::new(),
            proofs: BTreeMap::new(),
            spends: Vec::new(),
        }
    }
    #[must_use]
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    #[must_use]
    pub fn descriptor(&self) -> &AxtDescriptor {
        &self.descriptor
    }
    #[must_use]
    pub fn expected_dsids(&self) -> &BTreeSet<DataSpaceId> {
        &self.expected_dsids
    }
    pub fn record_touch(
        &mut self,
        dsid: DataSpaceId,
        manifest: TouchManifest,
    ) -> Result<(), VMError> {
        validate_touch_manifest(&manifest)?;
        if self.touches.contains_key(&dsid) {
            return Err(VMError::PermissionDenied);
        }
        if !self.expected_dsids.contains(&dsid) {
            return Err(VMError::PermissionDenied);
        }
        if let Some(spec) = self.descriptor.touch_for(&dsid) {
            if !manifest
                .read
                .iter()
                .all(|entry| spec.read.iter().any(|prefix| entry.starts_with(prefix)))
            {
                return Err(VMError::PermissionDenied);
            }
            if !manifest
                .write
                .iter()
                .all(|entry| spec.write.iter().any(|prefix| entry.starts_with(prefix)))
            {
                return Err(VMError::PermissionDenied);
            }
        } else if !manifest.read.is_empty() || !manifest.write.is_empty() {
            return Err(VMError::PermissionDenied);
        }
        self.touches.insert(dsid, manifest);
        Ok(())
    }
    #[must_use]
    pub fn has_touch(&self, dsid: &DataSpaceId) -> bool {
        self.touches.contains_key(dsid)
    }
    pub fn record_proof(
        &mut self,
        dsid: DataSpaceId,
        proof: Option<ProofBlob>,
        current_slot: Option<u64>,
    ) -> Result<(), VMError> {
        if !self.expected_dsids.contains(&dsid) {
            return Err(VMError::PermissionDenied);
        }
        if let Some(p) = proof {
            validate_proof_blob(&p)?;
            if let Some(expiry) = p.expiry_slot
                && let Some(slot) = current_slot
                && slot > 0
                && slot > expiry
            {
                return Err(VMError::PermissionDenied);
            }
            self.proofs.insert(dsid, p);
        } else {
            self.proofs.remove(&dsid);
        }
        Ok(())
    }
    #[must_use]
    pub fn touches(&self) -> &BTreeMap<DataSpaceId, TouchManifest> {
        &self.touches
    }
    #[must_use]
    pub fn proofs(&self) -> &BTreeMap<DataSpaceId, ProofBlob> {
        &self.proofs
    }
    /// Stage one canonical signed spend claim for transactional State admission.
    ///
    /// This checks only internally consistent public fields. It does not
    /// authenticate the claimed finalized source anchor, execution receipt,
    /// issuer key, or replay state; State must reject the completed envelope
    /// until those authorities are available.
    ///
    /// # Errors
    ///
    /// Rejects a spend outside the active descriptor, malformed static
    /// binding, or a local allocation failure before the vector grows.
    pub fn record_spend(&mut self, spend: AxtAnchoredSpendV1) -> Result<(), VMError> {
        if !self.expected_dsids.contains(&spend.draft.intent.asset_dsid)
            || spend.draft.handle.axt_binding != AxtBinding::new(self.binding)
            || validate_model_asset_handle(&spend.draft.handle).is_err()
            || validate_model_remote_spend_intent(&spend.draft.intent).is_err()
            || spend.issuer_payload_v1().is_err()
        {
            return Err(VMError::PermissionDenied);
        }
        if self.spends.len() >= iroha_data_model::nexus::MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1 {
            return Err(VMError::PermissionDenied);
        }
        self.spends.try_reserve(1).map_err(|_| {
            VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable)
        })?;
        self.spends.push(spend);
        Ok(())
    }
    /// Staged signed spends in exact VM call order.
    #[must_use]
    pub fn spends(&self) -> &[AxtAnchoredSpendV1] {
        &self.spends
    }
    /// Validate the staged envelope before its exact signed wires are materialized.
    ///
    /// This checks local one-use identities only. It does not grant source
    /// finality, issuer authority, or permission to apply a remote spend.
    ///
    /// # Errors
    /// Rejects missing declared material, duplicate signed issuer nonces or
    /// source transfer coordinates, and unavailable local index allocation.
    pub fn validate_commit(&self) -> Result<(), VMError> {
        for dsid in &self.expected_dsids {
            if self.descriptor.touch_for(dsid).is_some() && !self.touches.contains_key(dsid) {
                return Err(VMError::PermissionDenied);
            }
        }
        for dsid in &self.expected_dsids {
            if !self.proofs.contains_key(dsid)
                && !self
                    .spends
                    .iter()
                    .any(|spend| spend.draft.intent.asset_dsid == *dsid)
            {
                return Err(VMError::PermissionDenied);
            }
        }
        // One signed issuer nonce and one finalized source transfer may each
        // authorize at most one staged use. Compare the physical source
        // coordinate rather than the claim digest: a second handle/nonce must
        // not make the same transfer occurrence appear fresh. These bounded,
        // fallible indexes are local preflight only; State still owns durable
        // replay and rejects all remote spends until source finality is proven.
        let mut nonces = Vec::<AxtAnchoredSpendReplayKeyV1>::new();
        let mut occurrences = Vec::new();
        nonces.try_reserve_exact(self.spends.len()).map_err(|_| {
            VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable)
        })?;
        occurrences
            .try_reserve_exact(self.spends.len())
            .map_err(|_| {
                VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable)
            })?;
        for spend in &self.spends {
            nonces.push(spend.replay_key_v1());
            let anchor = &spend.authorization.anchor;
            let occurrence = &spend.draft.source_occurrence;
            occurrences.push((
                anchor.network_id,
                anchor.block_header_hash,
                occurrence.source_tx_index,
                occurrence.transcript_index,
                occurrence.delta_index,
            ));
        }
        nonces.sort_unstable();
        occurrences.sort_unstable();
        if nonces.windows(2).any(|pair| pair[0] == pair[1])
            || occurrences.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(VMError::PermissionDenied);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::nexus::AxtPolicyEntry as ModelAxtPolicyEntry;
    use iroha_model_base::domain::DomainId;
    const ACCOUNT_FROM_LITERAL: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
    const ACCOUNT_TO_LITERAL: &str = "sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76";
    fn quantity(value: u128) -> Quantity {
        value
            .to_string()
            .parse()
            .expect("test amount is a canonical quantity")
    }
    fn test_asset_definition_id() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("axt", "universal").expect("test asset domain"),
            "rose".parse().expect("test asset name"),
        )
    }
    #[test]
    fn expiry_slot_with_skew_respects_caps() {
        let slot = expiry_slot_with_skew(10, NonZeroU64::new(10).expect("slot length"), 5, Some(7));
        assert_eq!(slot, 11, "7ms skew rounds up into 1 slot of 10ms");
        let clamped =
            expiry_slot_with_skew(20, NonZeroU64::new(10).expect("slot length"), 5, Some(50));
        assert_eq!(
            clamped, 21,
            "override above config should clamp to config max"
        );
        let zero =
            expiry_slot_with_skew(5, NonZeroU64::new(10).expect("slot length"), 0, Some(100));
        assert_eq!(zero, 5, "zero skew leaves expiry unchanged");
    }
    #[test]
    fn binding_is_stable_for_descriptor() {
        let descriptor = AxtDescriptor {
            dsids: vec![DataSpaceId::new(1), DataSpaceId::new(2)],
            touches: vec![AxtTouchSpec {
                dsid: DataSpaceId::new(1),
                read: vec!["orders".into()],
                write: vec!["ledger".into()],
            }],
        };
        let first = compute_binding(&descriptor).expect("binding");
        let second = compute_binding(&descriptor).expect("binding");
        assert_eq!(first, second);
    }
    #[test]
    fn descriptor_validation_rejects_noncanonical_order_and_paths() {
        let first = DataSpaceId::new(1);
        let second = DataSpaceId::new(2);
        let valid = AxtDescriptor {
            dsids: vec![first, second],
            touches: vec![
                AxtTouchSpec {
                    dsid: first,
                    read: vec!["orders".into()],
                    write: vec!["ledger".into()],
                },
                AxtTouchSpec {
                    dsid: second,
                    read: Vec::new(),
                    write: Vec::new(),
                },
            ],
        };
        assert!(matches!(validate_descriptor(&valid), Ok(())));
        let mut cases = Vec::new();
        let mut descriptor = valid.clone();
        descriptor.dsids.swap(0, 1);
        cases.push(descriptor);
        let mut descriptor = valid.clone();
        descriptor.touches.swap(0, 1);
        cases.push(descriptor);
        for paths in [
            vec!["".to_owned()],
            vec![" orders".to_owned()],
            vec!["orders".to_owned(), "orders".to_owned()],
            vec!["z".to_owned(), "a".to_owned()],
        ] {
            let mut descriptor = valid.clone();
            descriptor.touches[0].read = paths;
            cases.push(descriptor);
        }
        for descriptor in cases {
            assert!(
                matches!(
                    validate_descriptor(&descriptor),
                    Err(VMError::PermissionDenied)
                ),
                "noncanonical descriptor must fail: {descriptor:?}"
            );
        }
    }
    fn sample_touch_manifest() -> TouchManifest {
        TouchManifest {
            read: vec!["orders/item".into()],
            write: vec!["ledger/item".into()],
        }
    }
    #[test]
    fn touch_manifest_rejects_empty_whitespace_duplicate_and_unsorted_keys() {
        assert!(matches!(
            validate_touch_manifest(&sample_touch_manifest()),
            Ok(())
        ));
        assert!(
            matches!(
                validate_touch_manifest(&TouchManifest {
                    read: Vec::new(),
                    write: Vec::new(),
                }),
                Ok(())
            ),
            "an explicitly empty runtime manifest is valid"
        );
        for keys in [
            vec!["".to_owned()],
            vec![" key".to_owned()],
            vec!["key".to_owned(), "key".to_owned()],
            vec!["z".to_owned(), "a".to_owned()],
        ] {
            assert!(matches!(
                validate_touch_manifest(&TouchManifest {
                    read: keys,
                    write: Vec::new(),
                }),
                Err(VMError::NoritoInvalid)
            ));
        }
    }
    fn sample_handle(
        dsid: DataSpaceId,
        binding: [u8; 32],
        remaining: u128,
        per_use: Option<u128>,
    ) -> ModelAssetHandle {
        ModelAssetHandle {
            asset_definition_id: test_asset_definition_id(),
            scope: vec!["transfer".into()],
            subject: ModelHandleSubject {
                account: ACCOUNT_FROM_LITERAL.into(),
                origin_dsid: Some(dsid),
            },
            budget: ModelHandleBudget {
                remaining: quantity(remaining),
                per_use: per_use.map(quantity),
            },
            handle_era: 1,
            sub_nonce: 7,
            group_binding: ModelGroupBinding {
                composability_group_id: vec![0; 32],
                epoch_id: 10,
            },
            target_lane: LaneId::new(0),
            axt_binding: AxtBinding::new(binding),
            manifest_view_root: [1; 32],
            expiry_slot: 99,
            max_clock_skew_ms: Some(0),
            issuer_context: AxtHandleIssuerContextV1 {
                asset_dsid: dsid,
                ..AxtHandleIssuerContextV1::default()
            },
            issuer_signature: Signature::from_bytes(&[1_u8; 64]),
        }
    }
    #[test]
    fn standalone_handle_validation_rejects_every_context_free_fault() {
        let dsid = DataSpaceId::new(7);
        let valid = sample_handle(dsid, [0x11; 32], 10, Some(5));
        assert!(matches!(validate_model_asset_handle(&valid), Ok(())));
        let mut malformed = valid.clone();
        malformed.group_binding.composability_group_id.clear();
        assert!(matches!(
            validate_model_asset_handle(&malformed),
            Err(VMError::NoritoInvalid)
        ));
        let mut unusable = valid.clone();
        unusable.scope.clear();
        assert!(matches!(
            validate_model_asset_handle(&unusable),
            Err(VMError::PermissionDenied)
        ));
        let mut unusable = valid.clone();
        unusable.budget.remaining = Quantity::zero();
        assert!(matches!(
            validate_model_asset_handle(&unusable),
            Err(VMError::PermissionDenied)
        ));
        let mut unusable = valid.clone();
        unusable.budget.per_use = Some(Quantity::zero());
        assert!(matches!(
            validate_model_asset_handle(&unusable),
            Err(VMError::PermissionDenied)
        ));
        for field in ["handle era", "sub nonce", "group epoch", "expiry slot"] {
            let mut unusable = valid.clone();
            match field {
                "handle era" => unusable.handle_era = 0,
                "sub nonce" => unusable.sub_nonce = 0,
                "group epoch" => unusable.group_binding.epoch_id = 0,
                "expiry slot" => unusable.expiry_slot = 0,
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    validate_model_asset_handle(&unusable),
                    Err(VMError::PermissionDenied)
                ),
                "zero {field} must fail validation"
            );
        }
        let malformed_mutations: [fn(&mut ModelAssetHandle); 4] = [
            |handle: &mut ModelAssetHandle| handle.scope[0].push(' '),
            |handle: &mut ModelAssetHandle| handle.scope.push("transfer".to_owned()),
            |handle: &mut ModelAssetHandle| {
                handle.scope = vec!["withdraw".to_owned(), "transfer".to_owned()];
            },
            |handle: &mut ModelAssetHandle| handle.subject.account.push(' '),
        ];
        for mutate in malformed_mutations {
            let mut malformed = valid.clone();
            mutate(&mut malformed);
            assert!(matches!(
                validate_model_asset_handle(&malformed),
                Err(VMError::NoritoInvalid)
            ));
        }
        let mut unusable = valid;
        unusable.subject.account.clear();
        assert!(matches!(
            validate_model_asset_handle(&unusable),
            Err(VMError::PermissionDenied)
        ));
    }
    #[test]
    fn asset_handle_subject_requires_canonical_account_id() {
        let dsid = DataSpaceId::new(7);
        let valid = sample_handle(dsid, [0x11; 32], 10, Some(5));
        assert!(matches!(validate_model_asset_handle(&valid), Ok(())));

        let mut malformed = ACCOUNT_FROM_LITERAL.to_owned();
        malformed.pop();
        let invalid_accounts = [
            ("alias", "spender@payments".to_owned()),
            ("malformed", malformed),
            (
                "noncanonical",
                ACCOUNT_FROM_LITERAL.replacen("sora", "ｓｏｒａ", 1),
            ),
            ("whitespace", format!(" {ACCOUNT_FROM_LITERAL}")),
        ];
        for (case, account) in invalid_accounts {
            let mut invalid = valid.clone();
            invalid.subject.account = account;
            assert!(
                matches!(
                    validate_model_asset_handle(&invalid),
                    Err(VMError::NoritoInvalid)
                ),
                "{case} subject account must fail"
            );
        }
    }
    #[test]
    fn standalone_proof_blob_validation_rejects_empty_and_zero_expiry() {
        let valid = ProofBlob {
            payload: vec![1],
            expiry_slot: Some(1),
        };
        assert!(matches!(validate_proof_blob(&valid), Ok(())));
        assert!(matches!(
            validate_proof_blob(&ProofBlob {
                payload: Vec::new(),
                expiry_slot: None,
            }),
            Err(VMError::NoritoInvalid)
        ));
        assert!(matches!(
            validate_proof_blob(&ProofBlob {
                payload: vec![1],
                expiry_slot: Some(0),
            }),
            Err(VMError::NoritoInvalid)
        ));
        assert!(matches!(
            validate_proof_blob(&ProofBlob {
                payload: vec![0; MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES + 1],
                expiry_slot: None,
            }),
            Err(VMError::NoritoInvalid)
        ));
    }
    #[test]
    fn proof_blob_requires_explicit_nullable_expiry_slot() {
        #[derive(Encode, norito::NoritoSchema)]
        #[norito_schema(
            name = "ivm_abi::axt::tests::proof_blob_requires_explicit_nullable_expiry_slot::ProofBlobWithoutExpiry"
        )]
        struct ProofBlobWithoutExpiry {
            payload: Vec<u8>,
        }
        crate::captured_identity_tests::assert_serialize::<ProofBlobWithoutExpiry>(
            "ivm_abi::axt::tests::proof_blob_requires_explicit_nullable_expiry_slot::ProofBlobWithoutExpiry",
        );

        let omitted = encode_canonical_norito(&ProofBlobWithoutExpiry { payload: vec![1] })
            .expect("encode pre-release proof blob without expiry slot");
        assert!(
            matches!(
                decode_canonical_norito::<ProofBlob>(&omitted),
                Err(VMError::NoritoInvalid)
            ),
            "V1 must reject a proof blob that omits its nullable expiry slot"
        );

        let explicit_none = ProofBlob {
            payload: vec![1],
            expiry_slot: None,
        };
        let encoded =
            encode_canonical_norito(&explicit_none).expect("encode explicit no-expiry proof blob");
        assert_eq!(
            (decode_canonical_norito::<ProofBlob>(&encoded))
                .expect("expected successful fixture result"),
            explicit_none,
            "an explicit None remains the authenticated no-expiry value"
        );
    }
    fn sample_intent(dsid: DataSpaceId, amount: Option<u128>) -> ModelRemoteSpendIntent {
        ModelRemoteSpendIntent {
            asset_dsid: dsid,
            op: ModelSpendOp {
                asset_definition_id: test_asset_definition_id(),
                kind: "transfer".into(),
                from: ACCOUNT_FROM_LITERAL.into(),
                to: ACCOUNT_TO_LITERAL.into(),
                amount: amount.map(|value| {
                    value
                        .to_string()
                        .parse::<Quantity>()
                        .expect("test amount is a canonical quantity")
                }),
            },
        }
    }
    #[test]
    fn remote_spend_intent_rejects_empty_whitespace_and_zero_values() {
        let dsid = DataSpaceId::new(7);
        let valid = sample_intent(dsid, Some(1));
        assert!(matches!(validate_model_remote_spend_intent(&valid), Ok(())));
        for field in ["kind", "from", "to"] {
            let mut invalid = valid.clone();
            match field {
                "kind" => invalid.op.kind.clear(),
                "from" => invalid.op.from.push(' '),
                "to" => invalid.op.to.clear(),
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    validate_model_remote_spend_intent(&invalid),
                    Err(VMError::NoritoInvalid)
                ),
                "invalid {field} must fail"
            );
        }
        assert!(matches!(
            validate_model_remote_spend_intent(&sample_intent(dsid, Some(0))),
            Err(VMError::PermissionDenied)
        ));
        assert!(
            matches!(
                validate_model_remote_spend_intent(&sample_intent(dsid, None)),
                Err(VMError::PermissionDenied)
            ),
            "a redacted intent cannot be authorized by a public proof scalar"
        );
        for kind in ["mint", "Transfer", " transfer", "transfer "] {
            let mut invalid = valid.clone();
            invalid.op.kind = kind.to_owned();
            assert!(
                matches!(
                    validate_model_remote_spend_intent(&invalid),
                    Err(VMError::NoritoInvalid)
                ),
                "non-transfer operation {kind:?} must fail closed"
            );
        }
    }

    #[test]
    fn remote_spend_asset_scope_requires_exact_authoritative_dataspace() {
        let dsid = DataSpaceId::new(7);
        assert!(matches!(
            validate_remote_spend_asset_scope(dsid, AssetBalanceScope::Dataspace(dsid)),
            Ok(())
        ));
        assert!(matches!(
            validate_remote_spend_asset_scope(DataSpaceId::UNIVERSAL, AssetBalanceScope::Global,),
            Ok(())
        ));
        assert!(matches!(
            validate_remote_spend_asset_scope(
                dsid,
                AssetBalanceScope::Dataspace(DataSpaceId::new(8)),
            ),
            Err(VMError::PermissionDenied)
        ));
        assert!(matches!(
            validate_remote_spend_asset_scope(dsid, AssetBalanceScope::Global),
            Err(VMError::PermissionDenied)
        ));
    }
    #[test]
    fn remote_spend_intent_from_and_to_require_canonical_account_ids() {
        let dsid = DataSpaceId::new(7);
        let valid = sample_intent(dsid, Some(1));
        assert!(matches!(validate_model_remote_spend_intent(&valid), Ok(())));

        let mut malformed = ACCOUNT_FROM_LITERAL.to_owned();
        malformed.pop();
        let invalid_accounts = [
            ("alias", "spender@payments".to_owned()),
            ("malformed", malformed),
            (
                "noncanonical",
                ACCOUNT_FROM_LITERAL.replacen("sora", "ｓｏｒａ", 1),
            ),
            ("whitespace", format!("{ACCOUNT_FROM_LITERAL} ")),
        ];
        for field in ["from", "to"] {
            for (case, account) in &invalid_accounts {
                let mut invalid = valid.clone();
                match field {
                    "from" => invalid.op.from.clone_from(account),
                    "to" => invalid.op.to.clone_from(account),
                    _ => unreachable!(),
                }
                assert!(
                    matches!(
                        validate_model_remote_spend_intent(&invalid),
                        Err(VMError::NoritoInvalid)
                    ),
                    "{case} {field} account must fail"
                );
            }
        }
    }
    fn sample_fastpq_binding(dsid: DataSpaceId) -> iroha_data_model::nexus::AxtFastpqBinding {
        iroha_data_model::nexus::AxtFastpqBinding {
            parameter: "fastpq-state-transition-stark-v1".to_string(),
            source_dsid: dsid.as_u64(),
            source_dataspace: "ivm-abi-test".to_string(),
            source_receipt_id: format!("receipt-{}", dsid.as_u64()),
            source_tx_commitment: "aa".repeat(32),
            claim_type: "authorization".to_string(),
            claim_digest: "bb".repeat(32),
            witness_commitment: "cc".repeat(32),
            policy_commitment: "dd".repeat(32),
            verified_effect_type: "test_effect".to_string(),
            corridor: "ivm-abi-test".to_string(),
            verifier_id: "fastpq".to_string(),
            verifier_version: "v1".to_string(),
            target_dsids: vec![dsid.as_u64()],
            effect_binding: None,
            remote_spend_intent_commitments: Vec::new(),
        }
    }
    fn proof_with_amount(
        dsid: DataSpaceId,
        committed_amount: Option<u128>,
        amount_commitment: Option<[u8; 32]>,
    ) -> ProofBlob {
        let payload = norito::to_bytes(&AxtProofEnvelope {
            dsid,
            manifest_root: [0xAB; 32],
            da_commitment: None,
            proof: vec![0x01, 0x02],
            fastpq_binding: Some(sample_fastpq_binding(dsid)),
            committed_amount,
            amount_commitment,
        })
        .expect("encode proof envelope");
        ProofBlob {
            payload,
            expiry_slot: Some(10),
        }
    }
    fn proof_with_derived_amount_commitment(
        dsid: DataSpaceId,
        committed_amount: u128,
    ) -> ProofBlob {
        let mut proof = proof_with_amount(dsid, Some(committed_amount), None);
        let amount = quantity(committed_amount);
        let commitment = derive_amount_commitment(dsid, &amount, Some(&proof.payload));
        let mut envelope = norito::decode_from_bytes::<AxtProofEnvelope>(&proof.payload)
            .expect("decode test proof envelope");
        envelope.amount_commitment = Some(commitment);
        proof.payload = norito::to_bytes(&envelope).expect("encode committed test proof envelope");
        proof
    }
    fn proof_for_remote_spends(
        intents: &[(&ModelAssetHandle, &ModelRemoteSpendIntent, Quantity)],
    ) -> ProofBlob {
        let dsid = intents
            .first()
            .expect("remote-spend proof fixture is non-empty")
            .1
            .asset_dsid;
        let mut binding = sample_fastpq_binding(dsid);
        binding.remote_spend_intent_commitments = intents
            .iter()
            .map(|(handle, intent, amount)| {
                expected_model_remote_spend_intent_commitment_v1(handle, intent, amount)
            })
            .collect();
        binding.remote_spend_intent_commitments.sort_unstable();
        binding.remote_spend_intent_commitments.dedup();
        ProofBlob {
            payload: norito::to_bytes(&AxtProofEnvelope {
                dsid,
                manifest_root: [0xAB; 32],
                da_commitment: None,
                proof: vec![0x01, 0x02],
                fastpq_binding: Some(binding),
                committed_amount: None,
                amount_commitment: None,
            })
            .expect("encode remote-spend proof envelope"),
            expiry_slot: Some(10),
        }
    }
    fn resolve_test_amount(
        intent: &ModelRemoteSpendIntent,
        proof: Option<&ProofBlob>,
    ) -> Result<ResolvedHandleAmount, HandleAmountResolutionError> {
        resolve_handle_amount_components(
            intent.asset_dsid,
            intent.op.amount.as_ref(),
            proof.map(|blob| blob.payload.as_slice()),
        )
    }
    fn validate_model_claim_for_test(
        handle: &ModelAssetHandle,
        intent: &ModelRemoteSpendIntent,
        amount: &Quantity,
        proof: &ProofBlob,
    ) -> Result<(), VMError> {
        validate_model_remote_spend_intent_commitment(
            handle,
            intent,
            amount,
            &ModelProofBlob {
                payload: proof.payload.clone(),
                expiry_slot: proof.expiry_slot,
            },
        )
    }
    #[test]
    fn proof_payload_decode_helpers_reject_oversized_canonical_envelope() {
        let dsid = DataSpaceId::new(94);
        let descriptor_binding = [0x94; 32];
        let intent = sample_intent(dsid, Some(5));
        let amount = quantity(5);
        let handle = sample_handle(dsid, descriptor_binding, 10, Some(10));
        let proof = proof_for_remote_spends(&[(&handle, &intent, amount.clone())]);
        let mut envelope = decode_canonical_norito::<AxtProofEnvelope>(&proof.payload)
            .expect("decode canonical remote-spend proof");
        envelope.proof = vec![0xA5; MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES];
        envelope.committed_amount = Some(5);
        envelope.amount_commitment = Some([0x5A; 32]);
        let oversized_payload =
            encode_canonical_norito(&envelope).expect("encode oversized canonical proof envelope");
        assert!(oversized_payload.len() > MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES);
        let oversized = ProofBlob {
            payload: oversized_payload,
            expiry_slot: Some(10),
        };

        assert!(matches!(
            validate_proof_blob(&oversized),
            Err(VMError::NoritoInvalid)
        ));
        assert_eq!(
            resolve_test_amount(&intent, Some(&oversized)),
            Err(HandleAmountResolutionError::InvalidProofEnvelope)
        );
        assert!(matches!(
            validate_model_claim_for_test(&handle, &intent, &amount, &oversized),
            Err(VMError::NoritoInvalid)
        ));
        let expected_raw = derive_amount_commitment_from_normalized_payload(
            dsid,
            &amount,
            Some(&oversized.payload),
        );
        assert_eq!(
            derive_amount_commitment(dsid, &amount, Some(&oversized.payload)),
            expected_raw,
            "oversized envelopes must be treated as opaque commitment bytes without decoding"
        );
    }
    #[test]
    fn remote_spend_intent_commitment_rejects_substitution_and_supports_proof_reuse() {
        let dsid = DataSpaceId::new(93);
        let descriptor_binding = [0x93; 32];
        let clear = sample_intent(dsid, Some(5));
        let mut second = sample_intent(dsid, Some(7));
        second.op.to = ACCOUNT_FROM_LITERAL.to_owned();
        let clear_amount = quantity(5);
        let second_amount = quantity(7);
        let clear_handle = sample_handle(dsid, descriptor_binding, 10, Some(10));
        let mut second_handle = clear_handle.clone();
        second_handle.sub_nonce += 1;
        let proof = proof_for_remote_spends(&[
            (&clear_handle, &clear, clear_amount.clone()),
            (&second_handle, &second, second_amount.clone()),
        ]);
        assert!(matches!(
            validate_model_claim_for_test(&clear_handle, &clear, &clear_amount, &proof,),
            Ok(())
        ));
        assert!(matches!(
            validate_model_claim_for_test(&second_handle, &second, &second_amount, &proof),
            Ok(())
        ));
        let mut redacted = second.clone();
        redacted.op.amount = None;
        assert!(
            matches!(
                validate_model_claim_for_test(&second_handle, &redacted, &second_amount, &proof,),
                Err(VMError::PermissionDenied)
            ),
            "semantic membership cannot admit a public-scalar hidden route"
        );
        let envelope = decode_canonical_norito::<AxtProofEnvelope>(&proof.payload)
            .expect("decode reusable proof once");
        let facts = AxtProofUseFacts::from_verified_envelope(envelope);
        let model_handle = clear_handle.clone();
        let model_clear = clear.clone();
        let mut model_redacted = clear.clone();
        model_redacted.op.amount = None;
        let model_proof = ModelProofBlob {
            payload: proof.payload.clone(),
            expiry_slot: proof.expiry_slot,
        };
        assert!(
            matches!(
                validate_model_remote_spend_intent_commitment(
                    &clear_handle,
                    &model_redacted,
                    &clear_amount,
                    &model_proof,
                ),
                Err(VMError::PermissionDenied)
            ),
            "a redacted intent cannot use a public proof scalar"
        );
        assert!(matches!(
            validate_model_remote_spend_intent_commitment_from_proof_facts(
                &model_handle,
                &model_clear,
                &clear_amount,
                &facts,
            ),
            Ok(())
        ));
        let mut reincarnated_model_handle = model_handle.clone();
        reincarnated_model_handle
            .issuer_context
            .asset_definition_incarnation = AxtAssetIncarnationV1::derive(
            &reincarnated_model_handle.issuer_context.network_id,
            &reincarnated_model_handle.asset_definition_id,
            &iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                Hash::new(b"ivm-abi-reincarnated-remote-spend-registration"),
            ),
            &Hash::new(b"ivm-abi-reincarnated-remote-spend-execution"),
            1,
        );
        assert!(
            matches!(
                validate_model_remote_spend_intent_commitment_from_proof_facts(
                    &reincarnated_model_handle,
                    &model_clear,
                    &clear_amount,
                    &facts,
                ),
                Err(VMError::PermissionDenied)
            ),
            "a claim for a retired asset incarnation must not authorize the current handle"
        );
        let mut substituted_model = model_clear.clone();
        substituted_model.op.to = ACCOUNT_FROM_LITERAL.to_owned();
        assert!(matches!(
            validate_model_remote_spend_intent_commitment_from_proof_facts(
                &model_handle,
                &substituted_model,
                &clear_amount,
                &facts,
            ),
            Err(VMError::PermissionDenied)
        ));
        for field in ["kind", "from", "to"] {
            let mut substituted = clear.clone();
            match field {
                "kind" => substituted.op.kind = "mint".to_owned(),
                "from" => substituted.op.from = ACCOUNT_TO_LITERAL.to_owned(),
                "to" => substituted.op.to = ACCOUNT_FROM_LITERAL.to_owned(),
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    validate_model_claim_for_test(
                        &clear_handle,
                        &substituted,
                        &clear_amount,
                        &proof,
                    ),
                    Err(VMError::PermissionDenied)
                ),
                "substituted {field} must not reuse the proof"
            );
        }
        let mut substituted_dsid = clear.clone();
        substituted_dsid.asset_dsid = DataSpaceId::new(94);
        assert!(
            matches!(
                validate_model_claim_for_test(
                    &clear_handle,
                    &substituted_dsid,
                    &clear_amount,
                    &proof,
                ),
                Err(VMError::PermissionDenied)
            ),
            "substituted asset dataspace must not reuse the proof"
        );
        assert!(matches!(
            validate_model_claim_for_test(&clear_handle, &clear, &quantity(6), &proof,),
            Err(VMError::PermissionDenied)
        ));
        let mut substituted_asset = clear.clone();
        substituted_asset.op.asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("axt", "universal").expect("test asset domain"),
            "iris".parse().expect("test asset name"),
        );
        assert!(
            matches!(
                validate_model_claim_for_test(
                    &clear_handle,
                    &substituted_asset,
                    &clear_amount,
                    &proof,
                ),
                Err(VMError::PermissionDenied)
            ),
            "substituted asset definition must not reuse the proof"
        );
        let mut substituted_handle = clear_handle.clone();
        substituted_handle.axt_binding = AxtBinding::new([0x94; 32]);
        assert!(matches!(
            validate_model_claim_for_test(&substituted_handle, &clear, &clear_amount, &proof,),
            Err(VMError::PermissionDenied)
        ));
        let mut reincarnated_handle = clear_handle.clone();
        reincarnated_handle
            .issuer_context
            .asset_definition_incarnation = AxtAssetIncarnationV1::derive(
            &reincarnated_handle.issuer_context.network_id,
            &reincarnated_handle.asset_definition_id,
            &iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                Hash::new(b"ivm-abi-reincarnated-remote-spend-registration"),
            ),
            &Hash::new(b"ivm-abi-reincarnated-remote-spend-execution"),
            1,
        );
        assert!(
            matches!(
                validate_model_claim_for_test(&reincarnated_handle, &clear, &clear_amount, &proof,),
                Err(VMError::PermissionDenied)
            ),
            "a proof for the retired incarnation must not authorize a current-incarnation handle"
        );
        let mut second_handle = clear_handle.clone();
        second_handle.sub_nonce += 1;
        assert!(
            matches!(
                validate_model_claim_for_test(&second_handle, &clear, &clear_amount, &proof,),
                Err(VMError::PermissionDenied)
            ),
            "a proof for one handle must not authorize a new handle identity"
        );

        let clear_commitment =
            expected_model_remote_spend_intent_commitment_v1(&clear_handle, &clear, &clear_amount);
        let second_commitment = expected_model_remote_spend_intent_commitment_v1(
            &second_handle,
            &second,
            &second_amount,
        );
        assert!(matches!(
            facts.validate_remote_spend_consumption(&[second_commitment, clear_commitment]),
            Ok(())
        ));
        assert!(
            matches!(
                facts.validate_remote_spend_consumption(&[clear_commitment, clear_commitment]),
                Err(VMError::PermissionDenied)
            ),
            "one proof claim cannot be consumed twice"
        );
        assert!(
            matches!(
                facts.validate_remote_spend_consumption(&[clear_commitment]),
                Err(VMError::PermissionDenied)
            ),
            "an unconsumed proof claim must fail closed"
        );

        // An empty intent set remains valid metadata for generic VERIFY_DS
        // proof flows, but it does not authorize a remote spend.
        let empty_proof = proof_with_amount(dsid, None, None);
        let mut empty_envelope =
            norito::decode_from_bytes::<AxtProofEnvelope>(&empty_proof.payload)
                .expect("decode empty remote-spend binding proof");
        preflight_fastpq_v1_proof_envelope_for_manifest(
            &empty_envelope,
            dsid,
            empty_envelope.manifest_root,
        )
        .expect("generic FastPQ proof accepts an empty remote-spend binding");
        assert!(matches!(
            validate_model_claim_for_test(&clear_handle, &clear, &clear_amount, &empty_proof,),
            Err(VMError::PermissionDenied)
        ));

        empty_envelope.fastpq_binding = None;
        let unbound_proof = ProofBlob {
            payload: norito::to_bytes(&empty_envelope).expect("encode unbound proof envelope"),
            expiry_slot: empty_proof.expiry_slot,
        };
        assert!(matches!(
            validate_model_claim_for_test(&clear_handle, &clear, &clear_amount, &unbound_proof,),
            Err(VMError::PermissionDenied)
        ));
    }
    #[test]
    fn preflight_fastpq_v1_proof_envelope_rejects_mislabeled_binding() {
        let dsid = DataSpaceId::new(90);
        let manifest_root = [0xAB; 32];
        let mut envelope = AxtProofEnvelope {
            dsid,
            manifest_root,
            da_commitment: None,
            proof: vec![0x01, 0x02],
            fastpq_binding: Some(sample_fastpq_binding(dsid)),
            committed_amount: None,
            amount_commitment: None,
        };
        preflight_fastpq_v1_proof_envelope_for_manifest(&envelope, dsid, manifest_root)
            .expect("valid FastPQ V1 envelope preflight");
        envelope
            .fastpq_binding
            .as_mut()
            .expect("binding")
            .verifier_id = "synthetic".to_string();
        assert!(matches!(
            preflight_fastpq_v1_proof_envelope_for_manifest(&envelope, dsid, manifest_root),
            Err(VMError::PermissionDenied)
        ));
        envelope
            .fastpq_binding
            .as_mut()
            .expect("binding")
            .verifier_id = "fastpq".to_string();
        envelope
            .fastpq_binding
            .as_mut()
            .expect("binding")
            .verifier_version = "v2".to_string();
        assert!(matches!(
            preflight_fastpq_v1_proof_envelope_for_manifest(&envelope, dsid, manifest_root),
            Err(VMError::PermissionDenied)
        ));
    }
    #[test]
    fn preflight_fastpq_v1_proof_envelope_rejects_synthetic_binding() {
        let dsid = DataSpaceId::new(91);
        let manifest_root = [0xAC; 32];
        let mut envelope = AxtProofEnvelope {
            dsid,
            manifest_root,
            da_commitment: None,
            proof: vec![0x01, 0x02],
            fastpq_binding: Some(sample_fastpq_binding(dsid)),
            committed_amount: None,
            amount_commitment: None,
        };
        envelope
            .fastpq_binding
            .as_mut()
            .expect("binding")
            .claim_digest = String::new();
        assert!(matches!(
            preflight_fastpq_v1_proof_envelope_for_manifest(&envelope, dsid, manifest_root),
            Err(VMError::PermissionDenied)
        ));
        envelope.fastpq_binding = Some(sample_fastpq_binding(dsid));
        envelope
            .fastpq_binding
            .as_mut()
            .expect("binding")
            .claim_type = "synthetic".to_string();
        assert!(matches!(
            preflight_fastpq_v1_proof_envelope_for_manifest(&envelope, dsid, manifest_root),
            Err(VMError::PermissionDenied)
        ));
        envelope.fastpq_binding = Some(sample_fastpq_binding(dsid));
        envelope
            .fastpq_binding
            .as_mut()
            .expect("binding")
            .target_dsids
            .clear();
        assert!(matches!(
            preflight_fastpq_v1_proof_envelope_for_manifest(&envelope, dsid, manifest_root),
            Err(VMError::PermissionDenied)
        ));
    }
    #[test]
    fn preflight_fastpq_v1_proof_envelope_rejects_noncanonical_binding_fields() {
        let dsid = DataSpaceId::new(92);
        let manifest_root = [0xAD; 32];
        let mut uppercase_digest = sample_fastpq_binding(dsid);
        uppercase_digest.claim_digest.make_ascii_uppercase();
        let mut unordered_targets = sample_fastpq_binding(dsid);
        unordered_targets.target_dsids = vec![dsid.as_u64() + 1, dsid.as_u64()];
        let mut untrimmed_corridor = sample_fastpq_binding(dsid);
        untrimmed_corridor.corridor.push(' ');
        for binding in [uppercase_digest, unordered_targets, untrimmed_corridor] {
            let envelope = AxtProofEnvelope {
                dsid,
                manifest_root,
                da_commitment: None,
                proof: vec![0x01, 0x02],
                fastpq_binding: Some(binding),
                committed_amount: None,
                amount_commitment: None,
            };
            assert!(matches!(
                preflight_fastpq_v1_proof_envelope_for_manifest(&envelope, dsid, manifest_root),
                Err(VMError::PermissionDenied)
            ));
        }
    }
    #[test]
    fn resolve_handle_amount_accepts_cleartext_intent() {
        let dsid = DataSpaceId::new(90);
        let intent = sample_intent(dsid, Some(42));
        let resolved = resolve_test_amount(&intent, None).expect("resolve amount");
        assert_eq!(resolved.amount, quantity(42));
        assert_eq!(resolved.amount_commitment, None);
    }
    #[test]
    fn amount_commitment_is_independent_of_ambient_norito_layout() {
        let dsid = DataSpaceId::new(90);
        let proof = proof_with_amount(dsid, Some(42), None);
        let amount = quantity(42);
        let expected = derive_amount_commitment(dsid, &amount, Some(&proof.payload));
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let ambient_before = norito::to_bytes(&AxtProofEnvelope {
            dsid,
            manifest_root: [0xAB; 32],
            da_commitment: None,
            proof: vec![0x01, 0x02],
            fastpq_binding: Some(sample_fastpq_binding(dsid)),
            committed_amount: Some(42),
            amount_commitment: None,
        })
        .expect("encode ambient proof");
        assert_eq!(
            derive_amount_commitment(dsid, &amount, Some(&proof.payload)),
            expected
        );
        assert_eq!(
            norito::to_bytes(
                &decode_canonical_norito::<AxtProofEnvelope>(&proof.payload)
                    .expect("decode canonical proof")
            )
            .expect("re-encode under ambient flags"),
            ambient_before,
            "canonical commitment derivation must restore the caller's ambient flags"
        );
    }
    #[test]
    fn resolve_handle_amount_rejects_malformed_and_alternate_proof_envelopes() {
        let dsid = DataSpaceId::new(90);
        let intent = sample_intent(dsid, Some(42));
        let malformed = ProofBlob {
            payload: vec![1, 2, 3],
            expiry_slot: None,
        };
        assert_eq!(
            resolve_test_amount(&intent, Some(&malformed)),
            Err(HandleAmountResolutionError::InvalidProofEnvelope)
        );
        let canonical = proof_with_amount(dsid, Some(42), None);
        let envelope = decode_canonical_norito::<AxtProofEnvelope>(&canonical.payload)
            .expect("decode canonical proof");
        let alternate = {
            let flags =
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
            let _alternate = norito::core::DecodeFlagsGuard::enter(flags);
            norito::to_bytes(&envelope).expect("encode alternate proof")
        };
        assert_ne!(alternate, canonical.payload);
        assert_eq!(
            resolve_test_amount(
                &intent,
                Some(&ProofBlob {
                    payload: alternate,
                    expiry_slot: canonical.expiry_slot,
                })
            ),
            Err(HandleAmountResolutionError::InvalidProofEnvelope)
        );
    }
    #[test]
    fn resolve_handle_amount_rejects_public_scalar_for_redacted_intent() {
        let dsid = DataSpaceId::new(91);
        let intent = sample_intent(dsid, None);
        let proof = proof_with_amount(dsid, Some(77), None);
        assert_eq!(
            resolve_test_amount(&intent, Some(&proof)),
            Err(HandleAmountResolutionError::MissingAmount)
        );
        assert_eq!(
            resolve_test_amount(&intent, None),
            Err(HandleAmountResolutionError::MissingAmount)
        );
        assert_eq!(
            resolve_handle_amount_components(dsid, None, Some(&proof.payload)),
            Err(HandleAmountResolutionError::MissingAmount)
        );
    }
    #[test]
    fn resolve_handle_amount_authenticates_supplied_commitment_without_circular_hashing() {
        let dsid = DataSpaceId::new(97);
        let intent = sample_intent(dsid, Some(77));
        let proof = proof_with_derived_amount_commitment(dsid, 77);
        let resolved = resolve_test_amount(&intent, Some(&proof))
            .expect("canonical supplied commitment must resolve");
        let expected = derive_amount_commitment(dsid, &quantity(77), Some(&proof.payload));
        assert_eq!(resolved.amount_commitment, Some(expected));
        let mut envelope = norito::decode_from_bytes::<AxtProofEnvelope>(&proof.payload)
            .expect("decode committed proof envelope");
        assert_eq!(envelope.amount_commitment, Some(expected));
        envelope.proof.push(0xFF);
        let mutated = ProofBlob {
            payload: norito::to_bytes(&envelope).expect("encode mutated proof envelope"),
            expiry_slot: proof.expiry_slot,
        };
        assert_eq!(
            resolve_test_amount(&intent, Some(&mutated)),
            Err(HandleAmountResolutionError::CommitmentMismatch)
        );
    }
    #[test]
    fn resolve_handle_amount_rejects_attacker_supplied_commitment() {
        let dsid = DataSpaceId::new(98);
        let intent = sample_intent(dsid, Some(9));
        let proof = proof_with_amount(dsid, Some(9), Some([0xA5; 32]));
        assert_eq!(
            resolve_test_amount(&intent, Some(&proof)),
            Err(HandleAmountResolutionError::CommitmentMismatch)
        );
    }
    #[test]
    fn component_amount_resolver_matches_host_amount_resolver() {
        let dsid = DataSpaceId::new(96);
        let intent = sample_intent(dsid, Some(31));
        let proof = proof_with_amount(dsid, Some(31), None);
        let host = resolve_test_amount(&intent, Some(&proof)).expect("host resolution");
        let components = resolve_handle_amount_components(
            dsid,
            intent.op.amount.as_ref(),
            Some(proof.payload.as_slice()),
        )
        .expect("component resolution");
        assert_eq!(components, host);
    }
    #[test]
    fn cached_proof_facts_match_payload_amount_resolution() {
        let dsid = DataSpaceId::new(96);
        let intent = sample_intent(dsid, Some(31));
        let proof = proof_with_derived_amount_commitment(dsid, 31);
        let expected = resolve_test_amount(&intent, Some(&proof)).expect("payload resolution");
        let envelope = decode_canonical_norito::<AxtProofEnvelope>(&proof.payload)
            .expect("decode canonical proof once");
        let facts = AxtProofUseFacts::from_verified_envelope(envelope);
        assert_eq!(
            (resolve_handle_amount_components_from_proof_facts(
                dsid,
                intent.op.amount.as_ref(),
                &facts,
            ))
            .expect("expected successful fixture result"),
            expected
        );
        assert_eq!(
            resolve_handle_amount_components_from_proof_facts(
                DataSpaceId::new(97),
                intent.op.amount.as_ref(),
                &facts,
            ),
            Err(HandleAmountResolutionError::InvalidProofEnvelope)
        );
        assert_eq!(
            resolve_handle_amount_components_from_proof_facts(dsid, None, &facts),
            Err(HandleAmountResolutionError::MissingAmount),
            "cached verified proof facts cannot authorize a redacted intent"
        );
        assert_eq!(
            resolve_handle_amount_components_from_proof_facts(dsid, Some(&quantity(32)), &facts,),
            Err(HandleAmountResolutionError::Mismatch)
        );
    }
    #[test]
    fn cached_proof_facts_preserve_cleartext_supplied_commitment() {
        let dsid = DataSpaceId::new(97);
        let amount = quantity(23);
        let intent = sample_intent(dsid, Some(23));
        let mut proof = proof_with_amount(dsid, None, None);
        let commitment = derive_amount_commitment(dsid, &amount, Some(&proof.payload));
        let mut envelope = decode_canonical_norito::<AxtProofEnvelope>(&proof.payload)
            .expect("decode proof for commitment");
        envelope.amount_commitment = Some(commitment);
        proof.payload = encode_canonical_norito(&envelope).expect("encode committed proof");

        let expected = resolve_test_amount(&intent, Some(&proof)).expect("payload resolution");
        let envelope = decode_canonical_norito::<AxtProofEnvelope>(&proof.payload)
            .expect("decode canonical proof once");
        let facts = AxtProofUseFacts::from_verified_envelope(envelope);
        assert_eq!(
            (resolve_handle_amount_components_from_proof_facts(
                dsid,
                intent.op.amount.as_ref(),
                &facts,
            ))
            .expect("expected successful fixture result"),
            expected
        );
        assert_eq!(
            resolve_handle_amount_components_from_proof_facts(dsid, Some(&quantity(24)), &facts,),
            Err(HandleAmountResolutionError::CommitmentMismatch)
        );
    }
    #[test]
    fn resolve_handle_amount_rejects_intent_proof_mismatch() {
        let dsid = DataSpaceId::new(92);
        let intent = sample_intent(dsid, Some(11));
        let proof = proof_with_amount(dsid, Some(12), None);
        assert_eq!(
            resolve_test_amount(&intent, Some(&proof)),
            Err(HandleAmountResolutionError::Mismatch)
        );
    }
    #[test]
    fn resolve_handle_amount_rejects_fractional_proof_scalar() {
        let dsid = DataSpaceId::new(93);
        let mut intent = sample_intent(dsid, None);
        intent.op.amount = Some("1.5".parse().expect("canonical fractional quantity"));
        let proof = proof_with_amount(dsid, Some(1), None);
        assert_eq!(
            resolve_test_amount(&intent, Some(&proof)),
            Err(HandleAmountResolutionError::InvalidProofScalar)
        );
    }
    #[test]
    fn resolve_handle_amount_rejects_proof_scalar_wider_than_u128() {
        let dsid = DataSpaceId::new(94);
        let mut intent = sample_intent(dsid, None);
        intent.op.amount = Some(
            "340282366920938463463374607431768211456"
                .parse()
                .expect("u128 maximum plus one fits the Quantity domain"),
        );
        let proof = proof_with_amount(dsid, Some(u128::MAX), None);
        assert_eq!(
            resolve_test_amount(&intent, Some(&proof)),
            Err(HandleAmountResolutionError::InvalidProofScalar)
        );
    }
    #[test]
    fn resolve_handle_amount_rejects_zero_committed_scalar() {
        let dsid = DataSpaceId::new(95);
        let intent = sample_intent(dsid, Some(0));
        let proof = proof_with_amount(dsid, Some(0), None);
        assert_eq!(
            resolve_test_amount(&intent, Some(&proof)),
            Err(HandleAmountResolutionError::ZeroAmount)
        );
    }
    #[test]
    fn snapshot_policy_rejects_noncanonical_snapshot_without_panicking() {
        let dsid = DataSpaceId::new(8);
        let entry = ModelAxtPolicyEntry {
            manifest_root: [0xAB; 32],
            target_lane: LaneId::new(0),
            active_handle_era: 1,
            next_handle_counter: 1,
            current_slot: 10,
        };
        let snapshot = ModelAxtPolicySnapshot {
            version: 1,
            entries: vec![iroha_data_model::nexus::AxtPolicyBinding {
                dsid,
                policy: entry,
            }],
        };
        assert!(matches!(
            SnapshotAxtPolicy::new(&snapshot),
            Err(ModelAxtPolicySnapshotValidationError::VersionMismatch { .. })
        ));
    }
    #[test]
    fn public_axt_commit_requires_one_proof_per_declared_dataspace() {
        let dsid = DataSpaceId::new(93);
        let descriptor = AxtDescriptor {
            dsids: vec![dsid],
            touches: Vec::new(),
        };
        let binding = compute_binding(&descriptor).expect("canonical binding");
        let mut state = HostAxtState::new(descriptor, binding);
        assert!(matches!(
            state.validate_commit(),
            Err(VMError::PermissionDenied)
        ));
        state
            .record_proof(dsid, Some(proof_with_amount(dsid, Some(5), None)), None)
            .expect("valid public proof record");
        assert!(matches!(state.validate_commit(), Ok(())));
    }
    #[test]
    fn signed_spends_stage_in_order_and_reject_inconsistent_binding() {
        let fixture: norito::json::Value = norito::json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../iroha_data_model/tests/fixtures/axt_envelope_multi_ds.json"
        )))
        .expect("current signed-spend fixture JSON");
        let happy = fixture["spends"]["happy"]
            .as_array()
            .expect("signed-spend fixture array");
        let spends: Vec<AxtAnchoredSpendV1> = happy
            .iter()
            .cloned()
            .map(|value| norito::json::from_value(value).expect("signed-spend fixture"))
            .collect();
        assert_eq!(spends.len(), 2);
        let descriptor = AxtDescriptor {
            dsids: spends
                .iter()
                .map(|spend| spend.draft.intent.asset_dsid)
                .collect(),
            touches: Vec::new(),
        };
        let binding = *spends[0].draft.handle.axt_binding.as_bytes();
        let mut state = HostAxtState::new(descriptor, binding);
        let mut wrong_binding = spends[0].clone();
        wrong_binding.draft.handle.axt_binding = AxtBinding::new([0xFF; 32]);
        assert!(matches!(
            state.record_spend(wrong_binding),
            Err(VMError::PermissionDenied)
        ));
        assert!(state.spends().is_empty());
        let mut wrong_amount = spends[0].clone();
        wrong_amount.draft.amount = Some(Quantity::from(99_u64));
        assert!(matches!(
            state.record_spend(wrong_amount),
            Err(VMError::PermissionDenied)
        ));
        assert!(state.spends().is_empty());
        let mut wrong_scope = spends[0].clone();
        wrong_scope.draft.handle.scope.clear();
        assert!(matches!(
            state.record_spend(wrong_scope),
            Err(VMError::PermissionDenied)
        ));
        assert!(state.spends().is_empty());
        let mut wrong_operation = spends[0].clone();
        wrong_operation.draft.intent.op.kind = "mint".to_owned();
        assert!(matches!(
            state.record_spend(wrong_operation),
            Err(VMError::PermissionDenied)
        ));
        assert!(state.spends().is_empty());
        for spend in &spends {
            state
                .record_spend(spend.clone())
                .expect("stage signed spend");
        }
        assert_eq!(state.spends(), spends);
        assert!(matches!(state.validate_commit(), Ok(())));
    }
    #[test]
    fn signed_spend_commit_rejects_reused_nonce_or_source_transfer_coordinate() {
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_data_model::nexus::AxtSpendNonceV1;

        let fixture: norito::json::Value = norito::json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../iroha_data_model/tests/fixtures/axt_envelope_multi_ds.json"
        )))
        .expect("current signed-spend fixture JSON");
        let first: AxtAnchoredSpendV1 =
            norito::json::from_value(fixture["spends"]["happy"][0].clone())
                .expect("canonical signed spend");
        let issuer = KeyPair::from_seed(vec![0xA5; 32], Algorithm::Ed25519);
        let anchor = first.authorization.anchor;
        let context = first.draft.handle.issuer_context;
        let binding = *first.draft.handle.axt_binding.as_bytes();
        let new_state = || {
            HostAxtState::new(
                AxtDescriptor {
                    dsids: vec![first.draft.intent.asset_dsid],
                    touches: Vec::new(),
                },
                binding,
            )
        };

        // A second valid issuer signature cannot reuse the same nonce even
        // when it names a different transfer coordinate.
        let mut another_coordinate = first.draft.clone();
        another_coordinate.source_occurrence.delta_index = 1;
        another_coordinate.source_occurrence.pair_ordinal = 1;
        let repeated_nonce = another_coordinate
            .sign_by_issuer_v1(
                anchor,
                first.authorization.expiry_slot,
                first.authorization.nonce,
                issuer.private_key(),
            )
            .expect("issuer signs a distinct claimed coordinate");
        assert!(matches!(
            repeated_nonce.verify_issuer_signatures_v1(context, anchor, issuer.public_key()),
            Ok(())
        ));
        let mut state = new_state();
        state
            .record_spend(first.clone())
            .expect("stage first spend");
        state
            .record_spend(repeated_nonce)
            .expect("stage second signed claim");
        assert!(matches!(
            state.validate_commit(),
            Err(VMError::PermissionDenied)
        ));
        assert_eq!(state.spends().len(), 2);

        // A fresh nonce cannot authorize the same source transfer again.
        let repeated_transfer = first
            .draft
            .clone()
            .sign_by_issuer_v1(
                anchor,
                first.authorization.expiry_slot,
                AxtSpendNonceV1::try_new([0xBC; 32]).expect("fresh nonce"),
                issuer.private_key(),
            )
            .expect("issuer signs the same claimed transfer with a fresh nonce");
        assert!(matches!(
            repeated_transfer.verify_issuer_signatures_v1(context, anchor, issuer.public_key()),
            Ok(())
        ));
        let mut state = new_state();
        state.record_spend(first).expect("stage first spend");
        state
            .record_spend(repeated_transfer)
            .expect("stage second signed claim");
        assert!(matches!(
            state.validate_commit(),
            Err(VMError::PermissionDenied)
        ));
        assert_eq!(state.spends().len(), 2);
    }
    #[test]
    fn handle_budget_key_groups_sub_nonces_but_separates_signed_assets() {
        let dsid = DataSpaceId::new(6);
        let binding = [0x5A; 32];
        let first = sample_handle(dsid, binding, 100, None);
        let mut next_nonce = first.clone();
        next_nonce.sub_nonce = next_nonce.sub_nonce.saturating_add(1);

        let first_key = ModelAxtHandleBudgetKey::from_handle(&first);
        let next_nonce_key = ModelAxtHandleBudgetKey::from_handle(&next_nonce);
        assert_eq!(
            first_key, next_nonce_key,
            "sub-nonces share the issuer-signed aggregate budget"
        );

        let mut other_asset = next_nonce;
        other_asset.asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("axt", "universal").expect("test asset domain"),
            "iris".parse().expect("test asset name"),
        );
        let other_asset_key = ModelAxtHandleBudgetKey::from_handle(&other_asset);
        assert_ne!(
            first_key, other_asset_key,
            "distinct issuer-signed assets must not share a budget"
        );
    }
    #[test]
    fn signed_model_handle_budget_key_binds_every_authorized_field() {
        let dsid = DataSpaceId::new(6);
        let mut abi_handle = sample_handle(dsid, [0x5A; 32], 123, Some(17));
        abi_handle.asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("axt", "universal").expect("test asset domain"),
            "iris".parse().expect("test asset name"),
        );
        abi_handle.scope = vec!["burn".into(), "transfer".into()];
        abi_handle.subject.origin_dsid = Some(DataSpaceId::new(42));
        abi_handle.handle_era = 33;
        abi_handle.group_binding.composability_group_id = vec![0x44; 32];
        abi_handle.group_binding.epoch_id = 71;
        abi_handle.target_lane = LaneId::new(9);
        abi_handle.manifest_view_root = [0xA5; 32];
        abi_handle.expiry_slot = 456;
        abi_handle.max_clock_skew_ms = Some(987);
        let network_id = iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            Hash::new(b"ivm-abi-budget-key-network"),
        ));
        let registration_header_hash =
            iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                Hash::new(b"ivm-abi-budget-key-asset-registration"),
            );
        let execution_identity = Hash::new(b"ivm-abi-budget-key-asset-execution");
        abi_handle.issuer_context = AxtHandleIssuerContextV1 {
            network_id,
            asset_dsid: dsid,
            asset_definition_incarnation: AxtAssetIncarnationV1::derive(
                &network_id,
                &abi_handle.asset_definition_id,
                &registration_header_hash,
                &execution_identity,
                0,
            ),
            issuer: iroha_data_model::nexus::UniversalAccountId::from_hash(Hash::new(
                b"ivm-abi-budget-key-issuer",
            )),
            issuer_manifest_root: [0xB1; 32],
            code_root: [0xB2; 32],
            abi_version: 1,
            abi_hash: [0xB3; 32],
        };
        let model_handle = abi_handle;
        let model_key = ModelAxtHandleBudgetKey::from_handle(&model_handle);

        let assert_model_mutation_changes_key = |mutated: ModelAssetHandle, field: &str| {
            assert_ne!(
                model_key,
                ModelAxtHandleBudgetKey::from_handle(&mutated),
                "{field} must remain part of the normalized budget identity"
            );
        };
        let mut mutated = model_handle.clone();
        mutated.asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("axt", "universal").expect("test asset domain"),
            "rose".parse().expect("test asset name"),
        );
        assert_model_mutation_changes_key(mutated, "asset definition");
        let mut mutated = model_handle.clone();
        mutated.subject.origin_dsid = Some(DataSpaceId::new(43));
        assert_model_mutation_changes_key(mutated, "subject origin");
        let mut mutated = model_handle.clone();
        mutated.group_binding.composability_group_id = vec![0x45; 32];
        assert_model_mutation_changes_key(mutated, "composability group");
        let mut mutated = model_handle.clone();
        mutated.group_binding.epoch_id = 72;
        assert_model_mutation_changes_key(mutated, "group epoch");
        let mut mutated = model_handle.clone();
        mutated.target_lane = LaneId::new(10);
        assert_model_mutation_changes_key(mutated, "target lane");
        let mut mutated = model_handle.clone();
        mutated.manifest_view_root = [0xA6; 32];
        assert_model_mutation_changes_key(mutated, "manifest root");
        let mut mutated = model_handle.clone();
        mutated.budget.remaining = quantity(124);
        assert_model_mutation_changes_key(mutated, "remaining budget");
        let mut mutated = model_handle.clone();
        mutated.budget.per_use = Some(quantity(18));
        assert_model_mutation_changes_key(mutated, "per-use budget");
        let mut mutated = model_handle.clone();
        mutated.expiry_slot = 457;
        assert_model_mutation_changes_key(mutated, "expiry slot");
        let mut mutated = model_handle.clone();
        mutated.max_clock_skew_ms = Some(988);
        assert_model_mutation_changes_key(mutated, "clock skew");
        let mut mutated = model_handle.clone();
        mutated.issuer_context.network_id =
            iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                Hash::new(b"ivm-abi-other-budget-key-network"),
            ));
        assert_model_mutation_changes_key(mutated, "issuer network");
        let mut mutated = model_handle.clone();
        mutated.issuer_context.asset_dsid = DataSpaceId::new(7);
        assert_model_mutation_changes_key(mutated, "issuer dataspace");
        let mut mutated = model_handle.clone();
        mutated.issuer_context.asset_definition_incarnation = AxtAssetIncarnationV1::derive(
            &mutated.issuer_context.network_id,
            &mutated.asset_definition_id,
            &iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                Hash::new(b"ivm-abi-other-asset-registration"),
            ),
            &Hash::new(b"ivm-abi-other-asset-execution"),
            0,
        );
        assert_model_mutation_changes_key(mutated, "asset-definition incarnation");
        let mut mutated = model_handle.clone();
        mutated.issuer_context.issuer = iroha_data_model::nexus::UniversalAccountId::from_hash(
            Hash::new(b"ivm-abi-other-budget-key-issuer"),
        );
        assert_model_mutation_changes_key(mutated, "issuer identity");
        let mut mutated = model_handle.clone();
        mutated.issuer_context.issuer_manifest_root = [0xB4; 32];
        assert_model_mutation_changes_key(mutated, "issuer manifest root");
        let mut mutated = model_handle.clone();
        mutated.issuer_context.code_root = [0xB5; 32];
        assert_model_mutation_changes_key(mutated, "issuer code root");
        let mut mutated = model_handle.clone();
        mutated.issuer_context.abi_version = 2;
        assert_model_mutation_changes_key(mutated, "issuer ABI version");
        let mut mutated = model_handle;
        mutated.issuer_context.abi_hash = [0xB6; 32];
        assert_model_mutation_changes_key(mutated, "issuer ABI hash");
    }
    #[test]
    fn record_proof_rejects_expired_slot() {
        let dsid = DataSpaceId::new(8);
        let descriptor = AxtDescriptor {
            dsids: vec![dsid],
            touches: vec![AxtTouchSpec {
                dsid,
                read: vec!["orders".into()],
                write: vec!["ledger".into()],
            }],
        };
        let binding = compute_binding(&descriptor).expect("binding");
        let mut state = HostAxtState::new(descriptor, binding);
        state
            .record_touch(dsid, sample_touch_manifest())
            .expect("touch recorded");
        let proof = ProofBlob {
            payload: vec![0xA5],
            expiry_slot: Some(5),
        };
        let err = state
            .record_proof(dsid, Some(proof), Some(10))
            .expect_err("expired proof should be rejected");
        assert!(matches!(err, VMError::PermissionDenied));
    }
    #[test]
    fn observed_declared_identities() {
        crate::captured_identity_tests::assert_bidirectional::<super::AxtDescriptor>(
            "ivm_abi::axt::AxtDescriptor",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::AxtTouchSpec>(
            "ivm_abi::axt::AxtTouchSpec",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::TouchManifest>(
            "ivm_abi::axt::TouchManifest",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::ProofBlob>(
            "ivm_abi::axt::ProofBlob",
        );
    }
}
