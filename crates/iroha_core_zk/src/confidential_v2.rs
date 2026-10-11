//! Shared confidential note, tree, and verifier-key primitives.
//!
//! Wallet applications construct proofs through
//! [`super::confidential::ConfidentialProver`], which owns secret inputs and
//! selects the canonical relation and key. Circuit-specific proof builders are
//! restricted to this ZK module so callers cannot bypass that workflow.

use blake3::Hasher as Blake3Hasher;
use ff::{Field as _, PrimeField as _};
use iroha_crypto::Hash as CryptoHash;
use iroha_data_model::proof::VerifyingKeyBox;
use iroha_data_model::{
    NetworkId,
    confidential::ConfidentialStatus,
    proof::{ProofBox, VerifyingKeyRecord},
    zk::{BackendTag, OpenVerifyEnvelope},
};
use iroha_pasta::Fp as Scalar;
use zeroize::{Zeroize, Zeroizing};
/// Canonical circuit identifier for two-input/two-output confidential transfers.
pub const CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID: &str = "pipa-r/pasta/confidential-transfer-v1";
/// Canonical circuit identifier for full confidential unshielding.
pub const CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID: &str = "pipa-r/pasta/confidential-unshield-full-v1";
/// Canonical circuit identifier for unshielding with one change output.
pub const CONFIDENTIAL_UNSHIELD_V3_CIRCUIT_ID: &str =
    "pipa-r/pasta/confidential-unshield-change-v1";
/// IPA domain exponent for confidential transfer V2.
pub const CONFIDENTIAL_TRANSFER_V2_IPA_K: u32 = 13;
/// IPA domain exponent for confidential unshield V2.
pub const CONFIDENTIAL_UNSHIELD_V2_IPA_K: u32 = 13;
/// IPA domain exponent for confidential unshield V3.
pub const CONFIDENTIAL_UNSHIELD_V3_IPA_K: u32 = 13;
/// Reviewed digest of the canonical full-unshield verifier key.
pub const CONFIDENTIAL_UNSHIELD_V2_VK_DIGEST_V1: [u8; 32] = [
    0x29, 0xb9, 0xab, 0xd2, 0x7a, 0x25, 0xf2, 0x90, 0xac, 0xa4, 0x7d, 0x25, 0x52, 0x3a, 0x7a, 0x16,
    0x85, 0x1f, 0xda, 0xde, 0x9b, 0x49, 0x5e, 0xc4, 0xe8, 0x2f, 0x54, 0x6e, 0x28, 0x18, 0xf8, 0x0d,
];
/// Reviewed digest of the canonical change-unshield verifier key.
pub const CONFIDENTIAL_UNSHIELD_V3_VK_DIGEST_V1: [u8; 32] = [
    0x11, 0x2e, 0xff, 0x63, 0x4e, 0xc4, 0x22, 0x71, 0x5a, 0xcf, 0x9c, 0x81, 0x0f, 0x33, 0xab, 0xda,
    0x93, 0xdc, 0x9f, 0x0d, 0x67, 0xb0, 0x5c, 0xec, 0xb4, 0x39, 0x93, 0x61, 0xe4, 0x7f, 0x60, 0xe3,
];
/// Fixed depth of the confidential commitment tree.
pub const CONFIDENTIAL_TREE_DEPTH_V2: usize = 16;
/// Maximum number of leaves in the confidential commitment tree.
pub const CONFIDENTIAL_TREE_CAPACITY_V2: usize = 1 << CONFIDENTIAL_TREE_DEPTH_V2;
/// Fixed-size incremental frontier persisted for the confidential tree.
///
/// Slot `level` contains the complete left subtree selected by bit `level` of
/// the current commitment count. A full tree has no populated lower frontier
/// slots; its separately persisted current root retains the completed root.
pub type ConfidentialTreeFrontierV2 = [Option<[u8; 32]>; CONFIDENTIAL_TREE_DEPTH_V2];
macro_rules! define_confidential_public_input_spec {
    (
        $(#[$struct_meta:meta])*
        $visibility:vis struct $values:ident;
        $field_visibility:vis enum $field:ident;
        constants $constant_visibility:vis const;
        count $count:literal;
        order $order:ident;
        schema $schema:ident = $prefix:literal, $suffix:literal;
        first $first_variant:ident => $first_member:ident,
            $first_name:literal, $first_doc:literal;
        rest $(
            $variant:ident => $member:ident,
                $name:literal, $doc:literal;
        )+
    ) => {
        $(#[$struct_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $visibility struct $values<T = [u8; 32]> {
            #[doc = $first_doc]
            pub $first_member: T,
            $(
                #[doc = $doc]
                pub $member: T,
            )+
        }
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $field_visibility enum $field {
            $first_variant,
            $($variant,)+
        }
        impl $field {
            $field_visibility const fn index(self) -> usize {
                self as usize
            }
            $field_visibility const fn name(self) -> &'static str {
                match self {
                    Self::$first_variant => $first_name,
                    $(Self::$variant => $name,)+
                }
            }
        }
        impl<T> $values<T> {
            $field_visibility fn into_array(self) -> [T; $count] {
                [self.$first_member, $(self.$member,)+]
            }
            $field_visibility fn try_map<U, E>(
                self,
                mut map: impl FnMut($field, T) -> Result<U, E>,
            ) -> Result<$values<U>, E> {
                Ok($values {
                    $first_member: map($field::$first_variant, self.$first_member)?,
                    $($member: map($field::$variant, self.$member)?,)+
                })
            }
        }
        #[doc = concat!("Public-column order generated from `", stringify!($values), "`.")]
        $constant_visibility const $order: &[&str] = &[$first_name, $($name,)+];
        #[doc = concat!("Canonical schema generated from `", stringify!($values), "`.")]
        $constant_visibility const $schema: &[u8] = concat!(
            $prefix,
            "\"", $first_name, "\"",
            $(",\"", $name, "\"",)+
            $suffix,
        )
        .as_bytes();
    };
}
/// Canonical public-input schema for confidential transfer V2.
pub const CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1: &[u8] = br#"{"schema":"confidential_transfer_v3","hash":"poseidon_t3_r2_rf8_rp57_mds0","merkle_leaf_domain":"cfleaf03","merkle_node_domain":"cfnode03","public_inputs":["input_commitment_0","input_commitment_1","nullifier_0","nullifier_1","output_commitment_0","output_commitment_1","root","asset_tag","network_tag"]}"#;
define_confidential_public_input_spec! {
    /// Typed full-unshield public-input contract.
    pub(crate) struct ConfidentialUnshieldFullPublicInputsV1;
    pub(crate) enum ConfidentialUnshieldFullPublicInputV1;
    constants pub const;
    count 8;
    order CONFIDENTIAL_UNSHIELD_V2_PUBLIC_INPUT_ORDER_V1;
    schema CONFIDENTIAL_UNSHIELD_V2_PUBLIC_INPUTS_SCHEMA_V1 =
        "{\"schema\":\"confidential_unshield_full_v3\",\"hash\":\"poseidon_t3_r2_rf8_rp57_mds0\",\"merkle_leaf_domain\":\"cfleaf03\",\"merkle_node_domain\":\"cfnode03\",\"public_inputs\":[",
        "]}";
    first InputCommitment0 => input_commitment_0,
        "input_commitment_0", "First authenticated input commitment.";
    rest
        InputCommitment1 => input_commitment_1,
            "input_commitment_1", "Optional second authenticated input commitment.";
        Nullifier0 => nullifier_0,
            "nullifier_0", "First authenticated spend nullifier.";
        Nullifier1 => nullifier_1,
            "nullifier_1", "Optional second authenticated spend nullifier.";
        Root => root,
            "root", "Authenticated commitment-tree root.";
        PublicAmount => public_amount,
            "public_amount", "Exact public redemption amount.";
        AssetTag => asset_tag,
            "asset_tag", "Asset-domain tag.";
        NetworkTag => network_tag,
            "network_tag", "Exact-network domain tag.";
}
define_confidential_public_input_spec! {
    /// Typed change-unshield public-input contract.
    pub(crate) struct ConfidentialUnshieldChangePublicInputsV1;
    pub(crate) enum ConfidentialUnshieldChangePublicInputV1;
    constants pub const;
    count 9;
    order CONFIDENTIAL_UNSHIELD_V3_PUBLIC_INPUT_ORDER_V1;
    schema CONFIDENTIAL_UNSHIELD_V3_PUBLIC_INPUTS_SCHEMA_V1 =
        "{\"schema\":\"confidential_unshield_change_v4\",\"hash\":\"poseidon_t3_r2_rf8_rp57_mds0\",\"merkle_leaf_domain\":\"cfleaf03\",\"merkle_node_domain\":\"cfnode03\",\"public_inputs\":[",
        "]}";
    first InputCommitment0 => input_commitment_0,
        "input_commitment_0", "First authenticated input commitment.";
    rest
        InputCommitment1 => input_commitment_1,
            "input_commitment_1", "Optional second authenticated input commitment.";
        Nullifier0 => nullifier_0,
            "nullifier_0", "First authenticated spend nullifier.";
        Nullifier1 => nullifier_1,
            "nullifier_1", "Optional second authenticated spend nullifier.";
        ChangeCommitment0 => change_commitment_0,
            "change_commitment_0", "Sole proof-authenticated change commitment.";
        Root => root,
            "root", "Authenticated commitment-tree root.";
        PublicAmount => public_amount,
            "public_amount", "Exact public redemption amount.";
        AssetTag => asset_tag,
            "asset_tag", "Asset-domain tag.";
        NetworkTag => network_tag,
            "network_tag", "Exact-network domain tag.";
}
/// Maximum accepted encoded confidential proof size.
pub const CONFIDENTIAL_V2_MAX_PROOF_BYTES: u32 = 192 * 1024;
/// Width of the pinned Axiom Poseidon secure permutation.
pub const CONFIDENTIAL_POSEIDON_T_V3: usize = 3;
/// Sponge rate of the pinned Axiom Poseidon secure permutation.
pub const CONFIDENTIAL_POSEIDON_RATE_V3: usize = 2;
/// Number of full rounds in the pinned Axiom Poseidon specification.
pub const CONFIDENTIAL_POSEIDON_FULL_ROUNDS_V3: usize = 8;
/// Number of partial rounds in the pinned Axiom Poseidon specification.
pub const CONFIDENTIAL_POSEIDON_PARTIAL_ROUNDS_V3: usize = 57;
/// Secure-MDS search index in the pinned Axiom Poseidon specification.
pub const CONFIDENTIAL_POSEIDON_SECURE_MDS_V3: usize = 0;
/// Domain word for owner-tag derivation.
pub const CONFIDENTIAL_POSEIDON_OWNER_DOMAIN_V3: u64 = u64::from_le_bytes(*b"cfownr03");
/// Domain word for note commitments.
pub const CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3: u64 = u64::from_le_bytes(*b"cfnote03");
/// Domain word for spend nullifiers.
pub const CONFIDENTIAL_POSEIDON_NULLIFIER_DOMAIN_V3: u64 = u64::from_le_bytes(*b"cfnull03");
/// Domain word for commitment-tree leaves.
pub const CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3: u64 = u64::from_le_bytes(*b"cfleaf03");
/// Domain word for commitment-tree internal nodes.
pub const CONFIDENTIAL_POSEIDON_MERKLE_NODE_DOMAIN_V3: u64 = u64::from_le_bytes(*b"cfnode03");
/// Domain word for asset tags.
pub const CONFIDENTIAL_POSEIDON_ASSET_DOMAIN_V3: u64 = u64::from_le_bytes(*b"cfasst03");
/// Domain word for network tags.
pub const CONFIDENTIAL_POSEIDON_NETWORK_DOMAIN_V3: u64 = u64::from_le_bytes(*b"cfnet_03");
// Secret openings and authentication paths must stay opaque in diagnostic logs.
macro_rules! confidential_redacted_debug_v2 {
    ($($name:ident),+ $(,)?) => {
        $(impl core::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        })+
    };
}
/// Canonical Merkle authentication path used by confidential circuits.
/// Debug formatting redacts all path fields.
#[derive(Clone)]
pub struct ConfidentialMerklePathV2 {
    /// Sibling node at each tree level, from leaf to root.
    pub siblings: Vec<[u8; 32]>,
    /// Canonical left/right direction bit at each level.
    pub directions: Vec<u8>,
    /// Recomputed parent node at each level.
    pub witness_nodes: Vec<[u8; 32]>,
    /// Root authenticated by the complete path.
    pub root: [u8; 32],
}
impl ConfidentialMerklePathV2 {
    /// Consume the path without bypassing its zeroizing `Drop` implementation.
    ///
    /// Moving individual fields out of a type that implements `Drop` is not
    /// permitted.  Callers that need to translate the path into another typed
    /// wire representation use this method, which replaces every retained
    /// field with its zero/empty value before the original allocation drops.
    #[must_use]
    pub fn into_parts(mut self) -> (Vec<[u8; 32]>, Vec<u8>, Vec<[u8; 32]>, [u8; 32]) {
        (
            std::mem::take(&mut self.siblings),
            std::mem::take(&mut self.directions),
            std::mem::take(&mut self.witness_nodes),
            std::mem::take(&mut self.root),
        )
    }
}
/// Secret opening and tree position for one transfer input.
/// Debug formatting redacts all opening fields.
#[derive(Clone)]
pub struct ConfidentialTransferInputV2 {
    /// Exact atomic amount opened by the note.
    pub amount: u128,
    /// Secret note nonce.
    pub rho: [u8; 32],
    /// Owner-key diversifier.
    pub diversifier: [u8; 32],
    /// Commitment-tree leaf index.
    pub leaf_index: usize,
}
/// Secret opening and owner binding for one transfer output.
/// Debug formatting redacts all opening fields.
#[derive(Clone)]
pub struct ConfidentialTransferOutputV2 {
    /// Exact atomic output amount.
    pub amount: u128,
    /// Secret note nonce.
    pub rho: [u8; 32],
    /// Recipient owner tag.
    pub owner_tag: [u8; 32],
}
/// Generated confidential transfer evidence and its public outputs.
#[derive(Debug, Clone)]
pub(super) struct ConfidentialTransferProofV2 {
    /// Nullifiers consumed by the transfer.
    pub nullifiers: Vec<[u8; 32]>,
    /// Commitments created by the transfer.
    pub output_commitments: Vec<[u8; 32]>,
    /// Authenticated input commitment-tree root.
    pub root: [u8; 32],
    /// Encoded native PIPA-R proof envelope.
    pub proof: ProofBox,
}
/// Secret opening and tree position for one unshield input.
/// Debug formatting redacts all opening fields.
#[derive(Clone)]
pub struct ConfidentialUnshieldInputV2 {
    /// Exact atomic amount opened by the note.
    pub amount: u128,
    /// Secret note nonce.
    pub rho: [u8; 32],
    /// Owner-key diversifier.
    pub diversifier: [u8; 32],
    /// Commitment-tree leaf index.
    pub leaf_index: usize,
}
/// Generated full-unshield evidence and public state.
#[derive(Debug, Clone)]
pub(super) struct ConfidentialUnshieldProofV2 {
    /// Nullifiers consumed by the unshield.
    pub nullifiers: Vec<[u8; 32]>,
    /// Authenticated input commitment-tree root.
    pub root: [u8; 32],
    /// Encoded native PIPA-R proof envelope.
    pub proof: ProofBox,
}
/// Secret opening for the optional unshield-change output.
/// Debug formatting redacts all opening fields.
#[derive(Clone)]
pub struct ConfidentialUnshieldOutputV3 {
    /// Exact atomic change amount.
    pub amount: u128,
    /// Secret change-note nonce.
    pub rho: [u8; 32],
}
/// Generated V3 full-or-change unshield evidence and public state.
#[derive(Debug, Clone)]
pub(super) struct ConfidentialUnshieldProofV3 {
    /// Nullifiers consumed by the unshield.
    pub nullifiers: Vec<[u8; 32]>,
    /// Confidential change commitments, empty for a full redemption.
    pub output_commitments: Vec<[u8; 32]>,
    /// Authenticated input commitment-tree root.
    pub root: [u8; 32],
    /// Encoded native PIPA-R proof envelope.
    pub proof: ProofBox,
}
confidential_redacted_debug_v2!(ConfidentialMerklePathV2);
confidential_redacted_debug_v2!(
    ConfidentialTransferInputV2,
    ConfidentialTransferOutputV2,
    ConfidentialUnshieldInputV2,
    ConfidentialUnshieldOutputV3,
    ConfidentialTransferWitnessV2,
    ConfidentialUnshieldWitnessV2,
    ConfidentialUnshieldWitnessV3,
);
impl Zeroize for ConfidentialMerklePathV2 {
    fn zeroize(&mut self) {
        self.siblings.zeroize();
        self.directions.zeroize();
        self.witness_nodes.zeroize();
        self.root.zeroize();
    }
}
impl Drop for ConfidentialMerklePathV2 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for ConfidentialTransferInputV2 {
    fn zeroize(&mut self) {
        self.amount.zeroize();
        self.rho.zeroize();
        self.diversifier.zeroize();
        self.leaf_index.zeroize();
    }
}
impl Drop for ConfidentialTransferInputV2 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for ConfidentialTransferOutputV2 {
    fn zeroize(&mut self) {
        self.amount.zeroize();
        self.rho.zeroize();
        self.owner_tag.zeroize();
    }
}
impl Drop for ConfidentialTransferOutputV2 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for ConfidentialUnshieldInputV2 {
    fn zeroize(&mut self) {
        self.amount.zeroize();
        self.rho.zeroize();
        self.diversifier.zeroize();
        self.leaf_index.zeroize();
    }
}
impl Drop for ConfidentialUnshieldInputV2 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for ConfidentialUnshieldOutputV3 {
    fn zeroize(&mut self) {
        self.amount.zeroize();
        self.rho.zeroize();
    }
}
impl Drop for ConfidentialUnshieldOutputV3 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
/// Return whether an identifier exactly selects the production confidential-transfer circuit.
#[inline]
pub fn is_confidential_transfer_v2_circuit_id(raw: &str) -> bool {
    raw == CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID
}
/// Return whether an identifier exactly selects the production full-unshield circuit.
#[inline]
pub fn is_confidential_unshield_v2_circuit_id(raw: &str) -> bool {
    raw == CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID
}
/// Return the exact compiled native transfer key carrier.
pub fn confidential_transfer_v2_vk_box() -> Result<VerifyingKeyBox, String> {
    native::verifying_key(native::Kind::Transfer)
}
/// Authenticate the exact compiled native transfer key carrier.
pub fn ensure_confidential_transfer_v2_canonical_vk_box(
    key: &VerifyingKeyBox,
) -> Result<(), String> {
    native::validate_key(native::Kind::Transfer, key)
}
/// Return the exact compiled native full-redemption key carrier.
pub fn confidential_unshield_v2_vk_box() -> Result<VerifyingKeyBox, String> {
    native::verifying_key(native::Kind::Full)
}
/// Authenticate the exact compiled native full-redemption key carrier.
pub fn ensure_confidential_unshield_v2_canonical_vk_box(
    key: &VerifyingKeyBox,
) -> Result<(), String> {
    native::validate_key(native::Kind::Full, key)
}
/// Return the exact compiled native redemption-with-change key carrier.
pub fn confidential_unshield_v3_vk_box() -> Result<VerifyingKeyBox, String> {
    native::verifying_key(native::Kind::Change)
}
/// Authenticate the exact compiled native redemption-with-change key carrier.
pub fn ensure_confidential_unshield_v3_canonical_vk_box(
    key: &VerifyingKeyBox,
) -> Result<(), String> {
    native::validate_key(native::Kind::Change, key)
}
fn confidential_v2_vk_record(
    name: &str,
    version: u32,
    circuit_id: &str,
    public_inputs_schema: &[u8],
    vk_box: VerifyingKeyBox,
) -> Result<VerifyingKeyRecord, String> {
    let mut record = VerifyingKeyRecord::new(
        version,
        circuit_id,
        BackendTag::NativePipaRPasta,
        "vesta",
        CryptoHash::new(public_inputs_schema).into(),
        super::hash_vk(&vk_box),
    );
    record.vk_len = u32::try_from(vk_box.bytes.len())
        .map_err(|_| "confidential v2 verifying key length overflowed u32".to_owned())?;
    record.max_proof_bytes = CONFIDENTIAL_V2_MAX_PROOF_BYTES;
    record.gas_schedule_id = Some("native_pipa_r_default".to_owned());
    record.key = Some(vk_box);
    record.status = ConfidentialStatus::Active;
    record.namespace = name.to_owned();
    Ok(record)
}
/// Build an active verifier record for confidential transfer V2.
pub fn confidential_transfer_v2_vk_record(
    name: &str,
    version: u32,
) -> Result<VerifyingKeyRecord, String> {
    confidential_v2_vk_record(
        name,
        version,
        CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
        CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1,
        confidential_transfer_v2_vk_box()?,
    )
}
/// Build an active verifier record for confidential unshield V2.
pub fn confidential_unshield_v2_vk_record(
    name: &str,
    version: u32,
) -> Result<VerifyingKeyRecord, String> {
    confidential_v2_vk_record(
        name,
        version,
        CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID,
        CONFIDENTIAL_UNSHIELD_V2_PUBLIC_INPUTS_SCHEMA_V1,
        confidential_unshield_v2_vk_box()?,
    )
}
/// Build an active verifier record for confidential unshield V3.
pub fn confidential_unshield_v3_vk_record(
    name: &str,
    version: u32,
) -> Result<VerifyingKeyRecord, String> {
    confidential_v2_vk_record(
        name,
        version,
        CONFIDENTIAL_UNSHIELD_V3_CIRCUIT_ID,
        CONFIDENTIAL_UNSHIELD_V3_PUBLIC_INPUTS_SCHEMA_V1,
        confidential_unshield_v3_vk_box()?,
    )
}
/// Return whether an identifier exactly selects the production change-unshield circuit.
#[inline]
pub fn is_confidential_unshield_v3_circuit_id(raw: &str) -> bool {
    raw == CONFIDENTIAL_UNSHIELD_V3_CIRCUIT_ID
}
#[cfg(test)]
/// Parse the exact public columns from a confidential-transfer proof envelope.
pub fn parse_transfer_public_inputs(
    proof_bytes: &[u8],
) -> Result<
    (
        [[u8; 32]; 2],
        [[u8; 32]; 2],
        [[u8; 32]; 2],
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ),
    String,
> {
    let envelope: OpenVerifyEnvelope =
        norito::decode_canonical(proof_bytes).map_err(|error| error.to_string())?;
    if envelope.circuit_id != CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID {
        return Err("not a native confidential transfer envelope".into());
    }
    let columns =
        super::native_pipa_r::public_instances(super::ZK_BACKEND_NATIVE_PIPA_R, &envelope)?;
    let rows = &columns[0];
    Ok((
        [rows[0].to_repr(), rows[1].to_repr()],
        [rows[2].to_repr(), rows[3].to_repr()],
        [rows[4].to_repr(), rows[5].to_repr()],
        rows[6].to_repr(),
        rows[7].to_repr(),
        rows[8].to_repr(),
    ))
}
pub(crate) fn scalar_from_repr(bytes: [u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_repr(bytes))
}
fn scalar_to_repr_bytes(value: Scalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(value.to_repr().as_ref());
    out
}
fn hash_to_scalar(label: &[u8], parts: &[&[u8]]) -> Scalar {
    let mut counter = 0u64;
    loop {
        let mut hasher = Blake3Hasher::new();
        hasher.update(label);
        hasher.update(&counter.to_le_bytes());
        for part in parts {
            hasher.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize();
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(digest.as_bytes());
        if let Some(value) = scalar_from_repr(candidate) {
            return value;
        }
        counter = counter.wrapping_add(1);
    }
}
fn scalar_from_u128(amount: u128) -> Scalar {
    let mut repr = <Scalar as ff::PrimeField>::Repr::default();
    repr.as_mut()[..16].copy_from_slice(&amount.to_le_bytes());
    Scalar::from_repr(repr).expect("u128 always fits inside Pasta Fp")
}
pub(crate) fn confidential_poseidon_hash_v3<F: iroha_pasta::poseidon::PoseidonField>(
    domain: u64,
    inputs: &[F],
) -> F {
    iroha_pasta::poseidon::hash_with_domain(domain, inputs)
}
#[path = "confidential_witness.rs"]
mod witness_validation;

/// Derive the default-diversifier owner tag for a confidential spend key.
pub fn derive_confidential_owner_tag_v2(spend_key: &[u8]) -> Result<[u8; 32], String> {
    derive_confidential_owner_tag_v2_with_diversifier(
        spend_key,
        default_confidential_diversifier_v2(),
    )
}
/// Return the canonical default owner diversifier.
pub fn default_confidential_diversifier_v2() -> [u8; 32] {
    scalar_to_repr_bytes(Scalar::ONE)
}
/// Derive a canonical owner diversifier from arbitrary seed bytes.
pub fn derive_confidential_diversifier_v2(seed: &[u8]) -> [u8; 32] {
    scalar_to_repr_bytes(hash_to_scalar(
        b"iroha.confidential.v3.diversifier",
        &[seed],
    ))
}
/// Derive an owner tag for a spend key and explicit diversifier.
pub fn derive_confidential_owner_tag_v2_with_diversifier(
    spend_key: &[u8],
    diversifier: [u8; 32],
) -> Result<[u8; 32], String> {
    derive_confidential_owner_tag_v3_with_diversifier(spend_key, diversifier)
}
#[cfg(test)]
/// Derive the field tag for an asset-definition identifier.
pub fn derive_confidential_asset_tag_v2(asset_definition_id: &str) -> [u8; 32] {
    derive_confidential_asset_tag_v3(asset_definition_id)
        .expect("validated asset identifiers derive non-zero V3 tags")
}
#[cfg(test)]
/// Derive the field tag for an exact genesis-derived network identity.
pub fn derive_confidential_network_tag_v2(network_id: &NetworkId) -> [u8; 32] {
    derive_confidential_network_tag_v3(network_id)
        .expect("exact network identities derive non-zero V3 tags")
}
/// Derive a confidential note commitment from its opening and context.
pub fn derive_confidential_note_v2(
    asset_definition_id: &str,
    amount: u128,
    rho: [u8; 32],
    owner_tag: [u8; 32],
) -> Result<[u8; 32], String> {
    derive_confidential_note_v3(
        derive_confidential_asset_tag_v3(asset_definition_id)?,
        amount,
        rho,
        owner_tag,
    )
}
#[cfg(any(test, feature = "test-utils"))]
/// Derive a confidential spend nullifier from its opening and context.
pub fn derive_confidential_nullifier_v2(
    network_id: &NetworkId,
    asset_definition_id: &str,
    spend_key: &[u8],
    rho: [u8; 32],
) -> [u8; 32] {
    derive_confidential_nullifier_v3(
        spend_key,
        rho,
        derive_confidential_asset_tag_v3(asset_definition_id).expect("validated asset identifier"),
        derive_confidential_network_tag_v3(network_id).expect("exact network identity"),
    )
    .expect("validated confidential nullifier inputs")
}
/// Return the canonical empty root of the fixed confidential tree.
pub fn poseidon_empty_root_v2() -> [u8; 32] {
    iroha_data_model::zk::CONFIDENTIAL_TREE_POSEIDON_PASTA_V1_EMPTY_ROOT
}
/// Return whether a persisted confidential-tree node is one canonical Pasta scalar.
///
/// Zero is accepted here because this validates the scalar representation of a
/// tree node, not a non-empty commitment leaf.
#[inline]
pub fn confidential_tree_node_is_canonical_v2(node: [u8; 32]) -> bool {
    scalar_from_repr(node).is_some()
}
/// Compute the fixed-tree root for canonical commitment leaves.
pub fn compute_confidential_root_v2(commitments: &[[u8; 32]]) -> Result<[u8; 32], String> {
    compute_confidential_root_v3(commitments)
}
/// Compute the canonical root after every non-empty commitment prefix.
pub fn compute_confidential_prefix_roots_v2(
    commitments: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>, String> {
    compute_confidential_prefix_roots_v3(commitments)
}
/// Compute a canonical fixed-tree authentication path for one leaf index.
pub fn compute_confidential_merkle_path_v2(
    commitments: &[[u8; 32]],
    leaf_index: usize,
) -> Result<ConfidentialMerklePathV2, String> {
    compute_confidential_merkle_path_v3(commitments, leaf_index)
}
/// Construct the private empty-tree path used only for an absent input slot.
///
/// The circuit gates this slot's root equality by its constrained presence
/// bit. The dummy root is never required to occur in the ledger's root history.
fn confidential_absent_input_path_v3<const DEPTH: usize>() -> ConfidentialMerklePathV2 {
    let mut node =
        confidential_poseidon_hash_v3(CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3, &[Scalar::ZERO]);
    let mut siblings = Vec::with_capacity(DEPTH);
    let mut witness_nodes = Vec::with_capacity(DEPTH);
    for _ in 0..DEPTH {
        siblings.push(scalar_to_repr_bytes(node));
        node = merkle_parent_v3(node, node);
        witness_nodes.push(scalar_to_repr_bytes(node));
    }
    ConfidentialMerklePathV2 {
        siblings,
        directions: vec![0; DEPTH],
        witness_nodes,
        root: scalar_to_repr_bytes(node),
    }
}
/// Resolve an optional tree-backed input without requiring an unused ledger leaf.
fn confidential_optional_input_path_v3(
    commitments: &[[u8; 32]],
    leaf_index: Option<usize>,
) -> Result<ConfidentialMerklePathV2, String> {
    match leaf_index {
        Some(index) => compute_confidential_merkle_path_v2(commitments, index),
        None => Ok(confidential_absent_input_path_v3::<
            CONFIDENTIAL_TREE_DEPTH_V2,
        >()),
    }
}
/// Reject impossible public tree shapes before hashing leaves or generating keys.
fn validate_confidential_tree_input_shape_v3(
    commitment_count: usize,
    leaf_indices: impl ExactSizeIterator<Item = usize>,
) -> Result<(), String> {
    if leaf_indices.len() == 0 || leaf_indices.len() > 2 {
        return Err("confidential proofs support one or two inputs".to_owned());
    }
    if commitment_count > CONFIDENTIAL_TREE_CAPACITY_V2 {
        return Err(format!(
            "confidential V3 tree supports at most {CONFIDENTIAL_TREE_CAPACITY_V2} leaves"
        ));
    }
    for leaf_index in leaf_indices {
        if leaf_index >= commitment_count {
            return Err(
                "confidential input leaf_index must identify a supplied tree commitment".to_owned(),
            );
        }
    }
    Ok(())
}
fn poseidon_tag_v3(domain: u64, label: &[u8], bytes: &[u8]) -> Result<Scalar, String> {
    let preimage = hash_to_scalar(label, &[bytes]);
    let tag = confidential_poseidon_hash_v3(domain, &[preimage]);
    if tag == Scalar::ZERO {
        Err("V3 domain-separated tag must not be zero".to_owned())
    } else {
        Ok(tag)
    }
}
fn strict_v3_identifier<'a>(value: &'a str, label: &str) -> Result<&'a str, String> {
    if value.is_empty() || value.trim() != value {
        Err(format!(
            "V3 {label} must be non-empty and contain no surrounding whitespace"
        ))
    } else {
        Ok(value)
    }
}
/// Derive a domain-separated V3 owner tag from a spend key and diversifier.
pub fn derive_confidential_owner_tag_v3_with_diversifier(
    spend_key: &[u8],
    diversifier: [u8; 32],
) -> Result<[u8; 32], String> {
    if spend_key.len() != 32 || spend_key.iter().all(|byte| *byte == 0) {
        return Err("V3 spend key must be exactly 32 non-zero bytes".to_owned());
    }
    let spend = hash_to_scalar(b"iroha.confidential.v3.spend_scalar", &[spend_key]);
    let diversifier = scalar_from_repr(diversifier)
        .filter(|value| *value != Scalar::ZERO)
        .ok_or_else(|| "V3 diversifier must be a non-zero canonical Pasta scalar".to_owned())?;
    let owner =
        confidential_poseidon_hash_v3(CONFIDENTIAL_POSEIDON_OWNER_DOMAIN_V3, &[spend, diversifier]);
    if owner == Scalar::ZERO {
        return Err("V3 owner tag must not be zero".to_owned());
    }
    Ok(scalar_to_repr_bytes(owner))
}
/// Derive the domain-separated V3 asset tag.
pub fn derive_confidential_asset_tag_v3(asset_definition_id: &str) -> Result<[u8; 32], String> {
    let canonical = strict_v3_identifier(asset_definition_id, "asset definition identifier")?;
    Ok(scalar_to_repr_bytes(poseidon_tag_v3(
        CONFIDENTIAL_POSEIDON_ASSET_DOMAIN_V3,
        b"iroha.confidential.v3.asset_preimage",
        canonical.as_bytes(),
    )?))
}
/// Derive the domain-separated V3 tag for an exact genesis-derived network.
pub fn derive_confidential_network_tag_v3(network_id: &NetworkId) -> Result<[u8; 32], String> {
    Ok(scalar_to_repr_bytes(poseidon_tag_v3(
        CONFIDENTIAL_POSEIDON_NETWORK_DOMAIN_V3,
        b"iroha.confidential.v3.network_id_preimage",
        network_id.as_bytes(),
    )?))
}
/// Derive a V3 note commitment with the full secure permutation.
pub fn derive_confidential_note_v3(
    asset_tag: [u8; 32],
    amount: u128,
    rho: [u8; 32],
    owner_tag: [u8; 32],
) -> Result<[u8; 32], String> {
    if amount == 0 || rho == [0; 32] {
        return Err("V3 note amount and rho must be non-zero".to_owned());
    }
    let asset = scalar_from_repr(asset_tag)
        .filter(|value| *value != Scalar::ZERO)
        .ok_or_else(|| "V3 asset tag must be a non-zero canonical Pasta scalar".to_owned())?;
    let owner = scalar_from_repr(owner_tag)
        .filter(|value| *value != Scalar::ZERO)
        .ok_or_else(|| "V3 owner tag must be a non-zero canonical Pasta scalar".to_owned())?;
    let rho = hash_to_scalar(b"iroha.confidential.v3.note_rho", &[&rho]);
    let commitment = confidential_poseidon_hash_v3(
        CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3,
        &[scalar_from_u128(amount), rho, owner, asset],
    );
    if commitment == Scalar::ZERO {
        return Err("V3 note commitment must not be zero".to_owned());
    }
    Ok(scalar_to_repr_bytes(commitment))
}
/// Derive a V3 spend nullifier with the full secure permutation.
pub fn derive_confidential_nullifier_v3(
    spend_key: &[u8],
    rho: [u8; 32],
    asset_tag: [u8; 32],
    network_tag: [u8; 32],
) -> Result<[u8; 32], String> {
    if spend_key.len() != 32 || spend_key.iter().all(|byte| *byte == 0) || rho == [0; 32] {
        return Err("V3 nullifier spend key and rho must be non-zero".to_owned());
    }
    let spend = hash_to_scalar(b"iroha.confidential.v3.spend_scalar", &[spend_key]);
    let rho = hash_to_scalar(b"iroha.confidential.v3.note_rho", &[&rho]);
    let asset = scalar_from_repr(asset_tag)
        .filter(|value| *value != Scalar::ZERO)
        .ok_or_else(|| "V3 asset tag must be a non-zero canonical Pasta scalar".to_owned())?;
    let network = scalar_from_repr(network_tag)
        .filter(|value| *value != Scalar::ZERO)
        .ok_or_else(|| "V3 network tag must be a non-zero canonical Pasta scalar".to_owned())?;
    let nullifier = confidential_poseidon_hash_v3(
        CONFIDENTIAL_POSEIDON_NULLIFIER_DOMAIN_V3,
        &[spend, rho, asset, network],
    );
    if nullifier == Scalar::ZERO {
        return Err("V3 nullifier must not be zero".to_owned());
    }
    Ok(scalar_to_repr_bytes(nullifier))
}
fn validate_confidential_tree_len_v3(commitments: &[[u8; 32]]) -> Result<(), String> {
    if commitments.len() > CONFIDENTIAL_TREE_CAPACITY_V2 {
        return Err(format!(
            "confidential V3 tree supports at most {} leaves",
            CONFIDENTIAL_TREE_CAPACITY_V2
        ));
    }
    Ok(())
}
fn merkle_parent_v3(left: Scalar, right: Scalar) -> Scalar {
    confidential_poseidon_hash_v3(CONFIDENTIAL_POSEIDON_MERKLE_NODE_DOMAIN_V3, &[left, right])
}
fn confidential_empty_subtree_roots_v3() -> [Scalar; CONFIDENTIAL_TREE_DEPTH_V2 + 1] {
    static ROOTS: std::sync::OnceLock<[Scalar; CONFIDENTIAL_TREE_DEPTH_V2 + 1]> =
        std::sync::OnceLock::new();
    *ROOTS.get_or_init(|| {
        let mut roots = [Scalar::ZERO; CONFIDENTIAL_TREE_DEPTH_V2 + 1];
        roots[0] = confidential_poseidon_hash_v3(
            CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3,
            &[Scalar::ZERO],
        );
        for level in 0..CONFIDENTIAL_TREE_DEPTH_V2 {
            roots[level + 1] = merkle_parent_v3(roots[level], roots[level]);
        }
        roots
    })
}
fn confidential_commitment_leaf_v3(commitment: [u8; 32], index: usize) -> Result<Scalar, String> {
    let commitment = scalar_from_repr(commitment)
        .filter(|value| *value != Scalar::ZERO)
        .ok_or_else(|| {
            format!("confidential V3 commitment[{index}] must be non-zero and canonical")
        })?;
    #[cfg(test)]
    CONFIDENTIAL_COMMITMENT_LEAF_HASH_CALLS_V3.with(|calls| {
        calls.set(calls.get().saturating_add(1));
    });
    Ok(confidential_poseidon_hash_v3(
        CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3,
        &[commitment],
    ))
}
#[cfg(test)]
std::thread_local! {
    #[cfg(test)]
    static CONFIDENTIAL_COMMITMENT_LEAF_HASH_CALLS_V3: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
#[cfg(test)]
fn reset_confidential_commitment_leaf_hash_calls_v3() {
    CONFIDENTIAL_COMMITMENT_LEAF_HASH_CALLS_V3.with(|calls| calls.set(0));
}
#[cfg(test)]
fn confidential_commitment_leaf_hash_calls_v3() -> usize {
    CONFIDENTIAL_COMMITMENT_LEAF_HASH_CALLS_V3.with(std::cell::Cell::get)
}
#[cfg(test)]
std::thread_local! {
    #[cfg(test)]
    static CONFIDENTIAL_FRONTIER_APPEND_PARENT_HASH_CALLS_V2: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
#[cfg(test)]
fn reset_confidential_frontier_append_parent_hash_calls_v2() {
    CONFIDENTIAL_FRONTIER_APPEND_PARENT_HASH_CALLS_V2.with(|calls| calls.set(0));
}
#[cfg(test)]
fn confidential_frontier_append_parent_hash_calls_v2() -> usize {
    CONFIDENTIAL_FRONTIER_APPEND_PARENT_HASH_CALLS_V2.with(std::cell::Cell::get)
}
fn confidential_subtree_root_v3(
    commitments: &[[u8; 32]],
    start: usize,
    height: usize,
    empty_roots: &[Scalar; CONFIDENTIAL_TREE_DEPTH_V2 + 1],
) -> Result<Scalar, String> {
    if start >= commitments.len() {
        return Ok(empty_roots[height]);
    }
    if height == 0 {
        return confidential_commitment_leaf_v3(commitments[start], start);
    }
    let half_width = 1_usize << (height - 1);
    let left = confidential_subtree_root_v3(commitments, start, height - 1, empty_roots)?;
    let right =
        confidential_subtree_root_v3(commitments, start + half_width, height - 1, empty_roots)?;
    Ok(merkle_parent_v3(left, right))
}
/// Compute the fixed-tree root using V3 leaf and internal-node domains.
pub fn compute_confidential_root_v3(commitments: &[[u8; 32]]) -> Result<[u8; 32], String> {
    let roots = compute_confidential_prefix_roots_v3(commitments)?;
    Ok(roots.last().copied().unwrap_or_else(poseidon_empty_root_v2))
}
fn append_confidential_tree_leaf_v3(
    mut position: usize,
    mut node: Scalar,
    frontier: &mut [Option<Scalar>; CONFIDENTIAL_TREE_DEPTH_V2],
    empty_roots: &[Scalar; CONFIDENTIAL_TREE_DEPTH_V2 + 1],
) -> Result<Scalar, String> {
    let mut frontier_carry_resolved = false;
    for level in 0..CONFIDENTIAL_TREE_DEPTH_V2 {
        if !frontier_carry_resolved && position & 1 == 0 {
            frontier[level] = Some(node);
            frontier_carry_resolved = true;
            node = merkle_parent_v3(node, empty_roots[level]);
        } else if let Some(left) = frontier[level] {
            if !frontier_carry_resolved {
                frontier[level] = None;
            }
            node = merkle_parent_v3(left, node);
        } else if !frontier_carry_resolved {
            return Err(format!(
                "missing confidential tree frontier at level {level}"
            ));
        } else {
            node = merkle_parent_v3(node, empty_roots[level]);
        }
        position >>= 1;
    }
    Ok(node)
}
fn compute_confidential_prefix_roots_v3(commitments: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, String> {
    validate_confidential_tree_len_v3(commitments)?;
    let empty_roots = confidential_empty_subtree_roots_v3();
    let mut frontier = [None; CONFIDENTIAL_TREE_DEPTH_V2];
    let mut roots = Vec::with_capacity(commitments.len());
    for (leaf_index, commitment) in commitments.iter().copied().enumerate() {
        let node = confidential_commitment_leaf_v3(commitment, leaf_index)?;
        let node = append_confidential_tree_leaf_v3(leaf_index, node, &mut frontier, &empty_roots)?;
        roots.push(scalar_to_repr_bytes(node));
    }
    Ok(roots)
}
/// One authenticated compact projection of the fixed confidential tree.
///
/// The projection stores only nodes whose subtrees intersect the persisted commitment prefix.
/// Building it hashes every commitment leaf exactly once and takes linear time and space.
/// Authentication paths then take exactly the fixed tree depth without rescanning commitments.
pub struct ConfidentialTreeProjectionV2 {
    layers: Vec<Vec<Scalar>>,
    empty_roots: [Scalar; CONFIDENTIAL_TREE_DEPTH_V2 + 1],
    commitment_count: usize,
    root: [u8; 32],
}
impl ConfidentialTreeProjectionV2 {
    /// Build one compact authenticated projection for an ordered commitment prefix.
    pub fn build(commitments: &[[u8; 32]]) -> Result<Self, String> {
        validate_confidential_tree_len_v3(commitments)?;
        let empty_roots = confidential_empty_subtree_roots_v3();
        let mut nodes = commitments
            .iter()
            .copied()
            .enumerate()
            .map(|(index, commitment)| confidential_commitment_leaf_v3(commitment, index))
            .collect::<Result<Vec<_>, _>>()?;
        let mut layers = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
        for level in 0..CONFIDENTIAL_TREE_DEPTH_V2 {
            let mut parents = Vec::with_capacity(nodes.len().div_ceil(2));
            for pair in nodes.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).copied().unwrap_or(empty_roots[level]);
                parents.push(merkle_parent_v3(left, right));
            }
            layers.push(nodes);
            nodes = parents;
        }
        let root = nodes
            .first()
            .copied()
            .unwrap_or(empty_roots[CONFIDENTIAL_TREE_DEPTH_V2]);
        Ok(Self {
            layers,
            empty_roots,
            commitment_count: commitments.len(),
            root: scalar_to_repr_bytes(root),
        })
    }
    /// Return the root authenticated by this projection.
    #[must_use]
    pub const fn root(&self) -> [u8; 32] {
        self.root
    }
    /// Reconstruct the fixed-size incremental frontier authenticated by this projection.
    pub fn frontier(&self) -> Result<ConfidentialTreeFrontierV2, String> {
        let mut frontier = [None; CONFIDENTIAL_TREE_DEPTH_V2];
        for (level, slot) in frontier.iter_mut().enumerate() {
            if (self.commitment_count >> level) & 1 == 0 {
                continue;
            }
            let position = (self.commitment_count >> level) - 1;
            let node = self.layers[level].get(position).copied().ok_or_else(|| {
                format!("confidential projection is missing frontier node at level {level}")
            })?;
            *slot = Some(scalar_to_repr_bytes(node));
        }
        Ok(frontier)
    }
    /// Compute one membership or zero-leaf path without rescanning commitments.
    pub fn compute_path(&self, leaf_index: usize) -> Result<ConfidentialMerklePathV2, String> {
        if leaf_index >= CONFIDENTIAL_TREE_CAPACITY_V2 {
            return Err(format!(
                "leaf_index must be < {} for confidential V3 proofs",
                CONFIDENTIAL_TREE_CAPACITY_V2
            ));
        }
        let mut node = self.layers[0]
            .get(leaf_index)
            .copied()
            .unwrap_or(self.empty_roots[0]);
        let mut siblings = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
        let mut directions = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
        let mut witness_nodes = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
        for level in 0..CONFIDENTIAL_TREE_DEPTH_V2 {
            let position = leaf_index >> level;
            let direction = (position & 1) as u8;
            let sibling = self.layers[level]
                .get(position ^ 1)
                .copied()
                .unwrap_or(self.empty_roots[level]);
            node = if direction == 0 {
                merkle_parent_v3(node, sibling)
            } else {
                merkle_parent_v3(sibling, node)
            };
            siblings.push(scalar_to_repr_bytes(sibling));
            directions.push(direction);
            witness_nodes.push(scalar_to_repr_bytes(node));
        }
        let computed_root = scalar_to_repr_bytes(node);
        if computed_root != self.root {
            return Err("confidential projection path did not authenticate its root".to_owned());
        }
        Ok(ConfidentialMerklePathV2 {
            siblings,
            directions,
            witness_nodes,
            root: computed_root,
        })
    }
}
/// Result of simulating one atomic append against a persisted tree frontier.
pub struct ConfidentialTreeAppendV2 {
    /// Frontier after the complete batch.
    pub frontier: ConfidentialTreeFrontierV2,
    /// Current root after the complete batch.
    pub current_root: [u8; 32],
    /// Root after each appended commitment, in request order.
    pub appended_roots: Vec<[u8; 32]>,
}
/// Validate the fixed-size frontier and its separately persisted current root.
pub fn validate_confidential_tree_frontier_v2(
    commitment_count: usize,
    frontier: &ConfidentialTreeFrontierV2,
    persisted_root: [u8; 32],
) -> Result<(), String> {
    if commitment_count > CONFIDENTIAL_TREE_CAPACITY_V2 {
        return Err(format!(
            "confidential tree capacity {} exceeded by {commitment_count} commitments",
            CONFIDENTIAL_TREE_CAPACITY_V2
        ));
    }
    if !confidential_tree_node_is_canonical_v2(persisted_root) {
        return Err(
            "persisted confidential current root is not a canonical Pasta scalar".to_owned(),
        );
    }
    for (level, slot) in frontier.iter().enumerate() {
        let should_be_populated = (commitment_count >> level) & 1 == 1;
        if slot.is_some() != should_be_populated {
            return Err(format!(
                "confidential frontier slot {level} does not match commitment-count shape"
            ));
        }
        if slot.is_some_and(|node| !confidential_tree_node_is_canonical_v2(node)) {
            return Err(format!(
                "confidential frontier slot {level} is not a canonical Pasta scalar"
            ));
        }
    }
    if commitment_count == CONFIDENTIAL_TREE_CAPACITY_V2 {
        // The final append consumes every lower slot. Full recovery validation
        // compares this separately persisted root with a rebuilt projection.
        return Ok(());
    }
    let empty_roots = confidential_empty_subtree_roots_v3();
    let mut node = empty_roots[0];
    for level in 0..CONFIDENTIAL_TREE_DEPTH_V2 {
        if let Some(left) = frontier[level] {
            let left = scalar_from_repr(left)
                .ok_or_else(|| format!("confidential frontier slot {level} is not canonical"))?;
            node = merkle_parent_v3(left, node);
        } else {
            node = merkle_parent_v3(node, empty_roots[level]);
        }
    }
    if scalar_to_repr_bytes(node) != persisted_root {
        return Err(
            "persisted confidential current root does not match the incremental frontier"
                .to_owned(),
        );
    }
    Ok(())
}
/// Simulate an ordered append in `O(batch * depth)` without mutating persisted state.
pub fn append_confidential_tree_frontier_v2(
    commitment_count: usize,
    frontier: ConfidentialTreeFrontierV2,
    persisted_root: [u8; 32],
    commitments: &[[u8; 32]],
) -> Result<ConfidentialTreeAppendV2, String> {
    let next_count = commitment_count
        .checked_add(commitments.len())
        .ok_or_else(|| "confidential commitment count overflow".to_owned())?;
    if next_count > CONFIDENTIAL_TREE_CAPACITY_V2 {
        return Err(format!(
            "confidential tree capacity {} exceeded by {next_count} commitments",
            CONFIDENTIAL_TREE_CAPACITY_V2
        ));
    }
    validate_confidential_tree_frontier_v2(commitment_count, &frontier, persisted_root)?;
    let leaves = commitments
        .iter()
        .copied()
        .enumerate()
        .map(|(offset, commitment)| {
            confidential_commitment_leaf_v3(commitment, commitment_count + offset)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if leaves.is_empty() {
        return Ok(ConfidentialTreeAppendV2 {
            frontier,
            current_root: persisted_root,
            appended_roots: Vec::new(),
        });
    }
    let empty_roots = confidential_empty_subtree_roots_v3();
    let mut frontier_scalars = frontier.map(|slot| slot.and_then(scalar_from_repr));
    let mut appended_roots = Vec::with_capacity(leaves.len());
    for (offset, node) in leaves.into_iter().enumerate() {
        let node = append_confidential_tree_leaf_v3(
            commitment_count + offset,
            node,
            &mut frontier_scalars,
            &empty_roots,
        )?;
        #[cfg(test)]
        CONFIDENTIAL_FRONTIER_APPEND_PARENT_HASH_CALLS_V2.with(|calls| {
            calls.set(calls.get().saturating_add(CONFIDENTIAL_TREE_DEPTH_V2));
        });
        appended_roots.push(scalar_to_repr_bytes(node));
    }
    Ok(ConfidentialTreeAppendV2 {
        frontier: frontier_scalars.map(|slot| slot.map(scalar_to_repr_bytes)),
        current_root: appended_roots.last().copied().unwrap_or(persisted_root),
        appended_roots,
    })
}
/// Compute an exact V3 authentication path, including redundant checked nodes.
pub fn compute_confidential_merkle_path_v3(
    commitments: &[[u8; 32]],
    leaf_index: usize,
) -> Result<ConfidentialMerklePathV2, String> {
    if leaf_index >= CONFIDENTIAL_TREE_CAPACITY_V2 {
        return Err(format!(
            "leaf_index must be < {} for confidential V3 proofs",
            CONFIDENTIAL_TREE_CAPACITY_V2
        ));
    }
    validate_confidential_tree_len_v3(commitments)?;
    let empty_roots = confidential_empty_subtree_roots_v3();
    let mut node = if leaf_index < commitments.len() {
        confidential_commitment_leaf_v3(commitments[leaf_index], leaf_index)?
    } else {
        empty_roots[0]
    };
    let mut siblings = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
    let mut directions = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
    let mut witness_nodes = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
    for level in 0..CONFIDENTIAL_TREE_DEPTH_V2 {
        let subtree_width = 1_usize << level;
        let subtree_start = (leaf_index >> level) << level;
        let direction = u8::from(!((leaf_index >> level).is_multiple_of(2)));
        let sibling_start = if direction == 0 {
            subtree_start + subtree_width
        } else {
            subtree_start - subtree_width
        };
        let sibling =
            confidential_subtree_root_v3(commitments, sibling_start, level, &empty_roots)?;
        node = if direction == 0 {
            merkle_parent_v3(node, sibling)
        } else {
            merkle_parent_v3(sibling, node)
        };
        siblings.push(scalar_to_repr_bytes(sibling));
        directions.push(direction);
        witness_nodes.push(scalar_to_repr_bytes(node));
    }
    Ok(ConfidentialMerklePathV2 {
        siblings,
        directions,
        witness_nodes,
        root: scalar_to_repr_bytes(node),
    })
}
/// Derive the next empty-leaf path from a supplied current root and path.
pub fn derive_confidential_next_zero_path_v2(
    previous_leaf_commitment: [u8; 32],
    previous_leaf_index: usize,
    previous_path: &ConfidentialMerklePathV2,
    root_hint: [u8; 32],
) -> Result<ConfidentialMerklePathV2, String> {
    let next_leaf_index = previous_leaf_index
        .checked_add(1)
        .ok_or_else(|| "next zero leaf_index overflowed usize".to_owned())?;
    if next_leaf_index >= CONFIDENTIAL_TREE_CAPACITY_V2 {
        return Err(format!(
            "next zero leaf_index must be < {CONFIDENTIAL_TREE_CAPACITY_V2}"
        ));
    }
    let previous_path = normalize_supplied_confidential_merkle_path_v2(
        previous_leaf_commitment,
        Some(previous_leaf_index),
        previous_path,
        root_hint,
        "previous latest confidential path",
    )?;
    let zero_subtrees = confidential_empty_subtree_roots_v3();
    let mut node = zero_subtrees[0];
    let previous_commitment = scalar_from_repr(previous_leaf_commitment)
        .filter(|value| *value != Scalar::ZERO)
        .ok_or_else(|| "previous commitment must be non-zero and canonical".to_owned())?;
    let mut previous_node = confidential_poseidon_hash_v3(
        CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3,
        &[previous_commitment],
    );
    let mut siblings = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
    let mut directions = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
    let mut witness_nodes = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
    for level in 0..CONFIDENTIAL_TREE_DEPTH_V2 {
        let previous_subtree_index = previous_leaf_index >> level;
        let next_subtree_index = next_leaf_index >> level;
        let direction = if next_subtree_index.is_multiple_of(2) {
            0
        } else {
            1
        };
        let sibling = if next_subtree_index == previous_subtree_index {
            scalar_from_repr(previous_path.siblings[level]).ok_or_else(|| {
                format!(
                    "previous latest confidential path sibling[{level}] must be a canonical Pasta scalar"
                )
            })?
        } else if direction == 1 && next_subtree_index == previous_subtree_index + 1 {
            previous_node
        } else {
            zero_subtrees[level]
        };
        node = if direction == 0 {
            merkle_parent_v3(node, sibling)
        } else {
            merkle_parent_v3(sibling, node)
        };
        siblings.push(scalar_to_repr_bytes(sibling));
        directions.push(direction);
        witness_nodes.push(scalar_to_repr_bytes(node));
        previous_node = scalar_from_repr(previous_path.witness_nodes[level]).ok_or_else(|| {
            format!(
                "previous latest confidential path witness_nodes[{level}] must be a canonical Pasta scalar"
            )
        })?;
    }
    let computed_root = scalar_to_repr_bytes(node);
    if computed_root != root_hint {
        return Err("derived next zero confidential path does not prove root_hint".to_owned());
    }
    Ok(ConfidentialMerklePathV2 {
        siblings,
        directions,
        witness_nodes,
        root: computed_root,
    })
}
/// One exact append-only output path derived from an authenticated next-zero frontier.
#[derive(Debug, Clone)]
pub struct ConfidentialSequentialAppendLeafPathsV3 {
    /// Consecutive confidential-tree leaf index assigned to this output.
    pub leaf_index: usize,
    /// Empty-leaf path against the root immediately before this output is inserted.
    pub update_path: ConfidentialMerklePathV2,
    /// Output membership path against the root after every requested output is inserted.
    pub membership_path: ConfidentialMerklePathV2,
}
/// Canonical result of advancing one authenticated confidential-tree frontier.
#[derive(Debug, Clone)]
pub struct ConfidentialSequentialAppendPathsV3 {
    /// Root authenticated by the supplied next-zero frontier.
    pub initial_root: [u8; 32],
    /// Root after inserting every requested output in order.
    pub final_root: [u8; 32],
    /// One or two consecutive output path pairs.
    pub leaves: Vec<ConfidentialSequentialAppendLeafPathsV3>,
    /// First canonical empty leaf after the inserted outputs.
    pub next_zero_leaf_index: usize,
    /// Empty-leaf path against `final_root` at `next_zero_leaf_index`.
    pub next_zero_path: ConfidentialMerklePathV2,
}
/// Recompute and validate one canonical empty-leaf frontier against its supplied root.
pub fn validate_confidential_next_zero_path_v3(
    next_zero_leaf_index: usize,
    next_zero_path: &ConfidentialMerklePathV2,
) -> Result<ConfidentialMerklePathV2, String> {
    normalize_supplied_confidential_merkle_path_v2(
        [0; 32],
        Some(next_zero_leaf_index),
        next_zero_path,
        next_zero_path.root,
        "confidential next-zero frontier",
    )
}
/// Recompute and validate one non-empty commitment membership path against its supplied root.
pub fn validate_confidential_membership_path_v3(
    commitment: [u8; 32],
    leaf_index: usize,
    membership_path: &ConfidentialMerklePathV2,
) -> Result<ConfidentialMerklePathV2, String> {
    if scalar_from_repr(commitment).is_none_or(|value| value == Scalar::ZERO) {
        return Err("confidential membership commitment must be non-zero and canonical".to_owned());
    }
    normalize_supplied_confidential_merkle_path_v2(
        commitment,
        Some(leaf_index),
        membership_path,
        membership_path.root,
        "confidential membership path",
    )
}
fn replace_confidential_path_leaf_v3(
    commitment: [u8; 32],
    leaf_index: usize,
    supplied: &ConfidentialMerklePathV2,
    context: &str,
) -> Result<ConfidentialMerklePathV2, String> {
    if leaf_index >= CONFIDENTIAL_TREE_CAPACITY_V2 {
        return Err(format!(
            "{context} leaf_index must be < {CONFIDENTIAL_TREE_CAPACITY_V2}"
        ));
    }
    if supplied.siblings.len() != CONFIDENTIAL_TREE_DEPTH_V2
        || supplied.directions.len() != CONFIDENTIAL_TREE_DEPTH_V2
    {
        return Err(format!(
            "{context} must contain exactly {CONFIDENTIAL_TREE_DEPTH_V2} siblings and directions"
        ));
    }
    let commitment = scalar_from_repr(commitment)
        .filter(|value| *value != Scalar::ZERO)
        .ok_or_else(|| format!("{context} commitment must be non-zero and canonical"))?;
    let mut node =
        confidential_poseidon_hash_v3(CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3, &[commitment]);
    let mut current_index = leaf_index;
    let mut witness_nodes = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
    for level in 0..CONFIDENTIAL_TREE_DEPTH_V2 {
        let expected_direction = u8::from(!current_index.is_multiple_of(2));
        if supplied.directions[level] != expected_direction {
            return Err(format!(
                "{context} direction[{level}] does not match leaf_index"
            ));
        }
        let sibling = scalar_from_repr(supplied.siblings[level]).ok_or_else(|| {
            format!("{context} sibling[{level}] must be a canonical Pasta scalar")
        })?;
        node = if expected_direction == 0 {
            merkle_parent_v3(node, sibling)
        } else {
            merkle_parent_v3(sibling, node)
        };
        witness_nodes.push(scalar_to_repr_bytes(node));
        current_index /= 2;
    }
    Ok(ConfidentialMerklePathV2 {
        siblings: supplied.siblings.clone(),
        directions: supplied.directions.clone(),
        witness_nodes,
        root: scalar_to_repr_bytes(node),
    })
}
/// Advance an authenticated append-only frontier by exactly one or two output commitments.
///
/// The supplied path must prove the canonical empty leaf at `next_zero_leaf_index`. Outputs are
/// inserted consecutively, and every returned membership path is rebound to the final root. This
/// is the only supported local derivation for ABI-21 output-membership witnesses.
pub fn derive_confidential_sequential_append_paths_v3(
    next_zero_leaf_index: usize,
    next_zero_path: &ConfidentialMerklePathV2,
    commitments: &[[u8; 32]],
) -> Result<ConfidentialSequentialAppendPathsV3, String> {
    if commitments.is_empty() || commitments.len() > 2 {
        return Err(
            "sequential confidential append requires exactly one or two outputs".to_owned(),
        );
    }
    let initial_root = next_zero_path.root;
    let mut frontier =
        validate_confidential_next_zero_path_v3(next_zero_leaf_index, next_zero_path)?;
    let mut leaves = Vec::with_capacity(commitments.len());
    let mut frontier_index = next_zero_leaf_index;
    for (offset, commitment) in commitments.iter().copied().enumerate() {
        let expected_index = next_zero_leaf_index
            .checked_add(offset)
            .ok_or_else(|| "sequential confidential append index overflowed".to_owned())?;
        if frontier_index != expected_index {
            return Err("sequential confidential append frontier is discontinuous".to_owned());
        }
        let membership_path = replace_confidential_path_leaf_v3(
            commitment,
            frontier_index,
            &frontier,
            "sequential confidential output",
        )?;
        let next_frontier = derive_confidential_next_zero_path_v2(
            commitment,
            frontier_index,
            &membership_path,
            membership_path.root,
        )?;
        leaves.push(ConfidentialSequentialAppendLeafPathsV3 {
            leaf_index: frontier_index,
            update_path: frontier,
            membership_path,
        });
        frontier_index = frontier_index
            .checked_add(1)
            .ok_or_else(|| "sequential confidential append index overflowed".to_owned())?;
        frontier = next_frontier;
    }
    let final_root = frontier.root;
    if leaves.len() == 2 {
        let first_index = leaves[0].leaf_index;
        let second_index = leaves[1].leaf_index;
        let differing_level =
            usize::BITS as usize - 1 - (first_index ^ second_index).leading_zeros() as usize;
        let second_subtree = if differing_level == 0 {
            let commitment = scalar_from_repr(commitments[1])
                .filter(|value| *value != Scalar::ZERO)
                .ok_or_else(|| {
                    "second sequential confidential output must be non-zero and canonical"
                        .to_owned()
                })?;
            confidential_poseidon_hash_v3(
                CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3,
                &[commitment],
            )
        } else {
            scalar_from_repr(leaves[1].membership_path.witness_nodes[differing_level - 1])
                .ok_or_else(|| {
                    "second sequential confidential output subtree is not canonical".to_owned()
                })?
        };
        leaves[0].membership_path.siblings[differing_level] = scalar_to_repr_bytes(second_subtree);
        leaves[0].membership_path = replace_confidential_path_leaf_v3(
            commitments[0],
            first_index,
            &leaves[0].membership_path,
            "first sequential confidential output final membership",
        )?;
    }
    if leaves
        .iter()
        .any(|leaf| leaf.membership_path.root != final_root)
    {
        return Err("sequential confidential append did not converge on one final root".to_owned());
    }
    Ok(ConfidentialSequentialAppendPathsV3 {
        initial_root,
        final_root,
        leaves,
        next_zero_leaf_index: frontier_index,
        next_zero_path: frontier,
    })
}
pub(super) fn normalize_supplied_confidential_merkle_path_v2(
    leaf_commitment: [u8; 32],
    leaf_index: Option<usize>,
    path: &ConfidentialMerklePathV2,
    root_hint: [u8; 32],
    context: &str,
) -> Result<ConfidentialMerklePathV2, String> {
    if let Some(index) = leaf_index
        && index >= CONFIDENTIAL_TREE_CAPACITY_V2
    {
        return Err(format!(
            "{context} leaf_index must be < {CONFIDENTIAL_TREE_CAPACITY_V2}"
        ));
    }
    if path.siblings.len() != CONFIDENTIAL_TREE_DEPTH_V2 {
        return Err(format!(
            "{context} must contain exactly {CONFIDENTIAL_TREE_DEPTH_V2} siblings"
        ));
    }
    if path.directions.len() != CONFIDENTIAL_TREE_DEPTH_V2 {
        return Err(format!(
            "{context} must contain exactly {CONFIDENTIAL_TREE_DEPTH_V2} directions"
        ));
    }
    if !path.witness_nodes.is_empty() && path.witness_nodes.len() != CONFIDENTIAL_TREE_DEPTH_V2 {
        return Err(format!(
            "{context} witness_nodes must contain exactly {CONFIDENTIAL_TREE_DEPTH_V2} nodes"
        ));
    }
    if path.root != root_hint {
        return Err(format!("{context} root does not match root_hint"));
    }
    let mut current_index = leaf_index;
    let commitment = scalar_from_repr(leaf_commitment)
        .ok_or_else(|| format!("{context} leaf commitment must be a canonical Pasta scalar"))?;
    let mut node =
        confidential_poseidon_hash_v3(CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3, &[commitment]);
    let mut witness_nodes = Vec::with_capacity(CONFIDENTIAL_TREE_DEPTH_V2);
    for level in 0..CONFIDENTIAL_TREE_DEPTH_V2 {
        let direction = path.directions[level];
        if direction > 1 {
            return Err(format!("{context} direction[{level}] must be 0 or 1"));
        }
        if let Some(index) = current_index.as_mut() {
            let expected = if index.is_multiple_of(2) { 0 } else { 1 };
            if direction != expected {
                return Err(format!(
                    "{context} direction[{level}] does not match leaf_index"
                ));
            }
            *index /= 2;
        }
        let sibling = scalar_from_repr(path.siblings[level]).ok_or_else(|| {
            format!("{context} sibling[{level}] must be a canonical Pasta scalar")
        })?;
        node = if direction == 0 {
            merkle_parent_v3(node, sibling)
        } else {
            merkle_parent_v3(sibling, node)
        };
        witness_nodes.push(scalar_to_repr_bytes(node));
    }
    let computed_root = scalar_to_repr_bytes(node);
    if computed_root != root_hint {
        return Err(format!("{context} does not prove the supplied root_hint"));
    }
    if !path.witness_nodes.is_empty() && path.witness_nodes != witness_nodes {
        return Err(format!(
            "{context} witness_nodes do not match the recomputed path"
        ));
    }
    Ok(ConfidentialMerklePathV2 {
        siblings: path.siblings.clone(),
        directions: path.directions.clone(),
        witness_nodes,
        root: computed_root,
    })
}
#[derive(Clone)]
/// Secret openings and authenticated paths consumed by the secure transfer
/// gadget when it is embedded in the recursive StepEq circuit.
pub(crate) struct ConfidentialTransferWitnessV2 {
    include_input_1: bool,
    include_output_1: bool,
    input_0_amount: u128,
    input_1_amount: u128,
    output_0_amount: u128,
    output_1_amount: u128,
    input_0_rho: [u8; 32],
    input_1_rho: [u8; 32],
    output_0_rho: [u8; 32],
    output_1_rho: [u8; 32],
    spend_scalar: [u8; 32],
    input_0_diversifier: [u8; 32],
    input_1_diversifier: [u8; 32],
    output_0_owner_tag: [u8; 32],
    output_1_owner_tag: [u8; 32],
    asset_tag: [u8; 32],
    network_tag: [u8; 32],
    input_0_path: ConfidentialMerklePathV2,
    input_1_path: ConfidentialMerklePathV2,
}
impl Zeroize for ConfidentialTransferWitnessV2 {
    fn zeroize(&mut self) {
        self.include_input_1.zeroize();
        self.include_output_1.zeroize();
        self.input_0_amount.zeroize();
        self.input_1_amount.zeroize();
        self.output_0_amount.zeroize();
        self.output_1_amount.zeroize();
        self.input_0_rho.zeroize();
        self.input_1_rho.zeroize();
        self.output_0_rho.zeroize();
        self.output_1_rho.zeroize();
        self.spend_scalar.zeroize();
        self.input_0_diversifier.zeroize();
        self.input_1_diversifier.zeroize();
        self.output_0_owner_tag.zeroize();
        self.output_1_owner_tag.zeroize();
        self.asset_tag.zeroize();
        self.network_tag.zeroize();
        self.input_0_path.zeroize();
        self.input_1_path.zeroize();
    }
}
impl Drop for ConfidentialTransferWitnessV2 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
#[derive(Clone)]
struct ConfidentialUnshieldWitnessV2 {
    include_input_1: bool,
    input_0_amount: u128,
    input_1_amount: u128,
    input_0_rho: [u8; 32],
    input_1_rho: [u8; 32],
    spend_scalar: [u8; 32],
    input_0_diversifier: [u8; 32],
    input_1_diversifier: [u8; 32],
    asset_tag: [u8; 32],
    network_tag: [u8; 32],
    input_0_path: ConfidentialMerklePathV2,
    input_1_path: ConfidentialMerklePathV2,
}
impl Zeroize for ConfidentialUnshieldWitnessV2 {
    fn zeroize(&mut self) {
        self.include_input_1.zeroize();
        self.input_0_amount.zeroize();
        self.input_1_amount.zeroize();
        self.input_0_rho.zeroize();
        self.input_1_rho.zeroize();
        self.spend_scalar.zeroize();
        self.input_0_diversifier.zeroize();
        self.input_1_diversifier.zeroize();
        self.asset_tag.zeroize();
        self.network_tag.zeroize();
        self.input_0_path.zeroize();
        self.input_1_path.zeroize();
    }
}
impl Drop for ConfidentialUnshieldWitnessV2 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
#[derive(Clone)]
/// Secret input openings, paths, and private change opening consumed by the
/// secure change-unshield gadget embedded in recursive StepEq.
pub(crate) struct ConfidentialUnshieldWitnessV3 {
    include_input_1: bool,
    include_output_0: bool,
    input_0_amount: u128,
    input_1_amount: u128,
    output_0_amount: u128,
    input_0_rho: [u8; 32],
    input_1_rho: [u8; 32],
    output_0_rho: [u8; 32],
    spend_scalar: [u8; 32],
    input_0_diversifier: [u8; 32],
    input_1_diversifier: [u8; 32],
    asset_tag: [u8; 32],
    network_tag: [u8; 32],
    input_0_path: ConfidentialMerklePathV2,
    input_1_path: ConfidentialMerklePathV2,
}
impl Zeroize for ConfidentialUnshieldWitnessV3 {
    fn zeroize(&mut self) {
        self.include_input_1.zeroize();
        self.include_output_0.zeroize();
        self.input_0_amount.zeroize();
        self.input_1_amount.zeroize();
        self.output_0_amount.zeroize();
        self.input_0_rho.zeroize();
        self.input_1_rho.zeroize();
        self.output_0_rho.zeroize();
        self.spend_scalar.zeroize();
        self.input_0_diversifier.zeroize();
        self.input_1_diversifier.zeroize();
        self.asset_tag.zeroize();
        self.network_tag.zeroize();
        self.input_0_path.zeroize();
        self.input_1_path.zeroize();
    }
}
impl Drop for ConfidentialUnshieldWitnessV3 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
fn encode_native_envelope(
    required_relation: super::ProofRelation,
    kind: native::Kind,
    vk_box: &VerifyingKeyBox,
    proved: iroha_data_model::zk::NativePipaRProofV1,
) -> Result<ProofBox, String> {
    native::validate_key(kind, vk_box)?;
    let envelope = OpenVerifyEnvelope {
        backend: BackendTag::NativePipaRPasta,
        circuit_id: kind.circuit_id().to_owned(),
        vk_hash: super::hash_vk(vk_box),
        public_inputs: kind.schema().to_vec(),
        proof_bytes: norito::encode_canonical(&proved).map_err(|error| error.to_string())?,
        aux: Vec::new(),
    };
    let proof = ProofBox::new(
        super::ZK_BACKEND_NATIVE_PIPA_R.to_owned(),
        norito::encode_canonical(&envelope).map_err(|error| error.to_string())?,
    );
    let cap = CONFIDENTIAL_V2_MAX_PROOF_BYTES as usize;
    super::verify_for_relation(
        required_relation,
        &proof,
        vk_box,
        super::ZkVerifyGuardrails {
            pipa_r_enabled: true,
            pipa_r_max_envelope_bytes: cap,
            pipa_r_max_proof_bytes: cap,
            stark_enabled: false,
            stark_max_envelope_bytes: 0,
            stark_max_proof_bytes: 0,
        },
    )
    .map_err(|error| format!("generated confidential proof failed local verification: {error}"))?;
    Ok(proof)
}
struct PreparedConfidentialTransferV3 {
    witness: ConfidentialTransferWitnessV2,
    input_commitments: [[u8; 32]; 2],
    nullifiers: [[u8; 32]; 2],
    output_commitments: [[u8; 32]; 2],
    root: [u8; 32],
    asset_tag: [u8; 32],
    network_tag: [u8; 32],
    input_count: usize,
    output_count: usize,
}
impl PreparedConfidentialTransferV3 {
    fn instance_columns(&self) -> Result<Vec<Vec<Scalar>>, String> {
        let values = [
            self.input_commitments[0],
            self.input_commitments[1],
            self.nullifiers[0],
            self.nullifiers[1],
            self.output_commitments[0],
            self.output_commitments[1],
            self.root,
            self.asset_tag,
            self.network_tag,
        ];
        values
            .into_iter()
            .enumerate()
            .map(|(index, bytes)| {
                scalar_from_repr(bytes)
                    .or_else(|| (bytes == [0; 32]).then_some(Scalar::ZERO))
                    .map(|value| vec![value])
                    .ok_or_else(|| {
                        format!(
                            "confidential transfer public column {index} is not a canonical Pasta scalar"
                        )
                    })
            })
            .collect()
    }
}
#[allow(clippy::too_many_arguments)]
fn prepare_confidential_transfer_v3_resolved_paths(
    network_id: &NetworkId,
    asset_definition_id: &str,
    spend_key: &[u8],
    inputs: &[ConfidentialTransferInputV2],
    outputs: &[ConfidentialTransferOutputV2],
    root_hint: [u8; 32],
    resolve_input_paths: impl FnOnce(
        &ConfidentialTransferInputV2,
        Option<&ConfidentialTransferInputV2>,
        [u8; 32],
        [u8; 32],
    ) -> Result<
        (ConfidentialMerklePathV2, ConfidentialMerklePathV2),
        String,
    >,
) -> Result<PreparedConfidentialTransferV3, String> {
    if inputs.is_empty() || inputs.len() > 2 {
        return Err("confidential transfer v2 supports one or two inputs".to_owned());
    }
    if outputs.is_empty() || outputs.len() > 2 {
        return Err("confidential transfer v2 supports one or two outputs".to_owned());
    }
    let input_total = inputs.iter().try_fold(0u128, |sum, input| {
        sum.checked_add(input.amount)
            .ok_or_else(|| "confidential transfer input sum overflows u128".to_owned())
    })?;
    let output_total = outputs.iter().try_fold(0u128, |sum, output| {
        sum.checked_add(output.amount)
            .ok_or_else(|| "confidential transfer output sum overflows u128".to_owned())
    })?;
    if input_total != output_total {
        return Err("confidential transfer input and output sums must match exactly".to_owned());
    }
    let spend_scalar = hash_to_scalar(b"iroha.confidential.v3.spend_scalar", &[spend_key]);
    let spend_scalar_bytes = Zeroizing::new(scalar_to_repr_bytes(spend_scalar));
    let asset_tag = derive_confidential_asset_tag_v3(asset_definition_id)?;
    let network_tag = derive_confidential_network_tag_v3(network_id)?;
    let input_0 = inputs
        .first()
        .cloned()
        .ok_or_else(|| "missing transfer input".to_owned())?;
    let input_1 = inputs.get(1).cloned();
    let output_0 = outputs
        .first()
        .cloned()
        .ok_or_else(|| "missing transfer output".to_owned())?;
    let output_1 = outputs.get(1).cloned();
    let input_0_owner_tag =
        derive_confidential_owner_tag_v2_with_diversifier(spend_key, input_0.diversifier)?;
    let input_0_commitment = derive_confidential_note_v2(
        asset_definition_id,
        input_0.amount,
        input_0.rho,
        input_0_owner_tag,
    )?;
    let input_1_commitment = if let Some(note) = input_1.as_ref() {
        let owner_tag =
            derive_confidential_owner_tag_v2_with_diversifier(spend_key, note.diversifier)?;
        derive_confidential_note_v2(asset_definition_id, note.amount, note.rho, owner_tag)?
    } else {
        [0u8; 32]
    };
    let (input_0_path, input_1_path) = resolve_input_paths(
        &input_0,
        input_1.as_ref(),
        input_0_commitment,
        input_1_commitment,
    )?;
    let output_0_commitment = derive_confidential_note_v2(
        asset_definition_id,
        output_0.amount,
        output_0.rho,
        output_0.owner_tag,
    )?;
    let output_1_commitment = if let Some(note) = output_1.as_ref() {
        derive_confidential_note_v2(asset_definition_id, note.amount, note.rho, note.owner_tag)?
    } else {
        [0u8; 32]
    };
    let nullifier_0 =
        derive_confidential_nullifier_v3(spend_key, input_0.rho, asset_tag, network_tag)?;
    let nullifier_1 = if let Some(note) = input_1.as_ref() {
        derive_confidential_nullifier_v3(spend_key, note.rho, asset_tag, network_tag)?
    } else {
        [0u8; 32]
    };
    let witness = ConfidentialTransferWitnessV2 {
        include_input_1: input_1.is_some(),
        include_output_1: output_1.is_some(),
        input_0_amount: input_0.amount,
        input_1_amount: input_1.as_ref().map_or(0, |note| note.amount),
        output_0_amount: output_0.amount,
        output_1_amount: output_1.as_ref().map_or(0, |note| note.amount),
        input_0_rho: input_0.rho,
        input_1_rho: input_1.as_ref().map_or([0u8; 32], |note| note.rho),
        output_0_rho: output_0.rho,
        output_1_rho: output_1.as_ref().map_or([0u8; 32], |note| note.rho),
        spend_scalar: *spend_scalar_bytes,
        input_0_diversifier: input_0.diversifier,
        input_1_diversifier: input_1.as_ref().map_or([0; 32], |note| note.diversifier),
        output_0_owner_tag: output_0.owner_tag,
        output_1_owner_tag: output_1.as_ref().map_or([0u8; 32], |note| note.owner_tag),
        asset_tag,
        network_tag,
        input_0_path,
        input_1_path,
    };
    witness_validation::validate_transfer_witness::<CONFIDENTIAL_TREE_DEPTH_V2>(&witness)?;
    Ok(PreparedConfidentialTransferV3 {
        witness,
        input_commitments: [input_0_commitment, input_1_commitment],
        nullifiers: [nullifier_0, nullifier_1],
        output_commitments: [output_0_commitment, output_1_commitment],
        root: root_hint,
        asset_tag,
        network_tag,
        input_count: inputs.len(),
        output_count: outputs.len(),
    })
}
#[allow(clippy::too_many_arguments)]
fn build_confidential_transfer_proof_v2_resolved_paths(
    network_id: &NetworkId,
    asset_definition_id: &str,
    spend_key: &[u8],
    inputs: &[ConfidentialTransferInputV2],
    outputs: &[ConfidentialTransferOutputV2],
    root_hint: [u8; 32],
    circuit_id: &str,
    vk_box: &VerifyingKeyBox,
    resolve_input_paths: impl FnOnce(
        &ConfidentialTransferInputV2,
        Option<&ConfidentialTransferInputV2>,
        [u8; 32],
        [u8; 32],
    ) -> Result<
        (ConfidentialMerklePathV2, ConfidentialMerklePathV2),
        String,
    >,
) -> Result<ConfidentialTransferProofV2, String> {
    ensure_confidential_transfer_v2_canonical_vk_box(vk_box)?;
    if circuit_id != native::Kind::Transfer.circuit_id() {
        return Err("unsupported native confidential circuit identifier".to_owned());
    }
    native::validate_key(native::Kind::Transfer, vk_box)?;
    let prepared = prepare_confidential_transfer_v3_resolved_paths(
        network_id,
        asset_definition_id,
        spend_key,
        inputs,
        outputs,
        root_hint,
        resolve_input_paths,
    )?;
    let instance_columns = prepared.instance_columns()?;
    let PreparedConfidentialTransferV3 {
        witness,
        nullifiers,
        output_commitments,
        root,
        input_count,
        output_count,
        ..
    } = prepared;
    let proved = native::prove_transfer(witness, instance_columns)?;
    let proof = encode_native_envelope(
        super::ProofRelation::ConfidentialTransfer,
        native::Kind::Transfer,
        vk_box,
        proved,
    )?;
    Ok(ConfidentialTransferProofV2 {
        nullifiers: nullifiers[..input_count].to_vec(),
        output_commitments: output_commitments[..output_count].to_vec(),
        root,
        proof,
    })
}
/// Build a confidential transfer proof, deriving input paths from the tree.
///
/// Wallet callers use [`super::confidential::ConfidentialProver`].
/// This circuit-specific entrypoint is internal:
///
/// ```compile_fail,E0603
/// use iroha_core_zk::confidential_v2::build_confidential_transfer_proof_v2;
/// ```
pub(super) fn build_confidential_transfer_proof_v2(
    network_id: &NetworkId,
    asset_definition_id: &str,
    spend_key: &[u8],
    tree_commitments: &[[u8; 32]],
    inputs: &[ConfidentialTransferInputV2],
    outputs: &[ConfidentialTransferOutputV2],
    root_hint: [u8; 32],
    circuit_id: &str,
    vk_box: &VerifyingKeyBox,
) -> Result<ConfidentialTransferProofV2, String> {
    validate_confidential_tree_input_shape_v3(
        tree_commitments.len(),
        inputs.iter().map(|input| input.leaf_index),
    )?;
    if outputs.is_empty() || outputs.len() > 2 {
        return Err("confidential transfer v2 supports one or two outputs".to_owned());
    }
    let computed_root = compute_confidential_root_v2(tree_commitments)?;
    if computed_root != root_hint {
        return Err("tree commitments do not match the supplied root_hint".to_owned());
    }
    build_confidential_transfer_proof_v2_resolved_paths(
        network_id,
        asset_definition_id,
        spend_key,
        inputs,
        outputs,
        root_hint,
        circuit_id,
        vk_box,
        |input_0, input_1, input_0_commitment, input_1_commitment| {
            if tree_commitments
                .get(input_0.leaf_index)
                .copied()
                .unwrap_or_default()
                != input_0_commitment
            {
                return Err(
                    "transfer input 0 does not match the current confidential tree".to_owned(),
                );
            }
            if let Some(note) = input_1
                && tree_commitments
                    .get(note.leaf_index)
                    .copied()
                    .unwrap_or_default()
                    != input_1_commitment
            {
                return Err(
                    "transfer input 1 does not match the current confidential tree".to_owned(),
                );
            }
            let input_0_path =
                compute_confidential_merkle_path_v2(tree_commitments, input_0.leaf_index)?;
            let input_1_path = confidential_optional_input_path_v3(
                tree_commitments,
                input_1.map(|note| note.leaf_index),
            )?;
            if input_0_path.root != root_hint
                || (input_1.is_some() && input_1_path.root != root_hint)
            {
                return Err("computed confidential Merkle path does not match root_hint".to_owned());
            }
            Ok((input_0_path, input_1_path))
        },
    )
}
fn normalize_confidential_transfer_paths_v3(
    input_paths: &[ConfidentialMerklePathV2],
    root_hint: [u8; 32],
    input_0: &ConfidentialTransferInputV2,
    input_1: Option<&ConfidentialTransferInputV2>,
    input_0_commitment: [u8; 32],
    input_1_commitment: [u8; 32],
) -> Result<(ConfidentialMerklePathV2, ConfidentialMerklePathV2), String> {
    let expected_paths = 1 + usize::from(input_1.is_some());
    if input_paths.len() != expected_paths {
        return Err(format!(
            "confidential transfer v2 path mode requires exactly {expected_paths} input paths"
        ));
    }
    let input_0_path = normalize_supplied_confidential_merkle_path_v2(
        input_0_commitment,
        Some(input_0.leaf_index),
        &input_paths[0],
        root_hint,
        "transfer input 0 path",
    )?;
    let input_1_path = if let Some(note) = input_1 {
        normalize_supplied_confidential_merkle_path_v2(
            input_1_commitment,
            Some(note.leaf_index),
            &input_paths[1],
            root_hint,
            "transfer input 1 path",
        )?
    } else {
        confidential_absent_input_path_v3::<CONFIDENTIAL_TREE_DEPTH_V2>()
    };
    Ok((input_0_path, input_1_path))
}
/// Build a confidential transfer proof with one membership path per actual input.
/// An absent second input is padded internally and needs no caller-supplied path.
///
/// Wallet callers use [`super::confidential::ConfidentialProver`].
/// This circuit-specific entrypoint is internal:
///
/// ```compile_fail,E0603
/// use iroha_core_zk::confidential_v2::build_confidential_transfer_proof_v2_with_paths;
/// ```
pub(super) fn build_confidential_transfer_proof_v2_with_paths(
    network_id: &NetworkId,
    asset_definition_id: &str,
    spend_key: &[u8],
    input_paths: &[ConfidentialMerklePathV2],
    inputs: &[ConfidentialTransferInputV2],
    outputs: &[ConfidentialTransferOutputV2],
    root_hint: [u8; 32],
    circuit_id: &str,
    vk_box: &VerifyingKeyBox,
) -> Result<ConfidentialTransferProofV2, String> {
    build_confidential_transfer_proof_v2_resolved_paths(
        network_id,
        asset_definition_id,
        spend_key,
        inputs,
        outputs,
        root_hint,
        circuit_id,
        vk_box,
        |input_0, input_1, input_0_commitment, input_1_commitment| {
            normalize_confidential_transfer_paths_v3(
                input_paths,
                root_hint,
                input_0,
                input_1,
                input_0_commitment,
                input_1_commitment,
            )
        },
    )
}
#[allow(clippy::too_many_arguments)]
fn build_confidential_unshield_proof_v2_resolved_paths(
    network_id: &NetworkId,
    asset_definition_id: &str,
    spend_key: &[u8],
    inputs: &[ConfidentialUnshieldInputV2],
    public_amount: u128,
    root_hint: [u8; 32],
    circuit_id: &str,
    vk_box: &VerifyingKeyBox,
    resolve_input_paths: impl FnOnce(
        &ConfidentialUnshieldInputV2,
        Option<&ConfidentialUnshieldInputV2>,
        [u8; 32],
        [u8; 32],
    ) -> Result<
        (ConfidentialMerklePathV2, ConfidentialMerklePathV2),
        String,
    >,
) -> Result<ConfidentialUnshieldProofV2, String> {
    if inputs.is_empty() || inputs.len() > 2 {
        return Err("confidential unshield v2 supports one or two inputs".to_owned());
    }
    let expected_public_amount = inputs.iter().try_fold(0u128, |sum, input| {
        sum.checked_add(input.amount)
            .ok_or_else(|| "full-unshield input sum overflows u128".to_owned())
    })?;
    if public_amount == 0 || public_amount != expected_public_amount {
        return Err(
            "full-unshield public amount must equal the exact non-zero input sum".to_owned(),
        );
    }
    ensure_confidential_unshield_v2_canonical_vk_box(vk_box)?;
    if circuit_id != native::Kind::Full.circuit_id() {
        return Err("unsupported native confidential circuit identifier".to_owned());
    }
    native::validate_key(native::Kind::Full, vk_box)?;
    let spend_scalar = hash_to_scalar(b"iroha.confidential.v3.spend_scalar", &[spend_key]);
    let spend_scalar_bytes = Zeroizing::new(scalar_to_repr_bytes(spend_scalar));
    let asset_tag = derive_confidential_asset_tag_v3(asset_definition_id)?;
    let network_tag = derive_confidential_network_tag_v3(network_id)?;
    let input_0 = inputs
        .first()
        .cloned()
        .ok_or_else(|| "missing unshield input".to_owned())?;
    let input_1 = inputs.get(1).cloned();
    let input_0_owner_tag =
        derive_confidential_owner_tag_v2_with_diversifier(spend_key, input_0.diversifier)?;
    let input_0_commitment = derive_confidential_note_v2(
        asset_definition_id,
        input_0.amount,
        input_0.rho,
        input_0_owner_tag,
    )?;
    let input_1_commitment = if let Some(note) = input_1.as_ref() {
        let owner_tag =
            derive_confidential_owner_tag_v2_with_diversifier(spend_key, note.diversifier)?;
        derive_confidential_note_v2(asset_definition_id, note.amount, note.rho, owner_tag)?
    } else {
        [0u8; 32]
    };
    let (input_0_path, input_1_path) = resolve_input_paths(
        &input_0,
        input_1.as_ref(),
        input_0_commitment,
        input_1_commitment,
    )?;
    let nullifier_0 =
        derive_confidential_nullifier_v3(spend_key, input_0.rho, asset_tag, network_tag)?;
    let nullifier_1 = if let Some(note) = input_1.as_ref() {
        derive_confidential_nullifier_v3(spend_key, note.rho, asset_tag, network_tag)?
    } else {
        [0u8; 32]
    };
    let witness = ConfidentialUnshieldWitnessV2 {
        include_input_1: input_1.is_some(),
        input_0_amount: input_0.amount,
        input_1_amount: input_1.as_ref().map_or(0, |note| note.amount),
        input_0_rho: input_0.rho,
        input_1_rho: input_1.as_ref().map_or([0u8; 32], |note| note.rho),
        spend_scalar: *spend_scalar_bytes,
        input_0_diversifier: input_0.diversifier,
        input_1_diversifier: input_1.as_ref().map_or([0; 32], |note| note.diversifier),
        asset_tag,
        network_tag,
        input_0_path,
        input_1_path,
    };
    let public = ConfidentialUnshieldFullPublicInputsV1 {
        input_commitment_0: input_0_commitment,
        input_commitment_1: input_1_commitment,
        nullifier_0,
        nullifier_1,
        root: root_hint,
        public_amount: scalar_to_repr_bytes(scalar_from_u128(public_amount)),
        asset_tag,
        network_tag,
    };
    let instance_columns = public
        .try_map(|field: ConfidentialUnshieldFullPublicInputV1, bytes| {
            scalar_from_repr(bytes)
                .or_else(|| (bytes == [0; 32]).then_some(Scalar::ZERO))
                .map(|value| vec![value])
                .ok_or_else(|| {
                    format!(
                        "full-unshield public input '{}' at column {} is not a canonical Pasta scalar",
                        field.name(),
                        field.index(),
                    )
                })
        })?
        .into_array()
        .to_vec();
    let proved = native::prove_full(witness, instance_columns)?;
    let proof = encode_native_envelope(
        super::ProofRelation::ConfidentialFullUnshield,
        native::Kind::Full,
        vk_box,
        proved,
    )?;
    Ok(ConfidentialUnshieldProofV2 {
        nullifiers: if input_1.is_some() {
            vec![nullifier_0, nullifier_1]
        } else {
            vec![nullifier_0]
        },
        root: root_hint,
        proof,
    })
}
/// Build a full confidential unshield proof from an in-memory tree.
///
/// Wallet callers use [`super::confidential::ConfidentialProver`].
/// This circuit-specific entrypoint is internal:
///
/// ```compile_fail,E0603
/// use iroha_core_zk::confidential_v2::build_confidential_unshield_proof_v2;
/// ```
pub(super) fn build_confidential_unshield_proof_v2(
    network_id: &NetworkId,
    asset_definition_id: &str,
    spend_key: &[u8],
    tree_commitments: &[[u8; 32]],
    inputs: &[ConfidentialUnshieldInputV2],
    public_amount: u128,
    root_hint: [u8; 32],
    circuit_id: &str,
    vk_box: &VerifyingKeyBox,
) -> Result<ConfidentialUnshieldProofV2, String> {
    validate_confidential_tree_input_shape_v3(
        tree_commitments.len(),
        inputs.iter().map(|input| input.leaf_index),
    )?;
    let computed_root = compute_confidential_root_v2(tree_commitments)?;
    if computed_root != root_hint {
        return Err("tree commitments do not match the supplied root_hint".to_owned());
    }
    build_confidential_unshield_proof_v2_resolved_paths(
        network_id,
        asset_definition_id,
        spend_key,
        inputs,
        public_amount,
        root_hint,
        circuit_id,
        vk_box,
        |input_0, input_1, input_0_commitment, input_1_commitment| {
            if tree_commitments
                .get(input_0.leaf_index)
                .copied()
                .unwrap_or_default()
                != input_0_commitment
            {
                return Err(
                    "unshield input 0 does not match the current confidential tree".to_owned(),
                );
            }
            if let Some(note) = input_1
                && tree_commitments
                    .get(note.leaf_index)
                    .copied()
                    .unwrap_or_default()
                    != input_1_commitment
            {
                return Err(
                    "unshield input 1 does not match the current confidential tree".to_owned(),
                );
            }
            let input_0_path =
                compute_confidential_merkle_path_v2(tree_commitments, input_0.leaf_index)?;
            let input_1_path = confidential_optional_input_path_v3(
                tree_commitments,
                input_1.map(|note| note.leaf_index),
            )?;
            if input_0_path.root != root_hint
                || (input_1.is_some() && input_1_path.root != root_hint)
            {
                return Err("computed confidential Merkle path does not match root_hint".to_owned());
            }
            Ok((input_0_path, input_1_path))
        },
    )
}
fn normalize_confidential_unshield_full_paths_v3(
    input_paths: &[ConfidentialMerklePathV2],
    root_hint: [u8; 32],
    input_0: &ConfidentialUnshieldInputV2,
    input_1: Option<&ConfidentialUnshieldInputV2>,
    input_0_commitment: [u8; 32],
    input_1_commitment: [u8; 32],
) -> Result<(ConfidentialMerklePathV2, ConfidentialMerklePathV2), String> {
    let expected_paths = 1 + usize::from(input_1.is_some());
    if input_paths.len() != expected_paths {
        return Err(format!(
            "full confidential unshield path mode requires exactly {expected_paths} input paths"
        ));
    }
    let input_0_path = normalize_supplied_confidential_merkle_path_v2(
        input_0_commitment,
        Some(input_0.leaf_index),
        &input_paths[0],
        root_hint,
        "full unshield input 0 path",
    )?;
    let input_1_path = if let Some(note) = input_1 {
        normalize_supplied_confidential_merkle_path_v2(
            input_1_commitment,
            Some(note.leaf_index),
            &input_paths[1],
            root_hint,
            "full unshield input 1 path",
        )?
    } else {
        confidential_absent_input_path_v3::<CONFIDENTIAL_TREE_DEPTH_V2>()
    };
    Ok((input_0_path, input_1_path))
}
/// Build a terminal full-redemption proof with one canonically normalized
/// membership path per actual input. No private change output is
/// invented and no change-preserving circuit is selected.
///
/// Wallet callers use [`super::confidential::ConfidentialProver`].
/// This circuit-specific entrypoint is internal:
///
/// ```compile_fail,E0603
/// use iroha_core_zk::confidential_v2::build_confidential_unshield_proof_v2_with_paths;
/// ```
#[allow(clippy::too_many_arguments)]
pub(super) fn build_confidential_unshield_proof_v2_with_paths(
    network_id: &NetworkId,
    asset_definition_id: &str,
    spend_key: &[u8],
    input_paths: &[ConfidentialMerklePathV2],
    inputs: &[ConfidentialUnshieldInputV2],
    public_amount: u128,
    root_hint: [u8; 32],
    circuit_id: &str,
    vk_box: &VerifyingKeyBox,
) -> Result<ConfidentialUnshieldProofV2, String> {
    build_confidential_unshield_proof_v2_resolved_paths(
        network_id,
        asset_definition_id,
        spend_key,
        inputs,
        public_amount,
        root_hint,
        circuit_id,
        vk_box,
        |input_0, input_1, input_0_commitment, input_1_commitment| {
            normalize_confidential_unshield_full_paths_v3(
                input_paths,
                root_hint,
                input_0,
                input_1,
                input_0_commitment,
                input_1_commitment,
            )
        },
    )
}
struct PreparedConfidentialUnshieldChangeV4 {
    witness: ConfidentialUnshieldWitnessV3,
    public: ConfidentialUnshieldChangePublicInputsV1,
    nullifiers: [[u8; 32]; 2],
    change_commitment: [u8; 32],
    root: [u8; 32],
    input_count: usize,
}
impl PreparedConfidentialUnshieldChangeV4 {
    fn instance_columns(&self) -> Result<Vec<Vec<Scalar>>, String> {
        self.public
            .try_map(|field, bytes| {
                scalar_from_repr(bytes)
                    .or_else(|| (bytes == [0; 32]).then_some(Scalar::ZERO))
                    .map(|value| vec![value])
                    .ok_or_else(|| {
                        format!(
                            "change-unshield public input '{}' at column {} is not a canonical Pasta scalar",
                            field.name(),
                            field.index(),
                        )
                    })
            })
            .map(|public| public.into_array().to_vec())
    }
}
#[allow(clippy::too_many_arguments)]
fn prepare_confidential_unshield_change_v4_resolved_paths(
    network_id: &NetworkId,
    asset_definition_id: &str,
    spend_key: &[u8],
    inputs: &[ConfidentialUnshieldInputV2],
    outputs: &[ConfidentialUnshieldOutputV3],
    public_amount: u128,
    root_hint: [u8; 32],
    resolve_input_paths: impl FnOnce(
        &ConfidentialUnshieldInputV2,
        Option<&ConfidentialUnshieldInputV2>,
        [u8; 32],
        [u8; 32],
    ) -> Result<
        (ConfidentialMerklePathV2, ConfidentialMerklePathV2),
        String,
    >,
) -> Result<PreparedConfidentialUnshieldChangeV4, String> {
    if inputs.is_empty() || inputs.len() > 2 {
        return Err("confidential unshield v3 supports one or two inputs".to_owned());
    }
    if outputs.len() > 1 {
        return Err(
            "confidential unshield v3 supports at most one private change output".to_owned(),
        );
    }
    let change_owner_tag = derive_confidential_owner_tag_v2(spend_key)?;
    let spend_scalar = hash_to_scalar(b"iroha.confidential.v3.spend_scalar", &[spend_key]);
    let spend_scalar_bytes = Zeroizing::new(scalar_to_repr_bytes(spend_scalar));
    let asset_tag = derive_confidential_asset_tag_v3(asset_definition_id)?;
    let network_tag = derive_confidential_network_tag_v3(network_id)?;
    let input_0 = inputs
        .first()
        .cloned()
        .ok_or_else(|| "missing unshield input".to_owned())?;
    let input_1 = inputs.get(1).cloned();
    let output_0 = outputs.first().cloned();
    let input_0_owner_tag =
        derive_confidential_owner_tag_v2_with_diversifier(spend_key, input_0.diversifier)?;
    let input_0_commitment = derive_confidential_note_v2(
        asset_definition_id,
        input_0.amount,
        input_0.rho,
        input_0_owner_tag,
    )?;
    let input_1_commitment = if let Some(note) = input_1.as_ref() {
        let owner_tag =
            derive_confidential_owner_tag_v2_with_diversifier(spend_key, note.diversifier)?;
        derive_confidential_note_v2(asset_definition_id, note.amount, note.rho, owner_tag)?
    } else {
        [0u8; 32]
    };
    let (input_0_path, input_1_path) = resolve_input_paths(
        &input_0,
        input_1.as_ref(),
        input_0_commitment,
        input_1_commitment,
    )?;
    let total_input_amount = input_0
        .amount
        .checked_add(input_1.as_ref().map_or(0, |note| note.amount))
        .ok_or_else(|| "confidential unshield v3 input amount sum overflows u128".to_owned())?;
    let expected_change_amount = total_input_amount
        .checked_sub(public_amount)
        .ok_or_else(|| "public amount exceeds the available confidential inputs".to_owned())?;
    let output_0_commitment = match (output_0.as_ref(), expected_change_amount) {
        (None, 0) => [0; 32],
        (Some(output_note), expected)
            if expected != 0 && output_note.amount == expected && output_note.rho != [0; 32] =>
        {
            derive_confidential_note_v2(
                asset_definition_id,
                output_note.amount,
                output_note.rho,
                change_owner_tag,
            )?
        }
        (None, _) => {
            return Err("non-zero unshield remainder requires a private change output".to_owned());
        }
        (Some(_), 0) => {
            return Err("terminal full unshield must not create private change".to_owned());
        }
        (Some(_), _) => {
            return Err("change note amount mismatch".to_owned());
        }
    };
    let nullifier_0 =
        derive_confidential_nullifier_v3(spend_key, input_0.rho, asset_tag, network_tag)?;
    let nullifier_1 = if let Some(note) = input_1.as_ref() {
        derive_confidential_nullifier_v3(spend_key, note.rho, asset_tag, network_tag)?
    } else {
        [0u8; 32]
    };
    let witness = ConfidentialUnshieldWitnessV3 {
        include_input_1: input_1.is_some(),
        include_output_0: output_0.is_some(),
        input_0_amount: input_0.amount,
        input_1_amount: input_1.as_ref().map_or(0, |note| note.amount),
        output_0_amount: output_0.as_ref().map_or(0, |note| note.amount),
        input_0_rho: input_0.rho,
        input_1_rho: input_1.as_ref().map_or([0u8; 32], |note| note.rho),
        output_0_rho: output_0.as_ref().map_or([0u8; 32], |note| note.rho),
        spend_scalar: *spend_scalar_bytes,
        input_0_diversifier: input_0.diversifier,
        input_1_diversifier: input_1.as_ref().map_or([0; 32], |note| note.diversifier),
        asset_tag,
        network_tag,
        input_0_path,
        input_1_path,
    };
    witness_validation::validate_unshield_v3_witness::<CONFIDENTIAL_TREE_DEPTH_V2>(&witness)?;
    Ok(PreparedConfidentialUnshieldChangeV4 {
        witness,
        public: ConfidentialUnshieldChangePublicInputsV1 {
            input_commitment_0: input_0_commitment,
            input_commitment_1: input_1_commitment,
            nullifier_0,
            nullifier_1,
            change_commitment_0: output_0_commitment,
            root: root_hint,
            public_amount: scalar_to_repr_bytes(scalar_from_u128(public_amount)),
            asset_tag,
            network_tag,
        },
        nullifiers: [nullifier_0, nullifier_1],
        change_commitment: output_0_commitment,
        root: root_hint,
        input_count: inputs.len(),
    })
}
#[allow(clippy::too_many_arguments)]
fn build_confidential_unshield_proof_v3_resolved_paths(
    network_id: &NetworkId,
    asset_definition_id: &str,
    spend_key: &[u8],
    inputs: &[ConfidentialUnshieldInputV2],
    outputs: &[ConfidentialUnshieldOutputV3],
    public_amount: u128,
    root_hint: [u8; 32],
    circuit_id: &str,
    vk_box: &VerifyingKeyBox,
    resolve_input_paths: impl FnOnce(
        &ConfidentialUnshieldInputV2,
        Option<&ConfidentialUnshieldInputV2>,
        [u8; 32],
        [u8; 32],
    ) -> Result<
        (ConfidentialMerklePathV2, ConfidentialMerklePathV2),
        String,
    >,
) -> Result<ConfidentialUnshieldProofV3, String> {
    ensure_confidential_unshield_v3_canonical_vk_box(vk_box)?;
    if circuit_id != native::Kind::Change.circuit_id() {
        return Err("unsupported native confidential circuit identifier".to_owned());
    }
    native::validate_key(native::Kind::Change, vk_box)?;
    let prepared = prepare_confidential_unshield_change_v4_resolved_paths(
        network_id,
        asset_definition_id,
        spend_key,
        inputs,
        outputs,
        public_amount,
        root_hint,
        resolve_input_paths,
    )?;
    let instance_columns = prepared.instance_columns()?;
    let PreparedConfidentialUnshieldChangeV4 {
        witness,
        nullifiers,
        change_commitment,
        root,
        input_count,
        ..
    } = prepared;
    let proved = native::prove_change(witness, instance_columns)?;
    let proof = encode_native_envelope(
        super::ProofRelation::ConfidentialChangeUnshield,
        native::Kind::Change,
        vk_box,
        proved,
    )?;
    Ok(ConfidentialUnshieldProofV3 {
        nullifiers: nullifiers[..input_count].to_vec(),
        output_commitments: (change_commitment != [0; 32])
            .then_some(change_commitment)
            .into_iter()
            .collect(),
        root,
        proof,
    })
}
/// Build a terminal-full or change-preserving V3 unshield proof, deriving input paths.
///
/// Wallet callers use [`super::confidential::ConfidentialProver`].
/// This circuit-specific entrypoint is internal:
///
/// ```compile_fail,E0603
/// use iroha_core_zk::confidential_v2::build_confidential_unshield_proof_v3;
/// ```
pub(super) fn build_confidential_unshield_proof_v3(
    network_id: &NetworkId,
    asset_definition_id: &str,
    spend_key: &[u8],
    tree_commitments: &[[u8; 32]],
    inputs: &[ConfidentialUnshieldInputV2],
    outputs: &[ConfidentialUnshieldOutputV3],
    public_amount: u128,
    root_hint: [u8; 32],
    circuit_id: &str,
    vk_box: &VerifyingKeyBox,
) -> Result<ConfidentialUnshieldProofV3, String> {
    validate_confidential_tree_input_shape_v3(
        tree_commitments.len(),
        inputs.iter().map(|input| input.leaf_index),
    )?;
    if outputs.len() > 1 {
        return Err(
            "confidential unshield v3 supports at most one private change output".to_owned(),
        );
    }
    let computed_root = compute_confidential_root_v2(tree_commitments)?;
    if computed_root != root_hint {
        return Err("tree commitments do not match the supplied root_hint".to_owned());
    }
    build_confidential_unshield_proof_v3_resolved_paths(
        network_id,
        asset_definition_id,
        spend_key,
        inputs,
        outputs,
        public_amount,
        root_hint,
        circuit_id,
        vk_box,
        |input_0, input_1, input_0_commitment, input_1_commitment| {
            if tree_commitments
                .get(input_0.leaf_index)
                .copied()
                .unwrap_or_default()
                != input_0_commitment
            {
                return Err(
                    "unshield input 0 does not match the current confidential tree".to_owned(),
                );
            }
            if let Some(note) = input_1
                && tree_commitments
                    .get(note.leaf_index)
                    .copied()
                    .unwrap_or_default()
                    != input_1_commitment
            {
                return Err(
                    "unshield input 1 does not match the current confidential tree".to_owned(),
                );
            }
            let input_0_path =
                compute_confidential_merkle_path_v2(tree_commitments, input_0.leaf_index)?;
            let input_1_path = confidential_optional_input_path_v3(
                tree_commitments,
                input_1.map(|note| note.leaf_index),
            )?;
            if input_0_path.root != root_hint
                || (input_1.is_some() && input_1_path.root != root_hint)
            {
                return Err("computed confidential Merkle path does not match root_hint".to_owned());
            }
            Ok((input_0_path, input_1_path))
        },
    )
}
fn normalize_confidential_unshield_change_paths_v4(
    input_paths: &[ConfidentialMerklePathV2],
    root_hint: [u8; 32],
    input_0: &ConfidentialUnshieldInputV2,
    input_1: Option<&ConfidentialUnshieldInputV2>,
    input_0_commitment: [u8; 32],
    input_1_commitment: [u8; 32],
) -> Result<(ConfidentialMerklePathV2, ConfidentialMerklePathV2), String> {
    let expected_paths = 1 + usize::from(input_1.is_some());
    if input_paths.len() != expected_paths {
        return Err(format!(
            "confidential unshield v3 path mode requires exactly {expected_paths} input paths"
        ));
    }
    let input_0_path = normalize_supplied_confidential_merkle_path_v2(
        input_0_commitment,
        Some(input_0.leaf_index),
        &input_paths[0],
        root_hint,
        "unshield input 0 path",
    )?;
    let input_1_path = if let Some(note) = input_1 {
        normalize_supplied_confidential_merkle_path_v2(
            input_1_commitment,
            Some(note.leaf_index),
            &input_paths[1],
            root_hint,
            "unshield input 1 path",
        )?
    } else {
        confidential_absent_input_path_v3::<CONFIDENTIAL_TREE_DEPTH_V2>()
    };
    Ok((input_0_path, input_1_path))
}
/// Build a terminal-full or change-preserving V3 unshield with one path per actual input.
/// An absent second input is padded internally and needs no caller-supplied path.
///
/// Wallet callers use [`super::confidential::ConfidentialProver`].
/// This circuit-specific entrypoint is internal:
///
/// ```compile_fail,E0603
/// use iroha_core_zk::confidential_v2::build_confidential_unshield_proof_v3_with_paths;
/// ```
pub(super) fn build_confidential_unshield_proof_v3_with_paths(
    network_id: &NetworkId,
    asset_definition_id: &str,
    spend_key: &[u8],
    input_paths: &[ConfidentialMerklePathV2],
    inputs: &[ConfidentialUnshieldInputV2],
    outputs: &[ConfidentialUnshieldOutputV3],
    public_amount: u128,
    root_hint: [u8; 32],
    circuit_id: &str,
    vk_box: &VerifyingKeyBox,
) -> Result<ConfidentialUnshieldProofV3, String> {
    build_confidential_unshield_proof_v3_resolved_paths(
        network_id,
        asset_definition_id,
        spend_key,
        inputs,
        outputs,
        public_amount,
        root_hint,
        circuit_id,
        vk_box,
        |input_0, input_1, input_0_commitment, input_1_commitment| {
            normalize_confidential_unshield_change_paths_v4(
                input_paths,
                root_hint,
                input_0,
                input_1,
                input_0_commitment,
                input_1_commitment,
            )
        },
    )
}
include!("confidential_v2_tests.rs");

#[path = "confidential_native/mod.rs"]
pub(crate) mod native;

#[cfg(test)]
#[path = "confidential_hash_tests.rs"]
mod native_hash_tests;
