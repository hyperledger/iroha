//! Fixed native PIPA-R backend for first-release SoraFS PoP membership proofs.
//!
//! The circuit proves two hidden statements at once: membership of a credential leaf in the signed
//! active credential tree, and non-membership of that leaf's private 128-bit revocation nonce in
//! the signed sparse revocation tree. The holder secret, credential identifier, holder commitment,
//! nonce, and both authentication paths remain advice values and never enter the public-input or
//! proof-envelope schemas. A separate public presentation binding commits the proof to its
//! authenticated recipient without changing the shared challenge/context nullifier domain.
use super::{
    POP_CREDENTIAL_TREE_DEPTH_V1, POP_MEMBERSHIP_PROOF_MAX_BYTES_V1,
    POP_MEMBERSHIP_PROOF_VERSION_V1, POP_REVOCATION_TREE_DEPTH_V1, PopCredentialV1,
    PopCredentialValidationError, PopEligibilityClassV1, PopMembershipProofSystemV1,
    PopMembershipProofV1, PopMembershipVerifierMaterialV1, PopMembershipWitnessV1,
    PopRevocationEntryV1, PopRevocationNonMembershipPathV1,
};
use blake3::Hasher;
use ff::{Field, PrimeField};
use iroha_pasta::{Eq, Fp, msm::MemoryBudget};
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Fixed, Instance, InstanceType, Selector},
    frontend::{
        Assigned, AssignedCell, Cell, Circuit, Error as PlonkError, Layouter, Region,
        SimpleFloorPlanner, Value,
    },
    keys::{
        DescriptorBinding, KeygenConfigV2, ProvingKey, VerifyingKey, keygen_pk_v2,
        keygen_vk_with_binding_v2,
    },
    pcs::ipa::PinnedParams,
    prover::{ProverConfig, ProverRandomness, Witness, create_proof_owned},
    verifier::verify_full,
};
use std::{collections::BTreeMap, sync::OnceLock};
pub(super) const POP_MEMBERSHIP_CIRCUIT_ID_V1: &str = "sorafs-pop-membership-pipa-r-v1";
pub(super) const POP_MEMBERSHIP_CIRCUIT_K_V1: u32 = 14;
const WIDTH: usize = 3;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 56;
const ROUND_COUNT: usize = FULL_ROUNDS + PARTIAL_ROUNDS;
const DOMAIN_HOLDER_COMMITMENT: u64 = 1;
const DOMAIN_CREDENTIAL_LEAF_ID: u64 = 2;
const DOMAIN_CREDENTIAL_LEAF_CLASS: u64 = 3;
const DOMAIN_CREDENTIAL_LEAF_ISSUED: u64 = 4;
const DOMAIN_CREDENTIAL_LEAF_EXPIRY: u64 = 5;
const DOMAIN_CREDENTIAL_LEAF_RENEWAL: u64 = 6;
const DOMAIN_CREDENTIAL_LEAF_REVOCATION: u64 = 7;
const DOMAIN_CREDENTIAL_LEAF_TREE_VERSION: u64 = 8;
const DOMAIN_CREDENTIAL_LEAF_LIST_VERSION: u64 = 9;
const DOMAIN_CREDENTIAL_LEAF_BINDING: u64 = 10;
const DOMAIN_CREDENTIAL_NODE_BASE: u64 = 1_000;
const DOMAIN_REVOCATION_LEAF: u64 = 2_000;
const DOMAIN_REVOCATION_NODE_BASE: u64 = 3_000;
const DOMAIN_NULLIFIER_CHALLENGE: u64 = 4_000;
const DOMAIN_NULLIFIER_CONTEXT: u64 = 4_001;
const PI_COMMITMENT_ROOT: usize = 0;
const PI_TREE_VERSION: usize = 1;
const PI_ELIGIBILITY_CLASS: usize = 2;
const PI_CHALLENGE: usize = 3;
const PI_CONTEXT: usize = 4;
const PI_EXPIRY: usize = 5;
const PI_REVOCATION_ROOT: usize = 6;
const PI_REVOCATION_LIST_VERSION: usize = 7;
const PI_NULLIFIER: usize = 8;
const PI_PRESENTATION_BINDING: usize = 9;
const PUBLIC_INPUT_COUNT: usize = 10;
struct PoseidonConstants {
    round_constants: Vec<[Fp; WIDTH]>,
    mds: [[Fp; WIDTH]; WIDTH],
}
fn poseidon_constants() -> &'static PoseidonConstants {
    static CONSTANTS: OnceLock<PoseidonConstants> = OnceLock::new();
    CONSTANTS.get_or_init(|| {
        let (round_constants, mds) = iroha_pasta::poseidon::grain::generate_constants::<Fp, WIDTH>(
            FULL_ROUNDS,
            PARTIAL_ROUNDS,
            0,
        );
        assert_eq!(round_constants.len(), ROUND_COUNT);
        PoseidonConstants {
            round_constants,
            mds,
        }
    })
}
fn pow5(value: Fp) -> Fp {
    let square = value.square();
    square.square() * value
}
fn poseidon_round(mut state: [Fp; WIDTH], round: usize) -> [Fp; WIDTH] {
    let constants = poseidon_constants();
    for (word, round_constant) in state
        .iter_mut()
        .zip(constants.round_constants[round].iter())
    {
        *word += round_constant;
    }
    let half = FULL_ROUNDS / 2;
    if round < half || round >= half + PARTIAL_ROUNDS {
        for word in &mut state {
            *word = pow5(*word);
        }
    } else {
        state[0] = pow5(state[0]);
    }
    std::array::from_fn(|row| {
        (0..WIDTH).fold(Fp::ZERO, |accumulator, column| {
            accumulator + constants.mds[row][column] * state[column]
        })
    })
}
fn poseidon_compress(domain: u64, left: Fp, right: Fp) -> Fp {
    let mut state = [left, right, Fp::from(domain)];
    for round in 0..ROUND_COUNT {
        state = poseidon_round(state, round);
    }
    state[0]
}
pub(super) fn canonical_scalar(bytes: [u8; 32]) -> Result<Fp, PopCredentialValidationError> {
    let mut representation = <Fp as PrimeField>::Repr::default();
    representation.as_mut().copy_from_slice(&bytes);
    Option::from(Fp::from_repr(representation)).ok_or(
        PopCredentialValidationError::InvalidScalarEncoding {
            field: "Pasta scalar",
        },
    )
}
fn scalar_to_bytes(value: Fp) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(value.to_repr().as_ref());
    bytes
}
fn hash_to_scalar(domain: &[u8], parts: &[&[u8]]) -> Fp {
    let mut counter = 0u64;
    loop {
        let mut hasher = Hasher::new();
        hasher.update(domain);
        hasher.update(&counter.to_le_bytes());
        for part in parts {
            hasher.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize();
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(digest.as_bytes());
        if let Ok(scalar) = canonical_scalar(candidate) {
            return scalar;
        }
        counter = counter.wrapping_add(1);
    }
}
fn u128_scalar(value: u128) -> Fp {
    let lower = value as u64;
    let upper = (value >> 64) as u64;
    let two_to_64 = Fp::from(u64::MAX) + Fp::ONE;
    Fp::from(lower) + Fp::from(upper) * two_to_64
}
pub(super) fn revocation_nonce_u128(nonce: [u8; 32]) -> Result<u128, PopCredentialValidationError> {
    if nonce[16..].iter().any(|byte| *byte != 0) {
        return Err(PopCredentialValidationError::InvalidRevocationNonceEncoding);
    }
    let mut lower = [0u8; 16];
    lower.copy_from_slice(&nonce[..16]);
    let value = u128::from_le_bytes(lower);
    if value == 0 {
        return Err(PopCredentialValidationError::InvalidDigest {
            field: "revocation nonce",
        });
    }
    Ok(value)
}
fn eligibility_class_scalar(class: PopEligibilityClassV1) -> Fp {
    let code = match class {
        PopEligibilityClassV1::General => 1,
        PopEligibilityClassV1::Regional => 2,
        PopEligibilityClassV1::Expert => 3,
        PopEligibilityClassV1::Emergency => 4,
        PopEligibilityClassV1::Observer => 5,
    };
    Fp::from(code)
}
fn credential_private_binding(
    credential: &PopCredentialV1,
) -> Result<Fp, PopCredentialValidationError> {
    let attributes = norito::encode_canonical(&credential.attributes).map_err(|error| {
        PopCredentialValidationError::SignaturePayloadEncoding {
            reason: error.to_string(),
        }
    })?;
    Ok(hash_to_scalar(
        b"sorafs.pop.credential.private-binding.v1",
        &[
            credential.issuer_id.as_bytes(),
            credential.issuer_signature.public_key.as_slice(),
            attributes.as_slice(),
        ],
    ))
}
pub(super) fn holder_commitment_v1(
    holder_secret: [u8; 32],
    credential_id: [u8; 32],
) -> Result<[u8; 32], PopCredentialValidationError> {
    let secret = canonical_scalar(holder_secret)?;
    if secret == Fp::ZERO {
        return Err(PopCredentialValidationError::InvalidDigest {
            field: "holder secret",
        });
    }
    let credential_id = canonical_scalar(credential_id)?;
    Ok(scalar_to_bytes(poseidon_compress(
        DOMAIN_HOLDER_COMMITMENT,
        secret,
        credential_id,
    )))
}
fn credential_leaf_scalar(
    credential: &PopCredentialV1,
) -> Result<Fp, PopCredentialValidationError> {
    let credential_id = canonical_scalar(credential.credential_id)?;
    let holder_commitment = canonical_scalar(credential.holder_commitment)?;
    let nonce = u128_scalar(revocation_nonce_u128(credential.revocation_nonce)?);
    let mut leaf = poseidon_compress(DOMAIN_CREDENTIAL_LEAF_ID, credential_id, holder_commitment);
    leaf = poseidon_compress(
        DOMAIN_CREDENTIAL_LEAF_CLASS,
        leaf,
        eligibility_class_scalar(credential.eligibility_class),
    );
    leaf = poseidon_compress(
        DOMAIN_CREDENTIAL_LEAF_ISSUED,
        leaf,
        Fp::from(credential.issued_at_epoch),
    );
    leaf = poseidon_compress(
        DOMAIN_CREDENTIAL_LEAF_EXPIRY,
        leaf,
        Fp::from(credential.expires_at_epoch),
    );
    leaf = poseidon_compress(
        DOMAIN_CREDENTIAL_LEAF_RENEWAL,
        leaf,
        Fp::from(credential.renewal_at_epoch),
    );
    leaf = poseidon_compress(DOMAIN_CREDENTIAL_LEAF_REVOCATION, leaf, nonce);
    leaf = poseidon_compress(
        DOMAIN_CREDENTIAL_LEAF_TREE_VERSION,
        leaf,
        Fp::from(credential.commitment_tree_version),
    );
    leaf = poseidon_compress(
        DOMAIN_CREDENTIAL_LEAF_LIST_VERSION,
        leaf,
        Fp::from(credential.revocation_list_version),
    );
    Ok(poseidon_compress(
        DOMAIN_CREDENTIAL_LEAF_BINDING,
        leaf,
        credential_private_binding(credential)?,
    ))
}
pub(super) fn credential_leaf_v1(
    credential: &PopCredentialV1,
) -> Result<[u8; 32], PopCredentialValidationError> {
    Ok(scalar_to_bytes(credential_leaf_scalar(credential)?))
}
pub(super) fn credential_root_from_path_v1(
    leaf: [u8; 32],
    siblings: &[[u8; 32]],
    directions: &[bool],
) -> Result<[u8; 32], PopCredentialValidationError> {
    let expected = usize::from(POP_CREDENTIAL_TREE_DEPTH_V1);
    if siblings.len() != expected || directions.len() != expected {
        return Err(PopCredentialValidationError::InvalidMerklePathDepth {
            tree: "credential",
            expected,
            siblings: siblings.len(),
            directions: directions.len(),
        });
    }
    let mut current = canonical_scalar(leaf)?;
    for (level, (sibling, direction)) in siblings.iter().zip(directions).enumerate() {
        let sibling = canonical_scalar(*sibling)?;
        let (left, right) = if *direction {
            (sibling, current)
        } else {
            (current, sibling)
        };
        current = poseidon_compress(DOMAIN_CREDENTIAL_NODE_BASE + level as u64, left, right);
    }
    Ok(scalar_to_bytes(current))
}
fn revocation_reason_code(entry: &PopRevocationEntryV1) -> u64 {
    match entry.reason {
        super::PopRevocationReasonV1::Rotated => 1,
        super::PopRevocationReasonV1::HolderRequested => 2,
        super::PopRevocationReasonV1::EnrollmentInvalid => 3,
        super::PopRevocationReasonV1::GovernanceSuspension => 4,
        super::PopRevocationReasonV1::Expired => 5,
    }
}
fn revocation_leaf(
    entry: &PopRevocationEntryV1,
) -> Result<(u128, Fp), PopCredentialValidationError> {
    let key = revocation_nonce_u128(entry.nonce)?;
    let binding = hash_to_scalar(
        b"sorafs.pop.revocation-entry.v1",
        &[
            &entry.revoked_at_epoch.to_le_bytes(),
            &revocation_reason_code(entry).to_le_bytes(),
        ],
    );
    Ok((
        key,
        poseidon_compress(DOMAIN_REVOCATION_LEAF, u128_scalar(key), binding),
    ))
}
type SparseRevocationLevels = (Vec<BTreeMap<u128, Fp>>, Vec<Fp>);
fn sparse_revocation_levels(
    entries: &[PopRevocationEntryV1],
) -> Result<SparseRevocationLevels, PopCredentialValidationError> {
    let depth = usize::from(POP_REVOCATION_TREE_DEPTH_V1);
    let mut levels = Vec::with_capacity(depth + 1);
    let mut leaves = BTreeMap::new();
    for entry in entries {
        let (key, leaf) = revocation_leaf(entry)?;
        if leaves.insert(key, leaf).is_some() {
            return Err(PopCredentialValidationError::DuplicateRevocationNonce);
        }
    }
    levels.push(leaves);
    let mut empty_nodes = Vec::with_capacity(depth + 1);
    empty_nodes.push(Fp::ZERO);
    for level in 0..depth {
        let empty = empty_nodes[level];
        empty_nodes.push(poseidon_compress(
            DOMAIN_REVOCATION_NODE_BASE + level as u64,
            empty,
            empty,
        ));
        let mut parents = BTreeMap::new();
        let current = &levels[level];
        for key in current.keys() {
            let parent = key >> 1;
            if parents.contains_key(&parent) {
                continue;
            }
            let left_key = parent << 1;
            let right_key = left_key | 1;
            let left = current.get(&left_key).copied().unwrap_or(empty);
            let right = current.get(&right_key).copied().unwrap_or(empty);
            parents.insert(
                parent,
                poseidon_compress(DOMAIN_REVOCATION_NODE_BASE + level as u64, left, right),
            );
        }
        levels.push(parents);
    }
    Ok((levels, empty_nodes))
}
pub(super) fn revocation_root_from_entries_v1(
    entries: &[PopRevocationEntryV1],
) -> Result<[u8; 32], PopCredentialValidationError> {
    let (levels, empty_nodes) = sparse_revocation_levels(entries)?;
    let depth = usize::from(POP_REVOCATION_TREE_DEPTH_V1);
    let root = levels[depth].get(&0).copied().unwrap_or(empty_nodes[depth]);
    Ok(scalar_to_bytes(root))
}
pub(super) fn build_revocation_non_membership_path_v1(
    entries: &[PopRevocationEntryV1],
    nonce: [u8; 32],
) -> Result<PopRevocationNonMembershipPathV1, PopCredentialValidationError> {
    let key = revocation_nonce_u128(nonce)?;
    let (levels, empty_nodes) = sparse_revocation_levels(entries)?;
    if levels[0].contains_key(&key) {
        return Err(PopCredentialValidationError::RevokedCredential);
    }
    let mut current_key = key;
    let mut siblings = Vec::with_capacity(usize::from(POP_REVOCATION_TREE_DEPTH_V1));
    for level in 0..usize::from(POP_REVOCATION_TREE_DEPTH_V1) {
        let sibling = levels[level]
            .get(&(current_key ^ 1))
            .copied()
            .unwrap_or(empty_nodes[level]);
        siblings.push(scalar_to_bytes(sibling));
        current_key >>= 1;
    }
    Ok(PopRevocationNonMembershipPathV1 { siblings })
}
fn revocation_root_from_path(
    nonce: u128,
    siblings: &[[u8; 32]],
) -> Result<Fp, PopCredentialValidationError> {
    let expected = usize::from(POP_REVOCATION_TREE_DEPTH_V1);
    if siblings.len() != expected {
        return Err(PopCredentialValidationError::InvalidMerklePathDepth {
            tree: "revocation",
            expected,
            siblings: siblings.len(),
            directions: expected,
        });
    }
    let mut current = Fp::ZERO;
    for (level, sibling) in siblings.iter().enumerate() {
        let sibling = canonical_scalar(*sibling)?;
        let direction = ((nonce >> level) & 1) == 1;
        let (left, right) = if direction {
            (sibling, current)
        } else {
            (current, sibling)
        };
        current = poseidon_compress(DOMAIN_REVOCATION_NODE_BASE + level as u64, left, right);
    }
    Ok(current)
}
fn challenge_scalar(challenge: [u8; 32]) -> Fp {
    hash_to_scalar(b"sorafs.pop.challenge.scalar.v1", &[&challenge])
}
fn context_scalar(context: &str) -> Fp {
    hash_to_scalar(b"sorafs.pop.context.scalar.v1", &[context.as_bytes()])
}
fn presentation_binding_scalar(binding: [u8; 32]) -> Fp {
    hash_to_scalar(b"sorafs.pop.presentation-binding.scalar.v1", &[&binding])
}
fn nullifier_scalar(secret: Fp, challenge: Fp, context: Fp) -> Fp {
    let challenge_bound = poseidon_compress(DOMAIN_NULLIFIER_CHALLENGE, secret, challenge);
    poseidon_compress(DOMAIN_NULLIFIER_CONTEXT, challenge_bound, context)
}
#[derive(Clone)]
struct ScalarCell {
    cell: Cell,
    value: Value<Fp>,
}
#[derive(Clone, Debug)]
struct PopMembershipConfig {
    state: [Column<Advice>; WIDTH],
    round_constants: [Column<Fixed>; WIDTH],
    hash_domain: Column<Fixed>,
    q_hash_init: Selector,
    q_full_round: Selector,
    q_partial_round: Selector,
    select_current: Column<Advice>,
    select_sibling: Column<Advice>,
    select_direction: Column<Advice>,
    select_left: Column<Advice>,
    select_right: Column<Advice>,
    q_select: Selector,
    bit: Column<Advice>,
    accumulator: Column<Advice>,
    q_bit: Selector,
    nonzero_value: Column<Advice>,
    nonzero_inverse: Column<Advice>,
    q_nonzero: Selector,
    input: Column<Advice>,
    instance: Column<Instance>,
}
#[derive(Clone)]
struct PopMembershipCircuit {
    holder_secret: Option<Fp>,
    credential_id: Option<Fp>,
    issued_at: Option<Fp>,
    expires_at: Option<Fp>,
    renewal_at: Option<Fp>,
    revocation_nonce: Option<Fp>,
    revocation_nonce_u128: Option<u128>,
    tree_version: Option<Fp>,
    credential_list_version: Option<Fp>,
    eligibility_class: Option<Fp>,
    private_binding: Option<Fp>,
    challenge: Option<Fp>,
    context: Option<Fp>,
    presentation_binding: Option<Fp>,
    current_list_version: Option<Fp>,
    credential_siblings: [Option<Fp>; POP_CREDENTIAL_TREE_DEPTH_V1 as usize],
    credential_directions: [Option<bool>; POP_CREDENTIAL_TREE_DEPTH_V1 as usize],
    revocation_siblings: [Option<Fp>; POP_REVOCATION_TREE_DEPTH_V1 as usize],
}
impl Default for PopMembershipCircuit {
    fn default() -> Self {
        Self {
            holder_secret: None,
            credential_id: None,
            issued_at: None,
            expires_at: None,
            renewal_at: None,
            revocation_nonce: None,
            revocation_nonce_u128: None,
            tree_version: None,
            credential_list_version: None,
            eligibility_class: None,
            private_binding: None,
            challenge: None,
            context: None,
            presentation_binding: None,
            current_list_version: None,
            credential_siblings: [None; POP_CREDENTIAL_TREE_DEPTH_V1 as usize],
            credential_directions: [None; POP_CREDENTIAL_TREE_DEPTH_V1 as usize],
            revocation_siblings: [None; POP_REVOCATION_TREE_DEPTH_V1 as usize],
        }
    }
}
fn optional_value(value: Option<Fp>) -> Value<Fp> {
    value.map(Value::known).unwrap_or_else(Value::unknown)
}
fn value_pow5(value: Value<Fp>) -> Value<Fp> {
    let square = value * value;
    square * square * value
}
impl PopMembershipCircuit {
    fn from_witness(
        credential: &PopCredentialV1,
        witness: &PopMembershipWitnessV1,
        challenge: [u8; 32],
        context: &str,
        presentation_binding: [u8; 32],
        current_list_version: u64,
    ) -> Result<Self, PopCredentialValidationError> {
        let credential_siblings = witness
            .credential_path
            .siblings
            .iter()
            .map(|sibling| canonical_scalar(*sibling).map(Some))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(
                |_: Vec<Option<Fp>>| PopCredentialValidationError::InvalidMerklePathDepth {
                    tree: "credential",
                    expected: usize::from(POP_CREDENTIAL_TREE_DEPTH_V1),
                    siblings: witness.credential_path.siblings.len(),
                    directions: witness.credential_path.directions.len(),
                },
            )?;
        let credential_directions = witness
            .credential_path
            .directions
            .iter()
            .copied()
            .map(Some)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_: Vec<Option<bool>>| {
                PopCredentialValidationError::InvalidMerklePathDepth {
                    tree: "credential",
                    expected: usize::from(POP_CREDENTIAL_TREE_DEPTH_V1),
                    siblings: witness.credential_path.siblings.len(),
                    directions: witness.credential_path.directions.len(),
                }
            })?;
        let revocation_siblings = witness
            .revocation_path
            .siblings
            .iter()
            .map(|sibling| canonical_scalar(*sibling).map(Some))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(
                |_: Vec<Option<Fp>>| PopCredentialValidationError::InvalidMerklePathDepth {
                    tree: "revocation",
                    expected: usize::from(POP_REVOCATION_TREE_DEPTH_V1),
                    siblings: witness.revocation_path.siblings.len(),
                    directions: usize::from(POP_REVOCATION_TREE_DEPTH_V1),
                },
            )?;
        Ok(Self {
            holder_secret: Some(canonical_scalar(witness.holder_secret)?),
            credential_id: Some(canonical_scalar(credential.credential_id)?),
            issued_at: Some(Fp::from(credential.issued_at_epoch)),
            expires_at: Some(Fp::from(credential.expires_at_epoch)),
            renewal_at: Some(Fp::from(credential.renewal_at_epoch)),
            revocation_nonce: Some(u128_scalar(revocation_nonce_u128(
                credential.revocation_nonce,
            )?)),
            revocation_nonce_u128: Some(revocation_nonce_u128(credential.revocation_nonce)?),
            tree_version: Some(Fp::from(credential.commitment_tree_version)),
            credential_list_version: Some(Fp::from(credential.revocation_list_version)),
            eligibility_class: Some(eligibility_class_scalar(credential.eligibility_class)),
            private_binding: Some(credential_private_binding(credential)?),
            challenge: Some(challenge_scalar(challenge)),
            context: Some(context_scalar(context)),
            presentation_binding: Some(presentation_binding_scalar(presentation_binding)),
            current_list_version: Some(Fp::from(current_list_version)),
            credential_siblings,
            credential_directions,
            revocation_siblings,
        })
    }
    fn assign_scalar(
        &self,
        config: &PopMembershipConfig,
        layouter: &mut impl Layouter<Fp>,
        row_cursor: &mut usize,
        value: Value<Fp>,
    ) -> Result<ScalarCell, PlonkError> {
        let row = *row_cursor;
        *row_cursor += 1;
        layouter.assign_region(
            || "PoP scalar",
            |mut region| {
                let assigned = region.assign_advice(config.input, row, value)?;
                Ok(ScalarCell {
                    cell: assigned.cell(),
                    value,
                })
            },
        )
    }
    fn assign_empty_revocation_leaf(
        &self,
        config: &PopMembershipConfig,
        layouter: &mut impl Layouter<Fp>,
        row_cursor: &mut usize,
    ) -> Result<ScalarCell, PlonkError> {
        let leaf = self.assign_scalar(config, layouter, row_cursor, Value::known(Fp::ZERO))?;
        layouter.assign_region(
            || "PoP empty revocation leaf",
            |mut region| region.constrain_constant(leaf.cell, Fp::ZERO),
        )?;
        Ok(leaf)
    }
    fn assign_state_row(
        region: &mut Region<'_, Fp>,
        config: &PopMembershipConfig,
        row: usize,
        values: [Value<Fp>; WIDTH],
    ) -> Result<[AssignedCell<Assigned<Fp>, Fp>; WIDTH], PlonkError> {
        (0..WIDTH)
            .map(|column| region.assign_advice(config.state[column], row, values[column]))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| PlonkError::Synthesis)
    }
    fn hash_pair(
        &self,
        config: &PopMembershipConfig,
        layouter: &mut impl Layouter<Fp>,
        row_cursor: &mut usize,
        domain: u64,
        left: &ScalarCell,
        right: &ScalarCell,
    ) -> Result<ScalarCell, PlonkError> {
        let constants = poseidon_constants();
        let base_row = *row_cursor;
        *row_cursor += ROUND_COUNT + 1;
        layouter.assign_region(
            || "PoP Poseidon permutation",
            |mut region| {
                config.q_hash_init.enable(&mut region, base_row)?;
                region.assign_fixed(config.hash_domain, base_row, Fp::from(domain))?;
                let mut values = [left.value, right.value, Value::known(Fp::from(domain))];
                let mut cells = Self::assign_state_row(&mut region, config, base_row, values)?;
                region.constrain_equal(cells[0].cell(), left.cell)?;
                region.constrain_equal(cells[1].cell(), right.cell)?;
                for round in 0..ROUND_COUNT {
                    for column in 0..WIDTH {
                        region.assign_fixed(
                            config.round_constants[column],
                            base_row + round,
                            constants.round_constants[round][column],
                        )?;
                    }
                    let half = FULL_ROUNDS / 2;
                    if round < half || round >= half + PARTIAL_ROUNDS {
                        config.q_full_round.enable(&mut region, base_row + round)?;
                    } else {
                        config
                            .q_partial_round
                            .enable(&mut region, base_row + round)?;
                    }
                    let mut sboxed: [Value<Fp>; WIDTH] = std::array::from_fn(|column| {
                        values[column] + Value::known(constants.round_constants[round][column])
                    });
                    if round < half || round >= half + PARTIAL_ROUNDS {
                        for word in &mut sboxed {
                            *word = value_pow5(*word);
                        }
                    } else {
                        sboxed[0] = value_pow5(sboxed[0]);
                    }
                    values = std::array::from_fn(|row| {
                        (0..WIDTH).fold(Value::known(Fp::ZERO), |accumulator, column| {
                            accumulator + sboxed[column] * Value::known(constants.mds[row][column])
                        })
                    });
                    cells =
                        Self::assign_state_row(&mut region, config, base_row + round + 1, values)?;
                }
                Ok(ScalarCell {
                    cell: cells[0].cell(),
                    value: values[0],
                })
            },
        )
    }
    fn select_children(
        &self,
        config: &PopMembershipConfig,
        layouter: &mut impl Layouter<Fp>,
        row_cursor: &mut usize,
        current: &ScalarCell,
        sibling: &ScalarCell,
        direction: &ScalarCell,
    ) -> Result<(ScalarCell, ScalarCell), PlonkError> {
        let row = *row_cursor;
        *row_cursor += 1;
        let left_value = current.value + direction.value * (sibling.value - current.value);
        let right_value = sibling.value + direction.value * (current.value - sibling.value);
        layouter.assign_region(
            || "PoP Merkle child selection",
            |mut region| {
                config.q_select.enable(&mut region, row)?;
                let current_cell =
                    region.assign_advice(config.select_current, row, current.value)?;
                let sibling_cell =
                    region.assign_advice(config.select_sibling, row, sibling.value)?;
                let direction_cell =
                    region.assign_advice(config.select_direction, row, direction.value)?;
                region.constrain_equal(current_cell.cell(), current.cell)?;
                region.constrain_equal(sibling_cell.cell(), sibling.cell)?;
                region.constrain_equal(direction_cell.cell(), direction.cell)?;
                let left = region.assign_advice(config.select_left, row, left_value)?;
                let right = region.assign_advice(config.select_right, row, right_value)?;
                Ok((
                    ScalarCell {
                        cell: left.cell(),
                        value: left_value,
                    },
                    ScalarCell {
                        cell: right.cell(),
                        value: right_value,
                    },
                ))
            },
        )
    }
    fn decompose_revocation_nonce(
        &self,
        config: &PopMembershipConfig,
        layouter: &mut impl Layouter<Fp>,
        row_cursor: &mut usize,
        nonce: &ScalarCell,
    ) -> Result<Vec<ScalarCell>, PlonkError> {
        let base_row = *row_cursor;
        *row_cursor += usize::from(POP_REVOCATION_TREE_DEPTH_V1) + 1;
        let bit_values: [Option<Fp>; POP_REVOCATION_TREE_DEPTH_V1 as usize] =
            std::array::from_fn(|index| {
                self.revocation_nonce_u128
                    .map(|value| Fp::from(((value >> index) & 1) as u64))
            });
        layouter.assign_region(
            || "PoP revocation nonce decomposition",
            |mut region| {
                let mut accumulator_value = Value::known(Fp::ZERO);
                let first_accumulator =
                    region.assign_advice(config.accumulator, base_row, accumulator_value)?;
                region.constrain_constant(first_accumulator.cell(), Fp::ZERO)?;
                let mut bit_cells: Vec<Option<ScalarCell>> =
                    vec![None; usize::from(POP_REVOCATION_TREE_DEPTH_V1)];
                let mut final_accumulator = None;
                for row in 0..usize::from(POP_REVOCATION_TREE_DEPTH_V1) {
                    let bit_index = usize::from(POP_REVOCATION_TREE_DEPTH_V1) - 1 - row;
                    let bit_value = optional_value(bit_values[bit_index]);
                    let bit = region.assign_advice(config.bit, base_row + row, bit_value)?;
                    bit_cells[bit_index] = Some(ScalarCell {
                        cell: bit.cell(),
                        value: bit_value,
                    });
                    config.q_bit.enable(&mut region, base_row + row)?;
                    accumulator_value = accumulator_value * Value::known(Fp::from(2)) + bit_value;
                    let accumulator = region.assign_advice(
                        config.accumulator,
                        base_row + row + 1,
                        accumulator_value,
                    )?;
                    final_accumulator = Some(accumulator.cell());
                }
                region.constrain_equal(
                    final_accumulator.expect("fixed non-zero revocation depth"),
                    nonce.cell,
                )?;
                Ok(bit_cells
                    .into_iter()
                    .map(|cell| cell.expect("every fixed bit is assigned"))
                    .collect())
            },
        )
    }
    fn constrain_nonzero(
        &self,
        config: &PopMembershipConfig,
        layouter: &mut impl Layouter<Fp>,
        row_cursor: &mut usize,
        value: &ScalarCell,
    ) -> Result<(), PlonkError> {
        let row = *row_cursor;
        *row_cursor += 1;
        let inverse_value = value
            .value
            .map(|scalar| Option::<Fp>::from(scalar.invert()).unwrap_or(Fp::ZERO));
        layouter.assign_region(
            || "PoP non-zero private scalar",
            |mut region| {
                config.q_nonzero.enable(&mut region, row)?;
                let assigned_value =
                    region.assign_advice(config.nonzero_value, row, value.value)?;
                region.constrain_equal(assigned_value.cell(), value.cell)?;
                region.assign_advice(config.nonzero_inverse, row, inverse_value)?;
                Ok(())
            },
        )
    }
}
impl Circuit<Fp> for PopMembershipCircuit {
    type Config = PopMembershipConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        let state = std::array::from_fn(|_| meta.advice_column());
        for column in state {
            meta.enable_equality(column);
        }
        let round_constants = std::array::from_fn(|_| meta.fixed_column());
        let hash_domain = meta.fixed_column();
        let q_hash_init = meta.selector();
        let q_full_round = meta.selector();
        let q_partial_round = meta.selector();
        meta.create_gate("PoP hash domain", |meta| {
            let enabled = meta.query_selector(q_hash_init);
            let capacity = meta.query_advice(state[2], iroha_plonk::cs::Rotation::cur());
            let domain = meta.query_fixed(hash_domain, iroha_plonk::cs::Rotation::cur());
            vec![enabled * (capacity - domain)]
        });
        let constants = poseidon_constants();
        meta.create_gate("PoP Poseidon full round", |meta| {
            let enabled = meta.query_selector(q_full_round);
            (0..WIDTH)
                .map(|row| {
                    let expected = (0..WIDTH).fold(
                        iroha_plonk::cs::Expression::Constant(Fp::ZERO),
                        |accumulator, column| {
                            let current =
                                meta.query_advice(state[column], iroha_plonk::cs::Rotation::cur());
                            let round_constant = meta.query_fixed(
                                round_constants[column],
                                iroha_plonk::cs::Rotation::cur(),
                            );
                            let shifted = current + round_constant;
                            let square = shifted.clone() * shifted.clone();
                            let fifth = square.clone() * square * shifted;
                            accumulator + fifth * constants.mds[row][column]
                        },
                    );
                    let next = meta.query_advice(state[row], iroha_plonk::cs::Rotation::next());
                    enabled.clone() * (expected - next)
                })
                .collect::<Vec<_>>()
        });
        meta.create_gate("PoP Poseidon partial round", |meta| {
            let enabled = meta.query_selector(q_partial_round);
            let shifted: [iroha_plonk::cs::Expression<Fp>; WIDTH] = std::array::from_fn(|column| {
                meta.query_advice(state[column], iroha_plonk::cs::Rotation::cur())
                    + meta.query_fixed(round_constants[column], iroha_plonk::cs::Rotation::cur())
            });
            let square = shifted[0].clone() * shifted[0].clone();
            let first_fifth = square.clone() * square * shifted[0].clone();
            (0..WIDTH)
                .map(|row| {
                    let expected = first_fifth.clone() * constants.mds[row][0]
                        + shifted[1].clone() * constants.mds[row][1]
                        + shifted[2].clone() * constants.mds[row][2];
                    let next = meta.query_advice(state[row], iroha_plonk::cs::Rotation::next());
                    enabled.clone() * (expected - next)
                })
                .collect::<Vec<_>>()
        });
        let select_current = meta.advice_column();
        let select_sibling = meta.advice_column();
        let select_direction = meta.advice_column();
        let select_left = meta.advice_column();
        let select_right = meta.advice_column();
        for column in [
            select_current,
            select_sibling,
            select_direction,
            select_left,
            select_right,
        ] {
            meta.enable_equality(column);
        }
        let q_select = meta.selector();
        meta.create_gate("PoP private Merkle direction", |meta| {
            let enabled = meta.query_selector(q_select);
            let current = meta.query_advice(select_current, iroha_plonk::cs::Rotation::cur());
            let sibling = meta.query_advice(select_sibling, iroha_plonk::cs::Rotation::cur());
            let direction = meta.query_advice(select_direction, iroha_plonk::cs::Rotation::cur());
            let left = meta.query_advice(select_left, iroha_plonk::cs::Rotation::cur());
            let right = meta.query_advice(select_right, iroha_plonk::cs::Rotation::cur());
            let one = iroha_plonk::cs::Expression::Constant(Fp::ONE);
            vec![
                enabled.clone() * direction.clone() * (direction.clone() - one),
                enabled.clone()
                    * (left
                        - (current.clone()
                            + direction.clone() * (sibling.clone() - current.clone()))),
                enabled * (right - (sibling.clone() + direction * (current - sibling))),
            ]
        });
        let bit = meta.advice_column();
        let accumulator = meta.advice_column();
        meta.enable_equality(bit);
        meta.enable_equality(accumulator);
        let q_bit = meta.selector();
        meta.create_gate("PoP 128-bit revocation nonce", |meta| {
            let enabled = meta.query_selector(q_bit);
            let bit_value = meta.query_advice(bit, iroha_plonk::cs::Rotation::cur());
            let accumulator_current =
                meta.query_advice(accumulator, iroha_plonk::cs::Rotation::cur());
            let accumulator_next =
                meta.query_advice(accumulator, iroha_plonk::cs::Rotation::next());
            let one = iroha_plonk::cs::Expression::Constant(Fp::ONE);
            let two = iroha_plonk::cs::Expression::Constant(Fp::from(2));
            vec![
                enabled.clone() * bit_value.clone() * (bit_value.clone() - one),
                enabled * (accumulator_next - (accumulator_current * two + bit_value)),
            ]
        });
        let nonzero_value = meta.advice_column();
        let nonzero_inverse = meta.advice_column();
        meta.enable_equality(nonzero_value);
        let q_nonzero = meta.selector();
        meta.create_gate("PoP non-zero private scalar", |meta| {
            let enabled = meta.query_selector(q_nonzero);
            let value = meta.query_advice(nonzero_value, iroha_plonk::cs::Rotation::cur());
            let inverse = meta.query_advice(nonzero_inverse, iroha_plonk::cs::Rotation::cur());
            vec![enabled * (value * inverse - iroha_plonk::cs::Expression::Constant(Fp::ONE))]
        });
        let input = meta.advice_column();
        meta.enable_equality(input);
        let instance = meta.instance_column(PUBLIC_INPUT_COUNT);
        meta.enable_equality(instance);
        PopMembershipConfig {
            state,
            round_constants,
            hash_domain,
            q_hash_init,
            q_full_round,
            q_partial_round,
            select_current,
            select_sibling,
            select_direction,
            select_left,
            select_right,
            q_select,
            bit,
            accumulator,
            q_bit,
            nonzero_value,
            nonzero_inverse,
            q_nonzero,
            input,
            instance,
        }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), PlonkError> {
        let mut row_cursor = 0usize;
        let holder_secret = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.holder_secret),
        )?;
        let credential_id = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.credential_id),
        )?;
        let issued_at = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.issued_at),
        )?;
        let expires_at = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.expires_at),
        )?;
        let renewal_at = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.renewal_at),
        )?;
        let revocation_nonce = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.revocation_nonce),
        )?;
        self.constrain_nonzero(&config, &mut layouter, &mut row_cursor, &holder_secret)?;
        self.constrain_nonzero(&config, &mut layouter, &mut row_cursor, &revocation_nonce)?;
        let tree_version = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.tree_version),
        )?;
        let credential_list_version = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.credential_list_version),
        )?;
        let eligibility_class = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.eligibility_class),
        )?;
        let private_binding = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.private_binding),
        )?;
        let challenge = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.challenge),
        )?;
        let context = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.context),
        )?;
        let presentation_binding = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.presentation_binding),
        )?;
        let current_list_version = self.assign_scalar(
            &config,
            &mut layouter,
            &mut row_cursor,
            optional_value(self.current_list_version),
        )?;
        layouter.constrain_instance(tree_version.cell, config.instance, PI_TREE_VERSION)?;
        layouter.constrain_instance(
            eligibility_class.cell,
            config.instance,
            PI_ELIGIBILITY_CLASS,
        )?;
        layouter.constrain_instance(challenge.cell, config.instance, PI_CHALLENGE)?;
        layouter.constrain_instance(context.cell, config.instance, PI_CONTEXT)?;
        layouter.constrain_instance(
            presentation_binding.cell,
            config.instance,
            PI_PRESENTATION_BINDING,
        )?;
        layouter.constrain_instance(expires_at.cell, config.instance, PI_EXPIRY)?;
        layouter.constrain_instance(
            current_list_version.cell,
            config.instance,
            PI_REVOCATION_LIST_VERSION,
        )?;
        let holder_commitment = self.hash_pair(
            &config,
            &mut layouter,
            &mut row_cursor,
            DOMAIN_HOLDER_COMMITMENT,
            &holder_secret,
            &credential_id,
        )?;
        let mut credential_leaf = self.hash_pair(
            &config,
            &mut layouter,
            &mut row_cursor,
            DOMAIN_CREDENTIAL_LEAF_ID,
            &credential_id,
            &holder_commitment,
        )?;
        for (domain, field) in [
            (DOMAIN_CREDENTIAL_LEAF_CLASS, &eligibility_class),
            (DOMAIN_CREDENTIAL_LEAF_ISSUED, &issued_at),
            (DOMAIN_CREDENTIAL_LEAF_EXPIRY, &expires_at),
            (DOMAIN_CREDENTIAL_LEAF_RENEWAL, &renewal_at),
            (DOMAIN_CREDENTIAL_LEAF_REVOCATION, &revocation_nonce),
            (DOMAIN_CREDENTIAL_LEAF_TREE_VERSION, &tree_version),
            (
                DOMAIN_CREDENTIAL_LEAF_LIST_VERSION,
                &credential_list_version,
            ),
            (DOMAIN_CREDENTIAL_LEAF_BINDING, &private_binding),
        ] {
            credential_leaf = self.hash_pair(
                &config,
                &mut layouter,
                &mut row_cursor,
                domain,
                &credential_leaf,
                field,
            )?;
        }
        let mut credential_node = credential_leaf;
        for level in 0..usize::from(POP_CREDENTIAL_TREE_DEPTH_V1) {
            let sibling = self.assign_scalar(
                &config,
                &mut layouter,
                &mut row_cursor,
                optional_value(self.credential_siblings[level]),
            )?;
            let direction = self.assign_scalar(
                &config,
                &mut layouter,
                &mut row_cursor,
                self.credential_directions[level]
                    .map(|direction| Value::known(Fp::from(direction as u64)))
                    .unwrap_or_else(Value::unknown),
            )?;
            let (left, right) = self.select_children(
                &config,
                &mut layouter,
                &mut row_cursor,
                &credential_node,
                &sibling,
                &direction,
            )?;
            credential_node = self.hash_pair(
                &config,
                &mut layouter,
                &mut row_cursor,
                DOMAIN_CREDENTIAL_NODE_BASE + level as u64,
                &left,
                &right,
            )?;
        }
        layouter.constrain_instance(credential_node.cell, config.instance, PI_COMMITMENT_ROOT)?;
        let nonce_bits = self.decompose_revocation_nonce(
            &config,
            &mut layouter,
            &mut row_cursor,
            &revocation_nonce,
        )?;
        let mut revocation_node =
            self.assign_empty_revocation_leaf(&config, &mut layouter, &mut row_cursor)?;
        for (level, direction) in nonce_bits.iter().enumerate() {
            let sibling = self.assign_scalar(
                &config,
                &mut layouter,
                &mut row_cursor,
                optional_value(self.revocation_siblings[level]),
            )?;
            let (left, right) = self.select_children(
                &config,
                &mut layouter,
                &mut row_cursor,
                &revocation_node,
                &sibling,
                direction,
            )?;
            revocation_node = self.hash_pair(
                &config,
                &mut layouter,
                &mut row_cursor,
                DOMAIN_REVOCATION_NODE_BASE + level as u64,
                &left,
                &right,
            )?;
        }
        layouter.constrain_instance(revocation_node.cell, config.instance, PI_REVOCATION_ROOT)?;
        let challenge_bound = self.hash_pair(
            &config,
            &mut layouter,
            &mut row_cursor,
            DOMAIN_NULLIFIER_CHALLENGE,
            &holder_secret,
            &challenge,
        )?;
        let nullifier = self.hash_pair(
            &config,
            &mut layouter,
            &mut row_cursor,
            DOMAIN_NULLIFIER_CONTEXT,
            &challenge_bound,
            &context,
        )?;
        layouter.constrain_instance(nullifier.cell, config.instance, PI_NULLIFIER)?;
        Ok(())
    }
}
struct CachedVerifierMaterial {
    params: PinnedParams<Eq>,
    verifying_key: VerifyingKey<Eq>,
    binding: DescriptorBinding,
    public: PopMembershipVerifierMaterialV1,
}
fn digest_with_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
fn backend(error: impl std::fmt::Display) -> PopCredentialValidationError {
    PopCredentialValidationError::ProofBackend {
        reason: error.to_string(),
    }
}
fn key_config() -> KeygenConfigV2 {
    KeygenConfigV2::pipa_r(vec![InstanceType::Field])
}
fn initialize_verifier_material() -> Result<CachedVerifierMaterial, PopCredentialValidationError> {
    let params = PinnedParams::<Eq>::derive(POP_MEMBERSHIP_CIRCUIT_K_V1).map_err(backend)?;
    let (binding, verifying_key) =
        keygen_vk_with_binding_v2(&params, &PopMembershipCircuit::default(), &key_config())
            .map_err(backend)?;
    let mut identity = binding.digest().to_vec();
    identity.extend_from_slice(verifying_key.to_bytes());
    let public = PopMembershipVerifierMaterialV1 {
        circuit_id: POP_MEMBERSHIP_CIRCUIT_ID_V1.to_owned(),
        circuit_k: POP_MEMBERSHIP_CIRCUIT_K_V1,
        credential_tree_depth: POP_CREDENTIAL_TREE_DEPTH_V1,
        revocation_tree_depth: POP_REVOCATION_TREE_DEPTH_V1,
        parameter_digest: digest_with_domain(b"sorafs.pop.pipa-r.parameters.v1", &params.digest()),
        verifying_key_digest: digest_with_domain(b"sorafs.pop.pipa-r.verifying-key.v1", &identity),
    };
    public.validate()?;
    Ok(CachedVerifierMaterial {
        params,
        verifying_key,
        binding,
        public,
    })
}
fn cached_verifier_material()
-> Result<&'static CachedVerifierMaterial, PopCredentialValidationError> {
    static MATERIAL: OnceLock<Result<CachedVerifierMaterial, String>> = OnceLock::new();
    MATERIAL
        .get_or_init(|| initialize_verifier_material().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(backend)
}
fn cached_proving_key() -> Result<&'static ProvingKey<Eq>, PopCredentialValidationError> {
    static KEY: OnceLock<Result<ProvingKey<Eq>, String>> = OnceLock::new();
    let verifier = cached_verifier_material()?;
    KEY.get_or_init(|| {
        let key = keygen_pk_v2(
            &verifier.params,
            &PopMembershipCircuit::default(),
            &key_config(),
        )
        .map_err(|e| e.to_string())?;
        if key.vk().to_bytes() != verifier.verifying_key.to_bytes()
            || key.binding() != &verifier.binding
        {
            return Err("PoP proving/verifying key mismatch".to_owned());
        }
        Ok(key)
    })
    .as_ref()
    .map_err(backend)
}
pub(super) fn verifier_material_v1()
-> Result<PopMembershipVerifierMaterialV1, PopCredentialValidationError> {
    Ok(cached_verifier_material()?.public.clone())
}
fn proof_public_inputs(
    proof: &PopMembershipProofV1,
) -> Result<[Fp; PUBLIC_INPUT_COUNT], PopCredentialValidationError> {
    Ok([
        canonical_scalar(proof.commitment_root)?,
        Fp::from(proof.commitment_tree_version),
        eligibility_class_scalar(proof.eligibility_class),
        challenge_scalar(proof.challenge_digest),
        context_scalar(&proof.verifier_context),
        Fp::from(proof.expires_at_epoch),
        canonical_scalar(proof.revocation_root)?,
        Fp::from(proof.revocation_list_version),
        canonical_scalar(proof.nullifier)?,
        presentation_binding_scalar(proof.presentation_binding_digest),
    ])
}
fn verify_proof_bytes(
    material: &CachedVerifierMaterial,
    proof_bytes: &[u8],
    public_inputs: &[Fp; PUBLIC_INPUT_COUNT],
) -> Result<(), PopCredentialValidationError> {
    verify_full(
        &material.params,
        &material.binding,
        &material.verifying_key,
        &[public_inputs.to_vec()],
        proof_bytes,
        MemoryBudget::DEFAULT,
    )
    .map_err(
        |error| PopCredentialValidationError::InvalidMembershipProof {
            reason: error.to_string(),
        },
    )
}
pub(super) fn prove_v1(
    credential: &PopCredentialV1,
    witness: &PopMembershipWitnessV1,
    commitment_root: [u8; 32],
    revocation_root: [u8; 32],
    current_list_version: u64,
    presentation: super::PopMembershipPresentationV1<'_>,
) -> Result<PopMembershipProofV1, PopCredentialValidationError> {
    let super::PopMembershipPresentationV1 {
        challenge_digest: challenge,
        verifier_context: context,
        presentation_binding_digest: presentation_binding,
    } = presentation;
    let secret = canonical_scalar(witness.holder_secret)?;
    let challenge_field = challenge_scalar(challenge);
    let context_field = context_scalar(context);
    let nullifier = scalar_to_bytes(nullifier_scalar(secret, challenge_field, context_field));
    let material = cached_verifier_material()?;
    let proving_key = cached_proving_key()?;
    let circuit = PopMembershipCircuit::from_witness(
        credential,
        witness,
        challenge,
        context,
        presentation_binding,
        current_list_version,
    )?;
    let mut proof = PopMembershipProofV1 {
        version: POP_MEMBERSHIP_PROOF_VERSION_V1,
        eligibility_class: credential.eligibility_class,
        commitment_root,
        commitment_tree_version: credential.commitment_tree_version,
        revocation_root,
        revocation_list_version: current_list_version,
        nullifier,
        challenge_digest: challenge,
        verifier_context: context.to_owned(),
        presentation_binding_digest: presentation_binding,
        proof_system: PopMembershipProofSystemV1::NativePipaRV1,
        verifier_material: material.public.clone(),
        proof_bytes: vec![1],
        expires_at_epoch: credential.expires_at_epoch,
    };
    let public_inputs = proof_public_inputs(&proof)?;
    let instances = [public_inputs.to_vec()];
    let witness = Witness::from_circuit(proving_key, &circuit, &instances).map_err(backend)?;
    proof.proof_bytes = create_proof_owned(
        &material.params,
        proving_key,
        witness,
        ProverRandomness::hedged(),
        ProverConfig::default(),
    )
    .map_err(backend)?;
    if proof.proof_bytes.is_empty() || proof.proof_bytes.len() > POP_MEMBERSHIP_PROOF_MAX_BYTES_V1 {
        return Err(PopCredentialValidationError::ResourceLimitExceeded {
            resource: "membership proof bytes",
            maximum: POP_MEMBERSHIP_PROOF_MAX_BYTES_V1,
            actual: proof.proof_bytes.len(),
        });
    }
    proof.validate()?;
    verify_v1(&proof)?;
    Ok(proof)
}
pub(super) fn verify_v1(proof: &PopMembershipProofV1) -> Result<(), PopCredentialValidationError> {
    proof.validate()?;
    let material = cached_verifier_material()?;
    if proof.verifier_material != material.public {
        return Err(PopCredentialValidationError::InvalidVerifierMaterial {
            reason: "proof parameter or verifying-key fingerprint is not pinned V1 material"
                .to_owned(),
        });
    }
    let public_inputs = proof_public_inputs(proof)?;
    verify_proof_bytes(material, &proof.proof_bytes, &public_inputs)
}
pub(super) fn validate_prover_paths(
    credential: &PopCredentialV1,
    witness: &PopMembershipWitnessV1,
    commitment_root: [u8; 32],
    revocation_root: [u8; 32],
) -> Result<(), PopCredentialValidationError> {
    let expected_holder = holder_commitment_v1(witness.holder_secret, credential.credential_id)?;
    if expected_holder != credential.holder_commitment {
        return Err(PopCredentialValidationError::ProofHolderCommitmentMismatch);
    }
    let leaf = credential_leaf_v1(credential)?;
    let computed_root = credential_root_from_path_v1(
        leaf,
        &witness.credential_path.siblings,
        &witness.credential_path.directions,
    )?;
    if computed_root != commitment_root {
        return Err(PopCredentialValidationError::WrongCommitmentRoot);
    }
    let nonce = revocation_nonce_u128(credential.revocation_nonce)?;
    let computed_revocation_root = scalar_to_bytes(revocation_root_from_path(
        nonce,
        &witness.revocation_path.siblings,
    )?);
    if computed_revocation_root != revocation_root {
        return Err(PopCredentialValidationError::RevocationRootMismatch);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn verify_with_reordered_public_inputs_for_test(
    proof: &PopMembershipProofV1,
) -> Result<(), PopCredentialValidationError> {
    let material = cached_verifier_material()?;
    let mut public_inputs = proof_public_inputs(proof)?;
    public_inputs.swap(PI_COMMITMENT_ROOT, PI_REVOCATION_ROOT);
    verify_proof_bytes(material, &proof.proof_bytes, &public_inputs)
}
fn _assert_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CachedVerifierMaterial>();
    assert_send_sync::<ProvingKey<Eq>>();
}

#[cfg(test)]
#[path = "../../../../fixtures/poseidon/reader.rs"]
mod reference;

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[test]
    fn native_rp56_parameters_match_every_upstream_constant() {
        let actual = poseidon_constants();
        let (rounds, mds) = reference::parameters::<3>(include_str!(
            "../../../../fixtures/poseidon/pasta-fp-w3-rp56.hex"
        ));
        let field = |bytes| Fp::from_repr(bytes).unwrap();
        let rounds = rounds.map(|row| row.map(field));
        let mds = mds.map(|row| row.map(field));
        assert_eq!(actual.round_constants.as_slice(), rounds.as_slice());
        assert_eq!(actual.mds, mds);
        assert_eq!(rounds.len(), 64);
    }

    #[test]
    fn pop_rp56_migration_vectors() {
        let constants = poseidon_constants();
        let mut bytes = Vec::new();
        for row in constants.round_constants.iter().chain(constants.mds.iter()) {
            for value in row {
                bytes.extend_from_slice(&scalar_to_bytes(*value));
            }
        }
        assert_eq!(
            blake3::hash(&bytes).to_hex().as_str(),
            "d08d900714da0701db7eea47ee6165f81c827249b8642f6509ba942bbf09a396"
        );
        for ((domain, left, right), expected) in [
            (1, Fp::ZERO, Fp::ZERO),
            (1, Fp::ONE, Fp::from(2)),
            (4001, -Fp::ONE, Fp::from(100)),
            (3127, Fp::from(50), -Fp::ONE),
        ]
        .into_iter()
        .zip([
            "eb352afc5b6e520ccf88fd789b048b4069661f81632c000f065d7775a4f8e801",
            "9bf594c6aae91d234c37528d0263ff5fd17c86d6fa7509debb8627fb4055632c",
            "b9ce8c1b94924f56a15126caa174a5a35ace8a06dbd950ce736146c267469b37",
            "cc3c3f6aec24540caebaae67031a109ef2e1f4b765bde62c91ed98590a68cf0d",
        ]) {
            assert_eq!(
                hex::encode(scalar_to_bytes(poseidon_compress(domain, left, right))),
                expected
            );
        }
    }

    #[derive(Clone, Copy)]
    enum RevocationComponent {
        Nonce { public_nonce: u128, bit_nonce: u128 },
        EmptyLeaf,
    }

    impl Circuit<Fp> for RevocationComponent {
        type Config = PopMembershipConfig;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            *self
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            PopMembershipCircuit::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), PlonkError> {
            let mut circuit = PopMembershipCircuit::default();
            let mut row = 0;
            match *self {
                Self::Nonce {
                    public_nonce,
                    bit_nonce,
                } => {
                    circuit.revocation_nonce_u128 = Some(bit_nonce);
                    let nonce = circuit.assign_scalar(
                        &config,
                        &mut layouter,
                        &mut row,
                        Value::known(u128_scalar(public_nonce)),
                    )?;
                    layouter.constrain_instance(nonce.cell, config.instance, 0)?;
                    circuit.decompose_revocation_nonce(&config, &mut layouter, &mut row, &nonce)?;
                }
                Self::EmptyLeaf => {
                    let leaf =
                        circuit.assign_empty_revocation_leaf(&config, &mut layouter, &mut row)?;
                    layouter.constrain_instance(leaf.cell, config.instance, 0)?;
                }
            }
            Ok(())
        }
    }

    #[test]
    fn nonce_initial_zero_rejects_consistent_shift_to_another_private_path() {
        use iroha_plonk::{check::CheckFailure, frontend::configure};
        use iroha_plonk_gadgets::tamper::{Tamper, check_tampers};
        let honest = RevocationComponent::Nonce {
            public_nonce: 64,
            bit_nonce: 64,
        };
        let mut public = vec![Fp::ZERO; PUBLIC_INPUT_COUNT];
        public[0] = Fp::from(64);
        assert!(
            check_tampers(&honest, 8, &[public.clone()], &[])
                .unwrap()
                .is_satisfied()
        );
        let forged = RevocationComponent::Nonce {
            public_nonce: 64,
            bit_nonce: 65,
        };
        let (_, config) = configure(&forged).unwrap();
        let two = Fp::from(2);
        let shift = -Option::<Fp>::from(two.pow_vartime([128]).invert()).unwrap();
        // Every recurrence still holds, and the final accumulator becomes 64.
        // Only the separately constrained initial zero rules this witness out.
        let tampers: Vec<_> = (0..=128)
            .map(|index| Tamper {
                column: config.accumulator.index(),
                row: 1 + index,
                delta: shift * two.pow_vartime([index as u64]),
            })
            .collect();
        assert_eq!(Fp::from(65) + tampers[128].delta, Fp::from(64));
        for pair in tampers.windows(2) {
            assert_eq!(pair[1].delta, two * pair[0].delta);
        }
        let report = check_tampers(&forged, 8, &[public], &tampers).unwrap();
        assert!(!report.is_satisfied());
        assert!(
            report
                .failures()
                .iter()
                .all(|failure| matches!(failure, CheckFailure::CopyMismatch { .. }))
        );
    }

    #[test]
    fn occupied_revocation_leaf_cannot_replace_the_required_empty_leaf() {
        use iroha_plonk::{check::CheckFailure, frontend::configure};
        use iroha_plonk_gadgets::tamper::{Tamper, check_tampers};
        let circuit = RevocationComponent::EmptyLeaf;
        let mut public = vec![Fp::ZERO; PUBLIC_INPUT_COUNT];
        assert!(
            check_tampers(&circuit, 6, &[public.clone()], &[])
                .unwrap()
                .is_satisfied()
        );
        let (_, config) = configure(&circuit).unwrap();
        public[0] = Fp::ONE;
        let report = check_tampers(
            &circuit,
            6,
            &[public],
            &[Tamper {
                column: config.input.index(),
                row: 0,
                delta: Fp::ONE,
            }],
        )
        .unwrap();
        assert!(!report.is_satisfied());
        assert!(
            report
                .failures()
                .iter()
                .all(|failure| matches!(failure, CheckFailure::CopyMismatch { .. }))
        );
    }
}
