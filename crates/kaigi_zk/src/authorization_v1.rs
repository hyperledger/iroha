//! Final V1 role-aware Kaigi authorization relation.
//!
//! One instance column binds all 31 ordered public scalars. Network and roster
//! bytes are injected as four little-endian u64 limbs; each identity uses all
//! six canonical Goldilocks limbs. Core must authenticate these identities,
//! the permanent call namespace, the pre-state, and participation sequence.
//! This relation makes no hidden Merkle-path or ledger-membership claim.
//!
//! Owned witness bytes and CPU sponge state are securely cleared. Pasta
//! arithmetic may create compiler/register copies, and native prover owns additional
//! Value, assignment, and prover buffers. Their erasure is not guaranteed here.

#[cfg(test)]
use core::array;
use core::fmt;

use ff::{Field, PrimeField};
use iroha_plonk::{
    cs::{ConstraintSystem, Expression, Rotation, Selector},
    frontend::{Cell, Circuit, Error, Layouter, SimpleFloorPlanner, Value},
};
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

use super::{POSEIDON_ROUNDS, Scalar};
use crate::relation_v1::{
    AssignedValue, KaigiRelationConfigV1, ScalarSlots, assign_range, assign_sponge, sponge,
};

/// Fixed log2 domain size for the complete authorization relation.
pub const KAIGI_AUTHORIZATION_CIRCUIT_K_V1: u32 = 13;
/// Exactly one instance column contains this many scalars.
pub const KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1: usize = 31;
/// Canonical circuit identity for the final authorization relation.
pub const KAIGI_AUTHORIZATION_CIRCUIT_ID_V1: &str = "pipa-r/pasta/kaigi-authorization-v1";
/// Exact native registry label for the compiled authorization relation.
pub const KAIGI_AUTHORIZATION_BACKEND_V1: &str = "pipa-r/pasta/kaigi-authorization-v1";
/// Canonical public-input schema for the final authorization relation.
pub const KAIGI_AUTHORIZATION_PUBLIC_INPUTS_SCHEMA_V1: &[u8] = b"kaigi-authorization-v1";
/// Goldilocks modulus; every identity limb is strictly below this value.
pub const KAIGI_IDENTITY_FIELD_MODULUS_V1: u64 = crate::relation_v1::GOLDILOCKS_MODULUS_V1;

const CONTEXT_WORDS: usize = 28;
const SEQUENCE_ROW: usize = 22;
const ACTION_ROW: usize = 23;
const ROOT_ROW: usize = 24;
const COMMITMENT_ROW: usize = 28;
const NULLIFIER_ROW: usize = 29;
const AUTHORIZATION_ROW: usize = 30;
const DOMAIN_COMMITMENT: u64 = 0x4b41_4947_4956_3143;
const DOMAIN_NULLIFIER: u64 = 0x4b41_4947_4956_314e;
const DOMAIN_AUTHORIZATION: u64 = 0x4b41_4947_4956_3141;

/// Closed action tags; no integer aliases are accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum KaigiAuthorizationActionV1 {
    /// Establish the permanent call namespace as its host.
    HostCreate = 0,
    /// Add one non-host participation at a positive sequence.
    Join = 1,
    /// Remove that same non-host participation.
    Leave = 2,
    /// End the call as its host.
    HostEnd = 3,
}

impl TryFrom<u64> for KaigiAuthorizationActionV1 {
    type Error = KaigiAuthorizationErrorV1;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::HostCreate),
            1 => Ok(Self::Join),
            2 => Ok(Self::Leave),
            3 => Ok(Self::HostEnd),
            _ => Err(KaigiAuthorizationErrorV1::UnknownAction(value)),
        }
    }
}

/// Invalid caller input before circuit construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KaigiAuthorizationErrorV1 {
    /// The action tag is outside the closed four-value set.
    UnknownAction(u64),
    /// An identity contains a noncanonical Goldilocks limb.
    NoncanonicalIdentityLimb {
        /// Identity role containing the invalid limb.
        role: &'static str,
        /// Zero-based limb index.
        limb: usize,
    },
    /// Host actions require subject equal to host and sequence zero.
    InvalidHostRole,
    /// Participant actions require a distinct subject and positive sequence.
    InvalidParticipantRole,
    /// Blinding must be one canonical nonzero full Pasta scalar.
    InvalidBlinding,
}

impl fmt::Display for KaigiAuthorizationErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownAction(value) => write!(f, "unknown Kaigi authorization action {value}"),
            Self::NoncanonicalIdentityLimb { role, limb } => {
                write!(f, "noncanonical Goldilocks {role} limb {limb}")
            }
            Self::InvalidHostRole => {
                f.write_str("host action requires host subject and sequence zero")
            }
            Self::InvalidParticipantRole => {
                f.write_str("participant action requires a non-host subject and positive sequence")
            }
            Self::InvalidBlinding => f.write_str("blinding must be canonical nonzero Pasta Fp"),
        }
    }
}
impl std::error::Error for KaigiAuthorizationErrorV1 {}

/// Typed public context, authenticated and recomputed from canonical bytes by Core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KaigiAuthorizationContextV1 {
    /// Exact genesis-derived network bytes, injected without field reduction.
    pub network_id: [u8; 32],
    /// Complete six-lane canonical call identity digest.
    pub call_id: [u64; 6],
    /// Complete six-lane canonical host account identity digest.
    pub host_id: [u64; 6],
    /// Complete six-lane canonical subject account identity digest.
    pub subject_id: [u64; 6],
    /// Ledger-owned participation sequence; zero is reserved for the host.
    pub participation_sequence: u64,
    /// Exact authorization action.
    pub action: KaigiAuthorizationActionV1,
    /// Complete authenticated pre-state roster root bytes.
    pub pre_roster_root: [u8; 32],
}

impl KaigiAuthorizationContextV1 {
    /// Check limb canonicality and the role/sequence contract.
    pub fn validate(&self) -> Result<(), KaigiAuthorizationErrorV1> {
        for (role, limbs) in [
            ("call", &self.call_id),
            ("host", &self.host_id),
            ("subject", &self.subject_id),
        ] {
            for (limb, value) in limbs.iter().enumerate() {
                if *value >= KAIGI_IDENTITY_FIELD_MODULUS_V1 {
                    return Err(KaigiAuthorizationErrorV1::NoncanonicalIdentityLimb { role, limb });
                }
            }
        }
        match self.action {
            KaigiAuthorizationActionV1::HostCreate | KaigiAuthorizationActionV1::HostEnd => {
                if self.subject_id != self.host_id || self.participation_sequence != 0 {
                    return Err(KaigiAuthorizationErrorV1::InvalidHostRole);
                }
            }
            KaigiAuthorizationActionV1::Join | KaigiAuthorizationActionV1::Leave => {
                if self.subject_id == self.host_id || self.participation_sequence == 0 {
                    return Err(KaigiAuthorizationErrorV1::InvalidParticipantRole);
                }
            }
        }
        Ok(())
    }

    pub(super) fn words(&self) -> [Scalar; CONTEXT_WORDS] {
        let mut words = [Scalar::ZERO; CONTEXT_WORDS];
        for (index, chunk) in self.network_id.chunks_exact(8).enumerate() {
            words[index] = Scalar::from(u64::from_le_bytes(chunk.try_into().expect("fixed limb")));
        }
        for (offset, limbs) in [(4, self.call_id), (10, self.host_id), (16, self.subject_id)] {
            for (index, limb) in limbs.into_iter().enumerate() {
                words[offset + index] = Scalar::from(limb);
            }
        }
        words[SEQUENCE_ROW] = Scalar::from(self.participation_sequence);
        words[ACTION_ROW] = Scalar::from(self.action as u64);
        for (index, chunk) in self.pre_roster_root.chunks_exact(8).enumerate() {
            words[ROOT_ROW + index] =
                Scalar::from(u64::from_le_bytes(chunk.try_into().expect("fixed limb")));
        }
        words
    }
}

/// Owned nonzero full-field blinding; Debug never exposes its encoding.
pub struct KaigiAuthorizationWitnessV1 {
    bytes: Box<[u8; 32]>,
}

impl KaigiAuthorizationWitnessV1 {
    /// Take canonical Pasta bytes and securely clear the supplied byte buffer,
    /// including when the encoding or nonzero check fails.
    pub fn take_blinding(bytes: &mut [u8; 32]) -> Result<Self, KaigiAuthorizationErrorV1> {
        let mut witness = Self {
            bytes: Box::new([0; 32]),
        };
        witness.bytes.copy_from_slice(bytes);
        iroha_crypto::zeroize_value_for_confidential_discard(bytes);
        let scalar = Option::<Scalar>::from(Scalar::from_repr(*witness.bytes));
        if scalar.is_none_or(|value| bool::from(value.is_zero())) {
            return Err(KaigiAuthorizationErrorV1::InvalidBlinding);
        }
        Ok(witness)
    }

    pub(super) fn scalar(&self) -> Scalar {
        Option::<Scalar>::from(Scalar::from_repr(*self.bytes)).expect("validated blinding")
    }

    #[cfg(test)]
    pub(super) fn unchecked_for_constraint_test(value: Scalar) -> Self {
        Self {
            bytes: Box::new(value.to_repr()),
        }
    }

    fn clear(&mut self) {
        iroha_crypto::zeroize_value_for_confidential_discard(self.bytes.as_mut());
    }
}
impl Clone for KaigiAuthorizationWitnessV1 {
    fn clone(&self) -> Self {
        let mut witness = Self {
            bytes: Box::new([0; 32]),
        };
        witness.bytes.copy_from_slice(self.bytes.as_ref());
        witness
    }
}
impl fmt::Debug for KaigiAuthorizationWitnessV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KaigiAuthorizationWitnessV1(<redacted>)")
    }
}
impl Drop for KaigiAuthorizationWitnessV1 {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Stable identity commitment, deterministic nullifier, and action authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KaigiAuthorizationOutputsV1 {
    /// Stable across Join/Leave and roster changes within one participation.
    pub commitment: Scalar,
    /// Depends on action and sequence, never on an arbitrary seed or blinding.
    pub nullifier: Scalar,
    /// Binds the exact action, pre-root, commitment, nullifier and private blinding.
    pub authorization: Scalar,
}
impl KaigiAuthorizationOutputsV1 {
    /// Exact canonical Pasta representations in C, N, A order; no Hash marker packing.
    #[must_use]
    pub fn canonical_bytes(&self) -> [[u8; 32]; 3] {
        [
            self.commitment.to_repr(),
            self.nullifier.to_repr(),
            self.authorization.to_repr(),
        ]
    }
}

/// Typed single-column statement with one immutable row order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KaigiAuthorizationPublicInputsV1 {
    /// Context whose 28 scalars occupy rows 0 through 27.
    pub context: KaigiAuthorizationContextV1,
    /// C, N and A occupy rows 28, 29 and 30 respectively.
    pub outputs: KaigiAuthorizationOutputsV1,
}
impl KaigiAuthorizationPublicInputsV1 {
    /// Encode network[4], call[6], host[6], subject[6], sequence, action,
    /// pre-root[4], C, N, A into the sole instance column.
    #[must_use]
    pub fn instance(&self) -> [Scalar; KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1] {
        let mut instance = [Scalar::ZERO; KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1];
        instance[..CONTEXT_WORDS].copy_from_slice(&self.context.words());
        instance[COMMITMENT_ROW] = self.outputs.commitment;
        instance[NULLIFIER_ROW] = self.outputs.nullifier;
        instance[AUTHORIZATION_ROW] = self.outputs.authorization;
        instance
    }
}

fn compute_words(words: &[Scalar; CONTEXT_WORDS], blinding: Scalar) -> KaigiAuthorizationOutputsV1 {
    let commitment =
        compute_identity_commitment_v1(words[..23].try_into().expect("fixed identity"), blinding);
    let mut payload = Zeroizing::new(ScalarSlots::<31>::default());
    payload.0[..23].copy_from_slice(&words[..23]);
    payload.0[23] = words[ACTION_ROW];
    let nullifier = sponge(DOMAIN_NULLIFIER, &payload.0[..24]);
    payload.0[24..28].copy_from_slice(&words[ROOT_ROW..CONTEXT_WORDS]);
    payload.0[28] = commitment;
    payload.0[29] = nullifier;
    payload.0[30] = blinding;
    let authorization = sponge(DOMAIN_AUTHORIZATION, &payload.0);
    KaigiAuthorizationOutputsV1 {
        commitment,
        nullifier,
        authorization,
    }
}

pub(super) fn compute_identity_commitment_v1(identity: &[Scalar; 23], blinding: Scalar) -> Scalar {
    let mut payload = Zeroizing::new(ScalarSlots::<24>::default());
    payload.0[..23].copy_from_slice(identity);
    payload.0[23] = blinding;
    sponge(DOMAIN_COMMITMENT, &payload.0)
}

pub(super) fn assign_identity_commitment_v1(
    layouter: &mut impl Layouter<Scalar>,
    shared: &KaigiRelationConfigV1,
    offset: usize,
    identity: &[AssignedValue; 23],
    secret: AssignedValue,
) -> Result<AssignedValue, Error> {
    let mut payload = identity.to_vec();
    payload.push(secret);
    assign_sponge(layouter, shared, offset, DOMAIN_COMMITMENT, &payload)
}

/// Compute the same fixed framed relation as the circuit after checking its public roles.
pub fn compute_authorization_v1(
    context: &KaigiAuthorizationContextV1,
    witness: &KaigiAuthorizationWitnessV1,
) -> Result<KaigiAuthorizationOutputsV1, KaigiAuthorizationErrorV1> {
    context.validate()?;
    let blinding = Zeroizing::new(ScalarSlots([witness.scalar()]));
    Ok(compute_words(&context.words(), blinding.0[0]))
}

/// Configuration of the fixed single-column authorization circuit.
#[derive(Clone, Debug)]
pub struct KaigiAuthorizationConfigV1 {
    shared: KaigiRelationConfigV1,
    q_host_identity: Selector,
    q_identity_difference: Selector,
    q_role: Selector,
}

/// Fixed-shape circuit with a redacted, erased-on-drop owned witness.
#[derive(Clone, Default)]
pub struct KaigiAuthorizationCircuitV1 {
    words: [Option<Scalar>; CONTEXT_WORDS],
    witness: Option<KaigiAuthorizationWitnessV1>,
}
impl fmt::Debug for KaigiAuthorizationCircuitV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KaigiAuthorizationCircuitV1")
            .field("context", &self.words)
            .field("witness", &self.witness)
            .finish()
    }
}
impl KaigiAuthorizationCircuitV1 {
    /// Construct a checked statement and take ownership of its full-field witness.
    pub fn new(
        context: KaigiAuthorizationContextV1,
        witness: KaigiAuthorizationWitnessV1,
    ) -> Result<Self, KaigiAuthorizationErrorV1> {
        context.validate()?;
        Ok(Self {
            words: context.words().map(Some),
            witness: Some(witness),
        })
    }
}

fn host_flag(action: Expression<Scalar>) -> Expression<Scalar> {
    (action.clone() - Expression::Constant(Scalar::ONE))
        * (action - Expression::Constant(Scalar::from(2)))
        * Scalar::from(2).invert().unwrap()
}

impl Circuit<Scalar> for KaigiAuthorizationCircuitV1 {
    type Config = KaigiAuthorizationConfigV1;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
        let shared = KaigiRelationConfigV1::configure(meta, KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1);
        let value = shared.value;
        let previous = shared.previous;
        let input = shared.input;
        let q_host_identity = meta.selector();
        let q_identity_difference = meta.selector();
        let q_role = meta.selector();
        meta.create_gate("Kaigi host identity", |meta| {
            vec![
                meta.query_selector(q_host_identity)
                    * host_flag(meta.query_advice(value, Rotation::cur()))
                    * (meta.query_advice(previous[0], Rotation::cur())
                        - meta.query_advice(previous[1], Rotation::cur())),
            ]
        });
        meta.create_gate("Kaigi participant identity difference", |meta| {
            vec![
                meta.query_selector(q_identity_difference)
                    * (meta.query_advice(input[1], Rotation::cur())
                        - meta.query_advice(input[0], Rotation::cur())
                        - (meta.query_advice(previous[0], Rotation::cur())
                            - meta.query_advice(previous[1], Rotation::cur()))
                            * meta.query_advice(previous[2], Rotation::cur())),
            ]
        });
        meta.create_gate("Kaigi closed action and roles", |meta| {
            let q = meta.query_selector(q_role);
            let action = meta.query_advice(value, Rotation::cur());
            let host = host_flag(action.clone());
            let participant = Expression::Constant(Scalar::ONE) - host.clone();
            let sequence = meta.query_advice(previous[0], Rotation::cur());
            let inverse = meta.query_advice(previous[1], Rotation::cur());
            let blinding = meta.query_advice(previous[2], Rotation::cur());
            let blinding_inverse = meta.query_advice(input[1], Rotation::cur());
            let difference = meta.query_advice(input[0], Rotation::cur());
            vec![
                q.clone()
                    * action.clone()
                    * (action.clone() - Expression::Constant(Scalar::ONE))
                    * (action.clone() - Expression::Constant(Scalar::from(2)))
                    * (action - Expression::Constant(Scalar::from(3))),
                q.clone() * host * sequence.clone(),
                q.clone()
                    * participant.clone()
                    * (sequence * inverse - Expression::Constant(Scalar::ONE)),
                q.clone() * participant * (difference - Expression::Constant(Scalar::ONE)),
                q * (blinding * blinding_inverse - Expression::Constant(Scalar::ONE)),
            ]
        });
        KaigiAuthorizationConfigV1 {
            shared,
            q_host_identity,
            q_identity_difference,
            q_role,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Scalar>,
    ) -> Result<(), Error> {
        let words = self
            .words
            .map(|value| value.map_or(Value::unknown(), Value::known));
        let blinding = self
            .witness
            .as_ref()
            .map_or(Value::unknown(), |witness| Value::known(witness.scalar()));
        let (cells, secret) = layouter.assign_region(
            || "Kaigi typed context",
            |mut region| {
                let cells: [Cell; CONTEXT_WORDS] = (0..CONTEXT_WORDS)
                    .map(|row| {
                        Ok(region
                            .assign_advice(config.shared.value, row, words[row])?
                            .cell())
                    })
                    .collect::<Result<Vec<_>, Error>>()?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let secret = region
                    .assign_advice(config.shared.value, CONTEXT_WORDS, blinding)?
                    .cell();
                Ok((cells, secret))
            },
        )?;
        let cells: [Cell; CONTEXT_WORDS] = cells;
        for (row, cell) in cells.iter().enumerate() {
            layouter.constrain_instance(*cell, config.shared.instance, row)?;
        }
        // The native SimpleFloorPlanner uses absolute assignment rows.
        // Reserve disjoint offsets explicitly for every fixed-shape gadget.
        let mut offset = CONTEXT_WORDS + 1;
        for row in (0..CONTEXT_WORDS).filter(|row| *row != ACTION_ROW) {
            assign_range::<64>(
                &mut layouter,
                &config.shared,
                offset,
                (cells[row], words[row]),
            )?;
            offset += 65;
            if (4..22).contains(&row) {
                let complement = words[row]
                    .map(|value| Scalar::from(KAIGI_IDENTITY_FIELD_MODULUS_V1 - 1) - value);
                let complement_cell = layouter.assign_region(
                    || "Kaigi Goldilocks complement",
                    |mut region| {
                        config.shared.q_goldilocks.enable(&mut region, offset)?;
                        let value = region
                            .assign_advice(config.shared.previous[0], offset, words[row])?
                            .cell();
                        region.constrain_equal(value, cells[row])?;
                        Ok(region
                            .assign_advice(config.shared.previous[1], offset, complement)?
                            .cell())
                    },
                )?;
                offset += 1;
                assign_range::<64>(
                    &mut layouter,
                    &config.shared,
                    offset,
                    (complement_cell, complement),
                )?;
                offset += 65;
            }
        }
        assign_roles(
            &mut layouter,
            &config,
            offset,
            &cells,
            &words,
            (secret, blinding),
        )?;
        offset += 7;
        let mut payload = cells[..23]
            .iter()
            .copied()
            .zip(words[..23].iter().copied())
            .collect::<Vec<_>>();
        payload.push((secret, blinding));
        let commitment = assign_identity_commitment_v1(
            &mut layouter,
            &config.shared,
            offset,
            payload[..23].try_into().expect("fixed identity"),
            (secret, blinding),
        )?;
        offset += (payload.len() + 2).div_ceil(2) * (POSEIDON_ROUNDS + 1);
        payload[23] = (cells[ACTION_ROW], words[ACTION_ROW]);
        let nullifier = assign_sponge(
            &mut layouter,
            &config.shared,
            offset,
            DOMAIN_NULLIFIER,
            &payload,
        )?;
        offset += (payload.len() + 2).div_ceil(2) * (POSEIDON_ROUNDS + 1);
        payload.extend(
            cells[ROOT_ROW..]
                .iter()
                .copied()
                .zip(words[ROOT_ROW..].iter().copied()),
        );
        payload.extend([commitment, nullifier, (secret, blinding)]);
        let authorization = assign_sponge(
            &mut layouter,
            &config.shared,
            offset,
            DOMAIN_AUTHORIZATION,
            &payload,
        )?;
        for (row, (cell, _)) in [
            (COMMITMENT_ROW, commitment),
            (NULLIFIER_ROW, nullifier),
            (AUTHORIZATION_ROW, authorization),
        ] {
            layouter.constrain_instance(cell, config.shared.instance, row)?;
        }
        Ok(())
    }
}

fn assign_roles(
    layouter: &mut impl Layouter<Scalar>,
    config: &KaigiAuthorizationConfigV1,
    offset: usize,
    cells: &[Cell; CONTEXT_WORDS],
    words: &[Value<Scalar>; CONTEXT_WORDS],
    secret: AssignedValue,
) -> Result<(), Error> {
    layouter.assign_region(
        || "Kaigi closed role relation",
        |mut region| {
            let mut selected = Value::known(false);
            let mut sum = Value::known(Scalar::ZERO);
            let mut previous_sum = None;
            for index in 0..6 {
                let row = offset + index;
                config.q_host_identity.enable(&mut region, row)?;
                config.q_identity_difference.enable(&mut region, row)?;
                for (column, source) in [
                    (config.shared.value, ACTION_ROW),
                    (config.shared.previous[0], 10 + index),
                    (config.shared.previous[1], 16 + index),
                ] {
                    let cell = region.assign_advice(column, row, words[source])?.cell();
                    region.constrain_equal(cell, cells[source])?;
                }
                let difference = words[10 + index] - words[16 + index];
                let inverse = difference.zip(selected).map(|(difference, selected)| {
                    if selected {
                        Scalar::ZERO
                    } else {
                        difference.invert().unwrap_or(Scalar::ZERO)
                    }
                });
                selected = selected
                    .zip(difference)
                    .map(|(selected, difference)| selected || !bool::from(difference.is_zero()));
                region.assign_advice(config.shared.previous[2], row, inverse)?;
                let before = region
                    .assign_advice(config.shared.input[0], row, sum)?
                    .cell();
                if let Some(previous) = previous_sum {
                    region.constrain_equal(before, previous)?;
                } else {
                    region.constrain_constant(before, Scalar::ZERO)?;
                }
                sum = sum + difference * inverse;
                previous_sum = Some(
                    region
                        .assign_advice(config.shared.input[1], row, sum)?
                        .cell(),
                );
            }
            let row = offset + 6;
            config.q_role.enable(&mut region, row)?;
            for (column, source) in [
                (config.shared.value, ACTION_ROW),
                (config.shared.previous[0], SEQUENCE_ROW),
            ] {
                let cell = region.assign_advice(column, row, words[source])?.cell();
                region.constrain_equal(cell, cells[source])?;
            }
            region.assign_advice(
                config.shared.previous[1],
                row,
                words[SEQUENCE_ROW].map(|v| v.invert().unwrap_or(Scalar::ZERO)),
            )?;
            let blind = region
                .assign_advice(config.shared.previous[2], row, secret.1)?
                .cell();
            region.constrain_equal(blind, secret.0)?;
            region.assign_advice(
                config.shared.input[1],
                row,
                secret.1.map(|v| v.invert().unwrap_or(Scalar::ZERO)),
            )?;
            let difference = region
                .assign_advice(config.shared.input[0], row, sum)?
                .cell();
            region.constrain_equal(difference, previous_sum.expect("six fixed identity limbs"))?;
            Ok(())
        },
    )
}
