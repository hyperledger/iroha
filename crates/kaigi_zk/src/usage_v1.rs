//! Final V1 call-bound usage authorization with an opening of the stored host C.
//!
//! Core authenticates network, permanent call, original host, pre-roster root,
//! segment and metrics. One exact 25-row column binds those facts, host C and U.
//! Owned blinding and CPU scratch cleanup use the authorization witness and
//! shared frame owner; native prover-owned copies remain outside that erasure guarantee.

use core::{array, fmt};
use ff::{Field, PrimeField};
use iroha_plonk::{
    cs::{ConstraintSystem, Expression, Rotation, Selector},
    frontend::{Cell, Circuit, Error, Layouter, SimpleFloorPlanner, Value},
};
use zeroize::Zeroizing;

use crate::{
    POSEIDON_ROUNDS, Scalar,
    authorization_v1::{
        KaigiAuthorizationActionV1, KaigiAuthorizationContextV1, KaigiAuthorizationErrorV1,
        KaigiAuthorizationWitnessV1, assign_identity_commitment_v1, compute_identity_commitment_v1,
    },
    relation_v1::{
        AssignedValue, GOLDILOCKS_MODULUS_V1, KaigiRelationConfigV1, ScalarSlots, assign_range,
        assign_sponge, sponge,
    },
};

/// Fixed IPA domain exponent for the complete final usage relation.
pub const KAIGI_USAGE_CIRCUIT_K_V1: u32 = 12;
/// Exactly one instance column contains this many rows.
pub const KAIGI_USAGE_INSTANCE_ROWS_V1: usize = 25;
/// Canonical circuit identity; the previous usage relation has no alternate path.
pub const KAIGI_USAGE_CIRCUIT_ID_V1: &str = "pipa-r/pasta/kaigi-usage-v1";
/// Exact native registry label for the compiled usage relation.
pub const KAIGI_USAGE_BACKEND_V1: &str = "pipa-r/pasta/kaigi-usage-v1";
/// Exact final public-input schema.
pub const KAIGI_USAGE_PUBLIC_INPUTS_SCHEMA_V1: &[u8] = b"kaigi-usage-v1";

const CONTEXT_WORDS: usize = 23;
const SEGMENT_ROW: usize = 20;
const DURATION_ROW: usize = 21;
const GAS_ROW: usize = 22;
const HOST_COMMITMENT_ROW: usize = 23;
const USAGE_COMMITMENT_ROW: usize = 24;
const ASSIGNED_ROWS: usize = 4037;
const DOMAIN_USAGE: u64 = 0x4b41_4947_4956_3155;

/// Invalid typed usage context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KaigiUsageErrorV1 {
    /// Complete call/host identity validation failed.
    Identity(KaigiAuthorizationErrorV1),
    /// A usage segment must have positive duration.
    ZeroDuration,
}
impl fmt::Display for KaigiUsageErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(error) => error.fmt(f),
            Self::ZeroDuration => f.write_str("Kaigi usage duration must be positive"),
        }
    }
}
impl std::error::Error for KaigiUsageErrorV1 {}

/// Complete trusted context for one host-authorized usage segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KaigiUsageContextV1 {
    /// Exact genesis-derived network bytes, without field reduction.
    pub network_id: [u8; 32],
    /// All six canonical Goldilocks call identity limbs.
    pub call_id: [u64; 6],
    /// All six canonical Goldilocks original host identity limbs.
    pub host_id: [u64; 6],
    /// Exact authenticated current roster root bytes.
    pub pre_roster_root: [u8; 32],
    /// Ledger-owned segment counter before this usage record is appended.
    pub segment_index: u32,
    /// Public instruction duration, constrained positive and within u64.
    pub duration_ms: u64,
    /// Public instruction billed gas, constrained within u64.
    pub billed_gas: u64,
}
impl KaigiUsageContextV1 {
    /// Validate identity canonicality and positive duration.
    pub fn validate(&self) -> Result<(), KaigiUsageErrorV1> {
        self.host_context()
            .validate()
            .map_err(KaigiUsageErrorV1::Identity)?;
        if self.duration_ms == 0 {
            return Err(KaigiUsageErrorV1::ZeroDuration);
        }
        Ok(())
    }
    fn host_context(&self) -> KaigiAuthorizationContextV1 {
        KaigiAuthorizationContextV1 {
            network_id: self.network_id,
            call_id: self.call_id,
            host_id: self.host_id,
            subject_id: self.host_id,
            participation_sequence: 0,
            action: KaigiAuthorizationActionV1::HostCreate,
            pre_roster_root: self.pre_roster_root,
        }
    }
    fn words(&self) -> [Scalar; CONTEXT_WORDS] {
        let host = self.host_context().words();
        let mut words = [Scalar::ZERO; CONTEXT_WORDS];
        words[..16].copy_from_slice(&host[..16]);
        words[16..20].copy_from_slice(&host[24..28]);
        words[SEGMENT_ROW] = Scalar::from(u64::from(self.segment_index));
        words[DURATION_ROW] = Scalar::from(self.duration_ms);
        words[GAS_ROW] = Scalar::from(self.billed_gas);
        words
    }
}

/// Canonical scalar commitments to the host opening and this usage segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KaigiUsageOutputsV1 {
    /// The same stable host C established by final authorization V1.
    pub host_commitment: Scalar,
    /// U binds every context field, host C and the private blinding.
    pub usage_commitment: Scalar,
}
impl KaigiUsageOutputsV1 {
    /// Exact raw canonical Pasta representations, in C/U order.
    #[must_use]
    pub fn canonical_bytes(&self) -> [[u8; 32]; 2] {
        [
            self.host_commitment.to_repr(),
            self.usage_commitment.to_repr(),
        ]
    }
}

/// Sole public column with one fixed final row order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KaigiUsagePublicInputsV1 {
    /// Trusted context occupies rows 0 through 22.
    pub context: KaigiUsageContextV1,
    /// Host C and U occupy rows 23 and 24.
    pub outputs: KaigiUsageOutputsV1,
}
impl KaigiUsagePublicInputsV1 {
    /// Encode network[4], call[6], host[6], root[4], segment, duration, gas, C, U.
    #[must_use]
    pub fn instance(&self) -> [Scalar; KAIGI_USAGE_INSTANCE_ROWS_V1] {
        let mut instance = [Scalar::ZERO; KAIGI_USAGE_INSTANCE_ROWS_V1];
        instance[..CONTEXT_WORDS].copy_from_slice(&self.context.words());
        instance[HOST_COMMITMENT_ROW] = self.outputs.host_commitment;
        instance[USAGE_COMMITMENT_ROW] = self.outputs.usage_commitment;
        instance
    }
}

fn identity_words(words: &[Scalar; CONTEXT_WORDS]) -> [Scalar; 23] {
    array::from_fn(|row| match row {
        0..16 => words[row],
        16..22 => words[row - 6],
        _ => Scalar::ZERO,
    })
}
fn compute_words(words: &[Scalar; CONTEXT_WORDS], blinding: Scalar) -> KaigiUsageOutputsV1 {
    let host_commitment = compute_identity_commitment_v1(&identity_words(words), blinding);
    let mut payload = Zeroizing::new(ScalarSlots::<25>::default());
    payload.0[..23].copy_from_slice(words);
    payload.0[23] = host_commitment;
    payload.0[24] = blinding;
    KaigiUsageOutputsV1 {
        host_commitment,
        usage_commitment: sponge(DOMAIN_USAGE, &payload.0),
    }
}

/// Compute final usage commitments with the same nonzero host opening witness.
pub fn compute_usage_v1(
    context: &KaigiUsageContextV1,
    witness: &KaigiAuthorizationWitnessV1,
) -> Result<KaigiUsageOutputsV1, KaigiUsageErrorV1> {
    context.validate()?;
    let secret = Zeroizing::new(ScalarSlots([witness.scalar()]));
    Ok(compute_words(&context.words(), secret.0[0]))
}

/// Configuration for the fixed call-bound host usage relation.
#[derive(Clone, Debug)]
pub struct KaigiUsageConfigV1 {
    shared: KaigiRelationConfigV1,
    q_nonzero: Selector,
}

/// Fixed-shape usage circuit with an owned, redacted host blinding witness.
#[derive(Clone, Default)]
pub struct KaigiUsageCircuitV1 {
    words: [Option<Scalar>; CONTEXT_WORDS],
    witness: Option<KaigiAuthorizationWitnessV1>,
}
impl fmt::Debug for KaigiUsageCircuitV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KaigiUsageCircuitV1")
            .field("context", &self.words)
            .field("witness", &self.witness)
            .finish()
    }
}
impl KaigiUsageCircuitV1 {
    /// Validate the context and take the same private blinding used for host C.
    pub fn new(
        context: KaigiUsageContextV1,
        witness: KaigiAuthorizationWitnessV1,
    ) -> Result<Self, KaigiUsageErrorV1> {
        context.validate()?;
        Ok(Self {
            words: context.words().map(Some),
            witness: Some(witness),
        })
    }
}
impl Circuit<Scalar> for KaigiUsageCircuitV1 {
    type Config = KaigiUsageConfigV1;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
        let shared = KaigiRelationConfigV1::configure(meta, KAIGI_USAGE_INSTANCE_ROWS_V1);
        let q_nonzero = meta.selector();
        meta.create_gate("Kaigi usage nonzero duration and host blinding", |meta| {
            vec![
                meta.query_selector(q_nonzero)
                    * (meta.query_advice(shared.previous[0], Rotation::cur())
                        * meta.query_advice(shared.previous[1], Rotation::cur())
                        - Expression::Constant(Scalar::ONE)),
            ]
        });
        KaigiUsageConfigV1 { shared, q_nonzero }
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
            .map_or(Value::unknown(), |secret| Value::known(secret.scalar()));
        let (cells, secret, zero) = layouter.assign_region(
            || "Kaigi usage typed context",
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
                    .assign_advice(config.shared.value, 23, blinding)?
                    .cell();
                let zero = region
                    .assign_advice(config.shared.value, 24, Value::known(Scalar::ZERO))?
                    .cell();
                region.constrain_constant(zero, Scalar::ZERO)?;
                Ok((cells, secret, zero))
            },
        )?;
        for (row, cell) in cells.iter().enumerate() {
            layouter.constrain_instance(*cell, config.shared.instance, row)?;
        }
        let mut offset = 25;
        for row in 0..CONTEXT_WORDS {
            if row == SEGMENT_ROW {
                assign_range::<32>(
                    &mut layouter,
                    &config.shared,
                    offset,
                    (cells[row], words[row]),
                )?;
                offset += 33;
            } else {
                assign_range::<64>(
                    &mut layouter,
                    &config.shared,
                    offset,
                    (cells[row], words[row]),
                )?;
                offset += 65;
            }
            if (4..16).contains(&row) {
                let complement =
                    words[row].map(|value| Scalar::from(GOLDILOCKS_MODULUS_V1 - 1) - value);
                let cell = layouter.assign_region(
                    || "Kaigi usage canonical identity",
                    |mut region| {
                        config.shared.q_goldilocks.enable(&mut region, offset)?;
                        let source = region
                            .assign_advice(config.shared.previous[0], offset, words[row])?
                            .cell();
                        region.constrain_equal(source, cells[row])?;
                        Ok(region
                            .assign_advice(config.shared.previous[1], offset, complement)?
                            .cell())
                    },
                )?;
                offset += 1;
                assign_range::<64>(&mut layouter, &config.shared, offset, (cell, complement))?;
                offset += 65;
            }
        }
        for (source, value) in [
            (secret, blinding),
            (cells[DURATION_ROW], words[DURATION_ROW]),
        ] {
            layouter.assign_region(
                || "Kaigi usage nonzero opening and duration",
                |mut region| {
                    config.q_nonzero.enable(&mut region, offset)?;
                    let cell = region
                        .assign_advice(config.shared.previous[0], offset, value)?
                        .cell();
                    region.constrain_equal(cell, source)?;
                    region.assign_advice(
                        config.shared.previous[1],
                        offset,
                        value.map(|v| v.invert().unwrap_or(Scalar::ZERO)),
                    )?;
                    Ok(())
                },
            )?;
            offset += 1;
        }
        let identity: [AssignedValue; 23] = array::from_fn(|row| match row {
            0..16 => (cells[row], words[row]),
            16..22 => (cells[row - 6], words[row - 6]),
            _ => (zero, Value::known(Scalar::ZERO)),
        });
        let commitment = assign_identity_commitment_v1(
            &mut layouter,
            &config.shared,
            offset,
            &identity,
            (secret, blinding),
        )?;
        offset += 13 * (POSEIDON_ROUNDS + 1);
        let mut payload: Vec<_> = cells.into_iter().zip(words).collect();
        payload.extend([commitment, (secret, blinding)]);
        let usage = assign_sponge(
            &mut layouter,
            &config.shared,
            offset,
            DOMAIN_USAGE,
            &payload,
        )?;
        offset += 14 * (POSEIDON_ROUNDS + 1);
        debug_assert_eq!(offset, ASSIGNED_ROWS);
        layouter.constrain_instance(commitment.0, config.shared.instance, HOST_COMMITMENT_ROW)?;
        layouter.constrain_instance(usage.0, config.shared.instance, USAGE_COMMITMENT_ROW)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
