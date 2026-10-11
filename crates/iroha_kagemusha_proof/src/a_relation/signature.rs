//! Signature exports from a hard-verified Q or its exact separately verified context projection.

use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, GlueChip, Word, ff::Nat, p256::VerifyMode};
use iroha_plonk_recursion::verifier::VerifierChip;

use super::{AProofPlan, VerifiedQCells, bounded_word};
use crate::q_signature::{QSignaturePlan, SLOT_WORDS, SignatureKey};

/// The exact message, raw unsigned key/signature and verdict proved by one Q
/// slot. No constructor from arbitrary scalar cells is exposed.
#[must_use = "bind the message, key and signature to the authenticated object and include its soft verdict"]
#[derive(Clone, Debug)]
pub struct SignatureProofCells {
    message: Word<Fp>,
    key: [Word<Fp>; 4],
    signature: [Word<Fp>; 4],
    valid: Bit<Fp>,
    key_policy: SignatureKey,
    mode: VerifyMode,
}
impl SignatureProofCells {
    /// Canonical Fp signing-message digest, before SHA-256.
    pub const fn message(&self) -> &Word<Fp> {
        &self.message
    }
    /// Exact raw x/y as low128/high128, including bit255.
    pub const fn key(&self) -> &[Word<Fp>; 4] {
        &self.key
    }
    /// Exact raw r/s as low128/high128, including bit255.
    pub const fn signature(&self) -> &[Word<Fp>; 4] {
        &self.signature
    }
    /// The proved exact ECDSA verdict; hard slots are constrained true.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }
    /// Immutable hard/soft mode of the admitted signature slot.
    pub const fn mode(&self) -> VerifyMode {
        self.mode
    }
    /// Immutable key policy enforced while extracting this admitted Q slot.
    /// Fixed coordinates are constrained to constants, never witness-selected.
    pub const fn key_policy(&self) -> SignatureKey {
        self.key_policy
    }
}

/// Signature slots kept with their exact Q identity, instances and pending opening.
/// A concrete stage binds this bundle to its committed instance cells and folds
/// `verified()`; extracting slots never discards that deferred proof obligation.
#[must_use = "bind to the owning context and retain the exact verified Q opening"]
#[derive(Clone, Debug)]
pub struct SignatureQCells {
    verified: VerifiedQCells,
    slots: Vec<SignatureProofCells>,
}
impl SignatureQCells {
    /// Original hard Q result, including the exact pending generator opening.
    pub const fn verified(&self) -> &VerifiedQCells {
        &self.verified
    }
    /// Ordered opaque signature exports of that same Q proof.
    pub fn slots(&self) -> &[SignatureProofCells] {
        &self.slots
    }
    /// Bind to this stage's fixed Q identity and the exact `D_ctx` instance cells.
    /// # Errors
    /// Wrong index/key/shape, layout failure, or an unsatisfied instance equality.
    pub fn bind_context(
        &self,
        region: &mut Region<'_, Fp>,
        operation: &AProofPlan,
        index: usize,
        instances: &[Vec<iroha_plonk_recursion::codec::ScalarCells<Ep>>],
    ) -> Result<(), Error> {
        let expected = operation.q(index).ok_or(Error::Synthesis)?;
        if self.verified.index != index || self.verified.instances.len() != instances.len() {
            return Err(Error::Synthesis);
        }
        GlueChip::assert_constant(
            region,
            &self.verified.key_digest,
            expected
                .key
                .kagemusha_digest(expected.verifier().binding())
                .map_err(|_| Error::Synthesis)?,
        )?;
        for (actual, expected) in self.verified.instances.iter().zip(instances) {
            if actual.len() != expected.len() {
                return Err(Error::Synthesis);
            }
            for (actual, expected) in actual.iter().zip(expected) {
                GlueChip::assert_equal(region, actual.lo().word(), expected.lo().word())?;
                GlueChip::assert_equal(region, actual.hi().word(), expected.hi().word())?;
            }
        }
        Ok(())
    }
}
/// A signature bundle paired with the instance cells committed by this stage's context.
#[derive(Clone, Copy, Debug)]
pub struct SignatureQContext<'a> {
    /// Same Q proof whose pending opening enters this stage's fixed fold.
    pub bundle: &'a SignatureQCells,
    /// Exact Q column cells from `ContextInputs::q_instances`.
    pub instances: &'a [Vec<iroha_plonk_recursion::codec::ScalarCells<Ep>>],
}

/// Bind an admitted hard Q output to a fixed signature schema and extract its
/// slots. The exact key digest, index and one-Bounded-column descriptor must
/// agree with the operation plan. Raw limbs retain all128bits and may encode
/// invalid P-256 coordinates or signatures in soft slots.
///
/// # Errors
/// Wrong Q index/schema/column count or layout failure. Wrong key identity,
/// fixed key limbs, nonboolean verdicts and false hard verdicts are unsatisfiable.
pub fn bind_signature_q(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    operation: &AProofPlan,
    index: usize,
    schema: &QSignaturePlan,
    verified: &VerifiedQCells,
) -> Result<SignatureQCells, Error> {
    let fixed = operation.q(index).ok_or(Error::Synthesis)?;
    let descriptor = fixed.verifier().binding().descriptor();
    if verified.index != index
        || descriptor.instance_lengths
            != [u32::try_from(schema.instance_length()).map_err(|_| Error::BoundsFailure)?]
        || descriptor.instance_types.as_deref() != Some(&QSignaturePlan::instance_types())
        || verified.instances.len() != 1
        || verified.instances[0].len() != schema.instance_length()
    {
        return Err(Error::Synthesis);
    }
    GlueChip::assert_constant(
        region,
        &verified.key_digest,
        fixed
            .key
            .kagemusha_digest(fixed.verifier().binding())
            .map_err(|_| Error::Synthesis)?,
    )?;
    let out = signature_slots(chip, region, schema, &verified.instances)?;
    Ok(SignatureQCells {
        verified: verified.clone(),
        slots: out,
    })
}

/// Typed Q public projection for a fixed consumer whose context separately
/// hard-verifies the Q exactly once. It carries no pending opening and cannot
/// replace `VerifiedQCells` in an accumulation ledger.
#[derive(Clone, Debug)]
pub(super) struct SignatureQProjection {
    index: usize,
    key_digest: Fp,
    instances: Vec<Vec<iroha_plonk_recursion::codec::ScalarCells<Ep>>>,
    slots: Vec<SignatureProofCells>,
}
impl SignatureQProjection {
    pub(super) fn slots(&self) -> &[SignatureProofCells] {
        &self.slots
    }
    pub(super) fn bind_context(
        &self,
        region: &mut Region<'_, Fp>,
        operation: &AProofPlan,
        index: usize,
        instances: &[Vec<iroha_plonk_recursion::codec::ScalarCells<Ep>>],
    ) -> Result<(), Error> {
        let fixed = operation.q(index).ok_or(Error::Synthesis)?;
        if self.index != index
            || self.key_digest
                != fixed
                    .key
                    .kagemusha_digest(fixed.verifier().binding())
                    .map_err(|_| Error::Synthesis)?
            || self.instances.len() != instances.len()
        {
            return Err(Error::Synthesis);
        }
        for (actual, expected) in self.instances.iter().zip(instances) {
            if actual.len() != expected.len() {
                return Err(Error::Synthesis);
            }
            for (a, b) in actual.iter().zip(expected) {
                GlueChip::assert_equal(region, a.lo().word(), b.lo().word())?;
                GlueChip::assert_equal(region, a.hi().word(), b.hi().word())?;
            }
        }
        Ok(())
    }
}

pub(super) fn project_signature_q(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    operation: &AProofPlan,
    index: usize,
    schema: &QSignaturePlan,
    instances: &[Vec<iroha_plonk_recursion::codec::ScalarCells<Ep>>],
) -> Result<SignatureQProjection, Error> {
    let fixed = operation.q(index).ok_or(Error::Synthesis)?;
    let descriptor = fixed.verifier().binding().descriptor();
    if descriptor.instance_lengths
        != [u32::try_from(schema.instance_length()).map_err(|_| Error::BoundsFailure)?]
        || descriptor.instance_types.as_deref() != Some(&QSignaturePlan::instance_types())
        || instances.len() != 1
        || instances[0].len() != schema.instance_length()
    {
        return Err(Error::Synthesis);
    }
    Ok(SignatureQProjection {
        index,
        key_digest: fixed
            .key
            .kagemusha_digest(fixed.verifier().binding())
            .map_err(|_| Error::Synthesis)?,
        instances: instances.to_vec(),
        slots: signature_slots(chip, region, schema, instances)?,
    })
}

fn signature_slots(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    schema: &QSignaturePlan,
    instances: &[Vec<iroha_plonk_recursion::codec::ScalarCells<Ep>>],
) -> Result<Vec<SignatureProofCells>, Error> {
    let mut out = Vec::with_capacity(schema.slots().len());
    for (slot, values) in schema
        .slots()
        .iter()
        .zip(instances[0].chunks_exact(SLOT_WORDS))
    {
        let words = values
            .iter()
            .map(|scalar| bounded_word(chip, region, scalar))
            .collect::<Result<Vec<_>, _>>()?;
        for word in &words[1..9] {
            chip.uint().range_check::<128>(region, word)?;
        }
        let valid = chip.uint().glue().assert_bool(region, &words[9])?;
        if slot.mode == VerifyMode::Hard {
            GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        }
        if let SignatureKey::Fixed(key) = slot.key {
            for (words, coordinate) in words[1..5].chunks_exact(2).zip([key.x, key.y]) {
                let coordinate = Nat::from_words(coordinate);
                for (word, integer) in words
                    .iter()
                    .zip([coordinate.low_u128(), coordinate.shr(128).low_u128()])
                {
                    GlueChip::assert_constant(region, word, Fp::from_u128(integer))?;
                }
            }
        }
        out.push(SignatureProofCells {
            message: words[0].clone(),
            key: core::array::from_fn(|i| words[1 + i].clone()),
            signature: core::array::from_fn(|i| words[5 + i].clone()),
            valid,
            key_policy: slot.key,
            mode: slot.mode,
        });
    }
    Ok(out)
}
