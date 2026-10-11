//! Mandatory own-step credential authorization shared by operation relations.
//!
//! A hard predecessor's history does not replace C4: every step verifies the
//! current credential and its direct Enrollment certificate again. Signature
//! inputs are opaque exports of hard-verified Q leaves, never witness verdicts.

use ff::Field;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{GlueChip, Word, p256::native::Affine};
use iroha_plonk_recursion::verifier::VerifierChip;

use super::SignatureProofCells;
use crate::{
    operation_relation::{
        map_effects::MapState,
        objects::{
            SignedObjectCells,
            credential::{CredentialAuthorization, CredentialCells},
        },
        state::StateCells,
        statement::StatementCells,
    },
    q_signature::SignatureKey,
};

/// Circuit-fixed provider contract and canonical scheme-root key.
///
/// The scheme identity depends on the finished artifact inventory. It is carried
/// by the constrained state and signed objects, never fixed into their keys.
#[derive(Clone, Copy, Debug)]
pub struct OwnPolicy {
    pub(super) provider: [u128; 2],
    pub(super) root: Affine,
}
pub(super) struct OwnScope {
    pub(super) scheme: [Word<Fp>; 2],
    pub(super) provider: [Word<Fp>; 2],
}
impl OwnPolicy {
    /// Check a nonzero fixed provider and a finite canonical root point.
    /// # Errors
    /// A zero provider or invalid P-256 point.
    pub fn new(provider: [u128; 2], root: Affine) -> Result<Self, Error> {
        if provider == [0; 2] || !root.is_valid() {
            return Err(Error::Synthesis);
        }
        Ok(Self { provider, root })
    }
    // Copy the already constrained own-state limbs, rather than allocate a
    // second claimed scheme. The owning stage binds that state to its hard
    // predecessor/public frame; native consumers pin the installed Scheme.
    pub(super) fn scope(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        current: &StateCells,
    ) -> Result<OwnScope, Error> {
        Ok(OwnScope {
            scheme: core::array::from_fn(|i| {
                current.core()[crate::witness::core_index::SCHEME + i].clone()
            }),
            provider: self.provider(chip, region)?,
        })
    }

    // Provider-only consumers need no independent scheme proposal.
    pub(super) fn provider(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
    ) -> Result<[Word<Fp>; 2], Error> {
        self.provider
            .map(|v| {
                chip.uint()
                    .constant::<128>(region, v)
                    .map(|v| v.word().clone())
            })
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }
}

/// Exact same-tape objects and state used by the mandatory current-credential check.
#[derive(Clone, Copy)]
pub struct CurrentAuthorization<'a> {
    /// Current credential, with every original signature byte retained.
    pub credential: &'a SignedObjectCells,
    /// Direct Enrollment-role certificate from the fixed scheme root.
    pub certificate: &'a SignedObjectCells,
    /// Q-proved credential signature under the certificate's delegated key.
    pub credential_proof: &'a SignatureProofCells,
    /// Q-proved certificate signature under a circuit-fixed scheme-root key.
    pub certificate_proof: &'a SignatureProofCells,
    /// State and public prefix whose current credential and payment key are used.
    pub current: MapState<'a>,
    /// Own hard statement, whose credential and scope must match that state.
    pub statement: &'a StatementCells,
}

/// Reverify C4 and bind its exact state, lineage, statement and provider scope.
///
/// This does not replace the own receipt signature or the recursive opening
/// obligations of either Q. A stage must retain the two Q signature exports in
/// its fixed schedule and commit these original object tapes in `D_ctx`.
/// # Errors
/// Wrong root-key policy/layout, or unsatisfiable own authentication/continuity.
pub fn authenticate_current(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    policy: OwnPolicy,
    input: CurrentAuthorization<'_>,
) -> Result<(), Error> {
    if input.certificate_proof.key_policy() != SignatureKey::Fixed(policy.root) {
        return Err(Error::Synthesis);
    }
    let OwnScope { scheme, provider } = policy.scope(chip, region, input.current.state)?;
    let mut uint = chip.uint();
    input
        .current
        .state
        .bind_lineage(&mut uint, region, input.current.lineage)?;
    let credential = CredentialCells::check(&mut uint, region, input.credential)?;
    let valid = credential.authenticate(
        &mut uint,
        region,
        &CredentialAuthorization {
            certificate: input.certificate,
            certificate_proof: input.certificate_proof,
            credential_proof: input.credential_proof,
            root_key: input.certificate_proof.key(),
            scheme: &scheme,
            provider: &provider,
        },
    )?;
    GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
    let valid = credential.bind_current(
        &mut uint,
        region,
        input.current.state,
        input.current.lineage,
    )?;
    GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
    GlueChip::assert_equal(
        region,
        input.credential.digest(),
        &input.statement.fields()[7],
    )?;
    for (actual, expected) in input.statement.fields()[3..7]
        .iter()
        .zip(&input.current.state.core()[1..5])
    {
        GlueChip::assert_equal(region, actual, expected)?;
    }
    Ok(())
}

/// Exact own consuming-step proof digest, linked to a hard predecessor and own sigma.
/// The constructor binds the 320-byte public transcript followed by
/// `πΩ || accP || accV`, exactly as the native lineage wire encoder.
#[derive(Clone, Debug)]
pub struct ConsumingProofCells {
    digest: Word<Fp>,
    predecessor: [Word<Fp>; 18],
    statement: Word<Fp>,
    sigma_chunks: Vec<Word<Fp>>,
}
impl ConsumingProofCells {
    /// Exact public lineage transcript size preceding the transport proof.
    pub const PUBLIC_BYTES: usize = 320;
    /// Required secondary views for `LE32 || public || πΩ || accP || accV`.
    /// # Errors
    /// Invalid fixed proof length or arithmetic overflow.
    pub fn omega_segments(
        proof_bytes: usize,
    ) -> Result<Vec<iroha_plonk_gadgets::bytes::tape::SegmentSpec>, Error> {
        use iroha_plonk_gadgets::bytes::{element::le_message_segments, tape::SegmentSpec};
        if proof_bytes == 0 || !proof_bytes.is_multiple_of(32) {
            return Err(Error::Synthesis);
        }
        let mut out = vec![SegmentSpec::little(0, 4), SegmentSpec::little(4, 2)];
        for offset in [2, 34, 98] {
            for limb in [0, 16] {
                out.push(SegmentSpec::little(4 + offset + limb, 16));
            }
        }
        for offset in [66, 130, 256, 288] {
            out.extend(le_message_segments(4 + offset, 1));
        }
        out.push(SegmentSpec::little(4 + 162, 1));
        for i in 0..4 {
            out.push(SegmentSpec::big(4 + 163 + i * 16, 16));
        }
        for (offset, bytes) in [(227, 1), (228, 8), (236, 4), (240, 16)] {
            out.push(SegmentSpec::little(4 + offset, bytes));
        }
        let transport = proof_bytes
            .checked_add(2 * iroha_plonk_recursion::ACCUMULATOR_BYTES)
            .ok_or(Error::BoundsFailure)?;
        out.extend(le_message_segments(4 + Self::PUBLIC_BYTES, transport / 32));
        out.sort_unstable_by_key(|spec| spec.start);
        Ok(out)
    }

    /// Bind two fixed canonical carriers `LE32 || Ω` and `LE32 || σ`.
    /// `omega` secondary views contain its LE32 length and every 32-byte element;
    /// `sigma` primary views are the same 31-byte chunks exported by hard Q sigma.
    /// Both carriers' primary segments must form the exact contiguous partition.
    /// # Errors
    /// Wrong descriptor capacities/segments, or unsatisfied length/byte/claim links.
    pub fn from_runs(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        predecessor: &super::PredecessorCells,
        sigma: &super::SigmaBindingCells,
        omega: &iroha_plonk_gadgets::bytes::tape::ByteRun<Fp>,
        sigma_run: &iroha_plonk_gadgets::bytes::tape::ByteRun<Fp>,
    ) -> Result<Self, Error> {
        use iroha_pasta::Fq;
        use iroha_plonk_gadgets::{
            UintChip,
            bytes::{
                PBytes,
                element::{
                    assert_foreign_point_bytes, assert_le_max, assert_point_bytes,
                    decode_le_element, modulus_max,
                },
                tape::SegmentSpec,
            },
        };
        let proof_len = predecessor
            .proof
            .messages()
            .len()
            .checked_mul(32)
            .ok_or(Error::BoundsFailure)?;
        let omega_len = proof_len
            .checked_add(2 * iroha_plonk_recursion::ACCUMULATOR_BYTES + Self::PUBLIC_BYTES)
            .ok_or(Error::BoundsFailure)?;
        if omega.len() != omega_len + 4
            || sigma_run.len() != sigma.carrier_length()?
            || sigma_run.primary().len() != sigma.proof_chunks().len()
            || predecessor.vesta.source_k() != 16
            || predecessor.pallas.source()
                != iroha_plonk_recursion::accumulation_circuit::FoldSource::Fixed(16)
        {
            return Err(Error::Synthesis);
        }
        GlueChip::assert_constant(
            region,
            predecessor.proof.length().word(),
            Fp::from(u64::try_from(proof_len).map_err(|_| Error::BoundsFailure)?),
        )?;
        let length = chip.uint().range_check::<32>(
            region,
            omega.secondary_segment(SegmentSpec::little(0, 4))?.word(),
        )?;
        GlueChip::assert_constant(
            region,
            length.word(),
            Fp::from(u64::try_from(omega_len).map_err(|_| Error::BoundsFailure)?),
        )?;
        for (segment, expected) in sigma_run.primary().iter().zip(sigma.proof_chunks()) {
            GlueChip::assert_equal(region, segment.word(), expected)?;
        }
        // This also requires the own binding to have checked its exact LE32 length.
        sigma.step_digest()?;
        Self::bind_public(chip, region, omega, &predecessor.public)?;
        GlueChip::assert_constant(region, predecessor.pallas.source_k(), Fp::from(16))?;
        for (index, expected) in predecessor.proof.messages().iter().enumerate() {
            let actual = decode_le_element(
                &mut chip.uint(),
                region,
                omega,
                4 + Self::PUBLIC_BYTES + 32 * index,
            )?;
            for (a, b) in [
                (actual.lo().word(), expected.lo().word()),
                (actual.hi().word(), expected.hi().word()),
                (actual.top().word(), expected.top().word()),
            ] {
                GlueChip::assert_equal(region, a, b)?;
            }
        }
        let p_offset = 4 + Self::PUBLIC_BYTES + proof_len;
        let element = decode_le_element(&mut chip.uint(), region, omega, p_offset)?;
        assert_point_bytes(
            &mut chip.uint(),
            region,
            &element,
            predecessor.pallas.g().x(),
            predecessor.pallas.g().y(),
        )?;
        for (i, scalar) in predecessor.pallas.challenges().iter().enumerate() {
            let element =
                decode_le_element(&mut chip.uint(), region, omega, p_offset + 32 * (i + 1))?;
            GlueChip::assert_equal(region, element.lo().word(), scalar.lo().word())?;
            GlueChip::assert_equal(region, element.hi().word(), scalar.hi().word())?;
            GlueChip::assert_constant(region, element.top().word(), Fp::ZERO)?;
        }
        let v_offset = p_offset + iroha_plonk_recursion::ACCUMULATOR_BYTES;
        let element = decode_le_element(&mut chip.uint(), region, omega, v_offset)?;
        let [x, y] = predecessor.vesta.coordinates();
        assert_foreign_point_bytes::<Fp, Fq>(
            &mut chip.uint(),
            region,
            &element,
            y.lo(),
            &UintChip::widen::<127, 128>(y.hi()),
        )?;
        GlueChip::assert_equal(region, element.lo().word(), x.lo().word())?;
        GlueChip::assert_equal(region, element.hi().word(), x.hi().word())?;
        for (i, scalar) in predecessor.vesta.challenges().iter().enumerate() {
            let element =
                decode_le_element(&mut chip.uint(), region, omega, v_offset + 32 * (i + 1))?;
            assert_le_max(
                &mut chip.uint(),
                region,
                element.lo().word(),
                &UintChip::widen::<127, 128>(element.hi()),
                modulus_max::<Fp>(),
            )?;
            GlueChip::assert_constant(region, element.top().word(), Fp::ZERO)?;
            let native = chip.uint().glue().linear(
                region,
                &[
                    (Fp::ONE, element.lo().word()),
                    (Fp::from(2).pow_vartime([128]), element.hi().word()),
                ],
                Fp::ZERO,
            )?;
            GlueChip::assert_equal(region, &native, scalar)?;
        }
        let mut tape = PBytes::new();
        for run in [omega, sigma_run] {
            let mut offset = 0;
            for segment in run.primary() {
                let size = (run.len() - offset).min(31);
                if segment.spec() != SegmentSpec::little(offset, size) {
                    return Err(Error::Synthesis);
                }
                tape.push_bounded_split(
                    &mut chip.uint(),
                    region,
                    &segment.bounded().ok_or(Error::Synthesis)?,
                )?;
                offset += size;
            }
            if offset != run.len() {
                return Err(Error::Synthesis);
            }
        }
        let lanes = chip.operation_lanes()?;
        let digest = tape.digest(
            lanes.glue,
            lanes.hash,
            region,
            u64::from_le_bytes(*b"kgwprf_1"),
        )?;
        Ok(Self {
            digest,
            predecessor: predecessor.public.clone(),
            statement: sigma.hard_statement()?.digest().clone(),
            sigma_chunks: sigma.proof_chunks().to_vec(),
        })
    }
    fn bind_public(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        run: &iroha_plonk_gadgets::bytes::tape::ByteRun<Fp>,
        public: &[Word<Fp>; 18],
    ) -> Result<(), Error> {
        use iroha_plonk_gadgets::{
            UintChip,
            bytes::{
                element::{assert_le_max, decode_le_element, modulus_max},
                tape::SegmentSpec,
            },
        };
        let at = |offset, bytes| {
            run.secondary_segment(SegmentSpec::little(4 + offset, bytes))
                .map(iroha_plonk_gadgets::bytes::Segment::word)
        };
        GlueChip::assert_equal(region, at(0, 2)?, &public[0])?;
        for (offset, index) in [(2, 1), (34, 3), (98, 6)] {
            for limb in 0..2 {
                GlueChip::assert_equal(region, at(offset + 16 * limb, 16)?, &public[index + limb])?;
            }
        }
        for (offset, index) in [(66, 5), (130, 8), (256, 15), (288, 16)] {
            let element = decode_le_element(&mut chip.uint(), region, run, 4 + offset)?;
            assert_le_max(
                &mut chip.uint(),
                region,
                element.lo().word(),
                &UintChip::widen::<127, 128>(element.hi()),
                modulus_max::<Fp>(),
            )?;
            GlueChip::assert_constant(region, element.top().word(), Fp::ZERO)?;
            let word = chip.uint().glue().linear(
                region,
                &[
                    (Fp::ONE, element.lo().word()),
                    (Fp::from(2).pow_vartime([128]), element.hi().word()),
                ],
                Fp::ZERO,
            )?;
            GlueChip::assert_equal(region, &word, &public[index])?;
        }
        GlueChip::assert_constant(region, at(162, 1)?, Fp::from(4))?;
        for (limb, index) in [10, 9, 12, 11].into_iter().enumerate() {
            let word = run
                .secondary_segment(SegmentSpec::big(4 + 163 + 16 * limb, 16))?
                .word();
            GlueChip::assert_equal(region, word, &public[index])?;
        }
        let packed = chip.uint().glue().linear(
            region,
            &[
                (Fp::ONE, at(227, 1)?),
                (Fp::from(2).pow_vartime([8]), at(228, 8)?),
                (Fp::from(2).pow_vartime([72]), at(236, 4)?),
            ],
            Fp::ZERO,
        )?;
        GlueChip::assert_equal(region, &packed, &public[13])?;
        GlueChip::assert_equal(region, at(240, 16)?, &public[14])
    }
    pub(super) fn bind(
        &self,
        region: &mut Region<'_, Fp>,
        predecessor: &super::LineagePublicCells,
        sigma: &super::SigmaBindingCells,
    ) -> Result<(), Error> {
        for (a, b) in self.predecessor.iter().zip(predecessor.fields()) {
            GlueChip::assert_equal(region, a, b)?;
        }
        if self.sigma_chunks.len() != sigma.proof_chunks().len() {
            return Err(Error::Synthesis);
        }
        for (a, b) in self.sigma_chunks.iter().zip(sigma.proof_chunks()) {
            GlueChip::assert_equal(region, a, b)?;
        }
        GlueChip::assert_equal(region, &self.statement, sigma.hard_statement()?.digest())
    }
    /// Digest of the exact bound Ω and sigma carriers, including both lengths.
    pub const fn digest(&self) -> &Word<Fp> {
        &self.digest
    }
}

#[cfg(test)]
mod tests {
    use super::ConsumingProofCells;
    #[test]
    fn consuming_secondary_segments_cover_the_exact_carrier_in_order() {
        for bytes in [32, 9856] {
            let mut cursor = 0;
            for segment in ConsumingProofCells::omega_segments(bytes).unwrap() {
                assert_eq!(segment.start, cursor);
                assert!((1..=31).contains(&segment.len));
                cursor = segment.end();
            }
            assert_eq!(cursor, 4 + 320 + bytes + 1088);
        }
        for bytes in [0, 31, 33, usize::MAX - 31] {
            assert!(ConsumingProofCells::omega_segments(bytes).is_err());
        }
    }
}

#[cfg(test)]
#[path = "own/scope_tests.rs"]
mod scope_tests;
