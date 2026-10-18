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

/// Exact public lineage transport layout `LE32 || public320 || πΩ || accP || accV`, as the
/// native lineage wire encoder writes it. Lean lineage binds no own consuming-step proof
/// digest, so only the incoming transport reads this layout.
#[derive(Clone, Copy, Debug)]
pub struct ConsumingProofCells;
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
