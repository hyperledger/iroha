//! Native witness proposals for the circuit's total incoming proof decoder.
//!
//! Original bytes remain unchanged for every digest. Invalid fixed-offset views
//! receive the exact circuit dummies; decoder failures and succinct-proof failures
//! remain false. Resource/profile failures are errors and cannot authorize a burn.

use ff::Field;
use iroha_kagemusha_proof::{
    a_relation::native::artifact::KeyArtifact,
    q_sigma::native::{IncomingMode, incoming_proof_failure as invalid_proof},
};
use iroha_pasta::{Ep, Eq, PastaAffine, PastaCurve, poseidon::hash_with_domain};
use iroha_plonk::{Protocol, pcs::ipa::PinnedParams, verifier::accumulate_generator_cancellable};
use iroha_plonk_gadgets::statement::foreign_limbs;
use iroha_plonk_recursion::{ACCUMULATOR_BYTES, AccumulatorT, FoldInput};

use super::*;

pub(super) struct TransportV1 {
    pub(super) public: [Fp; 18],
    pub(super) public_valid: bool,
    pub(super) pallas: AccumulatorT<Ep>,
    pub(super) vesta: AccumulatorT<Eq>,
    pub(super) opening: FoldInput<Ep>,
    pub(super) valid: bool,
}

fn view<const N: usize>(original: &[u8], start: usize) -> [u8; N] {
    std::array::from_fn(|i| original.get(start + i).copied().unwrap_or(0))
}
fn u128_at(original: &[u8], start: usize) -> Fp {
    Fp::from_u128(u128::from_le_bytes(view(original, start)))
}

/// Exact incoming_lineage.rs offsets and zero-selection of noncanonical Fp atoms.
fn public(original: &[u8], expected: usize, key: Fp) -> ([Fp; 18], bool) {
    let mut out = [Fp::ZERO; 18];
    out[0] = Fp::from(u64::from(u16::from_le_bytes(view(original, 0))));
    let mut valid =
        original.len() == expected && out[0] == Fp::ONE && original.get(162) == Some(&4);
    for (offset, index) in [(2, 1), (34, 3), (98, 6)] {
        out[index] = u128_at(original, offset);
        out[index + 1] = u128_at(original, offset + 16);
    }
    for (offset, index) in [(66, 5), (130, 8), (256, 15), (288, 16)] {
        let decoded = Option::<Fp>::from(Fp::from_repr(view(original, offset)));
        valid &= decoded.is_some();
        out[index] = decoded.unwrap_or(Fp::ZERO);
    }
    for (limb, index) in [10, 9, 12, 11].into_iter().enumerate() {
        out[index] = Fp::from_u128(u128::from_be_bytes(view(original, 163 + 16 * limb)));
    }
    let lifecycle = u128::from(original.get(227).copied().unwrap_or(0));
    let epoch = u128::from(u64::from_le_bytes(view(original, 228)));
    let controls = u128::from(u32::from_le_bytes(view(original, 236)));
    out[13] = Fp::from_u128(lifecycle | epoch << 8 | controls << 72);
    out[14] = u128_at(original, 240);
    out[17] = key;
    (out, valid)
}

fn opening<C: PastaCurve>(
    params: &PinnedParams<C>,
    key: &KeyArtifact<C>,
    instances: &[Vec<C::ScalarExt>],
    bytes: &[u8],
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<Option<FoldInput<C>>, Error> {
    match accumulate_generator_cancellable(
        params,
        key.binding(),
        key.key(),
        instances,
        bytes,
        budget,
        cancellation,
    ) {
        Ok(value) => Ok(Some(proof(FoldInput::from_opening(
            *value.g(),
            value.challenges(),
        ))?)),
        Err(error) if error.is_cancelled() => Err(Error::Cancelled),
        Err(error) if invalid_proof(&error) => Ok(None),
        Err(_) => Err(Error::Proof("incoming verifier resources or profile")),
    }
}

pub(super) fn transport(
    pparams: &PinnedParams<Ep>,
    vparams: &PinnedParams<Eq>,
    key: &KeyArtifact<Ep>,
    original: &[u8],
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<TransportV1, Error> {
    let proof_bytes = proof(Protocol::new(key.binding().descriptor()))?.proof_length();
    let total = 320usize
        .checked_add(proof_bytes)
        .and_then(|n| n.checked_add(2 * ACCUMULATOR_BYTES))
        .ok_or(Error::Proof("incoming transport bounds"))?;
    let trivial_p = proof(AccumulatorT::trivial_cancellable(
        pparams,
        budget,
        cancellation,
    ))?;
    let trivial_v = proof(AccumulatorT::trivial_cancellable(
        vparams,
        budget,
        cancellation,
    ))?;
    let key_digest = proof(key.key().kagemusha_digest(key.binding()))?;
    let (public, public_valid) = public(original, total, key_digest);
    let pallas =
        AccumulatorT::<Ep>::from_bytes(&view::<ACCUMULATOR_BYTES>(original, 320 + proof_bytes));
    let vesta = AccumulatorT::<Eq>::from_bytes(&view::<ACCUMULATOR_BYTES>(
        original,
        320 + proof_bytes + ACCUMULATOR_BYTES,
    ));
    let claims_valid = pallas.is_ok() && vesta.is_ok();
    let pallas = pallas.unwrap_or_else(|_| trivial_p.clone());
    let vesta = vesta.unwrap_or(trivial_v);
    let mut words = public.to_vec();
    let (x, y) =
        Option::<(Fp, Fp)>::from(pallas.g().coordinates()).ok_or(Error::Proof("incoming point"))?;
    words.extend([x, y]);
    for challenge in pallas.challenges() {
        words.extend(foreign_limbs(challenge).map(Fp::from_u128));
    }
    let digest = hash_with_domain(u64::from_le_bytes(*b"kgwomg_1"), &words);
    let (x, y) =
        Option::<(Fq, Fq)>::from(vesta.g().coordinates()).ok_or(Error::Proof("incoming point"))?;
    let instances = vec![
        vec![
            Option::<Fq>::from(Fq::from_repr(digest.to_repr()))
                .ok_or(Error::Proof("incoming digest"))?,
        ],
        vec![x, y],
        vesta
            .challenges()
            .iter()
            .map(|v| {
                Option::<Fq>::from(Fq::from_repr(v.to_repr()))
                    .ok_or(Error::Proof("incoming challenge"))
            })
            .collect::<Result<Vec<_>, _>>()?,
    ];
    // The circuit verifies the fixed padded view even when the outer length is
    // wrong, then conjoins outer validity. Preserve that opening on every path.
    let bytes = (0..proof_bytes)
        .map(|i| original.get(320 + i).copied().unwrap_or(0))
        .collect::<Vec<_>>();
    let actual = opening(pparams, key, &instances, &bytes, budget, cancellation)?;
    let valid = public_valid && claims_valid && actual.is_some();
    Ok(TransportV1 {
        public,
        public_valid,
        pallas,
        vesta,
        opening: actual.unwrap_or_else(|| trivial_p.as_input()),
        valid,
    })
}

// Correction is only reached after an explicit Undecidable decision. Bind every
// original challenge/source k and fully decide the distinct replacement before Q work.
fn corrected_point<C: PastaCurve>(
    original: &FoldInput<C>,
    params: &PinnedParams<C>,
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<C::AffineExt, Error> {
    let correction = proof(original.corrected_cancellable(params, budget, cancellation))?;
    let replacement = correction.replacement();
    if replacement.g() == original.g()
        || replacement.source_k() != original.source_k()
        || replacement.challenges() != original.challenges()
    {
        return Err(Error::Proof("incoming correction binding"));
    }
    proof(replacement.decide_cancellable(params, budget, cancellation))?;
    Ok(*replacement.g())
}

/// Select exactly one correction if all succinct predicates pass but a deferred
/// obligation fails. Any false predicate takes the all-Trivial branch instead.
pub(super) fn modes(
    p: &PinnedParams<Ep>,
    v: &PinnedParams<Eq>,
    soft: bool,
    transport: &TransportV1,
    sigma: Option<&FoldInput<Eq>>,
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<
    (
        [IncomingMode; 4],
        [iroha_pasta::EpAffine; 2],
        iroha_pasta::EqAffine,
    ),
    Error,
> {
    iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
    let (transport_modes, pc, vc) = status_modes(p, v, soft, transport, budget, cancellation)?;
    let mut selected = [IncomingMode::Trivial; 4];
    selected[..3].copy_from_slice(&transport_modes);
    if !soft || transport_modes.contains(&IncomingMode::Corrected) {
        return Ok((selected, pc, vc));
    }
    selected[3] = sigma_mode(v, true, sigma, budget, cancellation)?;
    if selected[3] == IncomingMode::Corrected {
        selected[..3].fill(IncomingMode::Trivial);
    }
    Ok((selected, pc, vc))
}

/// Archive Status has exactly the three original Omega obligations and no sigma.
pub(super) fn status_modes(
    p: &PinnedParams<Ep>,
    v: &PinnedParams<Eq>,
    soft: bool,
    transport: &TransportV1,
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<
    (
        [IncomingMode; 3],
        [iroha_pasta::EpAffine; 2],
        iroha_pasta::EqAffine,
    ),
    Error,
> {
    let trivial_p = proof(AccumulatorT::trivial_cancellable(p, budget, cancellation))?;
    let trivial_v = proof(AccumulatorT::trivial_cancellable(v, budget, cancellation))?;
    let mut corrections = [*trivial_p.g(); 2];
    let mut vcorrection = *trivial_v.g();
    if !soft {
        return Ok(([IncomingMode::Trivial; 3], corrections, vcorrection));
    }
    let mut selected = [IncomingMode::Accept; 3];
    for (index, claim) in [transport.pallas.as_input(), transport.opening.clone()]
        .iter()
        .enumerate()
    {
        match claim.decide_cancellable(p, budget, cancellation) {
            Ok(()) => {}
            Err(iroha_plonk_recursion::Error::Undecidable) => {
                corrections[index] = corrected_point(claim, p, budget, cancellation)?;
                selected.fill(IncomingMode::Trivial);
                selected[index] = IncomingMode::Corrected;
                return Ok((selected, corrections, vcorrection));
            }
            Err(error) if error.is_cancelled() => return Err(Error::Cancelled),
            Err(_) => return Err(Error::Proof("incoming decide resources")),
        }
    }
    match transport
        .vesta
        .as_input()
        .decide_cancellable(v, budget, cancellation)
    {
        Ok(()) => {}
        Err(iroha_plonk_recursion::Error::Undecidable) => {
            vcorrection = corrected_point(&transport.vesta.as_input(), v, budget, cancellation)?;
            selected.fill(IncomingMode::Trivial);
            selected[2] = IncomingMode::Corrected;
        }
        Err(error) if error.is_cancelled() => return Err(Error::Cancelled),
        Err(_) => return Err(Error::Proof("incoming decide resources")),
    }
    Ok((selected, corrections, vcorrection))
}

/// Archive Receive has one sigma obligation and no transported Omega claims.
/// The actual Q_sigma producer derives and proves its same-challenge correction.
pub(super) fn sigma_mode(
    params: &PinnedParams<Eq>,
    soft: bool,
    sigma: Option<&FoldInput<Eq>>,
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<IncomingMode, Error> {
    iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
    if !soft {
        return Ok(IncomingMode::Trivial);
    }
    let sigma = sigma.ok_or(Error::Proof("incoming sigma obligation"))?;
    match sigma.decide_cancellable(params, budget, cancellation) {
        Ok(()) => Ok(IncomingMode::Accept),
        Err(iroha_plonk_recursion::Error::Undecidable) => {
            corrected_point(sigma, params, budget, cancellation)?;
            Ok(IncomingMode::Corrected)
        }
        Err(error) if error.is_cancelled() => Err(Error::Cancelled),
        Err(_) => Err(Error::Proof("incoming decide resources")),
    }
}

#[cfg(test)]
mod tests {
    use iroha_plonk::{
        VerifyError,
        pcs::{ipa::IpaError, multiopen::MultiopenError},
        transcript::TranscriptError,
    };

    use super::*;
    #[test]
    fn cancellation_cannot_become_a_trivial_burn_branch() {
        let params = PinnedParams::<Eq>::derive(1).unwrap();
        let token = iroha_pasta::CancellationToken::new();
        token.cancel();
        assert!(matches!(
            sigma_mode(&params, false, None, MemoryBudget::DEFAULT, Some(&token)),
            Err(Error::Cancelled)
        ));
        assert!(matches!(
            sigma_mode(&params, false, None, MemoryBudget::DEFAULT, None),
            Ok(IncomingMode::Trivial)
        ));
    }

    #[test]
    fn total_failure_classification_keeps_nested_proof_errors_soft_and_profiles_hard() {
        for error in [
            VerifyError::Transcript(TranscriptError::ProofTruncated),
            VerifyError::Ipa(IpaError::Transcript(TranscriptError::ProofTruncated)),
            VerifyError::Multiopen(MultiopenError::Ipa(IpaError::Transcript(
                TranscriptError::ProofTruncated,
            ))),
            VerifyError::Ipa(IpaError::OpeningFailed),
            VerifyError::IdentityInstanceCommitment { column: 0 },
            VerifyError::ProofLength {
                expected: 32,
                actual: 31,
            },
        ] {
            assert!(invalid_proof(&error), "{error:?}");
        }
        for error in [
            VerifyError::Cancelled,
            VerifyError::Ipa(IpaError::Cancelled),
            VerifyError::Multiopen(MultiopenError::Cancelled),
            VerifyError::KeyMismatch,
            VerifyError::ParamsMismatch,
            VerifyError::SuffixRequired,
            VerifyError::Transcript(TranscriptError::ProfileMismatch),
            VerifyError::Ipa(IpaError::Transcript(TranscriptError::ProfileMismatch)),
            VerifyError::Ipa(IpaError::ParamsTooSmall {
                needed: 16,
                available: 12,
            }),
        ] {
            assert!(!invalid_proof(&error), "{error:?}");
        }
    }

    #[test]
    fn incoming_mode_selection_preserves_all_four_obligations_and_one_correction() {
        use p256::elliptic_curve::group::prime::PrimeCurveAffine;
        let budget = MemoryBudget::DEFAULT;
        let pp = PinnedParams::<Ep>::derive(16).unwrap();
        let vp = PinnedParams::<Eq>::derive(16).unwrap();
        let p = AccumulatorT::trivial(&pp, budget).unwrap();
        let v = AccumulatorT::trivial(&vp, budget).unwrap();
        let mut input = TransportV1 {
            public: [Fp::ZERO; 18],
            public_valid: true,
            pallas: p.clone(),
            vesta: v.clone(),
            opening: p.as_input(),
            valid: true,
        };
        let sigma = v.as_input();
        assert_eq!(
            modes(&pp, &vp, true, &input, Some(&sigma), budget, None)
                .unwrap()
                .0,
            [IncomingMode::Accept; 4]
        );
        assert_eq!(
            modes(&pp, &vp, false, &input, None, budget, None)
                .unwrap()
                .0,
            [IncomingMode::Trivial; 4]
        );
        let bad_p =
            AccumulatorT::<Ep>::new(iroha_pasta::EpAffine::generator(), *p.challenges()).unwrap();
        let bad_v =
            AccumulatorT::<Eq>::new(iroha_pasta::EqAffine::generator(), *v.challenges()).unwrap();
        assert!(matches!(
            bad_p.decide(&pp, budget),
            Err(iroha_plonk_recursion::Error::Undecidable)
        ));
        assert!(matches!(
            bad_v.decide(&vp, budget),
            Err(iroha_plonk_recursion::Error::Undecidable)
        ));
        for selected in 0..4 {
            input.pallas = if selected == 0 {
                bad_p.clone()
            } else {
                p.clone()
            };
            input.opening = if selected == 1 {
                bad_p.as_input()
            } else {
                p.as_input()
            };
            input.vesta = if selected == 2 {
                bad_v.clone()
            } else {
                v.clone()
            };
            let sigma = if selected == 3 {
                bad_v.as_input()
            } else {
                v.as_input()
            };
            let (actual, pc, vc) =
                modes(&pp, &vp, true, &input, Some(&sigma), budget, None).unwrap();
            let mut expected = [IncomingMode::Trivial; 4];
            expected[selected] = IncomingMode::Corrected;
            assert_eq!(actual, expected);
            if selected < 2 {
                assert_ne!(pc[selected], *bad_p.g());
            }
            if selected == 2 {
                assert_ne!(vc, *bad_v.g());
            }
        }
        // A failed soft predicate takes precedence over every nondeciding original.
        input.pallas = bad_p;
        input.vesta = bad_v;
        assert_eq!(
            modes(&pp, &vp, false, &input, None, budget, None)
                .unwrap()
                .0,
            [IncomingMode::Trivial; 4]
        );
    }

    #[test]
    fn archive_variants_select_only_their_actual_obligations() {
        use p256::elliptic_curve::group::prime::PrimeCurveAffine;
        let budget = MemoryBudget::DEFAULT;
        let pp = PinnedParams::<Ep>::derive(16).unwrap();
        let vp = PinnedParams::<Eq>::derive(16).unwrap();
        let p = AccumulatorT::trivial(&pp, budget).unwrap();
        let v = AccumulatorT::trivial(&vp, budget).unwrap();
        let mut input = TransportV1 {
            public: [Fp::ZERO; 18],
            public_valid: true,
            pallas: p.clone(),
            vesta: v.clone(),
            opening: p.as_input(),
            valid: true,
        };
        assert_eq!(
            status_modes(&pp, &vp, true, &input, budget, None)
                .unwrap()
                .0,
            [IncomingMode::Accept; 3]
        );
        assert_eq!(
            status_modes(&pp, &vp, false, &input, budget, None)
                .unwrap()
                .0,
            [IncomingMode::Trivial; 3]
        );
        for k in [12, 14] {
            let bad =
                FoldInput::from_opening(iroha_pasta::EqAffine::generator(), &vec![Fp::ONE; k])
                    .unwrap();
            let correction = bad.corrected(&vp, budget).unwrap();
            let good = correction.replacement();
            assert_eq!(
                sigma_mode(&vp, true, Some(good), budget, None).unwrap(),
                IncomingMode::Accept
            );
            assert_eq!(
                sigma_mode(&vp, true, Some(&bad), budget, None).unwrap(),
                IncomingMode::Corrected
            );
        }
        assert!(sigma_mode(&vp, true, None, budget, None).is_err());
        assert_eq!(
            sigma_mode(&vp, false, None, budget, None).unwrap(),
            IncomingMode::Trivial
        );
        input.vesta =
            AccumulatorT::new(iroha_pasta::EqAffine::generator(), *v.challenges()).unwrap();
        assert_eq!(
            status_modes(&pp, &vp, true, &input, budget, None)
                .unwrap()
                .0,
            [
                IncomingMode::Trivial,
                IncomingMode::Trivial,
                IncomingMode::Corrected
            ]
        );
    }

    #[test]
    fn multiple_undecidable_originals_keep_exactly_the_first_checked_correction() {
        use p256::elliptic_curve::group::prime::PrimeCurveAffine;
        let budget = MemoryBudget::DEFAULT;
        let p = PinnedParams::<Ep>::derive(16).unwrap();
        let v = PinnedParams::<Eq>::derive(16).unwrap();
        let good_p = AccumulatorT::trivial(&p, budget).unwrap();
        let good_v = AccumulatorT::trivial(&v, budget).unwrap();
        let bad_p =
            AccumulatorT::new(iroha_pasta::EpAffine::generator(), *good_p.challenges()).unwrap();
        let bad_v =
            AccumulatorT::new(iroha_pasta::EqAffine::generator(), *good_v.challenges()).unwrap();
        let transport = TransportV1 {
            public: [Fp::ZERO; 18],
            public_valid: true,
            pallas: bad_p.clone(),
            vesta: bad_v.clone(),
            opening: bad_p.as_input(),
            valid: true,
        };
        let (selected, corrections, _) = modes(
            &p,
            &v,
            true,
            &transport,
            Some(&bad_v.as_input()),
            budget,
            None,
        )
        .unwrap();
        assert_eq!(
            selected,
            [
                IncomingMode::Corrected,
                IncomingMode::Trivial,
                IncomingMode::Trivial,
                IncomingMode::Trivial
            ]
        );
        let replacement = FoldInput::<Ep>::from_normalized(
            corrections[0],
            bad_p.as_input().source_k(),
            *bad_p.challenges(),
        )
        .unwrap();
        assert_ne!(replacement.g(), bad_p.g());
        assert_eq!(replacement.challenges(), bad_p.challenges());
        replacement.decide(&p, budget).unwrap();
        assert_eq!(
            modes(&p, &v, false, &transport, None, budget, None)
                .unwrap()
                .0,
            [IncomingMode::Trivial; 4]
        );
    }

    #[test]
    fn correction_retains_actual_source_prefix_with_minimal_scratch() {
        use p256::elliptic_curve::group::prime::PrimeCurveAffine;
        let params = PinnedParams::<Eq>::derive(16).unwrap();
        let insufficient = PinnedParams::<Eq>::derive(3).unwrap();
        for k in [12, 14] {
            let original = FoldInput::<Eq>::from_opening(
                iroha_pasta::EqAffine::generator(),
                &vec![Fp::ONE; k],
            )
            .unwrap();
            assert!(matches!(
                original.decide(&params, MemoryBudget::DEFAULT),
                Err(iroha_plonk_recursion::Error::Undecidable)
            ));
            let point = corrected_point(&original, &params, MemoryBudget::DEFAULT, None).unwrap();
            let selected =
                FoldInput::from_normalized(point, original.source_k(), *original.challenges())
                    .unwrap();
            assert_eq!(selected.source_k(), k as u32);
            assert_eq!(selected.challenges(), original.challenges());
            assert_ne!(selected.g(), original.g());
            selected.decide(&params, MemoryBudget::DEFAULT).unwrap();
            // Parameter coverage is a real fallible contract for each source prefix.
            for budget in [MemoryBudget::DEFAULT, MemoryBudget::new(0)] {
                assert!(matches!(original.decide(&insufficient, budget),
                    Err(iroha_plonk_recursion::Error::Parameters(IpaError::ParamsTooSmall {
                        needed, available: 3
                    })) if needed == k as u32));
                assert!(matches!(original.corrected(&insufficient, budget),
                    Err(iroha_plonk_recursion::Error::Parameters(IpaError::ParamsTooSmall {
                        needed, available: 3
                    })) if needed == k as u32));
                assert!(matches!(
                    corrected_point(&original, &insufficient, budget, None),
                    Err(Error::Proof("native fold source or proof"))
                ));
            }
            // The complete MSM narrows its window when scratch is unavailable;
            // the budget is not an artificial proof-validation failure.
            assert_eq!(
                corrected_point(&original, &params, MemoryBudget::new(0), None).unwrap(),
                point
            );
            assert_eq!(
                sigma_mode(&params, true, Some(&original), MemoryBudget::new(0), None).unwrap(),
                IncomingMode::Corrected
            );
        }
        let deciding = AccumulatorT::<Eq>::trivial(&params, MemoryBudget::DEFAULT).unwrap();
        assert!(matches!(
            deciding
                .as_input()
                .corrected(&params, MemoryBudget::DEFAULT),
            Err(iroha_plonk_recursion::Error::NotCorrected)
        ));
        assert!(
            corrected_point(&deciding.as_input(), &params, MemoryBudget::DEFAULT, None).is_err()
        );
    }

    #[test]
    fn correction_parameter_failures_abort_without_a_replacement() {
        use p256::elliptic_curve::group::prime::PrimeCurveAffine;
        let params = PinnedParams::<Eq>::derive(12).unwrap();
        let original =
            FoldInput::<Eq>::from_opening(iroha_pasta::EqAffine::generator(), &[Fp::ONE; 14])
                .unwrap();
        for budget in [MemoryBudget::DEFAULT, MemoryBudget::new(0)] {
            assert!(matches!(
                original.corrected(&params, budget),
                Err(iroha_plonk_recursion::Error::Parameters(
                    IpaError::ParamsTooSmall {
                        needed: 14,
                        available: 12,
                    }
                ))
            ));
            assert!(corrected_point(&original, &params, budget, None).is_err());
            assert!(matches!(
                sigma_mode(&params, true, Some(&original), budget, None),
                Err(Error::Proof(_))
            ));
        }
    }

    #[test]
    fn zero_scratch_correction_preserves_binding_and_actual_sigma_modes() {
        use p256::elliptic_curve::group::prime::PrimeCurveAffine;
        let params = PinnedParams::<Eq>::derive(3).unwrap();
        let original = FoldInput::<Eq>::from_opening(
            iroha_pasta::EqAffine::generator(),
            &[Fp::from(2), Fp::from(3), Fp::from(5)],
        )
        .unwrap();
        let zero = MemoryBudget::new(0);
        assert!(matches!(
            original.decide(&params, zero),
            Err(iroha_plonk_recursion::Error::Undecidable)
        ));
        // The small source also checks exact Accept/Corrected mode selection through
        // the allocation-free fallback on the same retained parameter owner.
        let point = corrected_point(&original, &params, zero, None).unwrap();
        assert_eq!(
            point,
            corrected_point(&original, &params, MemoryBudget::DEFAULT, None).unwrap()
        );
        let selected =
            FoldInput::<Eq>::from_normalized(point, original.source_k(), *original.challenges())
                .unwrap();
        assert_eq!(selected.source_k(), 3);
        assert_eq!(selected.challenges(), original.challenges());
        assert_ne!(selected.g(), original.g());
        selected.decide(&params, zero).unwrap();
        assert_eq!(
            sigma_mode(&params, true, Some(&original), zero, None).unwrap(),
            IncomingMode::Corrected
        );
        assert_eq!(
            sigma_mode(&params, true, Some(&selected), zero, None).unwrap(),
            IncomingMode::Accept
        );
        // An already deciding source cannot supply the distinct correction witness.
        assert!(matches!(
            selected.corrected(&params, zero),
            Err(iroha_plonk_recursion::Error::NotCorrected)
        ));
        assert!(corrected_point(&selected, &params, zero, None).is_err());
    }

    #[test]
    fn total_prefix_preserves_raw_fields_and_zero_selects_only_noncanonical_atoms() {
        let mut raw = vec![0; 4800];
        raw[0] = 1;
        raw[162] = 4;
        for offset in [66, 130, 256, 288] {
            raw[offset] = 1;
        }
        let (fields, valid) = public(&raw, 4800, Fp::from(7));
        assert!(valid);
        assert_eq!(fields[17], Fp::from(7));
        raw[66..98].fill(255);
        let (fields, valid) = public(&raw, 4800, Fp::from(7));
        assert!(!valid);
        assert_eq!(fields[5], Fp::ZERO);
        assert_eq!(fields[8], Fp::ONE);
        raw[66..98].fill(0);
        raw[66] = 1;
        raw[162] = 3;
        assert!(!public(&raw, 4800, Fp::from(7)).1);
        raw[162] = 4;
        raw.push(0);
        assert!(!public(&raw, 4800, Fp::from(7)).1);
        assert!(!public(&[], 4800, Fp::from(7)).1);
    }
}

#[cfg(test)]
#[path = "incoming/soft_omega_differential.rs"]
mod soft_omega_differential;
