//! End-to-end FCMP++ membership verification.
//!
//! The public entry point first performs the strict `IFC1` decode and SAL
//! verification, then reconstructs the exact two verifier circuits used by
//! the pinned Monero FCMP++ implementation.  The root-blind equation and each
//! independent generalized Bulletproof equation are checked directly, without
//! randomized cross-proof batching.
#[cfg(test)]
use super::wire::decode_fcmp_plus_plus_wire_v1;
use super::{
    FCMP_LAYER_ONE_LEN_V1, FCMP_LAYER_TWO_LEN_V1, FcmpNativeErrorV1, FcmpSalProofV1,
    FcmpTreeCurveV1, FcmpTreeRootV1,
    circuit::{
        CYCLE_DLOG_PARAMETERS, ChallengedGenerator, Circuit, CircuitTranscript, CurveSpec,
        DiscreteLogChallenge, ED25519_DLOG_PARAMETERS, GeneratorTable, PointWithDlog,
        VectorCommitmentTape, additional_layer, additional_layer_discrete_log_challenge,
        first_layer,
    },
    field::{
        Field25519, HeliosPoint, HelioseleneField, SecretCycleCoordinatesV1, SelenePoint,
        decode_field25519_scalar, decode_helioselene_scalar, edwards_to_wei25519,
        encode_field25519, helios_hash_initializer, selene_hash_initializer,
    },
    proof_math::{
        HeliosSuite, ProofPoint, ProofSuite, SecretMultiexpBuilder, SeleneSuite,
        VerifierTranscript, helios_bp_generators, selene_bp_generators,
    },
    sal::{generator_t, generator_u, generator_v},
    verify_fcmp_sal_v1,
    wire::{FcmpProofInputPublicV1, ParsedFcmpPlusPlusWireV1, ipa_rows},
};
use blake2::{Blake2b, Digest as _, digest::consts::U32};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use p256::elliptic_curve::bigint::U256;
use std::sync::OnceLock;
fn secret_unblind_helios_coordinates_v1(
    prior_commitment: &HeliosPoint,
    mask: &HelioseleneField,
) -> Result<SecretCycleCoordinatesV1<Field25519>, FcmpNativeErrorV1> {
    let mut terms = SecretMultiexpBuilder::<HeliosSuite>::new(2)?;
    terms.push(&HelioseleneField::ONE, prior_commitment)?;
    let negative_h = -helios_bp_generators().h;
    terms.push(mask, &negative_h)?;
    let point = terms.evaluate()?;
    let coordinates = point
        .expose_ref()
        .secret_coordinates_ref_v1()
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
    drop(point);
    Ok(coordinates)
}
fn secret_unblind_selene_coordinates_v1(
    prior_commitment: &SelenePoint,
    mask: &Field25519,
) -> Result<SecretCycleCoordinatesV1<HelioseleneField>, FcmpNativeErrorV1> {
    let mut terms = SecretMultiexpBuilder::<SeleneSuite>::new(2)?;
    terms.push(&Field25519::ONE, prior_commitment)?;
    let negative_h = -selene_bp_generators().h;
    terms.push(mask, &negative_h)?;
    let point = terms.evaluate()?;
    let coordinates = point
        .expose_ref()
        .secret_coordinates_ref_v1()
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
    drop(point);
    Ok(coordinates)
}
const ED25519_WEI_A: U256 =
    U256::from_be_hex("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144");
const ED25519_WEI_B: U256 =
    U256::from_be_hex("7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864");
const HELIOS_B: U256 =
    U256::from_be_hex("22e8c739b0ea70b8be94a76b3ebb7b3b043f6f384113bf3522b49ee1edd73ad4");
const SELENE_B: U256 =
    U256::from_be_hex("70127713695876c17f51bba595ffe279f3944bdf06ae900e68de0983cb5a4558");
pub(super) fn ed25519_curve() -> CurveSpec<Field25519> {
    CurveSpec {
        a: Field25519::new(&ED25519_WEI_A),
        b: Field25519::new(&ED25519_WEI_B),
    }
}
pub(super) fn helios_curve() -> CurveSpec<Field25519> {
    CurveSpec {
        a: -Field25519::new(&U256::from(3_u8)),
        b: Field25519::new(&HELIOS_B),
    }
}
pub(super) fn selene_curve() -> CurveSpec<HelioseleneField> {
    CurveSpec {
        a: -HelioseleneField::new(&U256::from(3_u8)),
        b: HelioseleneField::new(&SELENE_B),
    }
}
pub(super) struct NativeParameters {
    pub(super) g: GeneratorTable<Field25519>,
    pub(super) t: GeneratorTable<Field25519>,
    pub(super) u: GeneratorTable<Field25519>,
    pub(super) v: GeneratorTable<Field25519>,
    /// Selene's Bulletproof blinding generator, embedded in the Helios circuit's scalar field.
    pub(super) h_1: GeneratorTable<HelioseleneField>,
    /// Helios's Bulletproof blinding generator, embedded in the Selene circuit's scalar field.
    pub(super) h_2: GeneratorTable<Field25519>,
}
pub(super) fn native_parameters() -> &'static NativeParameters {
    static PARAMETERS: OnceLock<NativeParameters> = OnceLock::new();
    PARAMETERS.get_or_init(|| {
        let ed25519 = ed25519_curve();
        let point = |point: curve25519_dalek::edwards::EdwardsPoint| {
            edwards_to_wei25519(point.compress().to_bytes())
                .expect("pinned canonical Ed25519 generator has Wei25519 coordinates")
        };
        let g = GeneratorTable::new(
            &ed25519,
            point(ED25519_BASEPOINT_POINT),
            ED25519_DLOG_PARAMETERS,
        )
        .expect("pinned Ed25519 basepoint table is valid");
        let t = GeneratorTable::new(&ed25519, point(generator_t()), ED25519_DLOG_PARAMETERS)
            .expect("pinned Monero T table is valid");
        let u = GeneratorTable::new(&ed25519, point(generator_u()), ED25519_DLOG_PARAMETERS)
            .expect("pinned Monero U table is valid");
        let v = GeneratorTable::new(&ed25519, point(generator_v()), ED25519_DLOG_PARAMETERS)
            .expect("pinned Monero V table is valid");
        let h_1 = GeneratorTable::new(
            &selene_curve(),
            selene_bp_generators()
                .h
                .coordinates()
                .expect("non-identity Selene H has affine coordinates"),
            CYCLE_DLOG_PARAMETERS,
        )
        .expect("pinned Selene H table is valid");
        let h_2 = GeneratorTable::new(
            &helios_curve(),
            helios_bp_generators()
                .h
                .coordinates()
                .expect("non-identity Helios H has affine coordinates"),
            CYCLE_DLOG_PARAMETERS,
        )
        .expect("pinned Helios H table is valid");
        NativeParameters {
            g,
            t,
            u,
            v,
            h_1,
            h_2,
        }
    })
}
#[derive(Clone)]
pub(super) struct TranscriptedInput {
    pub(super) output_key: (super::bulletproof::Variable, super::bulletproof::Variable),
    pub(super) linking_generator: (super::bulletproof::Variable, super::bulletproof::Variable),
    pub(super) amount_commitment: (super::bulletproof::Variable, super::bulletproof::Variable),
    pub(super) output_blind: PointWithDlog,
    pub(super) input_blind_u: PointWithDlog,
    pub(super) input_blind_v: PointWithDlog,
    pub(super) input_blind_blind: PointWithDlog,
    pub(super) commitment_blind: PointWithDlog,
}
pub(super) fn membership_context(
    root: FcmpTreeRootV1,
    public_inputs: &[FcmpProofInputPublicV1],
    root_blind_commitment: [u8; 32],
) -> Result<[u8; 32], FcmpNativeErrorV1> {
    let mut digest = Blake2b::<U32>::new();
    digest.update(match root.curve() {
        FcmpTreeCurveV1::Selene => [0_u8],
        FcmpTreeCurveV1::Helios => [1_u8],
    });
    digest.update(root.point());
    digest.update(
        u32::try_from(public_inputs.len())
            .map_err(|_| FcmpNativeErrorV1::TreeFull)?
            .to_le_bytes(),
    );
    for input in public_inputs {
        for point in [
            input.output_key_tilde,
            input.linking_tag_generator_tilde,
            input.rerandomization_commitment,
            input.pseudo_out,
        ] {
            let (x, y) = edwards_to_wei25519(point)?;
            digest.update(encode_field25519(x));
            digest.update(encode_field25519(y));
        }
    }
    digest.update(root_blind_commitment);
    Ok(digest.finalize().into())
}
fn commitment_index(variable: super::bulletproof::Variable) -> Result<usize, FcmpNativeErrorV1> {
    match variable {
        super::bulletproof::Variable::CG { commitment, .. } => Ok(commitment),
        _ => Err(FcmpNativeErrorV1::ArithmeticInvariant),
    }
}
fn verify_root_blind(
    transcript: &mut VerifierTranscript<'_>,
    parsed: &ParsedFcmpPlusPlusWireV1,
    root: FcmpTreeRootV1,
    root_variables: &[super::bulletproof::Variable],
    c1_commitments: &[SelenePoint],
    c2_commitments: &[HeliosPoint],
) -> Result<(), FcmpNativeErrorV1> {
    let root_variable = *root_variables
        .first()
        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
    let commitment = commitment_index(root_variable)?;
    match root.curve() {
        FcmpTreeCurveV1::Selene => {
            let claimed = selene_hash_initializer()
                + *c1_commitments
                    .get(commitment)
                    .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
            let actual = SelenePoint::decode(root.point(), false)?;
            let nonce = SelenePoint::decode(parsed.root_blind_commitment, false)?;
            let response = decode_field25519_scalar(parsed.root_blind_response)?;
            let challenge = transcript.challenge::<SeleneSuite>()?;
            if nonce + (claimed - actual).scale(challenge)
                != selene_bp_generators().h.scale(response)
            {
                return Err(FcmpNativeErrorV1::RootBlindEquation);
            }
        }
        FcmpTreeCurveV1::Helios => {
            let claimed = helios_hash_initializer()
                + *c2_commitments
                    .get(commitment)
                    .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
            let actual = HeliosPoint::decode(root.point(), false)?;
            let nonce = HeliosPoint::decode(parsed.root_blind_commitment, false)?;
            let response = decode_helioselene_scalar(parsed.root_blind_response)?;
            let challenge = transcript.challenge::<HeliosSuite>()?;
            if nonce + (claimed - actual).scale(challenge)
                != helios_bp_generators().h.scale(response)
            {
                return Err(FcmpNativeErrorV1::RootBlindEquation);
            }
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
#[allow(
    single_use_lifetimes,
    reason = "impl-Trait iterator items cannot use anonymous reference lifetimes"
)]
pub(super) fn constrain_input<'c1, 'c2, T: CircuitTranscript>(
    parameters: &NativeParameters,
    layers: usize,
    transcript: &mut T,
    c1_circuit: &mut Circuit<SeleneSuite>,
    c1_dlog_challenge: &mut Option<(
        DiscreteLogChallenge<Field25519>,
        ChallengedGenerator<Field25519>,
    )>,
    c2_circuit: &mut Circuit<HeliosSuite>,
    c2_dlog_challenge: &mut Option<(
        DiscreteLogChallenge<HelioseleneField>,
        ChallengedGenerator<HelioseleneField>,
    )>,
    root: &[super::bulletproof::Variable],
    c1_branches: &mut impl Iterator<Item = Vec<super::bulletproof::Variable>>,
    c2_branches: &mut impl Iterator<Item = Vec<super::bulletproof::Variable>>,
    c1_commitments: &mut impl Iterator<Item = (SelenePoint, Option<&'c1 Field25519>, PointWithDlog)>,
    c2_commitments: &mut impl Iterator<
        Item = (HeliosPoint, Option<&'c2 HelioseleneField>, PointWithDlog),
    >,
    public_input: &FcmpProofInputPublicV1,
    opening: TranscriptedInput,
) -> Result<(), FcmpNativeErrorV1> {
    let output_key_tilde = edwards_to_wei25519(public_input.output_key_tilde)?;
    let linking_generator_tilde = edwards_to_wei25519(public_input.linking_tag_generator_tilde)?;
    let rerandomization_commitment = edwards_to_wei25519(public_input.rerandomization_commitment)?;
    let pseudo_out = edwards_to_wei25519(public_input.pseudo_out)?;
    let leaf_branch = if layers == 1 {
        root.to_vec()
    } else {
        c1_branches
            .next()
            .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?
    };
    if leaf_branch.len() != 6 * FCMP_LAYER_ONE_LEN_V1 {
        return Err(FcmpNativeErrorV1::ArithmeticInvariant);
    }
    let branch = leaf_branch
        .chunks_exact(6)
        .map(<[super::bulletproof::Variable]>::to_vec)
        .collect::<Vec<_>>();
    first_layer::<SeleneSuite, _>(
        c1_circuit,
        transcript,
        &ed25519_curve(),
        ED25519_DLOG_PARAMETERS,
        &parameters.t,
        &parameters.u,
        &parameters.v,
        &parameters.g,
        output_key_tilde,
        opening.output_blind,
        opening.output_key,
        linking_generator_tilde,
        opening.input_blind_u,
        opening.linking_generator,
        rerandomization_commitment,
        opening.input_blind_v,
        opening.input_blind_blind,
        pseudo_out,
        opening.commitment_blind,
        opening.amount_commitment,
        branch,
    )?;
    let c1_branch_count = (layers / 2) + (layers % 2);
    let non_leaf_c1_count = c1_branch_count - 1;
    let c2_branch_count = layers / 2;
    if c1_dlog_challenge.is_none() && non_leaf_c1_count != 0 {
        *c1_dlog_challenge = Some(additional_layer_discrete_log_challenge::<SeleneSuite, _>(
            transcript,
            &helios_curve(),
            CYCLE_DLOG_PARAMETERS,
            &parameters.h_2,
        )?);
    }
    if c2_dlog_challenge.is_none() && c2_branch_count != 0 {
        *c2_dlog_challenge = Some(additional_layer_discrete_log_challenge::<HeliosSuite, _>(
            transcript,
            &selene_curve(),
            CYCLE_DLOG_PARAMETERS,
            &parameters.h_1,
        )?);
    }
    let root_is_c1 = layers % 2 == 1;
    let mut these_c1_branches = Vec::new();
    for _ in 0..non_leaf_c1_count.saturating_sub(usize::from(root_is_c1)) {
        these_c1_branches.push(
            c1_branches
                .next()
                .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?,
        );
    }
    if root_is_c1 && non_leaf_c1_count != 0 {
        these_c1_branches.push(root.to_vec());
    }
    let mut these_c2_branches = Vec::new();
    for _ in 0..c2_branch_count.saturating_sub(usize::from(!root_is_c1)) {
        these_c2_branches.push(
            c2_branches
                .next()
                .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?,
        );
    }
    if !root_is_c1 {
        these_c2_branches.push(root.to_vec());
    }
    for branch in these_c1_branches {
        if branch.len() != FCMP_LAYER_ONE_LEN_V1 {
            return Err(FcmpNativeErrorV1::ArithmeticInvariant);
        }
        let (prior_commitment, prior_mask, blind) = c2_commitments
            .next()
            .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
        let prior_commitment = prior_commitment + helios_hash_initializer();
        let (hash_x, hash_y, _) = match prior_mask {
            Some(mask) => {
                let hash_witness = secret_unblind_helios_coordinates_v1(&prior_commitment, mask)?;
                c1_circuit.mul_with_witness(None, None, Some(hash_witness.component_refs()))?
            }
            None => c1_circuit.mul_with_witness(None, None, None)?,
        };
        additional_layer::<SeleneSuite>(
            c1_circuit,
            &helios_curve(),
            CYCLE_DLOG_PARAMETERS,
            c1_dlog_challenge
                .as_ref()
                .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?,
            prior_commitment
                .coordinates()
                .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?,
            blind,
            (hash_x, hash_y),
            branch,
        )?;
    }
    for branch in these_c2_branches {
        if branch.len() != FCMP_LAYER_TWO_LEN_V1 {
            return Err(FcmpNativeErrorV1::ArithmeticInvariant);
        }
        let (prior_commitment, prior_mask, blind) = c1_commitments
            .next()
            .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?;
        let prior_commitment = prior_commitment + selene_hash_initializer();
        let (hash_x, hash_y, _) = match prior_mask {
            Some(mask) => {
                let hash_witness = secret_unblind_selene_coordinates_v1(&prior_commitment, mask)?;
                c2_circuit.mul_with_witness(None, None, Some(hash_witness.component_refs()))?
            }
            None => c2_circuit.mul_with_witness(None, None, None)?,
        };
        additional_layer::<HeliosSuite>(
            c2_circuit,
            &selene_curve(),
            CYCLE_DLOG_PARAMETERS,
            c2_dlog_challenge
                .as_ref()
                .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?,
            prior_commitment
                .coordinates()
                .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?,
            blind,
            (hash_x, hash_y),
            branch,
        )?;
    }
    Ok(())
}
fn verify_membership(
    parsed: &ParsedFcmpPlusPlusWireV1,
    public_inputs: &[FcmpProofInputPublicV1],
    root: FcmpTreeRootV1,
) -> Result<(), FcmpNativeErrorV1> {
    let inputs = public_inputs.len();
    let layers = usize::from(parsed.layers);
    let (c1_rows, c2_rows) = ipa_rows(inputs, layers)?;
    let mut c1_tape = VectorCommitmentTape::new(c1_rows)?;
    let mut c2_tape = VectorCommitmentTape::new(c2_rows)?;
    let mut c1_branches = Vec::with_capacity(inputs * layers.div_ceil(2));
    let mut c2_branches = Vec::with_capacity(inputs * (layers / 2));
    for _ in 0..inputs {
        for layer in 0..layers.saturating_sub(1) {
            if layer % 2 == 0 {
                c1_branches.push(c1_tape.append_branch(if layer == 0 {
                    6 * FCMP_LAYER_ONE_LEN_V1
                } else {
                    FCMP_LAYER_ONE_LEN_V1
                })?);
            } else {
                c2_branches.push(c2_tape.append_branch(FCMP_LAYER_TWO_LEN_V1)?);
            }
        }
    }
    let root_variables = if layers % 2 == 1 {
        c1_tape.append_branch(if layers == 1 {
            6 * FCMP_LAYER_ONE_LEN_V1
        } else {
            FCMP_LAYER_ONE_LEN_V1
        })?
    } else {
        c2_tape.append_branch(FCMP_LAYER_TWO_LEN_V1)?
    };
    let mut openings = Vec::with_capacity(inputs);
    for _ in 0..inputs {
        let (output_blind, output_key) = c1_tape.append_claimed_point(ED25519_DLOG_PARAMETERS)?;
        let (input_blind_u, linking_generator) =
            c1_tape.append_claimed_point(ED25519_DLOG_PARAMETERS)?;
        let (input_blind_v_divisor, _) = c1_tape.append_divisor(ED25519_DLOG_PARAMETERS)?;
        let (input_blind_blind, input_blind_v_point) =
            c1_tape.append_claimed_point(ED25519_DLOG_PARAMETERS)?;
        let (commitment_blind, amount_commitment) =
            c1_tape.append_claimed_point(ED25519_DLOG_PARAMETERS)?;
        if output_key.len() != 2
            || linking_generator.len() != 2
            || input_blind_v_point.len() != 2
            || amount_commitment.len() != 2
        {
            return Err(FcmpNativeErrorV1::ArithmeticInvariant);
        }
        let input_blind_v = PointWithDlog {
            point: (input_blind_v_point[0], input_blind_v_point[1]),
            dlog: input_blind_u.dlog.clone(),
            divisor: input_blind_v_divisor,
        };
        openings.push(TranscriptedInput {
            output_key: (output_key[0], output_key[1]),
            linking_generator: (linking_generator[0], linking_generator[1]),
            amount_commitment: (amount_commitment[0], amount_commitment[1]),
            output_blind,
            input_blind_u,
            input_blind_v,
            input_blind_blind,
            commitment_blind,
        });
    }
    let c1_blind_claim_count = if c1_branches.is_empty() {
        0
    } else {
        c1_branches
            .len()
            .checked_sub(inputs)
            .and_then(|count| count.checked_add(inputs * (layers % 2)))
            .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?
    };
    let mut c1_blind_claims = Vec::with_capacity(c1_blind_claim_count);
    for _ in 0..c1_blind_claim_count {
        c1_blind_claims.push(c1_tape.append_claimed_point(CYCLE_DLOG_PARAMETERS)?.0);
    }
    let c2_blind_claim_count = c2_branches
        .len()
        .checked_add(inputs * usize::from(layers % 2 == 0))
        .ok_or(FcmpNativeErrorV1::TreeFull)?;
    let mut c2_blind_claims = Vec::with_capacity(c2_blind_claim_count);
    for _ in 0..c2_blind_claim_count {
        c2_blind_claims.push(c2_tape.append_claimed_point(CYCLE_DLOG_PARAMETERS)?.0);
    }
    let context = membership_context(root, public_inputs, parsed.root_blind_commitment)?;
    let mut transcript = VerifierTranscript::new(context, &parsed.circuit_proof);
    let (proof_1_vcs, proof_1_scalars) =
        transcript.read_commitments::<SeleneSuite>(c1_tape.commitment_count(), 0)?;
    let (proof_2_vcs, proof_2_scalars) =
        transcript.read_commitments::<HeliosSuite>(c2_tape.commitment_count(), 0)?;
    if !proof_1_scalars.is_empty() || !proof_2_scalars.is_empty() {
        return Err(FcmpNativeErrorV1::ArithmeticInvariant);
    }
    verify_root_blind(
        &mut transcript,
        parsed,
        root,
        &root_variables,
        &proof_1_vcs,
        &proof_2_vcs,
    )?;
    let mut c1_circuit = Circuit::<SeleneSuite>::verify();
    let mut c2_circuit = Circuit::<HeliosSuite>::verify();
    let mut c1_dlog_challenge = None;
    let mut c2_dlog_challenge = None;
    let mut c1_branches = c1_branches.into_iter();
    let mut c2_branches = c2_branches.into_iter();
    let mut c1_commitments = proof_1_vcs
        .iter()
        .copied()
        .zip(c2_blind_claims)
        .map(|(commitment, blind)| (commitment, None::<&Field25519>, blind));
    let mut c2_commitments = proof_2_vcs
        .iter()
        .copied()
        .zip(c1_blind_claims)
        .map(|(commitment, blind)| (commitment, None::<&HelioseleneField>, blind));
    for (public_input, opening) in public_inputs.iter().zip(openings) {
        constrain_input(
            native_parameters(),
            layers,
            &mut transcript,
            &mut c1_circuit,
            &mut c1_dlog_challenge,
            &mut c2_circuit,
            &mut c2_dlog_challenge,
            &root_variables,
            &mut c1_branches,
            &mut c2_branches,
            &mut c1_commitments,
            &mut c2_commitments,
            public_input,
            opening,
        )?;
    }
    if c1_branches.next().is_some()
        || c2_branches.next().is_some()
        || c1_commitments.next().is_some()
        || c2_commitments.next().is_some()
    {
        return Err(FcmpNativeErrorV1::ArithmeticInvariant);
    }
    let expected_c1_muls = inputs
        .checked_mul(
            97_usize
                .checked_add(
                    layers
                        .saturating_sub(1)
                        .checked_div(2)
                        .ok_or(FcmpNativeErrorV1::ArithmeticInvariant)?
                        .checked_mul(52)
                        .ok_or(FcmpNativeErrorV1::TreeFull)?,
                )
                .ok_or(FcmpNativeErrorV1::TreeFull)?,
        )
        .ok_or(FcmpNativeErrorV1::TreeFull)?;
    let expected_c2_muls = inputs
        .checked_mul(
            (layers / 2)
                .checked_mul(32)
                .ok_or(FcmpNativeErrorV1::TreeFull)?,
        )
        .ok_or(FcmpNativeErrorV1::TreeFull)?;
    if c1_circuit.muls() != expected_c1_muls || c2_circuit.muls() != expected_c2_muls {
        return Err(FcmpNativeErrorV1::ArithmeticInvariant);
    }
    let c1_statement = c1_circuit.statement(
        <SeleneSuite as ProofSuite>::generators().reduce(c1_rows)?,
        proof_1_vcs,
    )?;
    c1_statement.verify(&mut transcript)?;
    let c2_statement = c2_circuit.statement(
        <HeliosSuite as ProofSuite>::generators().reduce(c2_rows)?,
        proof_2_vcs,
    )?;
    c2_statement.verify(&mut transcript)?;
    if transcript.consumed() != parsed.circuit_proof.len() {
        return Err(FcmpNativeErrorV1::TranscriptConsumption);
    }
    Ok(())
}
/// Verify the membership/SAL component of one already-structurally-decoded
/// first-release FCMP++ transfer proof.
///
/// `context_hash` must be a domain-separated hash of the authoritative transaction statement. It is
/// bound by every per-input SAL proof. The membership transcript additionally binds the typed tree
/// root, all rerandomized public input coordinates, and the root-blind nonce in the canonical
/// upstream order.
pub(super) fn verify_fcmp_membership_parsed_v1(
    context_hash: [u8; 32],
    parsed: &ParsedFcmpPlusPlusWireV1,
    public_inputs: &[FcmpProofInputPublicV1],
    root: FcmpTreeRootV1,
) -> Result<(), FcmpNativeErrorV1> {
    for (parsed_input, public_input) in parsed.inputs.iter().zip(public_inputs) {
        let proof = FcmpSalProofV1::new(parsed_input.sal_points, parsed_input.sal_scalars)?;
        verify_fcmp_sal_v1(context_hash, public_input, &proof)?;
    }
    verify_membership(parsed, public_inputs, root)
}
/// Test-only membership-component verifier used by upstream interoperability
/// fixtures. Production callers cannot bypass the complete transaction
/// verifier, which additionally enforces balance and the output range proof.
#[cfg(test)]
pub fn verify_fcmp_plus_plus_v1(
    context_hash: [u8; 32],
    proof_wire: &[u8],
    public_inputs: &[FcmpProofInputPublicV1],
    root: FcmpTreeRootV1,
) -> Result<(), FcmpNativeErrorV1> {
    let parsed = if proof_wire.get(6) == Some(&0) {
        super::wire::decode_fcmp_membership_fixture_v1(proof_wire, public_inputs, root)?
    } else {
        decode_fcmp_plus_plus_wire_v1(proof_wire, public_inputs, root)?
    };
    verify_fcmp_membership_parsed_v1(context_hash, &parsed, public_inputs, root)
}
#[cfg(test)]
mod tests {
    use super::*;
    struct EndToEndKat {
        context: [u8; 32],
        root: FcmpTreeRootV1,
        public: FcmpProofInputPublicV1,
        wire: Vec<u8>,
    }
    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&value[index..index + 2], 16)
                    .expect("pinned vector is hexadecimal")
            })
            .collect()
    }
    fn array(value: &str) -> [u8; 32] {
        decode_hex(value)
            .try_into()
            .expect("pinned field is exactly 32 bytes")
    }
    fn parse_end_to_end_kat(vector: &str, layers: u8) -> EndToEndKat {
        // Generated by monero-fcmp-plus-plus at pinned commit 15ef711 with
        // ChaCha20Rng seed 0x5a*32. This is an actual divisor-backed FCMP
        // proof, not a synthetic arithmetic-circuit fixture.
        let value = |name: &str| {
            vector
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .expect("pinned vector field exists")
        };
        let context = array(value("context"));
        let root = FcmpTreeRootV1::new(layers, array(value("root"))).expect("pinned root");
        let public = FcmpProofInputPublicV1::new(
            array(value("o_tilde")),
            array(value("i_tilde")),
            array(value("r")),
            array(value("c_tilde")),
            array(value("key_image")),
        )
        .expect("pinned public input");
        let proof = decode_hex(value("proof"));
        let mut wire = Vec::with_capacity(proof.len() + 8);
        wire.extend_from_slice(b"IFC1");
        wire.extend_from_slice(&[1, layers, 0, 0]);
        wire.extend_from_slice(&proof);
        EndToEndKat {
            context,
            root,
            public,
            wire,
        }
    }
    fn end_to_end_kat() -> EndToEndKat {
        parse_end_to_end_kat(include_str!("test_vectors/one_input_one_layer.txt"), 1)
    }
    #[test]
    fn embedded_parameter_tables_are_on_curve_and_complete() {
        let parameters = native_parameters();
        assert_eq!(parameters.g.len(), ED25519_DLOG_PARAMETERS.scalar_bits);
        assert_eq!(parameters.t.len(), ED25519_DLOG_PARAMETERS.scalar_bits);
        assert_eq!(parameters.u.len(), ED25519_DLOG_PARAMETERS.scalar_bits);
        assert_eq!(parameters.v.len(), ED25519_DLOG_PARAMETERS.scalar_bits);
        assert_eq!(parameters.h_1.len(), CYCLE_DLOG_PARAMETERS.scalar_bits);
        assert_eq!(parameters.h_2.len(), CYCLE_DLOG_PARAMETERS.scalar_bits);
    }
    #[test]
    fn pinned_upstream_end_to_end_proof_verifies() {
        for kat in [
            end_to_end_kat(),
            parse_end_to_end_kat(include_str!("test_vectors/one_input_two_layers.txt"), 2),
        ] {
            assert_eq!(
                verify_fcmp_plus_plus_v1(kat.context, &kat.wire, &[kat.public], kat.root),
                Ok(())
            );
        }
    }
    #[test]
    fn replay_public_root_and_every_proof_phase_fail_closed() {
        let kat = end_to_end_kat();
        let mut replay_context = kat.context;
        replay_context[0] ^= 1;
        assert_eq!(
            verify_fcmp_plus_plus_v1(replay_context, &kat.wire, &[kat.public], kat.root),
            Err(FcmpNativeErrorV1::SalEquation)
        );
        let replacement = super::super::output_from_multiples(101, 102, 103).components();
        for field in 0..5 {
            let mut public = kat.public;
            match field {
                0 => public.output_key_tilde = replacement.0,
                1 => public.linking_tag_generator_tilde = replacement.1,
                2 => public.rerandomization_commitment = replacement.2,
                3 => public.pseudo_out = replacement.0,
                4 => public.key_image = replacement.1,
                _ => unreachable!("five public fields"),
            }
            assert!(
                verify_fcmp_plus_plus_v1(kat.context, &kat.wire, &[public], kat.root).is_err(),
                "public field {field} was not bound"
            );
        }
        let alternate_root = FcmpTreeRootV1::new(1, selene_hash_initializer().encode())
            .expect("canonical alternate root");
        assert!(
            verify_fcmp_plus_plus_v1(kat.context, &kat.wire, &[kat.public], alternate_root)
                .is_err()
        );
        // For this 1-input/1-layer vector, the membership transcript is 88
        // field elements: 10 vector commitments, 50 Selene BP elements, and
        // 28 Helios BP elements. Mutate a representative from every phase:
        // vector commitments, A/T/scalar/IPA/final terms on each curve.
        let circuit_start = 8 + super::super::wire::FCMP_PROOF_INPUT_BYTES_V1;
        for element in [0_usize, 10, 13, 39, 42, 58, 60, 63, 69, 72, 86] {
            let mut mutation = kat.wire.clone();
            mutation[circuit_start + element * 32] ^= 1;
            assert!(
                verify_fcmp_plus_plus_v1(kat.context, &mutation, &[kat.public], kat.root).is_err(),
                "membership proof element {element} was not bound"
            );
        }
        for offset in [kat.wire.len() - 64, kat.wire.len() - 32] {
            let mut mutation = kat.wire.clone();
            mutation[offset] ^= 1;
            assert!(
                verify_fcmp_plus_plus_v1(kat.context, &mutation, &[kat.public], kat.root).is_err(),
                "root-blind proof field at {offset} was not bound"
            );
        }
    }
}
