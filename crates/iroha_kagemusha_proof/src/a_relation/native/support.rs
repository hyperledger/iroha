//! Shared exact native encodings, context commitments and full claim decisions.
//!
//! These helpers do not establish artifact authority or authenticate operation
//! semantics. Fixed source owners still bind every proposed context digest/result.

use crate::{
    a_relation::context::{ContextObjectSpec, ContextPlan},
    operation_relation::objects::ObjectKind,
    q_sigma::{QSigmaPlan, native::IncomingMode},
};
use ff::{Field, PrimeField};
use iroha_pasta::{
    Ep, EpAffine, Eq, EqAffine, Fp, Fq, msm::MemoryBudget, poseidon::hash_with_domain,
};
use iroha_plonk::{DescriptorBinding, VerifyingKey, pcs::ipa::PinnedParams};
use iroha_plonk_gadgets::{
    bytes::{le_value, p_bytes_native},
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{AccumulatorT, FoldInput};

/// Shared native source/claim failure; no error grants operation acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// Explicit cancellation, never an invalid proof verdict.
    Cancelled,
    /// Invalid source shape, canonical field/point or selected correction.
    Input,
    /// Original proof or selected full accumulator failed verification.
    Proof,
}

/// Canonical one-hot Accept, Trivial and Corrected words.
pub(super) fn mode_words(mode: IncomingMode) -> [Fp; 3] {
    match mode {
        IncomingMode::Accept => [Fp::ONE, Fp::ZERO, Fp::ZERO],
        IncomingMode::Trivial => [Fp::ZERO, Fp::ONE, Fp::ZERO],
        IncomingMode::Corrected => [Fp::ZERO, Fp::ZERO, Fp::ONE],
    }
}

/// Select and fully decide a Pallas obligation without dropping its original challenges.
#[cfg(test)]
pub(super) fn select_pallas(
    params: &PinnedParams<Ep>,
    original: &FoldInput<Ep>,
    mode: IncomingMode,
    correction: EpAffine,
    budget: MemoryBudget,
) -> Result<FoldInput<Ep>, Error> {
    select_pallas_cancellable(params, original, mode, correction, budget, None)
}
/// Execute the same native check with an explicit operation signal.
/// # Errors
/// As the ordinary entry point, or cancellation without a partial verdict.
pub(super) fn select_pallas_cancellable(
    params: &PinnedParams<Ep>,
    original: &FoldInput<Ep>,
    mode: IncomingMode,
    correction: EpAffine,
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<FoldInput<Ep>, Error> {
    iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
    let selected = match mode {
        IncomingMode::Accept => original.clone(),
        IncomingMode::Trivial => AccumulatorT::trivial_cancellable(params, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?
            .as_input(),
        IncomingMode::Corrected => {
            if correction == *original.g() {
                return Err(Error::Input);
            }
            FoldInput::from_normalized(correction, original.source_k(), *original.challenges())
                .map_err(|_| Error::Input)?
        }
    };
    selected
        .decide_cancellable(params, budget, cancellation)
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
    Ok(selected)
}

#[cfg(test)]
/// Select and fully decide a Vesta obligation without dropping its original challenges.
pub(super) fn select_vesta(
    params: &PinnedParams<Eq>,
    original: &FoldInput<Eq>,
    mode: IncomingMode,
    correction: EqAffine,
    budget: MemoryBudget,
) -> Result<FoldInput<Eq>, Error> {
    select_vesta_cancellable(params, original, mode, correction, budget, None)
}
/// Execute the same native check with an explicit operation signal.
/// # Errors
/// As the ordinary entry point, or cancellation without a partial verdict.
pub(super) fn select_vesta_cancellable(
    params: &PinnedParams<Eq>,
    original: &FoldInput<Eq>,
    mode: IncomingMode,
    correction: EqAffine,
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<FoldInput<Eq>, Error> {
    iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
    let selected = match mode {
        IncomingMode::Accept => original.clone(),
        IncomingMode::Trivial => AccumulatorT::trivial_cancellable(params, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?
            .as_input(),
        IncomingMode::Corrected => {
            if correction == *original.g() {
                return Err(Error::Input);
            }
            FoldInput::from_normalized(correction, original.source_k(), *original.challenges())
                .map_err(|_| Error::Input)?
        }
    };
    selected
        .decide_cancellable(params, budget, cancellation)
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
    Ok(selected)
}

/// Decode the exact plan-shaped Q accumulator export; the caller verifies Q first.
/// The fixed plan owns the slot count, source k and normalized challenge interval.
/// An own sigma is hard, so its verdict must be true; an incoming-only plan's
/// verdict is the incoming soft result and either value decodes.
pub(super) fn q_sigma_part(columns: &[Vec<Fq>], plan: &QSigmaPlan) -> Result<FoldInput<Eq>, Error> {
    if columns.len() != plan.instance_lengths().len()
        || columns.iter().map(Vec::len).ne(plan.instance_lengths())
    {
        return Err(Error::Input);
    }
    let [bounded, point, _, verdicts, source] = columns else {
        return Err(Error::Input);
    };
    if (plan.has_own() && verdicts[0] != Fq::ONE)
        || source.as_slice() != [Fq::from(u64::from(plan.part_source_k()))]
    {
        return Err(Error::Input);
    }
    let g = iroha_plonk::transcript::generator_from_coordinates::<Eq>(point[0], point[1])
        .map_err(|_| Error::Input)?;
    let u = bounded[plan.challenge_range()]
        .iter()
        .map(|v| Option::<Fp>::from(Fp::from_repr(v.to_repr())).ok_or(Error::Input))
        .collect::<Result<Vec<_>, _>>()?;
    FoldInput::from_normalized(
        g,
        plan.part_source_k(),
        u.try_into().map_err(|_| Error::Input)?,
    )
    .map_err(|_| Error::Input)
}

/// Prefix the exact original bytes with their checked LE32 length.
pub(super) fn frame(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = u32::try_from(raw.len())
        .map_err(|_| Error::Input)?
        .to_le_bytes()
        .to_vec();
    out.extend(raw);
    Ok(out)
}

/// Hash the fixed signed object with its original four signature limbs.
pub(super) fn object_digest(kind: ObjectKind, raw: &[u8]) -> Result<Fp, Error> {
    let end = kind.body_len();
    if raw.len() != end + 64 {
        return Err(Error::Input);
    }
    let mut words = vec![p_bytes_native(kind.signing_domain(), &raw[..end])];
    for offset in [16, 0, 48, 32] {
        words.push(Fp::from_u128(u128::from_be_bytes(
            raw[end + offset..end + offset + 16]
                .try_into()
                .map_err(|_| Error::Input)?,
        )));
    }
    Ok(hash_with_domain(kind.object_domain(), &words))
}

/// Bind the one hard own receipt tape to Q0's single slot under the predecessor
/// payment key. A lean route carries the credential and its certificate by
/// continuity, so no other own slot exists. This performs no proof verification
/// or semantic admission; the caller must still verify Q and every circuit owner.
pub(super) fn check_hard_own_receipt(
    receipt: &[u8],
    columns: &[Vec<Fq>],
    payment_key: [Fp; 4],
) -> Result<(), Error> {
    check_hard_own_receipt_slot(receipt, columns, 1, payment_key)
}

/// Bind the hard own receipt tape to slot 0 of a merged signature leaf with
/// `slots` slots under the predecessor payment key. The other slots are incoming
/// soft objects: their owners bind them to the original tapes in the circuit, and
/// this own-authorization interface deliberately leaves them untouched.
pub(super) fn check_hard_own_receipt_slot(
    receipt: &[u8],
    columns: &[Vec<Fq>],
    slots: usize,
    payment_key: [Fp; 4],
) -> Result<(), Error> {
    let kind = ObjectKind::Receipt;
    if receipt.len() != kind.body_len() + 64 || receipt[..2] != 1_u16.to_le_bytes() {
        return Err(Error::Input);
    }
    let [public] = columns else {
        return Err(Error::Input);
    };
    if slots == 0
        || slots
            .checked_mul(crate::q_signature::SLOT_WORDS)
            .is_none_or(|words| public.len() != words)
    {
        return Err(Error::Input);
    }
    check_hard_slot(
        kind,
        receipt,
        payment_key,
        &public[..crate::q_signature::SLOT_WORDS],
    )
}

/// One exported hard slot: body digest, authorized key, raw signature limbs, verdict.
fn check_hard_slot(
    kind: ObjectKind,
    raw: &[u8],
    authorized: [Fp; 4],
    proved: &[Fq],
) -> Result<(), Error> {
    let end = kind.body_len();
    let mut expected = vec![p_bytes_native(kind.signing_domain(), &raw[..end])];
    expected.extend(authorized);
    for offset in [16, 0, 48, 32] {
        expected.push(Fp::from_u128(u128::from_be_bytes(
            raw[end + offset..end + offset + 16]
                .try_into()
                .map_err(|_| Error::Input)?,
        )));
    }
    expected.push(Fp::ONE);
    // Compare canonical integer representations, never a reducing Fq -> Fp map.
    if proved.len() != expected.len()
        || proved
            .iter()
            .zip(expected)
            .any(|(a, b)| a.to_repr() != b.to_repr())
    {
        return Err(Error::Input);
    }
    Ok(())
}

/// Append the exact full-k16 Pallas claim in native context word order.
pub(super) fn push_pallas(words: &mut Vec<Fp>, claim: &FoldInput<Ep>) -> Result<(), Error> {
    if claim.source_k() != 16 {
        return Err(Error::Input);
    }
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<Ep>(claim.g());
    words.extend([Fp::from(16), x, y]);
    for u in claim.challenges() {
        words.extend(foreign_limbs(u).map(Fp::from_u128));
    }
    Ok(())
}

/// Encode Vesta point limbs and all normalized challenges in context word order.
pub(super) fn vesta_words(claim: &FoldInput<Eq>) -> Vec<Fp> {
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<Eq>(claim.g());
    let mut words = Vec::with_capacity(20);
    for v in [x, y] {
        words.extend(foreign_limbs(&v).map(Fp::from_u128));
    }
    words.extend(claim.challenges());
    words
}

/// Derive the exact `D_A` digest from public18 and the full-k16 Pallas claim.
pub(super) fn terminal_digest(public: &[Fp; 18], pallas: &FoldInput<Ep>) -> Result<Fp, Error> {
    let mut words = public.to_vec();
    let mut claim = vec![];
    push_pallas(&mut claim, pallas)?;
    words.extend(&claim[1..]);
    Ok(hash_with_domain(crate::a_relation::LINEAGE_DOMAIN, &words))
}

/// Encode the canonical three-column Omega or W public input.
pub(super) fn omega_instances(digest: Fp, vesta: &AccumulatorT<Eq>) -> Result<Vec<Vec<Fq>>, Error> {
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<Eq>(vesta.g());
    Ok(vec![
        vec![Option::<Fq>::from(Fq::from_repr(digest.to_repr())).ok_or(Error::Input)?],
        vec![x, y],
        vesta
            .challenges()
            .iter()
            .map(|v| Option::<Fq>::from(Fq::from_repr(v.to_repr())).ok_or(Error::Input))
            .collect::<Result<Vec<_>, _>>()?,
    ])
}

#[cfg(test)]
/// Verify the original Pallas proof and fully decide its generator opening.
pub(super) fn opening_pallas(
    params: &PinnedParams<Ep>,
    binding: &DescriptorBinding,
    key: &VerifyingKey<Ep>,
    instances: &[Vec<Fq>],
    proof: &[u8],
    budget: MemoryBudget,
) -> Result<FoldInput<Ep>, Error> {
    opening_pallas_cancellable(params, binding, key, instances, proof, budget, None)
}
/// Execute the same native check with an explicit operation signal.
/// # Errors
/// As the ordinary entry point, or cancellation without a partial verdict.
pub(super) fn opening_pallas_cancellable(
    params: &PinnedParams<Ep>,
    binding: &DescriptorBinding,
    key: &VerifyingKey<Ep>,
    instances: &[Vec<Fq>],
    proof: &[u8],
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<FoldInput<Ep>, Error> {
    iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
    let claim = iroha_plonk::verifier::accumulate_generator_cancellable(
        params,
        binding,
        key,
        instances,
        proof,
        budget,
        cancellation,
    )
    .map_err(|error| {
        if error.is_cancelled() {
            Error::Cancelled
        } else {
            Error::Proof
        }
    })?;
    let input =
        FoldInput::from_opening(*claim.g(), claim.challenges()).map_err(|_| Error::Proof)?;
    input
        .decide_cancellable(params, budget, cancellation)
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
    Ok(input)
}

#[cfg(test)]
/// Verify the original Vesta proof and fully decide its generator opening.
pub(super) fn opening_vesta(
    params: &PinnedParams<Eq>,
    binding: &DescriptorBinding,
    key: &VerifyingKey<Eq>,
    instances: &[Vec<Fp>],
    proof: &[u8],
    budget: MemoryBudget,
) -> Result<FoldInput<Eq>, Error> {
    opening_vesta_cancellable(params, binding, key, instances, proof, budget, None)
}
/// Execute the same native check with an explicit operation signal.
/// # Errors
/// As the ordinary entry point, or cancellation without a partial verdict.
pub(super) fn opening_vesta_cancellable(
    params: &PinnedParams<Eq>,
    binding: &DescriptorBinding,
    key: &VerifyingKey<Eq>,
    instances: &[Vec<Fp>],
    proof: &[u8],
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<FoldInput<Eq>, Error> {
    iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
    let claim = iroha_plonk::verifier::accumulate_generator_cancellable(
        params,
        binding,
        key,
        instances,
        proof,
        budget,
        cancellation,
    )
    .map_err(|error| {
        if error.is_cancelled() {
            Error::Cancelled
        } else {
            Error::Proof
        }
    })?;
    let input =
        FoldInput::from_opening(*claim.g(), claim.challenges()).map_err(|_| Error::Proof)?;
    input
        .decide_cancellable(params, budget, cancellation)
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
    Ok(input)
}

/// Match a fixed original byte tape's context commitment exactly.
pub(super) fn exact_context(
    spec: ContextObjectSpec,
    digest: Fp,
    raw: &[u8],
) -> Result<[Fp; 3], Error> {
    if spec.tag == 0 || usize::try_from(spec.capacity).ok() != Some(raw.len()) {
        return Err(Error::Input);
    }
    let mut words = vec![
        Fp::from(u64::from(spec.tag)),
        Fp::from(u64::from(spec.capacity)),
    ];
    for chunk in frame(raw)?.chunks(31) {
        words.push(le_value(chunk).ok_or(Error::Input)?);
    }
    Ok([
        digest,
        Fp::from(u64::from(spec.capacity)),
        hash_with_domain(u64::from_le_bytes(*b"kgwctap1"), &words),
    ])
}

/// Match an active original tape, preserving every admitted length and byte.
pub(super) fn active_context(
    spec: ContextObjectSpec,
    digest: Fp,
    raw: &[u8],
) -> Result<[Fp; 3], Error> {
    let length = u32::try_from(raw.len()).map_err(|_| Error::Input)?;
    if spec.tag == 0 || length > spec.capacity {
        return Err(Error::Input);
    }
    let domain = u64::from_le_bytes(*b"kgwcact1");
    let words = [
        Fp::from(u64::from(spec.tag)),
        Fp::from(u64::from(spec.capacity)),
        Fp::from(u64::from(length)),
        p_bytes_native(domain, &frame(raw)?),
    ];
    Ok([
        digest,
        Fp::from(u64::from(length)),
        hash_with_domain(domain, &words),
    ])
}

/// Match typed internal words; this commitment is not an original byte tape.
pub(super) fn internal_context(spec: ContextObjectSpec, values: &[Fp]) -> Result<[Fp; 3], Error> {
    let count = u32::try_from(values.len()).map_err(|_| Error::Input)?;
    if spec.tag == 0 || count == 0 || count.checked_mul(32) != Some(spec.capacity) {
        return Err(Error::Input);
    }
    let mut words = vec![Fp::from(u64::from(spec.tag)), Fp::from(u64::from(count))];
    words.extend_from_slice(values);
    let digest = hash_with_domain(u64::from_le_bytes(*b"kgwciw_1"), &words);
    Ok([digest, Fp::from(u64::from(spec.capacity)), digest])
}

/// Bind one internal stage and current Pallas claim to the immutable source context.
pub(super) fn stage_digest(
    plan: &ContextPlan,
    stage: usize,
    context: Fp,
    current: &AccumulatorT<Ep>,
) -> Result<Fp, Error> {
    let ordinal = stage.checked_add(1).ok_or(Error::Input)?;
    if ordinal >= plan.stage_count() {
        return Err(Error::Input);
    }
    let mut words = vec![
        Fp::ONE,
        *plan.schema().get(1).ok_or(Error::Input)?,
        Fp::from(u64::try_from(ordinal).map_err(|_| Error::Input)?),
        context,
    ];
    push_pallas(&mut words, &current.as_input())?;
    Ok(hash_with_domain(
        u64::from_le_bytes(crate::a_relation::context::STAGE_DOMAIN),
        &words,
    ))
}

/// Encode the fixed internal A frame, retaining its part and the prescribed trivial slots.
pub(super) fn internal_public(
    params: &PinnedParams<Eq>,
    digest: Fp,
    part: &FoldInput<Eq>,
) -> Result<Vec<Fp>, Error> {
    let mut words = vec![digest, Fp::from(u64::from(part.source_k()))];
    words.extend(vesta_words(part));
    let trivial = AccumulatorT::trivial(params, MemoryBudget::DEFAULT).map_err(|_| Error::Proof)?;
    let trivial = vesta_words(&trivial.as_input());
    words.extend(&trivial);
    words.extend(&trivial);
    words.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
    words.extend(&trivial[..4]);
    if words.len() != 69 {
        return Err(Error::Input);
    }
    Ok(words)
}

#[cfg(test)]
mod exact_original_tests;
#[cfg(test)]
mod tests;
