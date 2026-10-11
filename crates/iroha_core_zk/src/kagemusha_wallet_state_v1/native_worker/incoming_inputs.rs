//! Source-selected Receive/Archive proposals and exact adjusted-map effects.
//!
//! All result bits are derived from original circuit predicates or the total
//! native verifier. The final Q/A owners rederive them; no caller supplies verdicts.

use super::*;
use crate::kagemusha_wallet_preparation_v1::{
    ArchiveFoldFieldsV1, ArchiveFoldWitnessV1, ArchiveIncomingWitnessV1, FoldedStateV1,
    PreparationV1, PreparedOperationV1, ReceiveFoldFieldsV1, ReceiveFoldMapsV1,
};
use crate::kagemusha_wallet_state_v1::{FoldCustodyV1, ReleasedStep};
use ff::Field;
use iroha_data_model::kagemusha::kagemusha_wallet_v1::*;
use iroha_kagemusha_proof::{
    operation_relation::objects::ObjectKind,
    q_sigma::{
        SigmaSlotWitness,
        native::{IncomingMode, IncomingSigma},
    },
    tree::{IndexedInsert, IndexedLeaf},
};
use iroha_pasta::{Ep, Eq, poseidon::hash_with_domain};
use iroha_plonk::Protocol;
use iroha_plonk_gadgets::statement::STATEMENT_DOMAIN;
use iroha_plonk_recursion::{AccumulatorT, obligation::ledger::Variant};

fn word(bytes: [u8; 32]) -> Result<Fp, Error> {
    Option::<Fp>::from(Fp::from_repr(bytes)).ok_or(Error::Proof("native incoming field"))
}
fn history(
    leaf: KagemushaWalletIndexedLeafV1,
    opening: KagemushaWalletIndexedOpeningV1,
) -> Result<IndexedInsert<Fp>, Error> {
    let siblings = opening
        .siblings
        .into_iter()
        .map(word)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| Error::Proof("history depth"))?;
    Ok(IndexedInsert {
        leaf: IndexedLeaf {
            key: word(leaf.key)?,
            value: word(leaf.value)?,
            next_key: word(leaf.next_key)?,
        },
        leaf_slot: opening.slot,
        leaf_siblings: siblings,
        slot: 0,
        slot_siblings: [Fp::ZERO; 32],
    })
}
fn predecessor_claims(
    predecessor: &FoldedStateV1,
) -> Result<(AccumulatorT<Ep>, AccumulatorT<Eq>), Error> {
    let (_, p, v) = predecessor.transport();
    Ok((
        proof(AccumulatorT::from_bytes(p))?,
        proof(AccumulatorT::from_bytes(v))?,
    ))
}
// Q exports the original length independently of its fixed verifier view.
// Complete original bytes remain in the A object tapes and their context digest.
fn sigma_view(original: &[u8], expected: usize) -> Result<(Vec<u8>, u32), Error> {
    if expected == 0 || !expected.is_multiple_of(32) {
        return Err(Error::Proof("incoming sigma descriptor"));
    }
    let length =
        u32::try_from(original.len()).map_err(|_| Error::Proof("incoming sigma length"))?;
    let mut view = vec![0; expected];
    let count = original.len().min(expected);
    view[..count].copy_from_slice(&original[..count]);
    Ok((view, length))
}

fn sigma_slot(
    worker: &NativeFoldWorkerV1,
    selector: u8,
    statement: &[Fp; 26],
    original: &[u8],
) -> Result<SigmaSlotWitness, Error> {
    let key = worker
        .sources
        .sigmas()
        .key(selector)
        .ok_or(Error::Proof("incoming sigma source"))?;
    let expected = proof(Protocol::new(key.binding().descriptor()))?.proof_length();
    let (bytes, length) = sigma_view(original, expected)?;
    Ok(SigmaSlotWitness {
        key: key.key().clone(),
        statement: hash_with_domain(STATEMENT_DOMAIN, statement),
        proof: bytes,
        length,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn receive(
    worker: &NativeFoldWorkerV1,
    preparation: &PreparationV1<'_>,
    prepared: &PreparedOperationV1,
    step: &ReleasedStep,
    predecessor: &FoldedStateV1,
    public: &mut KagemushaWalletLineagePublicV1,
    custody: &mut FoldCustodyV1<'_>,
    route: OperationRoute,
    cancellation: &Cancellation,
) -> Result<(ReceiveFoldFieldsV1, Option<IncomingSigma>), Error> {
    cancellation.check()?;
    let pallas_params = worker.installed.verifier().pallas_parameters();
    let vesta_params = proof(worker.installed.verifier().vesta_parameters(16))?;
    let owner = prepared.owner();
    let monetary = prepared
        .monetary()
        .ok_or(Error::Proof("Receive preparation"))?;
    let sources = proof(preparation.receive_source_fields(
        owner,
        step,
        predecessor,
        monetary,
        public,
        worker.budget,
    ))?;
    let fixed = proof(worker.sources.route(route))?;
    let QualifiedOperationOwnerV1::Receive(prover) = fixed.owner() else {
        return Err(Error::Proof("Receive source route"));
    };
    let omega = fixed
        .candidate_omega()
        .ok_or(Error::Proof("Receive Omega source"))?;
    let incoming = super::incoming::transport(
        pallas_params,
        vesta_params,
        omega,
        &sources.objects[4],
        worker.budget,
        Some(cancellation.prover_token()),
    )?;
    let selector = route
        .incoming
        .ok_or(Error::Proof("Receive incoming selector"))?;
    let slot = sigma_slot(
        worker,
        selector,
        &sources.incoming_statement,
        &sources.objects[5],
    )?;
    let q = proof(worker.sources.q(route))?;
    let sigma = proof(q.sigma().incoming_original_cancellable(
        &slot,
        selector,
        worker.budget,
        Some(cancellation.prover_token()),
    ))?;
    let (history_leaf, history_opening) = custody.blacklist_history()?;
    let (pp, pv) = predecessor_claims(predecessor)?;
    let root = worker.sources.scope().root();
    let signatures = super::inputs::receive_signatures(
        &sources.objects,
        route.variant == Variant::ReceiveRenewed,
        [root.x, root.y],
    )?;
    let bits = proof(prover.propose_nonproof(receive::PredicateInputs {
        before: sources.before,
        after: sources.after,
        statement: sources.statement,
        consumed: sources.consumed,
        blacklist: history(history_leaf, history_opening)?,
        incoming_statement: sources.incoming_statement,
        objects: sources.objects.clone(),
        signatures,
        predecessor_pallas: pp,
        predecessor_vesta: pv,
        own_selector: route.own,
        incoming_selector: selector,
    }))?;
    let results = [
        incoming.valid && sigma.is_some(),
        bits[0],
        bits[1],
        bits[2],
        bits[3],
    ];
    let (modes, pc, vc) = super::incoming::modes(
        pallas_params,
        vesta_params,
        results.iter().all(|v| *v),
        &incoming,
        sigma.as_ref(),
        worker.budget,
        Some(cancellation.prover_token()),
    )?;
    let burned = modes.contains(&IncomingMode::Corrected) || !results.iter().all(|v| *v);
    let KagemushaWalletEffectV1::Receive { amount, .. } = step.frozen.capsule.statement.effect
    else {
        return Err(Error::Proof("Receive amount"));
    };
    public.burned_total = predecessor
        .lineage()
        .public
        .burned_total
        .checked_add(if burned { amount } else { 0 })
        .ok_or(Error::Proof("Receive burn overflow"))?;
    let credit = custody.credit_record(burned)?;
    public.credit_digest_root = custody.credit_root();
    let proposal = receive::IncomingWitness {
        public: incoming.public,
        public_valid: incoming.public_valid,
        pallas: incoming.pallas,
        vesta: incoming.vesta,
        opening: incoming.opening,
        results,
        modes,
        pallas_corrections: pc,
        vesta_correction: vc,
    };
    let fields = proof(preparation.receive_fold_fields(
        owner,
        step,
        predecessor,
        monetary,
        public,
        ReceiveFoldMapsV1 {
            credit,
            history_leaf,
            history_opening,
        },
        proposal,
        worker.budget,
    ))?;
    Ok((
        fields,
        Some(IncomingSigma {
            sigma: slot,
            mode: modes[3],
        }),
    ))
}

fn retained<'a>(
    step: &'a ReleasedStep,
    role: KagemushaWalletRetainedInputRoleV1,
) -> Result<&'a [u8], Error> {
    let mut found = step
        .frozen
        .capsule
        .retained_inputs
        .iter()
        .filter(|i| i.role == role);
    let original = found.next().ok_or(Error::WitnessLost("Archive original"))?;
    if found.next().is_some() {
        return Err(Error::WitnessLost("duplicate Archive original"));
    }
    Ok(&original.bytes)
}
fn status_witness(
    transport: &super::incoming::TransportV1,
    modes: [IncomingMode; 3],
    pc: [iroha_pasta::EpAffine; 2],
    vc: iroha_pasta::EqAffine,
) -> archive::StatusWitness {
    archive::StatusWitness {
        public: transport.public,
        public_valid: transport.public_valid,
        pallas: transport.pallas.clone(),
        vesta: transport.vesta.clone(),
        opening: transport.opening.clone(),
        modes,
        pallas_corrections: pc,
        vesta_correction: vc,
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) fn archive(
    worker: &NativeFoldWorkerV1,
    preparation: &PreparationV1<'_>,
    prepared: &PreparedOperationV1,
    step: &ReleasedStep,
    predecessor: &FoldedStateV1,
    public: &mut KagemushaWalletLineagePublicV1,
    custody: &mut FoldCustodyV1<'_>,
    route: OperationRoute,
    cancellation: &Cancellation,
) -> Result<(ArchiveFoldFieldsV1, Option<IncomingSigma>), Error> {
    cancellation.check()?;
    let pallas_params = worker.installed.verifier().pallas_parameters();
    let vesta_params = proof(worker.installed.verifier().vesta_parameters(16))?;
    let fixed = proof(worker.sources.route(route))?;
    let QualifiedOperationOwnerV1::Archive(prover) = fixed.owner() else {
        return Err(Error::Proof("Archive source route"));
    };
    let original = retained(step, KagemushaWalletRetainedInputRoleV1::Credited)?;
    if original.is_empty() || original.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
        return Err(Error::Proof("Archive evidence bound"));
    }
    let credited: KagemushaWalletCreditedV1 = proof(norito::decode_canonical_with_limits(
        original,
        norito::canonical_decode_limits(original.len()),
    ))?;
    let transport = match &credited.evidence {
        KagemushaWalletCreditedEvidenceV1::Status { status } => Some(super::incoming::transport(
            pallas_params,
            vesta_params,
            fixed
                .candidate_omega()
                .ok_or(Error::Proof("Archive Omega source"))?,
            &status.lineage.bytes(),
            worker.budget,
            Some(cancellation.prover_token()),
        )?),
        KagemushaWalletCreditedEvidenceV1::Receive { .. } => None,
    };
    let initial = if let Some(t) = &transport {
        let (m, p, v) = super::incoming::status_modes(
            pallas_params,
            vesta_params,
            false,
            t,
            worker.budget,
            Some(cancellation.prover_token()),
        )?;
        ArchiveIncomingWitnessV1::Status(Box::new(status_witness(t, m, p, v)))
    } else {
        ArchiveIncomingWitnessV1::Receive(Box::new(IncomingMode::Trivial))
    };
    let adjusted = custody.pending_remove()?;
    let mut fields = proof(preparation.archive_fold_fields(
        prepared.owner(),
        step,
        predecessor,
        public,
        ArchiveFoldWitnessV1 {
            adjusted_pending: adjusted,
            incoming: initial,
            results: [false; 3],
        },
        worker.budget,
    ))?;
    let (receipt, sigma_slot_value, sigma_claim) = match &fields.evidence {
        archive::Evidence::Receive {
            statement,
            receipt,
            sigma,
            ..
        } => {
            let selector = route
                .incoming
                .ok_or(Error::Proof("Archive Receive selector"))?;
            let slot = sigma_slot(worker, selector, statement, sigma)?;
            let q = proof(worker.sources.q(route))?;
            let claim = proof(q.sigma().incoming_original_cancellable(
                &slot,
                selector,
                worker.budget,
                Some(cancellation.prover_token()),
            ))?;
            (receipt, Some(slot), claim)
        }
        archive::Evidence::Status { receipt, .. } => (receipt, None, None),
    };
    let signature = super::inputs::signature(
        ObjectKind::Receipt,
        receipt,
        super::inputs::key(&fields.retained.signed[3], 130)?,
    )?;
    let (pp, pv) = predecessor_claims(predecessor)?;
    let bits = proof(prover.propose_nonproof(archive::PredicateInputs {
        state: fields.state,
        own: fields.own.clone(),
        retained: fields.retained.clone(),
        evidence: fields.evidence.clone(),
        signature,
        predecessor_pallas: pp,
        predecessor_vesta: pv,
        incoming_selector: route.incoming,
    }))?;
    let results = [
        transport
            .as_ref()
            .map_or(sigma_claim.is_some(), |t| t.valid),
        bits[0],
        bits[1],
    ];
    let soft = results.iter().all(|v| *v);
    let (proposal, q_incoming, accepted) = if let Some(t) = transport {
        let (m, p, v) = super::incoming::status_modes(
            pallas_params,
            vesta_params,
            soft,
            &t,
            worker.budget,
            Some(cancellation.prover_token()),
        )?;
        (
            ArchiveIncomingWitnessV1::Status(Box::new(status_witness(&t, m, p, v))),
            None,
            soft && m == [IncomingMode::Accept; 3],
        )
    } else {
        let mode = super::incoming::sigma_mode(
            vesta_params,
            soft,
            sigma_claim.as_ref(),
            worker.budget,
            Some(cancellation.prover_token()),
        )?;
        (
            ArchiveIncomingWitnessV1::Receive(Box::new(mode)),
            Some(IncomingSigma {
                sigma: sigma_slot_value.ok_or(Error::Proof("Archive incoming sigma"))?,
                mode,
            }),
            soft && mode == IncomingMode::Accept,
        )
    };
    let KagemushaWalletEffectV1::ArchiveSent { credit_id, .. } =
        step.frozen.capsule.statement.effect
    else {
        return Err(Error::Proof("Archive credit"));
    };
    public.pending_outgoing_root = if accepted {
        proof(adjusted.verify(
            &predecessor.lineage().public.pending_outgoing_root,
            &credit_id,
        ))?
    } else {
        predecessor.lineage().public.pending_outgoing_root
    };
    fields = proof(preparation.archive_fold_fields(
        prepared.owner(),
        step,
        predecessor,
        public,
        ArchiveFoldWitnessV1 {
            adjusted_pending: adjusted,
            incoming: proposal,
            results,
        },
        worker.budget,
    ))?;
    Ok((fields, q_incoming))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incoming_sigma_fixed_view_keeps_original_length_and_zero_padding() {
        let original = (0_u8..96).collect::<Vec<_>>();
        for length in [0, 1, 31, 32, 63, 64, 65, 96] {
            let (view, declared) = sigma_view(&original[..length], 64).unwrap();
            assert_eq!(declared as usize, length);
            assert_eq!(&view[..length.min(64)], &original[..length.min(64)]);
            assert!(view[length.min(64)..].iter().all(|v| *v == 0));
        }
        assert!(sigma_view(&original, 0).is_err());
        assert!(sigma_view(&original, 63).is_err());
    }
    #[test]
    fn history_projection_retains_exact_path_and_rejects_noncanonical_atoms() {
        let leaf = KagemushaWalletIndexedLeafV1 {
            key: Fp::from(1).to_repr(),
            value: Fp::from(2).to_repr(),
            next_key: Fp::from(9).to_repr(),
        };
        let mut opening = KagemushaWalletIndexedOpeningV1 {
            slot: 17,
            siblings: core::array::from_fn(|i| Fp::from(i as u64).to_repr()),
        };
        let native = history(leaf, opening).unwrap();
        assert_eq!(native.leaf_slot, 17);
        assert_eq!(native.leaf.key, Fp::ONE);
        assert_eq!(native.leaf_siblings[31], Fp::from(31));
        opening.siblings[12] = [255; 32];
        assert!(history(leaf, opening).is_err());
        let mut invalid = leaf;
        invalid.value = [255; 32];
        assert!(history(invalid, opening).is_err());
    }
}
