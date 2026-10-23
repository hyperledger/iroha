//! Exact current carrier accounting, framing and one-shot ownership controls.

use super::*;

#[test]
fn claimed_qpcs_source_carrier_pins_exact_retention_and_local_work() {
    let ledger = RNS_NATIVE_CLAIMED_QPCS_SOURCE_CARRIER_LOCAL_RESOURCE_LEDGER_V2;
    assert_eq!(ledger.relations, 200);
    assert_eq!(ledger.retained_public_evaluation_bytes, 140_800);
    assert_eq!(ledger.retained_numeric_tail_bytes, 4_800);
    assert_eq!(ledger.retained_numeric_cache_bytes, 145_600);
    assert_eq!(ledger.retained_terminal_chronology_bytes, 6_264);
    assert_eq!(ledger.retained_commitment_digest_bytes, 2_016);
    assert_eq!(ledger.retained_payload_bytes, 153_880);
    assert_eq!(ledger.canonical_checks, 18_200);
    assert_eq!(ledger.ring_power_squarings, 3_400);
    assert_eq!(ledger.modular_multiplications, 3_600);
    assert_eq!(ledger.modular_additions, 200);
    assert_eq!(ledger.numeric_tail_retention_work_units, 4_800);
    assert_eq!(ledger.pre_binding_local_work_units, 28_816);
    assert_eq!(ledger.claimed_source_binding_hash_bytes, 5_444);
    assert_eq!(ledger.carrier_binding_hash_bytes, 2_382);
    assert_eq!(ledger.combined_binding_hash_bytes, 7_826);
    assert_eq!(ledger.local_work_units, 7_179_426);
    assert_eq!(ledger.binding_lane_permutations, 4_224);
    assert_eq!(ledger.binding_poseidon_rounds, 274_560);
    assert_eq!(ledger.binding_field_multiplications, 3_839_616);
    assert_eq!(ledger.binding_field_additions, 3_303_168);
    assert_eq!(
        ledger.local_work_units,
        ledger.pre_binding_local_work_units
            + u32::from(ledger.combined_binding_hash_bytes)
            + ledger.binding_field_multiplications
            + ledger.binding_field_additions
    );
    assert_eq!(ledger.new_heap_bytes, 0);
    assert_eq!(ledger.new_spool_bytes, 0);
    assert_eq!(ledger.new_wire_bytes, 0);
    assert_eq!(ledger.new_authenticated_io_bytes, 0);
}

#[test]
fn claimed_qpcs_source_carrier_keeps_every_downstream_gate_closed() {
    const {
        assert!(RNS_NATIVE_CLAIMED_QPCS_SOURCE_CARRIER_SOURCE_SETTLED_V2);
        assert!(RNS_NATIVE_CLAIMED_QPCS_SOURCE_CARRIER_CONTRACT_IMPLEMENTED_V2);
        assert!(RNS_NATIVE_CLAIMED_QPCS_SOURCE_PREFLIGHT_ORDER_IMPLEMENTED_V2);
        assert!(RNS_NATIVE_CLAIMED_QPCS_NUMERIC_TAIL_IMPLEMENTED_V2);
        assert!(RNS_NATIVE_CLAIMED_QPCS_CARRIER_LEDGER_IS_ADDITIVE_V2);
        assert!(!RNS_NATIVE_CLAIMED_QPCS_SOURCE_CARRIER_LIVE_INTEGRATED_V2);
        assert!(!RNS_NATIVE_CLAIMED_QPCS_PRE_QPCS_Q_MASK_INTEGRATED_V2);
        assert!(!RNS_NATIVE_CLAIMED_QPCS_PRE_DIRECT_AXES_INTEGRATED_V2);
        assert!(!RNS_NATIVE_CLAIMED_QPCS_DIRECT_RELATION_INTEGRATED_V2);
        assert!(!RNS_NATIVE_CLAIMED_QPCS_INVENTORY_MEMBERSHIP_INTEGRATED_V2);
        assert!(!RNS_NATIVE_CLAIMED_QPCS_GLOBAL_ROOT_DISCHARGED_V2);
        assert!(!RNS_NATIVE_CLAIMED_QPCS_DIRECT_OPENINGS_AVAILABLE_V2);
        assert!(!RNS_NATIVE_CLAIMED_QPCS_RESOURCE_EVIDENCE_QUALIFIED_V2);
        assert!(!RNS_NATIVE_CLAIMED_QPCS_READINESS_V2);
        assert!(!RNS_NATIVE_CLAIMED_QPCS_RELEASE_AUTHORIZED_V2);
    }
}

#[test]
fn merkle_and_initial_rebind_admission_precedes_public_read_on_same_owner() {
    let source = include_str!("claimed_qpcs_source_carrier_v2.rs");
    let admission = source
        .split_once("pub(super) fn admit_canonical_merkle_and_rebind_leaf_hash_work_v2")
        .expect("budget admission must be exposed only on the started owner")
        .1
        .split_once("impl<K, P, S> RnsNativeQpcsOpeningHashWorkAdmittedStartedV2")
        .expect("qPCS transition must require the admitted owner")
        .0;
    assert!(admission.contains("self.source.original_budget_mut_v1()"));
    assert!(admission.contains("for_canonical_merkle_and_rebind_leaf_hashes_v1"));
    assert!(admission.contains("work.admit_v1(budget)"));
    assert!(admission.contains("Err((self, RnsNativeClaimedQpcsSourceCarrierErrorV2::Qpcs))"));
    assert!(
        admission.contains("Ok(RnsNativeQpcsOpeningHashWorkAdmittedStartedV2 { started: self })")
    );
    assert!(!admission.contains("RnsNativeSingleQpcsScheduleBatchV2::begin_v2"));
    assert!(!admission.contains("authenticate_rns_native_qpcs_pre_auth_claimed_v1"));
}

#[test]
fn local_ledger_explicitly_excludes_existing_subtransition_costs() {
    let source = include_str!("claimed_qpcs_source_carrier_v2.rs");
    let ledger_docs = source
        .split_once("/// Exact additive accounting for the carrier-local work")
        .expect("additive ledger scope")
        .1
        .split_once("pub(super) struct RnsNativeClaimedQpcsSourceCarrierLocalResourceLedgerV2")
        .expect("ledger declaration boundary")
        .0
        .replace("///", "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(ledger_docs.contains("not end-to-end accounting"));
    assert!(ledger_docs.contains("3,520-object/200-evaluation public read"));
    assert!(ledger_docs.contains("complete qPCS/FRI work"));
    assert!(ledger_docs.contains("both confidential-source passes"));
    assert!(ledger_docs.contains("later numeric-cursor destination"));
    assert!(ledger_docs.contains("zero additive carrier-local"));
    assert!(ledger_docs.contains("4,800-byte"));
    assert!(ledger_docs.contains("retained inline"));
    assert!(ledger_docs.contains("28,816 before"));
    assert!(ledger_docs.contains("7,826 binding bytes"));
    assert!(ledger_docs.contains("7,179,426 total"));
    assert!(ledger_docs.contains("per canonical check, modular operation"));
    assert!(ledger_docs.contains("not an instruction count"));
    assert!(ledger_docs.contains("excludes control-flow comparisons"));
}

#[test]
fn consuming_transition_preserves_the_audited_one_shot_order() {
    let source = include_str!("claimed_qpcs_source_carrier_v2.rs");
    let transition = source
        .split_once("pub(super) fn authenticate_claimed_qpcs_source_carrier_v2")
        .expect("sealed consuming transition")
        .1
        .split_once("fn map_public_read_error_v2")
        .expect("transition boundary")
        .0;
    let begin = transition
        .find("RnsNativeSingleQpcsScheduleBatchV2::begin_v2")
        .unwrap();
    let read = transition.find("take_next_evaluation_v2").unwrap();
    let finish = transition.find("batch.finish_v2").unwrap();
    let prepare = transition
        .find("prepare_rns_native_qpcs_pre_auth_claimed_v1")
        .unwrap();
    let authenticate = transition
        .find("authenticate_rns_native_qpcs_pre_auth_claimed_v1")
        .unwrap();
    let preflight = transition
        .find("preflight_rns_native_qpcs_authenticated_claimed_source_v1")
        .unwrap();
    let materialize = transition
        .find("materialize_numeric_and_take_schedule_v1")
        .unwrap();
    assert!(begin < read);
    assert!(read < finish);
    assert!(finish < prepare);
    assert!(prepare < authenticate);
    assert!(authenticate < preflight);
    assert!(preflight < materialize);
    assert_eq!(transition.matches("take_next_evaluation_v2").count(), 1);
    assert_eq!(transition.matches("batch.finish_v2").count(), 1);
    assert_eq!(
        transition
            .matches("materialize_numeric_and_take_schedule_v1")
            .count(),
        1
    );
}

#[test]
fn source_preflight_precedes_numeric_materialization_and_schedule_take() {
    let qpcs_source = include_str!("../../../rns_native_qpcs_fri_complete.rs");
    let preflight = qpcs_source
        .split_once("pub(super) fn preflight_rns_native_qpcs_authenticated_claimed_source_v1")
        .expect("claimed source preflight")
        .1
        .split_once("fn map_claimed_source_preflight_error_v1")
        .expect("preflight boundary")
        .0;
    let schedule_before = preflight
        .find("if !qpcs.has_relation_schedule_v1()")
        .unwrap();
    let source_call = preflight
        .find("preflight_rns_native_rlwe_source_statement_v1")
        .unwrap();
    let schedule_after = preflight
        .find("if !source.qpcs().has_relation_schedule_v1()")
        .unwrap();
    assert!(schedule_before < source_call);
    assert!(source_call < schedule_after);

    let materialize = qpcs_source
        .split_once("pub(super) fn materialize_numeric_and_take_schedule_v1")
        .expect("numeric materialization")
        .1
        .split_once("fn claimed_source_numeric_binding_digest_v1")
        .expect("materialization boundary")
        .0;
    let validate = materialize
        .find("validate_claimed_source_numeric_tail_v1")
        .unwrap();
    let take = materialize.find("take_qpcs_relation_schedule_v1").unwrap();
    let scheduleless_check = materialize
        .find("if self.source.qpcs().has_relation_schedule_v1()")
        .unwrap();
    assert!(validate < take);
    assert!(take < scheduleless_check);
    assert_eq!(
        materialize
            .matches("take_qpcs_relation_schedule_v1")
            .count(),
        1
    );
}

#[test]
fn retained_owners_are_move_only_opaque_and_do_not_downgrade_chronology() {
    let carrier_source = include_str!("claimed_qpcs_source_carrier_v2.rs");
    let qpcs_source = include_str!("../../../rns_native_qpcs_fri_complete.rs");

    let numeric_tail = qpcs_source
        .split_once("pub(super) struct RnsNativeQpcsAuthenticatedNumericTailV1")
        .expect("authenticated numeric tail")
        .1
        .split_once("impl RnsNativeQpcsAuthenticatedNumericTailV1")
        .expect("numeric tail boundary")
        .0;
    assert!(numeric_tail.contains("a: u64"));
    assert!(numeric_tail.contains("product: u64"));
    assert!(numeric_tail.contains("opening_quotient: u64"));
    assert!(!numeric_tail.contains("point: u64"));

    let retained = carrier_source
        .split_once("struct RnsNativeClaimedQpcsRetainedPublicationV2")
        .expect("retained publication")
        .1
        .split_once("pub(in crate::vega::zk_ams::mkhe) struct RnsNativeClaimedQpcsOwnedStageV2")
        .expect("retained publication boundary")
        .0;
    assert!(retained.contains("owners: RnsNativeWholePublicationOwnersV2"));
    assert!(retained.contains("read_receipt: RnsNativePublicPolynomialReadReceiptV1"));
    assert!(retained.contains("facts: RnsNativePreTranscriptPublicStatementFactsV2"));
    assert!(retained.contains("equation_commitment_digests:"));
    assert!(retained.contains("limb_commitment_digests:"));
    assert!(retained.contains("carrier_binding_digest:"));

    let exact_stage = carrier_source
        .split_once("pub(in crate::vega::zk_ams::mkhe) struct RnsNativeClaimedQpcsOwnedStageV2")
        .expect("exact stage")
        .1
        .split_once("struct RnsNativeClaimedQpcsSourceStageV2")
        .expect("exact-stage boundary")
        .0;
    assert!(exact_stage.contains("retained: RnsNativeClaimedQpcsRetainedPublicationV2"));
    assert!(exact_stage.contains("stage: Stage"));
    assert!(!exact_stage.contains("pub retained:"));
    assert!(!exact_stage.contains("pub stage:"));

    let carrier = carrier_source
        .split_once("pub(super) struct RnsNativeClaimedQpcsSourceCarrierV2")
        .expect("top carrier")
        .1
        .split_once("impl<'qpcs, S:")
        .expect("top carrier boundary")
        .0;
    assert!(carrier.contains("owned: RnsNativeClaimedQpcsOwnedStageV2"));
    assert!(!carrier.contains("relation_schedule:"));
    assert!(!carrier.contains("terminal_chronology:"));
    assert!(!carrier.contains("derive(Clone"));
    assert!(!carrier.contains("derive(Copy"));

    let scheduleless = qpcs_source
        .split_once("pub(super) struct RnsNativeQpcsSchedulelessClaimedSourceV1")
        .expect("opaque scheduleless source")
        .1
        .split_once("}\n\n/// One move-only owner joining")
        .expect("scheduleless source boundary")
        .0;
    assert_eq!(scheduleless.matches("relation_schedule:").count(), 1);
    assert_eq!(scheduleless.matches("terminal_chronology:").count(), 1);
    assert_eq!(scheduleless.matches("numeric_tails:").count(), 1);
    assert!(!scheduleless.contains("RnsNativeQpcsCompletedLineageV1"));
    assert!(!scheduleless.contains("ZkAmsMkheRnsNativeChallengeSeedsV1"));
    assert!(!scheduleless.contains("ZkAmsMkheRnsNativeQpcsBoundTranscriptV1"));

    let input = carrier_source
        .split_once("pub(super) struct RnsNativeClaimedQpcsAuthenticationInputV2")
        .expect("fixed authentication input")
        .1
        .split_once("impl<'digests, 'proof> RnsNativeClaimedQpcsAuthenticationInputV2")
        .expect("authentication input boundary")
        .0;
    assert!(!input.contains("transcript:"));
    assert!(!carrier_source.contains("RnsNativeCrossFieldRlweClaimedRelationV1"));
    assert!(!carrier_source.contains("fn into_parts"));
    assert!(!carrier_source.contains("fn relation_schedule_v2"));
    assert!(!carrier_source.contains("fn terminal_chronology_v2"));
    assert!(!carrier_source.contains("fn roots_v2"));
}

#[test]
fn numeric_authority_moves_once_and_only_the_parent_sidecar_implements_the_cursor() {
    let carrier = include_str!("claimed_qpcs_source_carrier_v2.rs");
    let direct = include_str!("../../../rns_native_cross_field_rlwe_direct.rs");

    assert!(!carrier.contains("RnsNativeCrossFieldNumericCursorV1\n    for RnsNativeClaimed"));
    let origin = carrier
        .split_once("pub(super) fn into_claimed_successor_stage_v2")
        .expect("sole origin transition")
        .1
        .split_once("impl<K, P, S>")
        .expect("origin boundary")
        .0;
    let mint = origin
        .find("RnsNativeClaimedDirectNumericOriginV2::mint_v2(")
        .unwrap();
    let move_into_parent = origin.find(".into_claimed_successor_stage_v2(").unwrap();
    assert!(mint < move_into_parent);

    let token_mint = carrier
        .split_once("fn mint_v2(")
        .expect("private origin mint")
        .1
        .split_once("pub(in crate::vega::zk_ams::mkhe) fn is_fresh_v2")
        .expect("private origin mint boundary")
        .0;
    let fresh = token_mint.find("cursor.next_relation != 0").unwrap();
    let exact_array = token_mint.find(".try_into()").unwrap();
    let retained_binding = token_mint
        .find("RnsNativeClaimedQpcsRetainedPublicationOriginBindingV2")
        .unwrap();
    assert!(fresh < exact_array && exact_array < retained_binding);

    let token_cursor = carrier
        .split_once("fn take_public_evaluation_v2(")
        .expect("numeric origin cursor")
        .1
        .split_once("fn is_complete_v2")
        .expect("numeric origin cursor boundary")
        .0;
    let poison = token_cursor.find("self.poisoned = true").unwrap();
    let order = token_cursor
        .find("limb != relation / REPETITIONS_V2")
        .unwrap();
    let public = token_cursor.find(".public_evaluations").unwrap();
    let commit = token_cursor.find("self.poisoned = false").unwrap();
    assert!(poison < order && order < public && public < commit);

    let sidecar = direct
        .split_once(
            "impl RnsNativeCrossFieldNumericCursorV1 for RnsNativeCrossFieldRlweNumericSidecarV2",
        )
        .expect("numeric sidecar cursor")
        .1
        .split_once("/// Authenticated public-point source")
        .expect("numeric sidecar boundary")
        .0;
    let clear = sidecar
        .find("*destination = RnsNativeCrossFieldNumericEvaluationV1::default()")
        .unwrap();
    let consume_origin = sidecar
        .find("self.origin.take_public_evaluation_v2(limb, repetition)")
        .unwrap();
    assert!(clear < consume_origin);
    assert!(direct.contains("if !numeric_sidecar.is_complete_v2()"));
    let direct_origin = direct
        .split_once("pub(super) fn into_claimed_successor_stage_v2(")
        .expect("direct origin consumer")
        .1
        .split_once("/// Opaque core")
        .expect("direct origin consumer boundary")
        .0;
    assert!(direct_origin.contains("numeric_origin: RnsNativeClaimedDirectNumericOriginV2"));
    assert!(!direct_origin.contains("Box<[RnsNativePublicPolynomialEvaluationV1"));
    assert!(!direct_origin.contains("next_relation:"));
    assert!(!direct_origin.contains("poisoned:"));
}

#[test]
fn exact_stage_wrapper_has_only_purpose_specific_forward_transitions() {
    let source = include_str!("claimed_qpcs_source_carrier_v2.rs");
    for transition in [
        "verify_comparator_product_v2",
        "verify_comparator_range_carry_v2",
        "verify_small_sign_disjointness_v2",
        "verify_q_mask_linear_relations_v2",
        "authenticate_existing_radix_v2",
        "verify_radix_complement_v2",
        "verify_centering_subtraction_v2",
        "derive_global_lookup_pre_z_v2",
        "authenticate_global_lookup_post_z_v2",
        "verify_global_inverse_product_v2",
        "verify_global_membership_v2",
        "verify_direct_global_membership_handoff_v2",
        "verify_source_packing_same_opening_v2",
        "verify_composite_v2",
    ] {
        assert!(source.contains(transition), "missing {transition}");
    }
    assert!(!source.contains("fn map_stage"));
    assert!(!source.contains("fn into_parts"));
    assert!(!source.contains("fn retained_publication"));
}

#[test]
fn final_claimed_qpcs_owner_consumes_the_context_directly_into_atomic_verification() {
    let source = include_str!("claimed_qpcs_source_carrier_v2.rs");
    let terminal = source
        .split_once("fn verify_composite_v2(")
        .expect("consuming composite terminal seam")
        .1
        .split_once("impl<'proof, Stage>")
        .expect("terminal seam boundary")
        .0;

    let split_owner = terminal
        .find("let Self { retained, stage } = self")
        .unwrap();
    let retain_authority = terminal
        .find("RnsNativeQpcsCompositeAuthorityV2 { retained, envelope }")
        .unwrap();
    let mint_context = terminal.find(".into_composite_context_v2(").unwrap();
    let map_handoff = terminal
        .find("RnsNativeClaimedQpcsCompositeVerificationErrorV2::Handoff")
        .unwrap();
    let verify = terminal
        .find("verify_zk_ams_mkhe_rns_native_composite_from_source_chain_v2(input)")
        .unwrap();
    let map_verification = terminal
        .find("RnsNativeClaimedQpcsCompositeVerificationErrorV2::CompositeVerification")
        .unwrap();

    assert!(split_owner < retain_authority);
    assert!(retain_authority < mint_context);
    assert!(mint_context < map_handoff);
    assert!(map_handoff < verify);
    assert!(verify < map_verification);
    assert_eq!(terminal.matches(".into_composite_context_v2(").count(), 1);
    assert_eq!(
        terminal
            .matches("verify_zk_ams_mkhe_rns_native_composite_from_source_chain_v2(input)")
            .count(),
        1
    );
    assert!(terminal.contains("ZkAmsMkheRnsNativeCompositeCandidateReceiptV1"));
    assert!(terminal.contains("RnsNativeClaimedQpcsCompositeVerificationErrorV2"));
    assert!(!source.contains("RnsNativeCrossFieldRlweCompositeInputV2"));
    assert!(!source.contains("fn into_parts"));
}

fn assert_exact_composite_transition_error_v2(
    error: RnsNativeDirectGlobalMembershipCompositeTransitionErrorV2,
) {
    match error {
        RnsNativeDirectGlobalMembershipCompositeTransitionErrorV2::SourcePacking(_) => {}
        RnsNativeDirectGlobalMembershipCompositeTransitionErrorV2::CompositeContext(_) => {}
    }
}

#[test]
fn composite_terminal_error_keeps_exact_transition_and_verification_failures_distinct() {
    let source_packing_transition = RnsNativeDirectGlobalMembershipCompositeTransitionErrorV2::from(
        RnsNativeSourcePackingSameOpeningErrorV1::InvalidContext,
    );
    let composite_context_transition =
        RnsNativeDirectGlobalMembershipCompositeTransitionErrorV2::from(
            RnsNativeCrossFieldRlweDirectErrorV1::InvalidContext,
        );
    assert_exact_composite_transition_error_v2(source_packing_transition);
    assert_exact_composite_transition_error_v2(composite_context_transition);

    let source_packing =
        RnsNativeClaimedQpcsCompositeVerificationErrorV2::Handoff(source_packing_transition);
    let composite_context =
        RnsNativeClaimedQpcsCompositeVerificationErrorV2::Handoff(composite_context_transition);
    let verification = RnsNativeClaimedQpcsCompositeVerificationErrorV2::CompositeVerification(
        ZkAmsMkheRnsNativeCompositeVerificationErrorV1::InvalidTranscript,
    );

    assert_eq!(
        source_packing,
        RnsNativeClaimedQpcsCompositeVerificationErrorV2::Handoff(
            RnsNativeDirectGlobalMembershipCompositeTransitionErrorV2::SourcePacking(
                RnsNativeSourcePackingSameOpeningErrorV1::InvalidContext,
            ),
        )
    );
    assert_eq!(
        composite_context,
        RnsNativeClaimedQpcsCompositeVerificationErrorV2::Handoff(
            RnsNativeDirectGlobalMembershipCompositeTransitionErrorV2::CompositeContext(
                RnsNativeCrossFieldRlweDirectErrorV1::InvalidContext,
            ),
        )
    );
    assert_eq!(
        verification,
        RnsNativeClaimedQpcsCompositeVerificationErrorV2::CompositeVerification(
            ZkAmsMkheRnsNativeCompositeVerificationErrorV1::InvalidTranscript,
        )
    );
    assert_ne!(source_packing, composite_context);
    assert_ne!(source_packing, verification);
    assert_ne!(composite_context, verification);
}

#[test]
fn final_composite_transition_type_excludes_earlier_root_failures() {
    let carrier = include_str!("claimed_qpcs_source_carrier_v2.rs");
    let terminal_error = carrier
        .split_once("enum RnsNativeClaimedQpcsCompositeVerificationErrorV2")
        .and_then(|(_, suffix)| suffix.split_once("impl fmt::Display"))
        .map(|(terminal_error, _)| terminal_error)
        .expect("terminal error declaration");
    assert!(terminal_error.contains("RnsNativeDirectGlobalMembershipCompositeTransitionErrorV2"));
    assert!(!terminal_error.contains("RnsNativeDirectGlobalMembershipHandoffErrorV1"));

    let handoff = include_str!("../../../rns_native_direct_global_membership_handoff.rs");
    let transition = handoff
        .split_once("RnsNativeSourcePackingCompositeTransitionV2<'proof, 'envelope>")
        .and_then(|(_, suffix)| suffix.split_once("fn map_source_replay_error_v2"))
        .map(|(transition, _)| transition)
        .expect("concrete final composite transition");
    assert!(
        transition
            .contains("type Error = RnsNativeDirectGlobalMembershipCompositeTransitionErrorV2")
    );
    assert_eq!(
        transition
            .matches("RnsNativeDirectGlobalMembershipCompositeTransitionErrorV2::from")
            .count(),
        2
    );
    assert!(!transition.contains("GlobalLookupRoot"));
    assert!(!transition.contains("ZeroPaddingRoot"));
}

fn carrier_test_axes_v1() -> (
    CarrierBindingContextV1,
    [ProofDigestV1; 2],
    [ProofDigestV1; 40],
) {
    let proof = |index| {
        crate::vega::zk_ams::mkhe::rns_native_proof_hash::test_proof_digest_v1(b"carrier", index)
    };
    (
        CarrierBindingContextV1 {
            public: core::array::from_fn(|i| [i as u8 + 1; 32]),
            native: [proof(0), proof(1)],
            objects: 3_520,
            counters: [123, 456, 789, 1011],
        },
        [proof(2), proof(3)],
        core::array::from_fn(|i| proof(i as u64 + 4)),
    )
}

#[test]
fn carrier_binding_replays_the_exact_current_mixed_role_frame() {
    let (axes, equations, limbs) = carrier_test_axes_v1();
    let mut fields = vec![
        CARRIER_BINDING_DOMAIN_V1.to_vec(),
        vec![1],
        40_u16.to_be_bytes().to_vec(),
        5_u16.to_be_bytes().to_vec(),
        43_u16.to_be_bytes().to_vec(),
        200_u16.to_be_bytes().to_vec(),
        axes.public[0].to_vec(),
        axes.public[1].to_vec(),
        axes.native[0].as_bytes().to_vec(),
        axes.public[2].to_vec(),
        axes.public[3].to_vec(),
        axes.public[4].to_vec(),
        axes.objects.to_be_bytes().to_vec(),
    ];
    fields.extend(axes.counters.map(|n| n.to_be_bytes().to_vec()));
    fields.push(axes.native[1].as_bytes().to_vec());
    fields.extend(
        equations
            .into_iter()
            .chain(limbs)
            .map(|digest| digest.as_bytes().to_vec()),
    );
    assert_eq!(fields.len(), 60);
    assert_eq!(fields.iter().map(Vec::len).sum::<usize>(), 2_382);
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    let context = RnsNativeProofHashContextV1::canonical().unwrap();
    let frame = context
        .frame(
            RnsNativeProofHashRoleV1::Transcript,
            RnsNativeProofHashPhaseV1::Binding,
            RnsNativeProofHashPositionV1 {
                level: 7,
                index: 0,
                counter: 0,
            },
            &refs,
        )
        .unwrap();
    assert_eq!(
        RnsNativeProofHashWorkV1::from_frame(&frame).unwrap(),
        CARRIER_BINDING_HASH_WORK_V1
    );
    assert_eq!(
        carrier_binding_hash_v1(axes, &equations, &limbs).unwrap(),
        ProofDigestV1::from_shared(frame.hash())
    );
}

#[test]
fn carrier_binding_binds_every_current_axis_and_every_native_lane() {
    let (axes, equations, limbs) = carrier_test_axes_v1();
    let original = carrier_binding_hash_v1(axes, &equations, &limbs).unwrap();
    for field in 0..5 {
        let mut changed = axes;
        changed.public[field][31] ^= 1;
        assert_ne!(
            carrier_binding_hash_v1(changed, &equations, &limbs).unwrap(),
            original
        );
        changed.public[field] = [0; 32];
        assert!(carrier_binding_hash_v1(changed, &equations, &limbs).is_err());
    }
    for field in 0..4 {
        let mut changed = axes;
        changed.counters[field] += 1;
        assert_ne!(
            carrier_binding_hash_v1(changed, &equations, &limbs).unwrap(),
            original
        );
    }
    let mut changed = axes;
    changed.objects += 1;
    assert_ne!(
        carrier_binding_hash_v1(changed, &equations, &limbs).unwrap(),
        original
    );
    for field in 0..44 {
        for lane in 0..6 {
            let (mut changed, mut changed_equations, mut changed_limbs) = (axes, equations, limbs);
            let digest = match field {
                0..2 => &mut changed.native[field],
                2..4 => &mut changed_equations[field - 2],
                _ => &mut changed_limbs[field - 4],
            };
            let mut bytes = digest.to_le_bytes();
            let word = u64::from_le_bytes(bytes[lane * 8..lane * 8 + 8].try_into().unwrap());
            bytes[lane * 8..lane * 8 + 8]
                .copy_from_slice(&((word + 1) % fastpq_isi::poseidon::FIELD_MODULUS).to_le_bytes());
            *digest = ProofDigestV1::from_le_bytes(bytes).unwrap();
            assert_ne!(
                carrier_binding_hash_v1(changed, &changed_equations, &changed_limbs).unwrap(),
                original,
                "field{field} lane{lane}"
            );
        }
        let (mut changed, mut changed_equations, mut changed_limbs) = (axes, equations, limbs);
        match field {
            0..2 => changed.native[field] = ProofDigestV1::ZERO,
            2..4 => changed_equations[field - 2] = ProofDigestV1::ZERO,
            _ => changed_limbs[field - 4] = ProofDigestV1::ZERO,
        }
        assert!(carrier_binding_hash_v1(changed, &changed_equations, &changed_limbs).is_err());
    }
    let mut swapped = equations;
    swapped.swap(0, 1);
    assert_ne!(
        carrier_binding_hash_v1(axes, &swapped, &limbs).unwrap(),
        original
    );
    let mut swapped = limbs;
    swapped.swap(0, 39);
    assert_ne!(
        carrier_binding_hash_v1(axes, &equations, &swapped).unwrap(),
        original
    );
}
