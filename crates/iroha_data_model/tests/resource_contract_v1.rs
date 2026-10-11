//! Exact-limit and one-over checks of the committed bounds in `specs/zk_resource_contract.json`.
//!
//! These are the predicates SDK preflight shares with node admission. This is a separate
//! target so it does not depend on the large internal unit suite.

use core::num::{NonZeroU32, NonZeroU64};

use iroha_data_model::{
    parameter::{
        Parameter, Parameters,
        system::{
            BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES, IVM_HEAP_MAX_BYTES,
            LANE_BATCH_FRAMING_RESERVE_BYTES, SumeragiParameter, TransactionInclusionRoute,
            TransactionNeverIncludable, max_includable_transaction_bytes,
        },
    },
    privacy::{
        PrivacyConsensusLimitsV1, PrivacyConsensusLimitsValidationError, PrivacyLimitFieldV1,
        PrivacyProofBytesV1, PrivacyProofValidationError, PrivacyZkX509CrlUpdateIntervalV1,
        PrivacyZkX509PresentationBoundsV1, PrivacyZkX509PresentationIntervalErrorV1,
        PrivacyZkX509PresentationWindowV1, TAIRA_PRIVACY_MAX_ACTION_BYTES_V1,
        TAIRA_PRIVACY_MAX_BYTES_PER_BLOCK_V1, TAIRA_PRIVACY_MAX_BYTES_PER_TRANSACTION_V1,
        TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1, ZK_X509_MAX_CRL_AGE_SECONDS_V1,
        ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1,
    },
    proof::{
        PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1,
        PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1, PROOF_BOX_MAX_ENCODED_BYTES_V1,
        ProofAttachment, ProofAttachmentList, ProofAttachmentListError, ProofBox, VerifyingKeyId,
        proof_box_max_proof_bytes_v1,
    },
    sumeragi_finality::{CHAIN_TRANSPORT_FRAME_LIMIT, ChainParamsRecord},
    transaction::executable::{ContractArgumentRecord, MAX_CONTRACT_ARGUMENT_RECORD_BYTES},
};
use iroha_sumeragi::{
    api::ConfigError,
    availability::{
        LayoutError, MAX_DA_CHUNK_COUNT, MAX_DA_CHUNK_SIZE_BYTES, MAX_DA_ENCODED_PAYLOAD_BYTES,
        MAX_DA_PAYLOAD_SIZE_BYTES, recommended_data_availability_layout,
    },
    pacemaker::FRAME_OVERHEAD,
};

const MIB: u64 = 1024 * 1024;
/// The zk-X509 proof ceiling the delivery plan keeps fixed.
const X509_PROOF_CEILING_BYTES: u64 = 9_437_184;
/// The signed-transaction cap the delivery plan keeps fixed.
const TRANSACTION_CAP_BYTES: u64 = 10_485_760;

fn with_max_block_bytes(bytes: u32) -> Parameters {
    let mut parameters = Parameters::default();
    parameters.set_parameter(Parameter::Sumeragi(SumeragiParameter::MaxBlockBytes(
        NonZeroU32::new(bytes).expect("nonzero payload limit"),
    )));
    parameters
}

#[test]
fn committed_defaults_are_the_values_the_contract_records() {
    let parameters = Parameters::default();
    let transaction = parameters.transaction();
    assert_eq!(transaction.max_tx_bytes().get(), TRANSACTION_CAP_BYTES);
    assert_eq!(
        transaction.max_decompressed_bytes().get(),
        TRANSACTION_CAP_BYTES
    );
    assert_eq!(transaction.max_signatures().get(), 16);
    assert_eq!(transaction.max_instructions().get(), 100_000);
    assert_eq!(transaction.ivm_bytecode_size().get(), 4 * MIB);
    assert_eq!(transaction.max_metadata_depth().get(), 8);
    assert_eq!(transaction.max_time_to_live_ms().get(), 86_400_000);
    assert_eq!(parameters.sumeragi().max_block_bytes().get(), 4_194_304);
    assert_eq!(parameters.sumeragi().exec_budget_ms().get(), 4_000);
    assert_eq!(parameters.sumeragi().apply_budget_ms().get(), 1_000);
    assert_eq!(parameters.block().max_transactions().get(), 512);
    let contract = parameters.smart_contract();
    assert_eq!(contract.fuel().get(), 55_000_000);
    assert_eq!(contract.memory().get(), MIB);
    assert_eq!(contract.memory().get(), IVM_HEAP_MAX_BYTES);
    assert_eq!(contract.execution_depth(), 3);
    assert_eq!(contract.max_output_items().get(), 4_096);
    assert_eq!(contract.max_output_bytes().get(), 8 * MIB);
    assert_eq!(BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES, 65_536);
    assert_eq!(LANE_BATCH_FRAMING_RESERVE_BYTES, 64);
}

/// SDK preflight: the largest includable transaction is accepted and one byte more is not.
#[test]
fn includable_transaction_bound_accepts_the_limit_and_rejects_one_over() {
    let parameters = Parameters::default();
    let route = TransactionInclusionRoute::Global;
    // Today's defaults: the 4 MiB payload less the proposer's reserve is below the 10 MiB cap.
    let limit = parameters.max_includable_transaction_bytes(route);
    assert_eq!(limit, 4_194_304 - 65_536);
    assert_eq!(
        parameters.check_signed_transaction_bytes(limit, route),
        Ok(())
    );
    assert_eq!(
        parameters.check_signed_transaction_bytes(limit + 1, route),
        Err(TransactionNeverIncludable {
            encoded_bytes: limit + 1,
            max_bytes: limit,
        })
    );
    // The relation X.2 must establish: with a 16 MiB payload the transaction cap is the bound.
    let target = with_max_block_bytes(16 * 1024 * 1024);
    assert_eq!(
        target.max_includable_transaction_bytes(route),
        TRANSACTION_CAP_BYTES
    );
    assert_eq!(
        target.check_signed_transaction_bytes(TRANSACTION_CAP_BYTES, route),
        Ok(())
    );
    assert!(
        target
            .check_signed_transaction_bytes(TRANSACTION_CAP_BYTES + 1, route)
            .is_err()
    );
}

#[test]
fn includable_transaction_bound_takes_the_larger_proposer_budget() {
    let cap = NonZeroU64::new(TRANSACTION_CAP_BYTES).unwrap();
    let global = NonZeroU32::new(4_194_304).unwrap();
    let lane = |bytes: u32| TransactionInclusionRoute::NativeLane {
        max_block_bytes: NonZeroU32::new(bytes).unwrap(),
    };
    // A lane proposer that fits more than the global one raises the bound, up to the cap.
    assert_eq!(
        max_includable_transaction_bytes(cap, global, lane(8 * 1024 * 1024)),
        8 * MIB - 64
    );
    assert_eq!(
        max_includable_transaction_bytes(cap, global, lane(16 * 1024 * 1024)),
        TRANSACTION_CAP_BYTES
    );
    // A smaller lane payload never lowers what the global proposer can select.
    assert_eq!(
        max_includable_transaction_bytes(cap, global, lane(1_024)),
        4_194_304 - 65_536
    );
    // No payload room at all: nothing is includable, and the subtraction does not wrap.
    let tiny = NonZeroU32::new(1).unwrap();
    assert_eq!(
        max_includable_transaction_bytes(cap, tiny, TransactionInclusionRoute::Global),
        0
    );
    assert_eq!(max_includable_transaction_bytes(cap, tiny, lane(64)), 0);
    assert_eq!(max_includable_transaction_bytes(cap, tiny, lane(65)), 1);
    let parameters = with_max_block_bytes(1);
    assert_eq!(
        parameters.check_signed_transaction_bytes(1, TransactionInclusionRoute::Global),
        Err(TransactionNeverIncludable {
            encoded_bytes: 1,
            max_bytes: 0,
        })
    );
}

/// The SDK predicate takes the route. A lane payload above the global one raises the bound of
/// a transaction routed to that lane only: the same length routed to lane zero is refused, as
/// queue admission refuses it.
#[test]
fn includable_transaction_bound_follows_the_route() {
    let parameters = Parameters::default();
    let global = parameters.max_includable_transaction_bytes(TransactionInclusionRoute::Global);
    let lane_payload = NonZeroU32::new(8 * 1024 * 1024).unwrap();
    let native = TransactionInclusionRoute::NativeLane {
        max_block_bytes: lane_payload,
    };
    let lane = u64::from(lane_payload.get() - LANE_BATCH_FRAMING_RESERVE_BYTES);
    assert!(lane > global);
    assert_eq!(parameters.max_includable_transaction_bytes(native), lane);
    // Above the global budget, up to the lane budget: includable on the lane route only.
    for bytes in [global + 1, lane] {
        assert_eq!(
            parameters.check_signed_transaction_bytes(bytes, native),
            Ok(())
        );
        assert_eq!(
            parameters.check_signed_transaction_bytes(bytes, TransactionInclusionRoute::Global),
            Err(TransactionNeverIncludable {
                encoded_bytes: bytes,
                max_bytes: global,
            })
        );
    }
    // One byte over the lane budget is refused on both routes.
    assert_eq!(
        parameters.check_signed_transaction_bytes(lane + 1, native),
        Err(TransactionNeverIncludable {
            encoded_bytes: lane + 1,
            max_bytes: lane,
        })
    );
    // The global bound is a sufficient condition on every route.
    assert_eq!(
        parameters.check_signed_transaction_bytes(global, native),
        Ok(())
    );
    // A lane payload below the global one never lowers the bound of its route.
    let small = TransactionInclusionRoute::NativeLane {
        max_block_bytes: NonZeroU32::new(1_024).unwrap(),
    };
    assert_eq!(parameters.max_includable_transaction_bytes(small), global);
}

/// The proof ceiling is inclusive: exactly 9,437,184 bytes pass and one more byte fails.
#[test]
fn privacy_proof_ceiling_accepts_the_limit_and_rejects_one_over() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    assert_eq!(
        u64::from(limits.max_proof_bytes_per_action),
        X509_PROOF_CEILING_BYTES
    );
    assert_eq!(
        u64::from(TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1),
        X509_PROOF_CEILING_BYTES
    );
    let exact = usize::try_from(X509_PROOF_CEILING_BYTES).unwrap();
    let mut proof = PrivacyProofBytesV1::new(vec![0xA5; exact]);
    assert_eq!(proof.validate(&limits), Ok(()));
    proof.bytes.push(0xA5);
    assert_eq!(
        proof.validate(&limits),
        Err(PrivacyProofValidationError::TooLarge {
            bytes: X509_PROOF_CEILING_BYTES + 1,
            max: TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1,
        })
    );
}

/// Today's privacy profile and the relations it does and does not satisfy.
#[test]
fn privacy_limits_keep_their_order_and_record_the_open_envelope_relation() {
    let limits = PrivacyConsensusLimitsV1::taira_default();
    assert_eq!(limits.validate(), Ok(()));
    assert_eq!(limits.max_action_bytes, TAIRA_PRIVACY_MAX_ACTION_BYTES_V1);
    assert_eq!(
        limits.max_privacy_bytes_per_transaction,
        TAIRA_PRIVACY_MAX_BYTES_PER_TRANSACTION_V1
    );
    assert_eq!(
        limits.max_privacy_bytes_per_block,
        TAIRA_PRIVACY_MAX_BYTES_PER_BLOCK_V1
    );
    // A proof bound above the action bound is an invalid policy: one over is rejected.
    let mut inverted = limits;
    inverted.max_action_bytes = limits.max_proof_bytes_per_action - 1;
    assert_eq!(
        inverted.validate(),
        Err(PrivacyConsensusLimitsValidationError::InconsistentOrder {
            smaller_field: PrivacyLimitFieldV1::ProofBytesPerAction,
            smaller_value: limits.max_proof_bytes_per_action,
            larger_field: PrivacyLimitFieldV1::ActionBytes,
            larger_value: limits.max_proof_bytes_per_action - 1,
        })
    );
    // No field may exceed its hard ceiling: one over is rejected.
    let mut raised = limits;
    raised.max_proof_bytes_per_action += 1;
    assert_eq!(
        raised.validate(),
        Err(PrivacyConsensusLimitsValidationError::ExceedsHardMaximum {
            field: PrivacyLimitFieldV1::ProofBytesPerAction,
            value: TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1 + 1,
            hard_max: TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1,
        })
    );
    // Open relation recorded by the contract (owner X.2): the action bound equals the proof
    // bound, so the Norito frame of a ceiling-sized proof alone is already larger than the
    // action bound, and the per-block privacy bound is larger than today's block payload.
    assert_eq!(limits.max_action_bytes, limits.max_proof_bytes_per_action);
    let ceiling = usize::try_from(X509_PROOF_CEILING_BYTES).unwrap();
    let framed = norito::to_bytes(&PrivacyProofBytesV1::new(vec![0xA5; ceiling])).unwrap();
    assert!(framed.len() as u64 > u64::from(limits.max_action_bytes));
    assert!(
        u64::from(limits.max_privacy_bytes_per_block)
            > u64::from(Parameters::default().sumeragi().max_block_bytes().get())
    );
}

/// The proof-box codec ceiling is inclusive on the canonical encoding.
#[test]
fn proof_box_codec_ceiling_accepts_the_limit_and_rejects_one_over() {
    let backend = "fastpq";
    let largest = proof_box_max_proof_bytes_v1(backend).expect("backend fits the codec ceiling");
    let mut proof = ProofBox::new(backend.into(), vec![0; largest]);
    let exact = proof.canonical_encoded_len_v1().expect("exact length");
    assert!(exact <= PROOF_BOX_MAX_ENCODED_BYTES_V1);
    proof.bytes.push(0);
    assert!(
        proof
            .canonical_encoded_len_v1()
            .is_none_or(|length| length > PROOF_BOX_MAX_ENCODED_BYTES_V1)
    );
    // The codec ceiling is above every chain bound, so it never decides admission.
    assert!(PROOF_BOX_MAX_ENCODED_BYTES_V1 as u64 > TRANSACTION_CAP_BYTES);
    assert!(largest as u64 > X509_PROOF_CEILING_BYTES);
}

/// A signed transaction carries proofs as signed attachment occurrences. One occurrence holds
/// exactly the zk-X509 proof ceiling, the complete attachment frame is bounded by that ceiling
/// plus a 64 KiB allowance, and the complete signed transaction with a ceiling-sized proof is
/// within the transaction cap: relation `attachment_list_frame_holds_a_ceiling_proof` of the
/// contract. Count and bytes are independent bounds, all inclusive.
#[test]
fn signed_attachment_bounds_accept_the_limit_and_reject_one_over() {
    use iroha_data_model::transaction::{
        SignedAttachmentErrorV1, SignedAttachmentPlanV1, SignedAttachmentsV1,
        signed_attachments::{
            ActionAuthorityBindingV1, ActionInvocationBindingV1, ActionOperationV1,
            ActionPublicInputsDigestV1, ActionRoleV1, AttachmentKindV1, AttachmentRoleV1,
            OrderedIntentDigestV1, PlannedActionV1, PlannedAttachmentV1,
            SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1, SIGNED_ATTACHMENTS_MAX_ACTIONS_V1,
            SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1, SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1,
        },
    };
    assert_eq!(
        SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1 as u64,
        X509_PROOF_CEILING_BYTES
    );
    assert_eq!(
        SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1 as u64,
        X509_PROOF_CEILING_BYTES + 64 * 1024
    );
    assert!(SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1 as u64 <= TRANSACTION_CAP_BYTES);
    assert_eq!(SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1, 16);
    assert_eq!(SIGNED_ATTACHMENTS_MAX_ACTIONS_V1, 16);

    let contract_subject = iroha_data_model::account::AccountId::new(
        iroha_crypto::KeyPair::from_seed(vec![0x41; 32], iroha_crypto::Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    // One native action issued by a contract, with the given proof occurrences.
    let with_proofs = |proofs: Vec<Vec<u8>>| -> SignedAttachmentsV1 {
        let mut plan = SignedAttachmentPlanV1::new();
        plan.push_action(PlannedActionV1 {
            operation: ActionOperationV1::NativeInstruction("iroha.privacy.submit_proof.v1".into()),
            role: ActionRoleV1::ProofEffect,
            authority: ActionAuthorityBindingV1::ContractSubject(contract_subject.clone()),
            invocation: ActionInvocationBindingV1::Contract {
                root_index: 0,
                call_path: Vec::new(),
            },
            public_inputs_digest: ActionPublicInputsDigestV1::new([0x5a; 32]),
            attachments: proofs
                .into_iter()
                .map(|bytes| PlannedAttachmentV1 {
                    kind: AttachmentKindV1::Proof,
                    role: AttachmentRoleV1::ActionProof,
                    bytes,
                })
                .collect(),
        });
        let mut declared = plan.declare();
        declared
            .bind_statements_v1(OrderedIntentDigestV1::new([0x11; 32]))
            .expect("bound statements");
        declared
    };

    // A ceiling-sized proof is one occurrence; one byte more is not.
    let ceiling = usize::try_from(X509_PROOF_CEILING_BYTES).unwrap();
    let at_ceiling = with_proofs(vec![vec![0x5a; ceiling]]);
    at_ceiling
        .validate_v1()
        .expect("a ceiling-sized proof is carriable");
    let frame = norito::encode_canonical(&at_ceiling).expect("canonical frame");
    assert!(frame.len() <= SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1);
    assert!((frame.len() as u64) < TRANSACTION_CAP_BYTES);
    assert_eq!(
        norito::decode_canonical::<SignedAttachmentsV1>(&frame).expect("the bound itself decodes"),
        at_ceiling
    );
    let over = with_proofs(vec![vec![0x5a; ceiling + 1]]);
    assert_eq!(
        over.validate_v1(),
        Err(SignedAttachmentErrorV1::OccurrenceTooLarge {
            index: 0,
            actual: ceiling + 1,
            maximum: ceiling,
        })
    );
    assert!(
        norito::decode_canonical::<SignedAttachmentsV1>(
            &norito::encode_canonical(&over).expect("canonical frame")
        )
        .is_err()
    );

    // Count: sixteen occurrences are carried, seventeen are not.
    let distinct = |count: usize| {
        (0..count)
            .map(|slot| vec![slot as u8, 1, 2])
            .collect::<Vec<_>>()
    };
    with_proofs(distinct(SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1))
        .validate_v1()
        .expect("sixteen occurrences");
    assert_eq!(
        with_proofs(distinct(SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1 + 1)).validate_v1(),
        Err(SignedAttachmentErrorV1::TooManyOccurrences {
            actual: SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1 + 1,
            maximum: SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1,
        })
    );

    // Bytes are bounded independently of the count: two occurrences that
    // together exceed the frame bound are refused although each is admissible.
    let two = with_proofs(vec![vec![0x5a; ceiling], vec![0xa5; ceiling]]);
    assert!(matches!(
        two.validate_v1(),
        Err(SignedAttachmentErrorV1::FrameTooLarge { actual, maximum })
            if actual > maximum && maximum == SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1
    ));
}

/// The bounded proof attachment list is the body format of Torii's non-consensus prover API
/// and a staging container of SDK builders; it is not a signed-transaction field. It is bounded
/// in count and in its complete canonical frame, both inclusive, and stays below the zk-X509
/// proof ceiling, which travels as a signed attachment occurrence instead.
#[test]
fn attachment_list_bounds_accept_the_limit_and_reject_one_over() {
    assert_eq!(PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1, 16);
    assert_eq!(
        PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1 as u64,
        8 * MIB
    );
    let attachment = |proof_bytes: usize| {
        ProofAttachment::new_ref(
            "halo2/ipa".into(),
            ProofBox::new("halo2/ipa".into(), vec![0_u8; proof_bytes]),
            VerifyingKeyId::new("halo2/ipa", "vk_1"),
        )
    };
    // Count: sixteen attachments are a list, seventeen are not.
    let full = vec![attachment(1); PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1];
    assert!(ProofAttachmentList::try_from(full.clone()).is_ok());
    let mut over = full;
    over.push(attachment(1));
    assert_eq!(
        ProofAttachmentList::try_from(over),
        Err(ProofAttachmentListError::TooMany {
            actual: PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1 + 1,
            maximum: PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1,
        })
    );
    // Frame: the largest proof whose list fills the frame bound exactly, and one byte more.
    let (mut low, mut high) = (1_usize, PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1);
    while low < high {
        let midpoint = low + (high - low).div_ceil(2);
        if ProofAttachmentList::try_from(vec![attachment(midpoint)]).is_ok() {
            low = midpoint;
        } else {
            high = midpoint - 1;
        }
    }
    let exact = ProofAttachmentList::try_from(vec![attachment(low)]).expect("largest fitting");
    let frame = norito::encode_canonical(&exact).expect("canonical frame");
    assert_eq!(
        frame.len(),
        PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
        "the framing is part of the bound"
    );
    assert_eq!(
        norito::decode_canonical::<ProofAttachmentList>(&frame).expect("the bound itself decodes"),
        exact
    );
    assert_eq!(
        ProofAttachmentList::try_from(vec![attachment(low + 1)]),
        Err(ProofAttachmentListError::CanonicalFrameTooLarge {
            actual: PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1 + 1,
            maximum: PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1,
        })
    );
    // The frame is within the transaction cap, and a ceiling-sized proof does not fit it.
    assert!(PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1 as u64 <= TRANSACTION_CAP_BYTES);
    assert!((low as u64) < X509_PROOF_CEILING_BYTES);
    let ceiling = usize::try_from(X509_PROOF_CEILING_BYTES).unwrap();
    assert!(matches!(
        ProofAttachmentList::try_from(vec![attachment(ceiling)]),
        Err(ProofAttachmentListError::CanonicalFrameTooLarge { actual, .. })
            if actual as u64 > X509_PROOF_CEILING_BYTES
    ));
}

/// The fixed zk-X509 validity windows: a signed CRL is fresh for exactly 300 seconds and a
/// presentation window is at most 300 seconds wide, both inclusive. These are consensus
/// validity bounds; the 300-second prover time target is a separate engineering number.
#[test]
fn x509_validity_windows_are_fixed_and_inclusive() {
    /// The CRL age and window width the delivery plan keeps fixed.
    const FIXED_SECONDS: u64 = 300;
    /// 2023-01-01T00:00:00Z.
    const T: u64 = 1_672_531_200;
    assert_eq!(ZK_X509_MAX_CRL_AGE_SECONDS_V1, FIXED_SECONDS);
    assert_eq!(ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1, FIXED_SECONDS);
    let window = PrivacyZkX509PresentationWindowV1::new;
    // Window width: exactly 300 seconds passes, 301 does not.
    assert_eq!(window(T, T + FIXED_SECONDS).validate(), Ok(()));
    assert_eq!(
        window(T, T + FIXED_SECONDS + 1).validate(),
        Err(PrivacyZkX509PresentationIntervalErrorV1::InvalidWindow {
            start: T,
            end: T + FIXED_SECONDS + 1,
            max_seconds: FIXED_SECONDS,
        })
    );
    // CRL age: a long-lived CRL admits a window that ends exactly 300 seconds after its
    // thisUpdate and none that ends one second later.
    let bounds = PrivacyZkX509PresentationBoundsV1::from_crl(
        PrivacyZkX509CrlUpdateIntervalV1::new(T, T + 86_400),
    )
    .expect("CRL bounds");
    assert_eq!(bounds.latest_end_unix_seconds(), T + FIXED_SECONDS);
    assert_eq!(bounds.admit(window(T, T + FIXED_SECONDS)), Ok(()));
    assert_eq!(
        bounds.admit(window(T + 1, T + FIXED_SECONDS + 1)),
        Err(PrivacyZkX509PresentationIntervalErrorV1::EndsAfterBounds)
    );
}

#[test]
fn contract_argument_record_accepts_the_limit_and_rejects_one_over() {
    assert_eq!(MAX_CONTRACT_ARGUMENT_RECORD_BYTES, 1024 * 1024);
    assert!(ContractArgumentRecord::try_new(vec![0; MAX_CONTRACT_ARGUMENT_RECORD_BYTES]).is_ok());
    let error = ContractArgumentRecord::try_new(vec![0; MAX_CONTRACT_ARGUMENT_RECORD_BYTES + 1])
        .expect_err("one byte over the argument-record cap");
    assert_eq!(error.actual, MAX_CONTRACT_ARGUMENT_RECORD_BYTES + 1);
    assert_eq!(error.max, MAX_CONTRACT_ARGUMENT_RECORD_BYTES);
    // A ceiling-sized proof cannot travel as a contract argument record.
    assert!((MAX_CONTRACT_ARGUMENT_RECORD_BYTES as u64) < X509_PROOF_CEILING_BYTES);
}

/// Committed chain parameters: the payload limit is validated against the chain frame limit.
#[test]
fn committed_block_payload_limit_accepts_the_frame_limit_and_rejects_one_over() {
    assert_eq!(FRAME_OVERHEAD, 264_224);
    assert_eq!(
        CHAIN_TRANSPORT_FRAME_LIMIT,
        16 * MIB + u64::from(FRAME_OVERHEAD)
    );
    let largest = u32::try_from(CHAIN_TRANSPORT_FRAME_LIMIT - u64::from(FRAME_OVERHEAD)).unwrap();
    assert_eq!(u64::from(largest), 16 * MIB);
    let record =
        |bytes: u32| ChainParamsRecord::from_parameters(with_max_block_bytes(bytes).sumeragi());
    assert_eq!(record(largest).validate(), Ok(()));
    assert_eq!(
        record(largest + 1).validate(),
        Err(ConfigError::MaxBlockBytesAboveTransport)
    );
    assert_eq!(
        ChainParamsRecord::from_parameters(Parameters::default().sumeragi()).validate(),
        Ok(())
    );
}

/// The signed RS16 layout: the payload bound is inclusive and the geometry is consistent.
#[test]
fn rs16_layout_accepts_the_payload_limit_and_rejects_one_over() {
    let layout = recommended_data_availability_layout();
    assert_eq!(layout.validate(), Ok(()));
    assert_eq!(layout.max_payload_size_bytes, MAX_DA_PAYLOAD_SIZE_BYTES);
    assert_eq!(MAX_DA_PAYLOAD_SIZE_BYTES, 16 * MIB);
    assert_eq!((layout.data_shards, layout.parity_shards), (4, 2));
    let maximum = layout
        .shape(MAX_DA_PAYLOAD_SIZE_BYTES)
        .expect("maximum payload");
    // 16 MiB over 256 KiB data chunks is 64 data rows; four data and two parity rows per
    // stripe make 96 chunks and 24 MiB of encoded shards.
    assert_eq!(maximum.chunk_count(), 96);
    assert_eq!(maximum.encoded_bytes() as u64, 24 * MIB);
    assert!(maximum.chunk_count() <= MAX_DA_CHUNK_COUNT as usize);
    assert!(maximum.encoded_bytes() as u64 <= MAX_DA_ENCODED_PAYLOAD_BYTES);
    assert_eq!(MAX_DA_CHUNK_SIZE_BYTES, 256 * 1024);
    assert_eq!(
        layout.shape(MAX_DA_PAYLOAD_SIZE_BYTES + 1),
        Err(LayoutError::InvalidPayloadLength)
    );
    assert_eq!(layout.shape(0), Err(LayoutError::InvalidPayloadLength));
    let mut oversized = layout;
    oversized.max_payload_size_bytes = MAX_DA_PAYLOAD_SIZE_BYTES + 1;
    assert_eq!(oversized.validate(), Err(LayoutError::InvalidLayout));
    // Every committed payload limit fits the protocol-wide RS16 payload bound.
    assert!(
        u64::from(Parameters::default().sumeragi().max_block_bytes().get())
            <= MAX_DA_PAYLOAD_SIZE_BYTES
    );
    assert!(CHAIN_TRANSPORT_FRAME_LIMIT - u64::from(FRAME_OVERHEAD) <= MAX_DA_PAYLOAD_SIZE_BYTES);
}
