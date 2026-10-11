//! Cold production registry lookups and original-budget rejected-filter regressions.

use super::super::{FAIL_SIZE, measured, populated_manifest};
use iroha_allocation::{AllocationBudget, AllocationReservation};
use iroha_data_model::{
    Level,
    events::{
        EventFilterBox,
        pipeline::{PipelineEventFilterBox, TransactionEventFilter, TransactionStatus},
    },
    isi::{
        InstructionBox, InstructionRegistry, Log, instruction_wire_id, set_instruction_registry,
    },
    parameter::TransactionParameters,
    smart_contract::manifest::{ContractManifest, TriggerCallback, TriggerDescriptor},
    transaction::error::{InstructionExecutionFail, TransactionRejectionReason},
    trigger::action::Repeats,
};
use norito::core::{
    BoundedEncodeError, DecodeBudgetContext, DecodeLimits, Error, SerializePayload,
};
use std::process::Command;

const CHILD_MODE: &str = "IROHA_TEST_COLD_INSTRUCTION_REGISTRY_MODE";

fn isolated(mode: &str, test: &str, body: fn()) {
    if std::env::var(CHILD_MODE).ok().as_deref() == Some(mode) {
        body();
        return;
    }
    // A new executable process is necessary: a thread cannot reset the production OnceLock.
    let output = Command::new(std::env::current_exe().expect("current native test image"))
        .args(["--exact", test, "--nocapture"])
        .env(CHILD_MODE, mode)
        .output()
        .expect("spawn original current test image");
    assert!(
        output.status.success(),
        "isolated {mode} control failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("test {test} ... ok")),
        "isolated exact test was not executed: {stdout}"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "isolated membership changed: {stdout}"
    );
}

fn original_context(
    allocated: usize,
) -> (AllocationBudget, AllocationReservation, DecodeBudgetContext) {
    let cap = usize::try_from(TransactionParameters::default().max_tx_bytes().get())
        .expect("native transaction cap");
    let pool = AllocationBudget::new(allocated + DecodeBudgetContext::allocation_layout().size());
    let mut grant = pool
        .try_reserve_bytes(pool.limit_bytes())
        .expect("one original finite grant");
    let context = DecodeBudgetContext::from_reservation(
        DecodeLimits::new(
            cap,
            cap,
            cap,
            allocated,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        ),
        &mut grant,
    )
    .expect("original counter");
    context.with(|| {}); // Initialize only the thread-local owner scope, never a serializer/registry.
    (pool, grant, context)
}

fn original_instruction() -> InstructionBox {
    Log::new(Level::INFO, "original_native_instruction_".repeat(8)).into()
}

fn rejected_instruction_manifest() -> ContractManifest {
    let mut manifest = populated_manifest();
    let rejection = TransactionRejectionReason::InstructionExecution(
        InstructionExecutionFail::new(original_instruction(), "original_native_refusal".into()),
    );
    let filter =
        TransactionEventFilter::new().for_status(TransactionStatus::Rejected(Box::new(rejection)));
    manifest.entrypoints.as_mut().expect("original entrypoint")[0].triggers =
        vec![TriggerDescriptor {
            id: "native_rejection".parse().expect("trigger"),
            repeats: Repeats::Exactly(1),
            filter: EventFilterBox::Pipeline(PipelineEventFilterBox::Transaction(filter)),
            authority: None,
            metadata: iroha_model_base::metadata::Metadata::default(),
            callback: TriggerCallback {
                namespace: None,
                entrypoint: "pay".into(),
            },
        }];
    manifest
}

fn cold_body() {
    let instruction = original_instruction();
    let manifest = rejected_instruction_manifest();
    let (_pool, _grant, context) = original_context(0);
    let (facts, allocations) = measured(|| {
        context.with(|| {
            (
                instruction_wire_id(&instruction),
                instruction.encoded_len_exact(),
                instruction.encoded_len_hint(),
                norito::canonical_frame_len(&instruction),
                norito::canonical_frame_len(&manifest.signature_payload()),
            )
        })
    });
    assert_eq!(allocations, 0, "cold count initialized an unowned registry");
    assert_eq!(facts.0, Some("iroha.log"));
    assert_eq!(facts.1, facts.2);
    assert!(facts.1.is_some());
    assert!(facts.3.is_ok());
    let exact = facts
        .4
        .expect("genuine cold rejected-instruction manifest count");
    assert_eq!(context.consumed_allocated_bytes(), 0);
    let (pool, mut grant, context) = original_context(exact);
    let frame = grant
        .try_partition_bytes(exact)
        .expect("original exact output frame");
    let (short, allocations) = measured(|| manifest.signature_payload_bytes(&context, exact - 1));
    assert!(
        matches!(short, Err(BoundedEncodeError::FrameTooLarge { encoded_bytes, max_bytes })
        if encoded_bytes == exact && max_bytes == exact - 1)
    );
    assert_eq!(allocations, 0);
    assert_eq!(context.consumed_allocated_bytes(), 0);
    // The canonical wire oracle runs outside the output census, after the genuine cold count.
    // The measured output must satisfy its own exact allocation assertion; no registry is warmed.
    let expected = norito::encode_canonical(&manifest.signature_payload()).expect("original wire");
    let (payload, allocations) = measured(|| manifest.signature_payload_bytes(&context, exact));
    let payload = payload.expect("one original bounded output");
    assert_eq!(payload, expected);
    assert_eq!(allocations, 1, "only the exact original frame may allocate");
    assert_eq!(context.consumed_allocated_bytes(), exact as u64);
    drop(payload);
    drop(frame);
    let physical = pool
        .try_reserve_bytes(exact)
        .expect("real original frame refunded");
    let (second, allocations) =
        measured(|| manifest.signature_payload_bytes(&context.clone(), exact));
    assert!(
        matches!(second, Err(BoundedEncodeError::Serialization(ref error)) if error.is_decode_resource_limit())
    );
    assert_eq!(allocations, 0);
    drop(physical);
    drop(context);
    drop(grant);
    assert_eq!(pool.reserved_bytes(), 0);

    let (_pool, mut grant, context) = original_context(exact);
    let _frame = grant
        .try_partition_bytes(exact)
        .expect("same original refused output frame");
    FAIL_SIZE.with(|size| size.set(Some(exact)));
    let (refused, allocations) = measured(|| manifest.signature_payload_bytes(&context, exact));
    assert!(
        matches!(refused, Err(BoundedEncodeError::AllocationFailed { bytes }) if bytes == exact)
    );
    assert_eq!(
        allocations, 1,
        "only the original exact output request was refused"
    );
    assert_eq!(context.consumed_allocated_bytes(), exact as u64);
}

fn empty_body() {
    // Replacing an installed default removes its authority; cold defaults cannot reappear.
    set_instruction_registry(iroha_data_model::instruction_registry::default());
    set_instruction_registry(InstructionRegistry::new());
    let instruction = original_instruction();
    let manifest = rejected_instruction_manifest();
    let (_pool, _grant, context) = original_context(0);
    let (facts, allocations) = measured(|| {
        context.with(|| {
            (
                instruction_wire_id(&instruction),
                instruction.encoded_len_exact(),
                instruction.encoded_len_hint(),
                norito::canonical_frame_len(&instruction),
                manifest.signature_payload_bytes(&context, 10 * 1024 * 1024),
            )
        })
    });
    assert_eq!(
        allocations, 0,
        "authoritative missing entry allocated an error string"
    );
    assert_eq!(facts.0, None);
    assert_eq!(facts.1, None);
    assert_eq!(facts.2, None);
    assert!(matches!(
        facts.3,
        Err(Error::InvalidValue {
            context: "unregistered instruction"
        })
    ));
    assert!(matches!(
        facts.4,
        Err(BoundedEncodeError::Serialization(Error::InvalidValue {
            context: "unregistered instruction"
        }))
    ));
    assert_eq!(context.consumed_allocated_bytes(), 0);
}

fn custom_body() {
    set_instruction_registry(
        InstructionRegistry::new().register_with_id::<Log>("test.current.original.log"),
    );
    let instruction = original_instruction();
    let (_pool, _grant, context) = original_context(0);
    let (facts, allocations) = measured(|| {
        context.with(|| {
            (
                instruction_wire_id(&instruction),
                instruction.encoded_len_exact(),
                instruction.encoded_len_hint(),
                norito::canonical_frame_len(&instruction),
            )
        })
    });
    assert_eq!(allocations, 0);
    assert_eq!(facts.0, Some("test.current.original.log"));
    assert_eq!(facts.1, facts.2);
    assert!(facts.3.is_ok());
    let embedded = iroha_data_model::isi::framed_instruction_payload(&instruction)
        .expect("same authoritative custom registry");
    assert_eq!(embedded.0, "test.current.original.log");
    let expected = norito::codec::Encode::encode(&(embedded.0.to_owned(), embedded.1));
    assert_eq!(norito::codec::Encode::encode(&instruction), expected);
    assert_eq!(facts.1, Some(expected.len()));
}

fn installed_default_body() {
    set_instruction_registry(iroha_data_model::instruction_registry::default());
    let instruction = original_instruction();
    let (_pool, _grant, context) = original_context(0);
    let (facts, allocations) = measured(|| {
        context.with(|| {
            (
                instruction_wire_id(&instruction),
                instruction.encoded_len_exact(),
                instruction.encoded_len_hint(),
                norito::canonical_frame_len(&instruction),
            )
        })
    });
    assert_eq!(allocations, 0);
    assert_eq!(facts.0, Some("iroha.log"));
    assert_eq!(facts.1, facts.2);
    assert!(facts.3.is_ok());
}

#[test]
fn cold_default_instruction_encoding_and_nested_manifest_count_do_not_initialize_a_heap_registry() {
    isolated(
        "cold",
        "projection_tests::instruction_registry_projection_tests::cold_default_instruction_encoding_and_nested_manifest_count_do_not_initialize_a_heap_registry",
        cold_body,
    );
}

#[test]
fn explicit_empty_production_registry_refuses_without_default_fallback_or_heap_error() {
    isolated(
        "empty",
        "projection_tests::instruction_registry_projection_tests::explicit_empty_production_registry_refuses_without_default_fallback_or_heap_error",
        empty_body,
    );
}

#[test]
fn explicit_custom_production_registry_retains_original_wire_and_hint_geometry() {
    isolated(
        "custom",
        "projection_tests::instruction_registry_projection_tests::explicit_custom_production_registry_retains_original_wire_and_hint_geometry",
        custom_body,
    );
}

#[test]
fn explicitly_installed_default_registry_matches_the_cold_default_wire_identity() {
    isolated(
        "default",
        "projection_tests::instruction_registry_projection_tests::explicitly_installed_default_registry_matches_the_cold_default_wire_identity",
        installed_default_body,
    );
}
