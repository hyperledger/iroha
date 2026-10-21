// Generic display projection; business approval still binds the original native instruction.

use super::*;
use iroha_executor_data_model::isi::multisig::MultisigProposalValue;

fn execute_proposal(args: Value) -> (dm::AccountId, MultisigProposalValue) {
    let account = checked_multisig_selector_account_id(0x7b, "trigger display account");
    let instruction = dm::ExecuteTrigger::new("court_approval_fixture".parse().unwrap())
        .with_args(args)
        .into();
    let proposal = occurrence_fixture_value(vec![instruction], 100, 200, BTreeSet::new());
    (account, proposal)
}

#[test]
fn single_execute_trigger_preserves_exact_arguments_without_business_inference() {
    let source = checked_multisig_selector_account_id(0x7c, "court display source");
    let destination = checked_multisig_selector_account_id(0x7d, "court display destination");
    let args = norito::json!({
        "order_id": "order-1",
        "digest": (format!("0x{}", "ab".repeat(32))),
        "expected_source": (source.to_string()),
        "expected_destination": (destination.to_string()),
        "expected_amount": "12.5",
    });
    let (account, proposal) = execute_proposal(args.clone());
    let original_hash = HashOf::new(&proposal.instructions);
    let world = World::default();
    let view = world.view();
    let intent = multisig_proposal_intent(&view, &account, &proposal)
        .unwrap()
        .try_into_any_norito::<Value>()
        .unwrap();
    assert_eq!(
        intent,
        norito::json!({
            "kind": "EXECUTE_TRIGGER",
            "trigger_id": "court_approval_fixture",
            "args": args,
        })
    );
    assert_eq!(
        multisig_proposal_operation_type(&view, &account, &proposal),
        "EXECUTE_TRIGGER"
    );
    assert_eq!(HashOf::new(&proposal.instructions), original_hash);
    // No world binding was installed. This generic projection cannot claim a
    // court mandate, asset, controller or source authority from an ID's spelling.
    assert_eq!(intent.as_object().unwrap().len(), 3);
}

#[test]
fn execute_trigger_projection_keeps_arbitrary_json_types_and_rejects_partial_batches() {
    for args in [
        Value::Null,
        norito::json!(["12.5", 12, true, {"nested": [1, 2]}]),
    ] {
        let (account, mut proposal) = execute_proposal(args.clone());
        let world = World::default();
        let view = world.view();
        let intent = multisig_proposal_intent(&view, &account, &proposal)
            .unwrap()
            .try_into_any_norito::<Value>()
            .unwrap();
        assert_eq!(intent["args"], args);
        proposal.instructions.push(proposal.instructions[0].clone());
        assert!(multisig_proposal_intent(&view, &account, &proposal).is_none());
        assert_eq!(
            multisig_proposal_operation_type(&view, &account, &proposal),
            "ONCHAIN_MULTISIG"
        );
        proposal.instructions.clear();
        assert!(multisig_proposal_intent(&view, &account, &proposal).is_none());
    }
}

#[test]
fn execute_trigger_display_size_boundary_preserves_native_proposal() {
    for (bytes, projected) in [
        (MULTISIG_EXECUTE_TRIGGER_DISPLAY_MAX_ARGS_BYTES, true),
        (MULTISIG_EXECUTE_TRIGGER_DISPLAY_MAX_ARGS_BYTES + 1, false),
    ] {
        // A canonical ASCII JSON string has exactly two quote bytes.
        let (_, proposal) = execute_proposal(Value::from("x".repeat(bytes - 2)));
        let original_hash = HashOf::new(&proposal.instructions);
        assert_eq!(
            single_multisig_execute_trigger_intent(&proposal).is_some(),
            projected
        );
        assert_eq!(HashOf::new(&proposal.instructions), original_hash);
    }
}

#[test]
fn execute_trigger_maximum_native_json_depth_remains_opaque_without_panicking() {
    let mut last_valid = IrohaJson::new(0);
    for depth in 1..=norito::json::MAX_JSON_VALUE_NESTING_DEPTH + 1 {
        let text = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        match IrohaJson::from_raw_json(text) {
            Ok(value) => last_valid = value,
            Err(_) => break,
        }
    }
    let (_, mut proposal) = execute_proposal(Value::Null);
    proposal.instructions[0] = dm::ExecuteTrigger {
        trigger: "court_approval_fixture".parse().unwrap(),
        args: last_valid,
    }
    .into();
    assert!(single_multisig_execute_trigger_intent(&proposal).is_none());
}
