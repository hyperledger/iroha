//! Real Unload execution and permanent replay after the exact funded native exchange.
use super::*;

mod fee;
mod online_charge;

fn ledger_rows(setup: &ExecutedKagemushaSetup) -> Vec<(KagemushaWalletLedgerKeyV1, Vec<u8>)> {
    setup
        .chain
        .state()
        .view()
        .world()
        .kagemusha_wallet_ledger()
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect()
}

fn require_conservation(setup: &ExecutedKagemushaSetup, expected: [u128; 4]) {
    let accounts = [
        &setup.account,
        &setup.recipients[0],
        &setup.recipients[1],
        &setup.reserve,
    ];
    let mut selected_total = Quantity::zero();
    for (account, amount) in accounts.into_iter().zip(expected) {
        let actual = balance(setup, account);
        assert_eq!(
            actual,
            Quantity::from_canonical_numeric(Numeric::new(amount, SCALE)).unwrap()
        );
        selected_total = selected_total.checked_add(&actual).unwrap();
    }
    let supply = Quantity::from_canonical_numeric(Numeric::new(SUPPLY, SCALE)).unwrap();
    assert_eq!(selected_total, supply);
    let view = setup.chain.state().view();
    let world = view.world();
    assert_eq!(
        world
            .asset_definition(&setup.asset.asset)
            .unwrap()
            .total_quantity(),
        &supply
    );
    let all_balances = world
        .assets()
        .iter()
        .filter(|(id, _)| id.definition() == &setup.asset.asset)
        .try_fold(Quantity::zero(), |sum, (_, value)| {
            sum.checked_add(value.as_ref())
        })
        .unwrap();
    assert_eq!(
        all_balances, supply,
        "no unobserved account or bucket can gain value"
    );
}

// Recover a genuinely fresh State through the production certified-frame replay owner.
// This neither clones World rows nor invokes a fixture verifier. Kura is the test chain's
// in-memory store, so this establishes StateExecutor recovery, not disk/power-loss behavior.
fn replay_into_fresh_state(source: ExecutedKagemushaSetup) -> ExecutedKagemushaSetup {
    let mut recovered = start();
    assert!(!Arc::ptr_eq(source.chain.state(), recovered.chain.state()));
    assert!(!Arc::ptr_eq(source.chain.kura(), recovered.chain.kura()));
    assert_eq!(recovered.asset, source.asset);
    assert_eq!(recovered.account, source.account);
    assert_eq!(recovered.recipients, source.recipients);
    assert_eq!(recovered.reserve, source.reserve);
    assert_eq!(
        norito::encode_canonical(&recovered.manifest).unwrap(),
        norito::encode_canonical(&source.manifest).unwrap()
    );
    recovered.chain.replay_from(&source.chain).unwrap();
    assert_eq!(recovered.chain.height(), source.chain.height());
    assert_eq!(ledger_rows(&recovered), ledger_rows(&source));
    for account in [
        &source.account,
        &source.recipients[0],
        &source.recipients[1],
        &source.reserve,
    ] {
        assert_eq!(balance(&recovered, account), balance(&source, account));
    }
    for height in 1..=source.chain.height() {
        assert_eq!(
            recovered
                .chain
                .committed(height)
                .block()
                .encode_wire()
                .unwrap(),
            source
                .chain
                .committed(height)
                .block()
                .encode_wire()
                .unwrap(),
            "recovery must retain the exact canonical certified original at {height}"
        );
    }
    drop(source);
    recovered
}

#[test]
fn fresh_state_replay_preserves_executed_genesis_supply_and_certified_suffix() {
    let mut source = start();
    require_conservation(&source, [SUPPLY, 0, 0, 0]);
    // commit_at supplies a real signed Log; it never produces an empty block.
    assert!(source.chain.commit_at(3_000, Vec::new()).is_empty());
    assert!(
        source
            .chain
            .committed(3)
            .block()
            .network_entrypoints()
            .next()
            .is_some()
    );
    let recovered = replay_into_fresh_state(source);
    assert_eq!(recovered.chain.height(), 3);
    require_conservation(&recovered, [SUPPLY, 0, 0, 0]);
    assert!(ledger_rows(&recovered).is_empty());
}

fn require_funded_receipt(setup: &ExecutedKagemushaSetup, input: &Inputs) {
    let original = read(
        &selected("KAGEMUSHA_NATIVE_LOAD_RECEIPT"),
        4_096,
        pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256"),
    );
    let view = setup.chain.state().view();
    let source =
        CommittedLoadReceipts::new(&view, 2_000_000, norito::canonical_decode_limits(2_000_000))
            .unwrap();
    let Action::IssueLoad {
        wallet, request_id, ..
    } = &input.load.action
    else {
        panic!("selected actual Load")
    };
    let receipt = source
        .receipt_for(
            &setup.account,
            &input.scheme.scheme_id(),
            wallet,
            request_id,
        )
        .unwrap();
    assert_eq!(
        norito::encode_canonical(&receipt).unwrap(),
        original,
        "recreated chain must execute the exact already-proved funded receipt"
    );
}

// The native producer already signed this adversarial fixture using the retained simulated
// C key. Read its exact public original; never create another signature or wallet operation.
fn retained_bad_sigma_claim(
    input: &Inputs,
    claim: &KagemushaWalletUnloadClaimV1,
) -> (Vec<u8>, [u8; 32]) {
    let path = selected("KAGEMUSHA_NATIVE_EXCHANGE_RESULT");
    let bytes = read(
        &path,
        16 << 10,
        pin("KAGEMUSHA_NATIVE_EXCHANGE_RESULT_SHA256"),
    );
    let result: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(
        result["schema"].as_str(),
        Some("iroha.kagemusha.native-abc-result.v1")
    );
    assert_eq!(
        result["target_sha256"].as_str().unwrap(),
        hex::encode(input.target_sha256)
    );
    assert_eq!(
        result["c_unload_claim_sha256"].as_str().unwrap(),
        hex::encode(pin("KAGEMUSHA_NATIVE_UNLOAD_CLAIM_SHA256"))
    );
    let row = &result["c_unload_bad_sigma_claim"];
    assert_eq!(
        row["name"].as_str(),
        Some("c-unload-bad-sigma-claim.norito")
    );
    assert_eq!(row["mutation"].as_str(), Some("sigma_ipa_f_plus_one"));
    assert_eq!(row["model_verified"].as_bool(), Some(true));
    assert_eq!(row["native_proof_rejected"].as_bool(), Some(true));
    assert_eq!(row["adversarial_fixture_signatures"].as_u64(), Some(1));
    let digest: [u8; 32] = hex::decode(row["sha256"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let bytes = read(
        &path
            .parent()
            .unwrap()
            .join("c-unload-bad-sigma-claim.norito"),
        KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1,
        digest,
    );
    assert_eq!(row["bytes"].as_u64(), Some(bytes.len() as u64));
    let mut bad =
        KagemushaWalletUnloadClaimV1::decode_canonical(&bytes, &input.scheme.scheme_id()).unwrap();
    let paid = bad.verify(&input.scheme).unwrap();
    assert_eq!(
        (paid.amount, paid.account_payout, paid.online_charge),
        (100, 100, 0)
    );
    // The pinned native producer checked the Vesta transcript schedule and f -> f+1.
    // Independently constrain its only proof-byte change to that final scalar window.
    let original = &claim.package.step_proof.bytes;
    let changed = &bad.package.step_proof.bytes;
    assert_eq!(changed.len(), original.len());
    assert!(original.len() >= 96 && original.len().is_multiple_of(32));
    let f_offset = original.len() - 64;
    assert_eq!(&changed[..f_offset], &original[..f_offset]);
    assert_ne!(
        &changed[f_offset..f_offset + 32],
        &original[f_offset..f_offset + 32]
    );
    assert_eq!(&changed[f_offset + 32..], &original[f_offset + 32..]);
    assert_ne!(
        bad.package.receipt.signature,
        claim.package.receipt.signature
    );
    bad.package.step_proof.bytes = original.clone();
    bad.package.receipt.signature = claim.package.receipt.signature;
    assert_eq!(
        &bad, claim,
        "every field except the documented scalar and receipt signature stays exact"
    );
    (bytes, digest)
}

fn settlement_proofs(
    setup: &ExecutedKagemushaSetup,
    output: &Path,
    instruction: &KagemushaWalletLedgerV1,
    transaction_hash: [u8; 32],
    bad_sigma_claim_sha256: [u8; 32],
) {
    assert!(!output.exists());
    let mut directory = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        directory.mode(0o700);
    }
    directory.create(output).unwrap();
    let mut verifier = native(setup);
    let Action::Unload(claim) = &instruction.action else {
        panic!("exact original Unload instruction")
    };
    let mut records = vec![
        publish(output, "unload-claim.norito", claim),
        publish(
            output,
            "unload-instruction.norito",
            &norito::encode_canonical(instruction).unwrap(),
        ),
    ];
    for height in 1..=setup.chain.height() {
        let proof =
            crate::sumeragi::finality::build_proof(&setup.chain.state().view(), height).unwrap();
        let authenticated = verifier.verify(&proof).unwrap();
        assert_eq!(
            authenticated.result(),
            setup.chain.committed(height).result()
        );
        if height == 6 {
            // Retain the exact signed transaction from the verified successful block.
            let iroha_data_model::transaction::TransactionEntrypoint::External(signed) =
                authenticated.block().network_entrypoint_at(0).unwrap()
            else {
                panic!("exact external Unload transaction")
            };
            assert_eq!(*signed.hash().as_ref(), transaction_hash);
            assert!(
                authenticated
                    .block()
                    .network_output_at(0)
                    .unwrap()
                    .1
                    .result
                    .is_ok()
            );
            records.push(publish(
                output,
                "unload-block.norito",
                &authenticated.block().encode_wire().unwrap(),
            ));
            records.push(publish(
                output,
                "unload-signed-transaction.norito",
                &norito::encode_canonical(signed).unwrap(),
            ));
        }
        records.push(publish(
            output,
            &format!("native-proof-{height}.norito"),
            &norito::encode_canonical(&proof).unwrap(),
        ));
    }
    let receipt = norito::json!({
        "schema": "iroha.kagemusha.executed-unload-settlement.v1",
        "network_hex": (hex::encode(setup.chain.network_id().as_bytes())),
        "target_sha256": (hex::encode(pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"))),
        "receipt_sha256": (hex::encode(pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256"))),
        "claim_sha256": (hex::encode(pin("KAGEMUSHA_NATIVE_UNLOAD_CLAIM_SHA256"))),
        "settlement_height": 6,
        "settlement_transaction_hash_hex": (hex::encode(transaction_hash)),
        "settlement_block_hash_hex": (hex::encode(setup.chain.committed(6).block().hash().as_ref())),
        "settlement_instruction_index": 0,
        "certified_replay_heights": (vec![6, 9]),
        "preproposal_refusals": (vec!["unload_claim.account", "receipt_signature"]),
        "crypto_rejection_height": 8,
        "crypto_rejection": "KAGEMUSHA ledger: native package proof rejected",
        "bad_sigma_claim_sha256": (hex::encode(bad_sigma_claim_sha256)),
        "native_exchange_result_sha256": (hex::encode(pin("KAGEMUSHA_NATIVE_EXCHANGE_RESULT_SHA256"))),
        "signed_log_height": 9,
        "fresh_state_replay_executed": true,
        "disk_restart_executed": false,
        "initial_supply_atomic_units": "1000",
        "final_supply_atomic_units": "1000",
        "payer_balance_atomic_units": "900",
        "recipient_b_balance_atomic_units": "0",
        "recipient_c_balance_atomic_units": "100",
        "reserve_balance_atomic_units": "0",
        "exact_once_payout": true,
        "scope": "Actual native proof verification and ledger execution with exact receipt replay; fresh StateExecutor recovery from original certified frames before exact retry and after two preproposal refusals, a model-valid native-proof rejection at height 8, and a signed Log at height 9. Fixture signs exactly three votes of a four-seat committee. Disk/power-loss, real P2P rounds and physical hardware qualification remain separate.",
        "originals": records,
    });
    publish(
        output,
        "settlement.json",
        norito::json::to_json(&receipt).unwrap().as_bytes(),
    );
    File::open(output).unwrap().sync_all().unwrap();
    File::open(output.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

#[test]
#[ignore = "requires complete installed native A→B→C proof originals and exact funded receipt; executes real ledger Unload and replay"]
fn execute_actual_c_unload_with_conservation_and_permanent_replay() {
    let mut setup = start();
    let input = inputs(&setup);
    fund(&mut setup, &input);
    require_conservation(&setup, [900, 0, 0, 100]);
    require_funded_receipt(&setup, &input);
    let original = read(
        &selected("KAGEMUSHA_NATIVE_UNLOAD_CLAIM"),
        KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1,
        pin("KAGEMUSHA_NATIVE_UNLOAD_CLAIM_SHA256"),
    );
    let claim =
        KagemushaWalletUnloadClaimV1::decode_canonical(&original, &input.scheme.scheme_id())
            .unwrap();
    assert_eq!(claim.account, setup.recipients[1]);
    assert_ne!(claim.account, setup.account);
    assert_ne!(claim.account, setup.recipients[0]);
    let paid = claim.verify(&input.scheme).unwrap();
    assert_eq!(
        (paid.amount, paid.account_payout, paid.online_charge),
        (100, 100, 0)
    );

    let instruction =
        KagemushaWalletLedgerV1::new(input.scheme.scheme_id(), Action::Unload(original));
    let transaction = setup
        .chain
        .sign(&key(43), [instruction.clone().into()], 5_999);
    let transaction_hash = *transaction.hash().as_ref();
    assert_eq!(setup.chain.commit_at(6_000, vec![transaction]), [true]);
    require_conservation(&setup, [900, 0, 100, 0]);
    setup = replay_into_fresh_state(setup);
    require_funded_receipt(&setup, &input);
    require_conservation(&setup, [900, 0, 100, 0]);
    assert_eq!(
        balance(&setup, &setup.account),
        Quantity::from_canonical_numeric(Numeric::new(900, SCALE)).unwrap()
    );
    assert_eq!(balance(&setup, &setup.recipients[0]), Quantity::zero());
    assert_eq!(
        balance(&setup, &setup.recipients[1]),
        Quantity::from_canonical_numeric(Numeric::new(100, SCALE)).unwrap()
    );
    assert_eq!(balance(&setup, &setup.reserve), Quantity::zero());
    let rows = ledger_rows(&setup);

    // An exact claim retry returns the retained outcome and cannot pay a second time.
    let transaction = setup
        .chain
        .sign(&key(43), [instruction.clone().into()], 6_999);
    assert_eq!(setup.chain.commit_at(7_000, vec![transaction]), [true]);
    require_conservation(&setup, [900, 0, 100, 0]);
    assert_eq!(ledger_rows(&setup), rows);
    assert_eq!(
        balance(&setup, &setup.recipients[1]),
        Quantity::from_canonical_numeric(Numeric::new(100, SCALE)).unwrap()
    );
    assert_eq!(balance(&setup, &setup.reserve), Quantity::zero());

    // These claims are structurally refused before block assembly, not failed ledger
    // executions. Assert both the exact model reason and the production routing boundary.
    for (index, changed) in [
        {
            let mut changed = claim.clone();
            changed.account = setup.account.clone();
            changed
        },
        {
            let mut changed = claim.clone();
            changed.package.step_proof.bytes[0] ^= 1;
            changed
        },
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = norito::encode_canonical(&changed).unwrap();
        let require_reason = |error: KagemushaWalletValidationErrorV1| match (index, error) {
            (
                0,
                KagemushaWalletValidationErrorV1::InvalidField {
                    field: "unload_claim.account",
                },
            )
            | (
                1,
                KagemushaWalletValidationErrorV1::InvalidSignature {
                    domain: KagemushaWalletSigningDomainV1::Receipt,
                },
            ) => {}
            (_, error) => panic!("unexpected preproposal refusal for mutation {index}: {error:?}"),
        };
        require_reason(
            KagemushaWalletUnloadClaimV1::decode_canonical(&bytes, &input.scheme.scheme_id())
                .unwrap_err(),
        );
        let changed_instruction =
            KagemushaWalletLedgerV1::new(input.scheme.scheme_id(), Action::Unload(bytes));
        let transaction = setup
            .chain
            .sign(&key(43), [changed_instruction.clone().into()], 7_999);
        let view = setup.chain.state().view();
        match crate::kagemusha_wallet_v1::routing::dataspace(view.world(), &changed_instruction) {
            Err(crate::kagemusha_wallet_v1::Error::Model(error)) => require_reason(error),
            result => panic!("expected the exact model refusal during routing: {result:?}"),
        }
        assert_eq!(
            crate::sumeragi::lanes::routing::RoutingSnapshot::of(&view)
                .unwrap()
                .inputs(view.world())
                .execution_route(transaction.payload(), 8)
                .unwrap(),
            None
        );
        drop(view);
        assert_eq!(
            setup.chain.height(),
            7,
            "preproposal refusal creates no certified height"
        );
        require_conservation(&setup, [900, 0, 100, 0]);
        assert_eq!(ledger_rows(&setup), rows);
    }

    // A model-valid, correctly re-signed but cryptographically invalid sigma must reach
    // the real ledger verifier and be rejected before the permanent replay lookup.
    let (bad_sigma, bad_sigma_claim_sha256) = retained_bad_sigma_claim(&input, &claim);
    let changed_instruction =
        KagemushaWalletLedgerV1::new(input.scheme.scheme_id(), Action::Unload(bad_sigma));
    let transaction = setup
        .chain
        .sign(&key(43), [changed_instruction.into()], 7_999);
    assert_eq!(setup.chain.commit_at(8_000, vec![transaction]), [false]);
    assert_eq!(
        setup.chain.committed(8).block().output_error(0),
        Some(
            &iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                iroha_data_model::ValidationFail::InstructionFailed(
                    iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
                        "KAGEMUSHA ledger: native package proof rejected".into()
                    )
                )
            )
        )
    );
    require_conservation(&setup, [900, 0, 100, 0]);
    assert_eq!(ledger_rows(&setup), rows);

    // Retain height 9 honestly with a real signed Log, preserving the confirmation fixture's
    // original certified suffix without pretending either preproposal refusal was committed.
    let log = setup.chain.tick(8_999);
    let log_hash = log.hash();
    assert_eq!(setup.chain.commit_at(9_000, vec![log]), [true]);
    let log_block = setup.chain.committed(9);
    let iroha_data_model::transaction::TransactionEntrypoint::External(signed) =
        log_block.block().network_entrypoint_at(0).unwrap()
    else {
        panic!("exact signed Log transaction")
    };
    assert_eq!(signed.hash(), log_hash);
    assert_eq!(setup.chain.height(), 9);
    require_conservation(&setup, [900, 0, 100, 0]);
    assert_eq!(ledger_rows(&setup), rows);
    assert_eq!(
        balance(&setup, &setup.account),
        Quantity::from_canonical_numeric(Numeric::new(900, SCALE)).unwrap()
    );
    assert_eq!(balance(&setup, &setup.recipients[0]), Quantity::zero());
    assert_eq!(
        balance(&setup, &setup.recipients[1]),
        Quantity::from_canonical_numeric(Numeric::new(100, SCALE)).unwrap()
    );
    assert_eq!(balance(&setup, &setup.reserve), Quantity::zero());
    setup = replay_into_fresh_state(setup);
    assert_eq!(ledger_rows(&setup), rows);
    require_funded_receipt(&setup, &input);
    require_conservation(&setup, [900, 0, 100, 0]);
    settlement_proofs(
        &setup,
        &selected("KAGEMUSHA_EXECUTED_UNLOAD_OUTPUT"),
        &instruction,
        transaction_hash,
        bad_sigma_claim_sha256,
    );
}
