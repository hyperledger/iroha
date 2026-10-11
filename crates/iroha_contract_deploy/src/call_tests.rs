//! Durable mutable-call custody, substitution, and ambiguous-dispatch regressions.
use super::*;
use std::cell::Cell;

/// One in-place substitution applied to an otherwise valid prepared call.
type PlanMutation = Box<dyn Fn(&mut PreparedContractCall)>;

#[test]
fn call_authorization_resolves_only_the_authenticated_permission_declaration() -> Result<()> {
    let (_, prepared, _) = fixture()?;
    let address = prepared.plan.intent.invocation.contract_address;
    for (source, entrypoint, expected) in [
        (
            "seiyaku Open { kotoage fn run() authorize(anyone) {} }",
            "run",
            None,
        ),
        (
            "seiyaku Scoped { permission Admin; kotoage fn run() authorize(Admin) {} }",
            "run",
            Some(Permission::from(CanUseContractPermission {
                contract: address.clone(),
                permission: "Admin".parse()?,
            })),
        ),
        (
            "seiyaku Shared { import permission \"SharedOperators\" as Operator; kotoage fn run() authorize(Operator) {} }",
            "run",
            Some(Permission::new("SharedOperators".to_owned(), Json::new(()))),
        ),
        (
            "seiyaku Lifecycle { hajimari() {} }",
            "hajimari",
            Some(Permission::from(CanInvokeContractEntrypoint {
                contract: address.clone(),
                entrypoint: "hajimari".to_owned(),
            })),
        ),
    ] {
        let artifact = kotodama_lang::compiler::Compiler::new()
            .compile_source(source)
            .map_err(|error| eyre!(error))?;
        let verified = ivm_artifact_admission::verify_contract_artifact(&artifact)?;
        let (intent, _) = trusted_contract_intent(
            &artifact,
            address.clone(),
            entrypoint,
            norito::json!({}),
            false,
        )?;
        assert_eq!(required_permission(&verified, &intent)?, expected);
        if let Some(expected) = expected {
            let message = missing_call_permission(&expected, &prepared.plan.authority).to_string();
            assert!(message.contains(&norito::json::to_string(&expected)?));
            assert!(message.contains("iroha account permission grant --id"));
        }
    }
    Ok(())
}

fn fixture() -> Result<(Config, PreparedContractCall, TransactionRecord)> {
    let (config, _) = crate::service_tests::fixture()?;
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku Example { hajimari() {} }")
        .map_err(|error| eyre!(error))?;
    let address = ContractAddress::derive(
        &config.network_id,
        &config.account,
        7,
        DataSpaceId::UNIVERSAL,
    )?;
    let (intent, payload) =
        trusted_contract_intent(&artifact, address, "hajimari", norito::json!({}), false)?;
    let fee = FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1_500_000));
    let transaction_ttl_ms = u64::try_from(config.transaction_ttl.as_millis())?;
    let mut builder =
        TransactionBuilder::new(config.network_id, config.account.clone(), fee.clone());
    builder.set_creation_time(Duration::from_millis(1));
    builder.set_ttl(Duration::from_millis(transaction_ttl_ms.min(59_999)));
    let call = builder
        .with_metadata(intent.metadata.clone())
        .with_executable(Executable::ContractCall(intent.invocation.clone()))
        .try_sign(config.key_pair.private_key())?;
    let mut plan = CallPlan {
        version: 1,
        network_id: config.network_id,
        chain_id: config.chain.to_string(),
        authority: config.account.clone(),
        chain_discriminant: config.account_chain_discriminant,
        created_at_ns: 1,
        artifact_hex: hex::encode(artifact),
        alias: "example::universal".parse()?,
        payload,
        intent,
        requested_fee: fee,
        authorization: CallAuthorization {
            signing_deadline_unix_ms: 60_000,
            max_total_fees: BTreeMap::from([(
                AssetDefinitionId::derive_from_components(
                    iroha_model_base::domain::DomainId::parse_fully_qualified(
                        "wonderland.universal",
                    )?,
                    "xor".parse()?,
                ),
                Quantity::from(1_000_000_u32),
            )]),
        },
        transaction_ttl_ms,
        grant: None,
        call: transaction_record("contract-call", &call),
    };
    bind_operation_metadata(&mut plan)?;
    let mut prepared = PreparedContractCall {
        plan,
        signature_hex: String::new(),
    };
    let step = refresh_prepared_call(&config, &mut prepared)?;
    Ok((config, prepared, step))
}
fn refresh_prepared_call(
    config: &Config,
    prepared: &mut PreparedContractCall,
) -> Result<TransactionRecord> {
    bind_operation_metadata(&mut prepared.plan)?;
    let signed = fixture_builder(config, prepared)?
        .with_metadata(prepared.plan.intent.metadata.clone())
        .with_executable(Executable::ContractCall(
            prepared.plan.intent.invocation.clone(),
        ))
        .try_sign(config.key_pair.private_key())?;
    let step = transaction_record("contract-call", &signed);
    prepared.plan.call = step.clone();
    prepared.signature_hex = hex::encode(
        Signature::try_new(
            config.key_pair.private_key(),
            &plan_signing_bytes(&prepared.plan)?,
        )?
        .payload(),
    );
    Ok(step)
}
fn fixture_builder(config: &Config, prepared: &PreparedContractCall) -> Result<TransactionBuilder> {
    let mut builder = TransactionBuilder::new(
        config.network_id,
        config.account.clone(),
        prepared.plan.requested_fee.clone(),
    );
    builder.set_creation_time(Duration::from_millis(1));
    builder.set_ttl(Duration::from_millis(
        prepared
            .plan
            .authorization
            .ttl_ms(1, prepared.plan.transaction_ttl_ms)?,
    ));
    Ok(builder)
}
struct Transport {
    submits: Cell<usize>,
    ambiguous: Cell<bool>,
}
impl DeploymentTransport for Transport {
    fn submit(&self, _: &SignedTransaction) -> Result<()> {
        self.submits.set(self.submits.get() + 1);
        if self.ambiguous.get() {
            Err(eyre!("connection lost after write"))
        } else {
            Ok(())
        }
    }
    fn wait(&self, hash: HashOf<SignedTransaction>) -> Result<AppliedEvidence> {
        if self.ambiguous.get() {
            return Err(eyre!("transaction outcome unavailable"));
        }
        Ok(AppliedEvidence {
            hash: hash.to_string(),
            terminal_kind: "Applied".into(),
            block_height: 42,
            scope: "global".into(),
            resolved_from: "state".into(),
            charge: None,
        })
    }
}
#[test]
fn call_resume_never_resubmits_after_ambiguous_dispatch() -> Result<()> {
    let (config, prepared, step) = fixture()?;
    validate_plan(&prepared, &config)?;
    validate_call_transaction(&prepared.plan, &step)?;
    let temporary = tempfile::tempdir()?;
    let journal = Journal::open(&temporary.path().join("call"), true)?;
    journal.put_exact("plan.json", &prepared)?;
    let transport = Transport {
        submits: Cell::new(0),
        ambiguous: Cell::new(true),
    };
    let error = execute_step(&journal, &step, 1, &transport)
        .expect_err("ambiguous submit must retain pending ownership");
    assert!(error.downcast_ref::<ContractCallPending>().is_some());
    assert_eq!(transport.submits.get(), 1);
    validate_attempt(&journal, &step, 1)?;
    transport.ambiguous.set(false);
    let applied = execute_step(&journal, &step, 1, &transport)?;
    assert_eq!(applied.hash, step.hash);
    assert_eq!(transport.submits.get(), 1);
    assert_eq!(execute_step(&journal, &step, 1, &transport)?, applied);
    assert_eq!(transport.submits.get(), 1);
    Ok(())
}
#[test]
fn call_signed_plan_and_transaction_reject_substitution() -> Result<()> {
    let (config, prepared, step) = fixture()?;
    validate_plan(&prepared, &config)?;
    let mutations: Vec<PlanMutation> = vec![
        Box::new(|p| p.plan.authorization.signing_deadline_unix_ms += 1),
        Box::new(|p| p.plan.authorization.max_total_fees.clear()),
        Box::new(|p| p.plan.transaction_ttl_ms += 1),
        Box::new(|p| p.plan.intent.invocation.entrypoint = "other".into()),
        Box::new(|p| p.plan.alias = "other::universal".parse().unwrap()),
        Box::new(|p| p.plan.created_at_ns += 1),
        Box::new(|p| p.plan.chain_id = "other".into()),
        Box::new(|p| p.plan.payload = Some(norito::json!({"amount": "1000"}))),
        Box::new(|p| p.plan.artifact_hex.push_str("00")),
        Box::new(|p| {
            let mut bytes = hex::decode(&p.signature_hex).unwrap();
            bytes[0] ^= 1;
            p.signature_hex = hex::encode(bytes);
        }),
    ];
    for mutate in mutations {
        let mut changed = prepared.clone();
        mutate(&mut changed);
        assert!(validate_plan(&changed, &config).is_err());
    }
    let mut later = prepared.clone();
    later.plan.created_at_ns += 1;
    refresh_prepared_call(&config, &mut later)?;
    validate_plan(&later, &config)?;
    assert_ne!(later.operation_id()?, prepared.operation_id()?);
    assert!(
        validate_call_transaction(&later.plan, &step).is_err(),
        "an earlier identical call must not satisfy a new operation"
    );
    later.plan.intent.metadata.remove(&operation_metadata_key());
    later.signature_hex = hex::encode(
        Signature::try_new(
            config.key_pair.private_key(),
            &plan_signing_bytes(&later.plan)?,
        )?
        .payload(),
    );
    assert!(
        validate_plan(&later, &config).is_err(),
        "even a signed plan must retain its operation tag"
    );
    // Re-signing the exact executable without the plan-bound operation metadata is a substitution.
    let original = decode_transaction(&step)?;
    let changed = TransactionBuilder::new(
        config.network_id,
        config.account.clone(),
        prepared.plan.requested_fee.clone(),
    )
    .with_executable(original.instructions().clone())
    .try_sign(config.key_pair.private_key())?;
    assert!(
        validate_call_transaction(
            &prepared.plan,
            &transaction_record("contract-call", &changed)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn call_authorization_checked_totals_and_fixed_expiry_survive_recovery() -> Result<()> {
    use iroha::data_model::transaction::{FeeChargeKind, FeeChargeLimit};
    let (config, prepared, step) = fixture()?;
    let asset = prepared
        .plan
        .authorization
        .max_total_fees
        .keys()
        .next()
        .unwrap()
        .clone();
    let auth = CallAuthorization {
        signing_deadline_unix_ms: 60_000,
        max_total_fees: BTreeMap::from([(asset.clone(), Quantity::from(10_u32))]),
    };
    let fee = |amount| {
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                asset.clone(),
                Quantity::from(amount),
            )],
            std::num::NonZeroU64::new(1_500_000),
        )
    };
    auth.check_fees([&fee(4_u32), &fee(6_u32)])?;
    assert!(auth.check_fees([&fee(4_u32), &fee(7_u32)]).is_err());
    assert_eq!(auth.ttl_ms(59_999, 30_000)?, 1);
    assert!(auth.ttl_ms(60_000, 30_000).is_err());
    assert!(auth.require_signing().is_err());
    // Expired signing authorization does not invalidate an already signed exact transaction.
    validate_plan(&prepared, &config)?;
    validate_call_transaction(&prepared.plan, &step)?;
    let original = decode_transaction(&step)?;
    let mut changed = original.payload().clone();
    changed.time_to_live_ms = std::num::NonZeroU64::new(60_000);
    let changed = Client::new(config.clone())?
        .account_client()
        .sign_transaction(changed)?;
    assert!(validate_transaction_expiry(&prepared.plan, &changed).is_err());
    assert!(
        validate_call_transaction(
            &prepared.plan,
            &transaction_record("contract-call", &changed)
        )
        .is_err()
    );
    let bytes = norito::json::to_vec(&prepared)?;
    let roundtrip: PreparedContractCall = norito::json::from_slice(&bytes)?;
    assert_eq!(roundtrip.operation_id()?, prepared.operation_id()?);
    for field in ["authorization", "transaction_ttl_ms", "call"] {
        let mut missing: Value = norito::json::from_slice(&bytes)?;
        missing
            .as_object_mut()
            .unwrap()
            .get_mut("plan")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(norito::json::from_value::<PreparedContractCall>(missing).is_err());
    }
    let mut null: Value = norito::json::from_slice(&bytes)?;
    null.as_object_mut()
        .unwrap()
        .get_mut("plan")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("call".into(), Value::Null);
    assert!(norito::json::from_value::<PreparedContractCall>(null).is_err());
    Ok(())
}

#[test]
fn contract_arguments_are_admitted_before_decode_and_bind_local_schema() -> Result<()> {
    assert!(parse_contract_arguments(&format!("\"{}\"", "x".repeat(64 * 1024))).is_err());
    let depth = format!("{}0{}", "[".repeat(129), "]".repeat(129));
    assert!(parse_contract_arguments(&depth).is_err());
    let many = format!("[{}]", vec!["0"; 8193].join(","));
    assert!(parse_contract_arguments(&many).is_err());
    let (config, prepared, _) = fixture()?;
    let artifact = kotodama_lang::compiler::Compiler::new().compile_source("seiyaku Example { permission Update;  kotoage fn write(int next) authorize(Update) {} view fn read() authorize(anyone) -> int { return 1; } }").map_err(|error| eyre!(error))?;
    let (intent, payload) = trusted_contract_intent(
        &artifact,
        prepared.contract_address().clone(),
        "write",
        parse_contract_arguments(r#"{"next":"7"}"#)?,
        false,
    )?;
    validate_trusted_intent(&artifact, &intent, &payload, false)?;
    assert!(
        validate_trusted_intent(
            &artifact,
            &intent,
            &Some(norito::json!({"next":"8"})),
            false
        )
        .is_err()
    );
    assert!(intent.invocation.arguments.is_some());
    assert!(payload.is_some());
    let unexpected = trusted_contract_intent(
        &artifact,
        prepared.contract_address().clone(),
        "write",
        norito::json!({"wrong":"7"}),
        false,
    )
    .expect_err("undeclared argument name");
    assert!(
        unexpected.to_string().contains("argument `next`"),
        "{unexpected:#}"
    );
    let number = trusted_contract_intent(
        &artifact,
        prepared.contract_address().clone(),
        "write",
        norito::json!({"next": 7}),
        false,
    )
    .expect_err("JSON numbers are not int arguments");
    assert_eq!(
        number.to_string(),
        "arguments do not match the verified entrypoint schema: argument `next` expects int as \
         a canonical decimal integer string such as \"5\", found JSON number 7"
    );
    assert!(
        trusted_contract_intent(
            &artifact,
            prepared.contract_address().clone(),
            "read",
            norito::json!({}),
            false
        )
        .is_err()
    );
    let (_, payload) = trusted_contract_intent(
        &artifact,
        prepared.contract_address().clone(),
        "read",
        norito::json!({}),
        true,
    )?;
    assert!(payload.is_none());
    validate_plan(&prepared, &config)?;
    Ok(())
}
#[test]
fn hook_arguments_are_checked_without_a_contract_address() -> Result<()> {
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source(
            "seiyaku Vault { state int limit; hajimari(int start) { limit = start; } view fn current() authorize(anyone) -> int { return limit; } }",
        )
        .map_err(|error| eyre!(error))?;
    check_contract_arguments(&artifact, "hajimari", &norito::json!({"start": "5"}), false)?;
    let missing = check_contract_arguments(&artifact, "hajimari", &norito::json!({}), false)
        .expect_err("the hook declares one argument");
    assert!(
        missing.to_string().contains("argument `start`"),
        "{missing:#}"
    );
    let number =
        check_contract_arguments(&artifact, "hajimari", &norito::json!({"start": 5}), false)
            .expect_err("JSON numbers are not int arguments");
    assert!(
        number.to_string().contains("found JSON number 5"),
        "{number:#}"
    );
    assert!(check_contract_arguments(&artifact, "current", &norito::json!({}), true).is_ok());
    assert!(check_contract_arguments(&artifact, "current", &norito::json!({}), false).is_err());
    assert!(check_contract_arguments(&artifact, "absent", &norito::json!({}), false).is_err());
    assert!(check_contract_arguments(b"", "hajimari", &norito::json!({}), false).is_err());
    Ok(())
}
#[test]
fn call_rejects_retired_payload_and_conflicting_retained_evidence() -> Result<()> {
    let (_, prepared, step) = fixture()?;
    let temporary = tempfile::tempdir()?;
    let journal = Journal::open(&temporary.path().join("call"), true)?;
    journal.put_exact(
        "attempt-0001.json",
        &TransactionAttempt {
            name: step.name.clone(),
            hash: step.hash.clone(),
        },
    )?;
    let retired = Journal::open(&temporary.path().join("retired-call"), true)?;
    retired.put_exact("call.json", &step)?;
    assert!(validate_stage_layout(&retired, &prepared.plan).is_err());
    validate_stage_layout(&journal, &prepared.plan)?;
    let transport = Transport {
        submits: Cell::new(0),
        ambiguous: Cell::new(false),
    };
    let mut false_evidence = transport.wait(decode_transaction(&step)?.hash())?;
    false_evidence.block_height += 1;
    journal.put_exact("applied-0001.json", &false_evidence)?;
    assert!(execute_step(&journal, &step, 1, &transport).is_err());
    assert_eq!(transport.submits.get(), 0);
    Ok(())
}
#[test]
fn call_both_signed_stages_are_retained_before_dispatch_and_grant_applies_first() -> Result<()> {
    let (config, mut prepared, _) = fixture()?;
    let artifact = hex::decode(&prepared.plan.artifact_hex)?;
    let verified = ivm_artifact_admission::verify_contract_artifact(&artifact)?;
    let permission =
        required_permission(&verified, &prepared.plan.intent)?.expect("guarded entrypoint");
    let grant = fixture_builder(&config, &prepared)?
        .with_instructions([Grant::account_permission(
            permission,
            config.account.clone(),
        )])
        .try_sign(config.key_pair.private_key())?;
    prepared.plan.grant = Some(transaction_record("entrypoint-grant", &grant));
    let step = refresh_prepared_call(&config, &mut prepared)?;
    validate_plan(&prepared, &config)?;
    let temporary = tempfile::tempdir()?;
    let journal = Journal::open(&temporary.path().join("call"), true)?;
    journal.put_exact("plan.json", &prepared)?;
    assert_eq!(
        read_call_plan(&journal)?.plan.call.norito_hex,
        step.norito_hex
    );
    validate_stage_layout(&journal, &prepared.plan)?;
    let bad = Journal::open(&temporary.path().join("bad-order"), true)?;
    bad.put_exact(
        "attempt-0001.json",
        &TransactionAttempt {
            name: step.name.clone(),
            hash: step.hash.clone(),
        },
    )?;
    assert!(validate_stage_layout(&bad, &prepared.plan).is_err());
    let transport = Transport {
        submits: Cell::new(0),
        ambiguous: Cell::new(true),
    };
    let retained_call = read_call_plan(&journal)?.plan.call;
    let grant = prepared.plan.grant.as_ref().unwrap();
    let error = execute_step(&journal, grant, 0, &transport).expect_err("ambiguous grant");
    assert!(error.downcast_ref::<ContractCallPending>().is_some());
    assert_eq!(transport.submits.get(), 1);
    let recovered = read_call_plan(&journal)?;
    assert_eq!(recovered.operation_id()?, prepared.operation_id()?);
    assert_eq!(recovered.plan.call.norito_hex, retained_call.norito_hex);
    assert!(!journal.exists("attempt-0001.json")?);
    transport.ambiguous.set(false);
    execute_step(
        &journal,
        prepared.plan.grant.as_ref().unwrap(),
        0,
        &transport,
    )?;
    validate_stage_layout(&journal, &prepared.plan)?;
    execute_step(&journal, &step, 1, &transport)?;
    assert_eq!(
        transport.submits.get(),
        2,
        "grant recovery must not resubmit; the call is the second original dispatch"
    );
    let other = KeyPair::random();
    let wrong_grant = fixture_builder(&config, &prepared)?
        .with_instructions([Grant::account_permission(
            CanInvokeContractEntrypoint {
                contract: prepared.plan.intent.invocation.contract_address.clone(),
                entrypoint: "hajimari".into(),
            },
            AccountId::new(other.public_key().clone()),
        )])
        .try_sign(config.key_pair.private_key())?;
    prepared.plan.grant = Some(transaction_record("entrypoint-grant", &wrong_grant));
    refresh_prepared_call(&config, &mut prepared)?;
    assert!(validate_plan(&prepared, &config).is_err());
    Ok(())
}
#[test]
fn call_cancellation_rejects_any_attempt_or_foreign_operation() -> Result<()> {
    let (config, prepared, step) = fixture()?;
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("call");
    let service = ContractCallService::new(config)?;
    service.persist(&prepared, &path)?;
    assert_eq!(service.cancel(&path)?, prepared.operation_id()?);
    assert!(matches!(
        service.inspect(&path)?,
        ContractCallDisposition::Cancelled
    ));
    assert!(
        service
            .resume(&path)
            .unwrap_err()
            .to_string()
            .contains("cancelled")
    );
    let journal = Journal::open(&path, false)?;
    journal.put_exact(
        "attempt-0001.json",
        &TransactionAttempt {
            name: step.name.clone(),
            hash: step.hash.clone(),
        },
    )?;
    assert!(is_cancelled(&journal, &prepared).is_err());
    let foreign = Journal::open(&temporary.path().join("foreign"), true)?;
    foreign.put_exact("cancelled.json", &"wrong-operation")?;
    assert!(is_cancelled(&foreign, &prepared).is_err());
    Ok(())
}

#[test]
fn call_failure_cannot_overwrite_applied_or_change_the_exact_hash() -> Result<()> {
    struct FailedTransport {
        different_hash: bool,
    }
    impl DeploymentTransport for FailedTransport {
        fn submit(&self, _: &SignedTransaction) -> Result<()> {
            panic!("retained attempts must never be submitted again");
        }
        fn wait(&self, hash: HashOf<SignedTransaction>) -> Result<AppliedEvidence> {
            let bound_hash = if self.different_hash {
                HashOf::from_untyped_unchecked(Hash::new(b"different transaction"))
            } else {
                hash
            };
            let response = norito::json::from_value(norito::json!({
                "hash": (bound_hash.to_string()), "scope": "global", "resolved_from": "state",
                "status": { "kind": "Rejected" }
            }))?;
            let proof = TransactionFinalityFailure::from_response(bound_hash, response)?
                .expect("canonical rejection fixture");
            Err(eyre::Report::new(proof))
        }
    }
    let (_, _, step) = fixture()?;
    for retained_applied in [false, true] {
        let temporary = tempfile::tempdir()?;
        let journal = Journal::open(&temporary.path().join("call"), true)?;
        journal.put_exact(
            "attempt-0001.json",
            &TransactionAttempt {
                name: step.name.clone(),
                hash: step.hash.clone(),
            },
        )?;
        if retained_applied {
            let transport = Transport {
                submits: Cell::new(0),
                ambiguous: Cell::new(false),
            };
            journal.put_exact(
                "applied-0001.json",
                &transport.wait(decode_transaction(&step)?.hash())?,
            )?;
        }
        assert!(
            execute_step(
                &journal,
                &step,
                1,
                &FailedTransport {
                    different_hash: true
                }
            )
            .is_err()
        );
        assert!(!journal.exists("failed-0001.json")?);
        let error = execute_step(
            &journal,
            &step,
            1,
            &FailedTransport {
                different_hash: false,
            },
        )
        .expect_err("rejection is terminal or contradicts retained Applied evidence");
        assert_eq!(journal.exists("failed-0001.json")?, !retained_applied);
        if retained_applied {
            assert!(error.to_string().contains("conflicts"));
        } else {
            assert!(error.downcast_ref::<TransactionFinalityFailure>().is_some());
        }
    }
    let hash = decode_transaction(&step)?.hash();
    let make_proof = |hash: HashOf<SignedTransaction>| -> Result<TransactionFinalityFailure> {
        let response = norito::json::from_value(norito::json!({
            "hash": (hash.to_string()), "scope": "global", "resolved_from": "state",
            "status": { "kind": "Rejected" }
        }))?;
        Ok(TransactionFinalityFailure::from_response(hash, response)?.expect("rejection"))
    };
    let proof = make_proof(hash)?;
    for foreign in [false, true] {
        let temporary = tempfile::tempdir()?;
        let journal = Journal::open(&temporary.path().join("call"), true)?;
        if foreign {
            journal.put_exact(
                "failed-0001.json",
                &make_proof(HashOf::from_untyped_unchecked(Hash::new(
                    b"another operation",
                )))?,
            )?;
        } else {
            journal.put_exact("failed-0001.json", &"malformed retained failure")?;
        }
        assert!(
            validate_retained_failure(&journal, 1, hash, &proof).is_err(),
            "bad retained evidence must not release the operation gate"
        );
    }
    Ok(())
}

/// Read one bounded HTTP/1.1 request head and its `Content-Length` body from a fixture socket.
fn read_fixture_request(stream: &mut std::net::TcpStream) -> Result<(String, Vec<u8>)> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.len() > 64 * 1024 {
            return Err(eyre!("resolution fixture headers exceed bound"));
        }
    }
    let headers = String::from_utf8(bytes)?;
    let length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>())
        })
        .transpose()?
        .unwrap_or(0);
    if length > 64 * 1024 {
        return Err(eyre!("resolution fixture body exceeds bound"));
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    Ok((headers, body))
}

#[test]
fn call_standalone_resolution_uses_configured_discriminant_and_restores_caller() -> Result<()> {
    use std::{io::Write as _, net::TcpListener, thread, time::Instant};
    let (mut config, prepared, _) = fixture()?;
    config.account_chain_discriminant = 42;
    let expected_authority = config.account.to_i105_for_discriminant(42)?;
    let alias = prepared.plan.alias.clone();
    let expected_address = prepared.plan.intent.invocation.contract_address.clone();
    let capabilities = norito::json::to_vec(&norito::json!({
        "data_model_version": (iroha::data_model::DATA_MODEL_VERSION),
        "signed_transaction_schema_hash_hex": (hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>()))
    }))?;
    let state = norito::json::to_vec(&norito::json!({
        "authority": (expected_authority.clone()), "contract_alias": (alias.to_string()),
        "deploy_nonce": "8", "dataspace_alias": "universal", "dataspace_id": "0",
        "previous_contract_address": (expected_address.to_string()),
        "observed_block_height": "9",
        "observed_block_hash": (HashOf::<iroha::data_model::block::BlockHeader>::from_untyped_unchecked(Hash::new(b"deployment state response fixture")).to_string()),
        "ledger_time_ms": "1000", "chain_discriminant": "42"
    }))?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    config.torii_api_url = format!("http://{}/", listener.local_addr()?).parse()?;
    let server = thread::spawn(move || -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        for (index, response) in [capabilities, state].into_iter().enumerate() {
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err(eyre!("resolution fixture timed out"));
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            let (headers, body) = read_fixture_request(&mut stream)?;
            if index == 0 {
                assert!(headers.starts_with("GET /v1/node/capabilities "));
            } else {
                assert!(headers.starts_with("POST /v1/contracts/deployment-state "));
                assert!(
                    headers
                        .to_ascii_lowercase()
                        .contains("\r\nx-iroha-signature:")
                );
                let request: Value = norito::json::from_slice(&body)?;
                assert_eq!(
                    request.get("authority").and_then(Value::as_str),
                    Some(expected_authority.as_str())
                );
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )?;
            stream.write_all(&response)?;
        }
        Ok(())
    });
    let service = ContractCallService::new(config)?;
    let _caller_profile = ChainDiscriminantGuard::enter(73);
    let resolved = service.resolve_address(&alias);
    assert_eq!(
        iroha::data_model::account::address::chain_discriminant(),
        73
    );
    server
        .join()
        .map_err(|_| eyre!("resolution fixture panicked"))??;
    assert_eq!(resolved?, expected_address);
    Ok(())
}
#[test]
fn simulated_gas_gains_bounded_headroom() {
    assert_eq!(gas_limit_with_headroom(0), 10_000);
    assert_eq!(gas_limit_with_headroom(100_000), 160_000);
    assert_eq!(gas_limit_with_headroom(1_000_001), 1_510_001);
    assert_eq!(gas_limit_with_headroom(9_000_000), MAX_CALL_GAS_LIMIT);
    assert_eq!(gas_limit_with_headroom(u64::MAX), MAX_CALL_GAS_LIMIT);
    const { assert!(UNSIMULATED_CALL_GAS_LIMIT <= MAX_CALL_GAS_LIMIT) };
}
#[test]
fn simulation_responses_are_bound_to_the_exact_intent() -> Result<()> {
    let (_, prepared, _) = fixture()?;
    let intent = &prepared.plan.intent;
    let code_hash = hex::encode(intent.invocation.expected_code_hash.as_ref());
    let executed = norito::json!({
        "ok": true, "code_hash_hex": (code_hash.clone()), "entrypoint": "hajimari",
        "gas_used": 1234, "error": null, "vm_diagnostic": null
    });
    assert_eq!(
        interpret_call_simulation(&executed, intent)?,
        CallSimulation::Executed { gas_used: 1234 }
    );
    let rejected = norito::json!({
        "ok": false, "code_hash_hex": (code_hash.clone()), "entrypoint": "hajimari",
        "gas_used": 77, "error": "contract rejected: ZeroStep", "vm_diagnostic": null
    });
    assert_eq!(
        interpret_call_simulation(&rejected, intent)?,
        CallSimulation::Rejected {
            message: "contract rejected: ZeroStep".to_owned(),
            gas_used: 77,
        }
    );
    let foreign = norito::json!({
        "ok": true, "code_hash_hex": ("00".repeat(32)), "entrypoint": "hajimari", "gas_used": 1
    });
    assert!(interpret_call_simulation(&foreign, intent).is_err());
    let other_entrypoint = norito::json!({
        "ok": true, "code_hash_hex": (code_hash.clone()), "entrypoint": "other", "gas_used": 1
    });
    assert!(interpret_call_simulation(&other_entrypoint, intent).is_err());
    let missing_gas = norito::json!({
        "ok": true, "code_hash_hex": (code_hash), "entrypoint": "hajimari"
    });
    assert!(interpret_call_simulation(&missing_gas, intent).is_err());
    Ok(())
}
#[test]
fn applied_charge_projects_the_committed_fee_receipt() -> Result<()> {
    use iroha::data_model::block::consensus::{
        NexusFeeReceipt, NexusFeeScheduleInputs, NexusFeeSettlementV1,
    };
    let (config, _, _) = fixture()?;
    let asset = AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::parse_fully_qualified("wonderland.universal")?,
        "xor".parse()?,
    );
    let mut result = TransactionResult::new(Ok(Vec::default()));
    assert_eq!(AppliedCharge::from_result(&result), None);
    result.set_nexus_fee_receipt(Some(NexusFeeReceipt {
        version: NexusFeeReceipt::VERSION,
        source_id: [1; 32],
        dataspace_id: DataSpaceId::UNIVERSAL,
        lane_id: iroha_model_base::topology::LaneId::new(0),
        block_height: 9,
        debit_source: iroha::data_model::nexus::FeeDebitSource::Account(config.account.clone()),
        fee_asset_id: asset.clone(),
        program_revision: None,
        lease_id: None,
        fee_amount: Quantity::from(3_u32),
        settlement: NexusFeeSettlementV1::Burn,
        schedule: NexusFeeScheduleInputs {
            tx_bytes_len: 100,
            instruction_count: 1,
            gas_used: 4_321,
            base_fee: Quantity::from(3_u32),
            per_byte_fee: Quantity::zero(),
            per_instruction_fee: Quantity::zero(),
            per_gas_unit_fee: Quantity::zero(),
        },
    }));
    let charge = AppliedCharge::from_result(&result).expect("committed charge");
    assert_eq!(charge.gas_used, 4_321);
    assert_eq!(charge.fee_asset, asset);
    assert_eq!(charge.fee_amount, Quantity::from(3_u32));
    let evidence = AppliedEvidence {
        hash: "hash".to_owned(),
        terminal_kind: "Applied".to_owned(),
        block_height: 9,
        scope: "global".to_owned(),
        resolved_from: "state".to_owned(),
        charge: Some(charge),
    };
    let encoded = norito::json::to_value(&evidence)?;
    assert_eq!(
        encoded.pointer("/charge/gas_used").and_then(Value::as_u64),
        Some(4_321)
    );
    let decoded: AppliedEvidence = norito::json::from_value(encoded)?;
    assert_eq!(decoded, evidence);
    Ok(())
}
