#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Torii contract manifest endpoints: bytecode deploy wraps ISIs and GET reads the derived on-chain manifest.
#[path = "contracts/ivm_proved.rs"]
mod ivm_proved;
use eyre::{Result, eyre};
use integration_tests::{manifest::ManifestEncodingBudget, sandbox};
use iroha::crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha::data_model::prelude::*;
use iroha::data_model::{
    isi::smart_contract_code::{
        AcceptContractOwnership, ActivateContractInstance, DeactivateContractInstance,
        OfferContractOwnership, SetContractParliamentDelegation,
    },
    parameter::{
        CustomParameter, CustomParameterId,
        system::{ConsensusHandshakeMetadata, SumeragiConsensusMode, consensus_metadata},
    },
    smart_contract::{ContractAddress, ContractLifecycleOwnerV1},
};
use iroha_executor_data_model::permission::{
    account::{AccountAliasPermissionScope, CanManageAccountAlias},
    governance::CanEnactGovernance,
    smart_contract::CanManageSmartContractCode,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_sumeragi::availability::recommended_data_availability_layout;
use iroha_test_network::{NetworkBuilder, read_on_dedicated_thread};
use reqwest::StatusCode;
use std::time::{Duration, Instant};
use std::{num::NonZeroU64, str::FromStr as _};
fn minimal_contract_artifact() -> Vec<u8> {
    kotodama_lang::compiler::Compiler::new_with_options(kotodama_lang::compiler::CompilerOptions {
        max_cycles: 1_000,
        ..Default::default()
    })
    .compile_source("seiyaku TestContract { view fn main() authorize(anyone) { () } }")
    .expect("compile the minimal contract with its canonical callable table")
}

#[test]
fn minimal_contract_artifact_binds_unit_entrypoint_to_canonical_callable() {
    let artifact = minimal_contract_artifact();
    let verified = ivm::verify_contract_artifact(&artifact).expect("admit minimal contract");
    assert_eq!(verified.metadata.abi_version, 1);
    assert_eq!(verified.metadata.max_cycles, 1_000);
    let mut interface = verified.contract_interface;
    assert_eq!(interface.seiyaku_name, "TestContract");
    assert_eq!(interface.entrypoints.len(), 1);
    let entrypoint = &interface.entrypoints[0];
    assert_eq!(entrypoint.name, "main");
    assert_eq!(
        entrypoint.kind,
        iroha_data_model::smart_contract::manifest::EntryPointKind::View
    );
    assert!(entrypoint.params.is_empty());
    assert_eq!(entrypoint.return_type.as_deref(), Some("()"));
    assert_eq!(
        entrypoint.authorization,
        iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone
    );
    assert!(interface.permissions.is_empty());
    assert_eq!(interface.callables.len(), 1);
    let callable = &interface.callables[0];
    assert_eq!(callable.entry_pc, entrypoint.entry_pc);
    assert_ne!(callable.entry_pc, 0, "raw entry must not dispatch main");
    assert!(callable.validate());
    assert_eq!(callable.arguments, ivm::call::CallSchemaV1::empty());
    assert_eq!(callable.results, ivm::call::CallSchemaV1::unit());

    // Preserve all remaining compiler sections while removing only the
    // authenticated callable descriptor; admission must reject that omission.
    let section_end = verified.header_len + interface.encode_section().len();
    interface.callables.clear();
    let mut missing_callable = artifact[..verified.header_len].to_vec();
    missing_callable.extend_from_slice(&interface.encode_section());
    missing_callable.extend_from_slice(&artifact[section_end..]);
    let error = ivm::verify_contract_artifact(&missing_callable)
        .expect_err("public entrypoints require their canonical callable descriptors");
    assert!(
        error.to_string().contains(
            "CNTR callable descriptors must cover exactly every entrypoint and direct-call root"
        ),
        "unexpected admission error: {error}"
    );
}

// The 200-entry probe uses about 3.9M gas locally. Reserve headroom for
// instance-scoped state paths and bounded scan precharges on real validators.
const CONTRACT_STATE_PROBE_GAS_LIMIT: u64 = 5_000_000;

// Proposal selection reserves the full signed call bound. Grant this isolated
// workload the same block budget in genesis, without changing node defaults.
fn contract_probe_block_gas_parameter() -> Parameter {
    Parameter::Custom(CustomParameter::new(
        CustomParameterId::new(
            "ivm_gas_limit_per_block"
                .parse()
                .expect("canonical block gas parameter name"),
        ),
        iroha_primitives::json::Json::new(CONTRACT_STATE_PROBE_GAS_LIMIT),
    ))
}

#[test]
fn contract_v1_probe_block_gas_budget_matches_signed_call_limit() {
    let parameter = contract_probe_block_gas_parameter();
    let encoded = norito::to_bytes(&parameter).expect("encode governed block gas parameter");
    let decoded: Parameter =
        norito::decode_from_bytes(&encoded).expect("decode governed block gas parameter");
    assert_eq!(decoded, parameter);
    let Parameter::Custom(custom) = decoded else {
        panic!("the block gas budget must use the canonical custom parameter");
    };
    assert_eq!(custom.id().name().as_ref(), "ivm_gas_limit_per_block");
    assert_eq!(
        custom.payload().get(),
        "5000000",
        "canonical numeric u64 JSON"
    );
    let budget: u64 = norito::json::from_str(custom.payload().get())
        .expect("block gas budget must decode as u64");
    assert!(budget > 0);
    assert_eq!(budget, CONTRACT_STATE_PROBE_GAS_LIMIT);
}

fn contract_state_probe_artifact() -> Vec<u8> {
    let src = r#"
seiyaku ContractStateProbe { import permission "CanEnactGovernance" as CanEnactGovernance;
  error enum ProbeError {
    NotInitialized = 1;
    WrongValue = 2
  }

  struct Receipt { int recipient; int amount; () memo; }

  state int Initialized;
  state int StoredValue;
  state int probe_readback;
  state () Marker;
  state Result<(), ProbeError> Outcome;
  state StateMap<int, int> Entries;
  const int PAGE_SIZE = 32 * 2;

  fn paginated_sum() -> int {
    var Option<StateCursor<int>> cursor = Option::none;
    var sum = 0;
    for iteration in range(4) {
      let page = Entries.page(after: cursor, limit: PAGE_SIZE);
      for (key, value) in page.items { sum += value; }
      cursor = page.next;
    }
    return sum;
  }

  kotoage fn main() authorize(CanEnactGovernance) -> int {
    return 0;
  }

  fn initialize_impl() {
    Initialized = 1;
    StoredValue = 7;
    probe_readback = 0;
    Marker = ();
    Outcome = Result::ok(());
  }

  hajimari() {
    initialize_impl();
  }

  kotoage fn verify() authorize(CanEnactGovernance) {
    require(Initialized == 1, ProbeError::NotInitialized);
    require(Marker == (), ProbeError::WrongValue);
    match Outcome {
      Result::ok(value) => { require(value == (), ProbeError::WrongValue); },
      Result::err(_) => { require(false, ProbeError::WrongValue); },
    };
    var List<int, 1> values = [StoredValue];
    match values.try_push(99) {
      Result::ok(_) => { require(false, ProbeError::WrongValue); },
      Result::err(failure) => {
        require(failure == ListError::CapacityExceeded, ProbeError::WrongValue);
      },
    };
    values.set(index: 0, value: StoredValue);
    let Receipt { amount, recipient: payee, memo: _ } =
      Receipt { amount: StoredValue, recipient: 2, memo: () };
    require(amount == 7 && payee == 2 && values.len() == 1, ProbeError::WrongValue);
    let rounded = decimal::from_int(amount).mul_div_round(
      multiplier: 2.0, divisor: 3.0, scale: 2, mode: Rounding::floor);
    require(rounded == 4.66, ProbeError::WrongValue);
    for index in range(200) { Entries[index] = index; }
    require(paginated_sum() == 19900, ProbeError::WrongValue);
    probe_readback = StoredValue;
  }

  view fn readback() authorize(anyone) -> int {
    require(Marker == (), ProbeError::WrongValue);
    match Outcome {
      Result::ok(value) => { require(value == (), ProbeError::WrongValue); },
      Result::err(_) => { require(false, ProbeError::WrongValue); },
    };
    require(paginated_sum() == 19900, ProbeError::WrongValue);
    return probe_readback;
  }
}
"#;
    kotodama_lang::compiler::Compiler::new()
        .compile_source(src)
        .expect("compile contract-state probe program")
}
fn contract_probe_call_intent(
    artifact: &[u8],
    contract_address: &ContractAddress,
    contract_alias: &iroha_data_model::smart_contract::ContractAlias,
    entrypoint: &str,
) -> Result<iroha::client::ContractCallDraftIntent> {
    let verified = ivm::verify_contract_artifact(artifact)
        .map_err(|error| eyre!("verify contract probe artifact: {error}"))?;
    let descriptor = verified
        .contract_interface
        .entrypoints
        .iter()
        .find(|descriptor| descriptor.name == entrypoint)
        .ok_or_else(|| eyre!("contract probe entrypoint `{entrypoint}` is missing"))?;
    if !descriptor.params.is_empty() || descriptor.argument_schema.is_some() {
        return Err(eyre!(
            "contract probe `{entrypoint}` must have no arguments"
        ));
    }
    let mut metadata = Metadata::default();
    for (key, value) in [
        ("contract_address", contract_address.to_string()),
        ("contract_code_hash", verified.code_hash.to_string()),
        ("contract_alias", contract_alias.to_string()),
        ("contract_entrypoint", entrypoint.to_owned()),
    ] {
        metadata.insert(
            Name::from_str(key)?,
            iroha_primitives::json::Json::new(value),
        );
    }
    Ok(iroha::client::ContractCallDraftIntent {
        invocation: iroha_data_model::transaction::executable::ContractInvocation {
            contract_address: contract_address.clone(),
            expected_code_hash: verified.code_hash,
            entrypoint: entrypoint.to_owned(),
            arguments: None,
        },
        metadata,
    })
}

// Exercise the real detached endpoint once, after the SDK validates the exact
// unsigned draft. The request-account signature and transaction signature have
// separate owners; only their public fields cross HTTP.
async fn submit_contract_probe_detached(
    client: &iroha::blocking::Client,
    contract_alias: &iroha_data_model::smart_contract::ContractAlias,
    intent: &iroha::client::ContractCallDraftIntent,
    gas_limit: u64,
) -> Result<norito::json::Value> {
    use base64::Engine as _;
    use iroha_torii::{
        HEADER_ACCOUNT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP_MS,
        canonical_network_request_signature_message, signature_header_value,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    assert_eq!(intent.invocation.entrypoint, "verify");
    assert!(intent.invocation.arguments.is_none());
    let prepared = client
        .account_client()
        .post_contract_call_json(
            &iroha_test_samples::ALICE_ID,
            None,
            None,
            Some(contract_alias),
            "verify",
            None,
            None,
            None,
            None,
            &FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(gas_limit)),
            intent,
        )
        .await?;
    let payload_b64 = prepared["transaction_payload_b64"]
        .as_str()
        .ok_or_else(|| eyre!("validated detached draft has no payload"))?;
    let payload_bytes = base64::engine::general_purpose::STANDARD.decode(payload_b64)?;
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(&payload_bytes),
        payload_b64
    );
    let builder = TransactionBuilder::decode_payload(&payload_bytes)?;
    assert_eq!(builder.encode_payload(), payload_bytes);
    let signing_message_b64 = prepared["signing_message_b64"]
        .as_str()
        .ok_or_else(|| eyre!("validated detached draft has no signing message"))?;
    let signing_message = base64::engine::general_purpose::STANDARD.decode(signing_message_b64)?;
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(&signing_message),
        signing_message_b64
    );
    assert_eq!(signing_message, builder.payload_hash_bytes());
    let transaction_signature = iroha_crypto::Signature::try_new(
        iroha_test_samples::ALICE_KEYPAIR.private_key(),
        &signing_message,
    )?;
    let signed = builder
        .clone()
        .build_with_signature(transaction_signature.clone());
    signed.verify_signature()?;
    assert_eq!(signed.payload(), builder.payload());
    assert_eq!(
        TransactionBuilder::from_payload(signed.payload().clone())?.encode_payload(),
        payload_bytes
    );
    let tx_hash_hex = hex::encode(signed.hash().as_ref());
    let entrypoint_hash_hex = hex::encode(signed.hash_as_entrypoint().as_ref());
    let request = norito::json!({
        "authority": (iroha_test_samples::ALICE_ID.clone()),
        "public_key_hex": (hex::encode(iroha_test_samples::ALICE_KEYPAIR.public_key().to_bytes().1)),
        "signature_b64": (base64::engine::general_purpose::STANDARD.encode(transaction_signature.payload())),
        "transaction_payload_b64": payload_b64,
        "contract_alias": (contract_alias.clone()),
        "entrypoint": "verify",
        "creation_time_ms": (builder.payload().creation_time_ms),
        "transaction_ttl_ms": (prepared["transaction_ttl_ms"].clone()),
        "fee_payment": (builder.payload().fee_payment.clone()),
    });
    assert!(request.get("private_key").is_none());
    let body = norito::json::to_vec(&request)?;
    let bound_client = client.client();
    let url = bound_client.endpoint().join("v1/contracts/call")?;
    let uri: iroha_torii::Uri = match url.query() {
        Some(query) => format!("{}?{query}", url.path()).parse()?,
        None => url.path().parse()?,
    };
    let timestamp_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let nonce = format!(
        "contract-detached-{timestamp_ms}-{}",
        NONCE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let request_message = canonical_network_request_signature_message(
        bound_client.network_id(),
        &iroha_torii::Method::POST,
        &uri,
        &body,
        timestamp_ms,
        &nonce,
    )?;
    let request_signature =
        iroha_crypto::Signature::try_new(bound_client.key_pair().private_key(), &request_message)?;
    // Keep the existing integration HTTP timeout. Disable redirect/retry so this
    // signed POST cannot become an unobserved second submission.
    let http = reqwest::Client::builder()
        .timeout(integration_tests::http::request_timeout())
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()?;
    let response = http
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .header(HEADER_ACCOUNT, bound_client.account().to_canonical_hex()?)
        .header(
            HEADER_SIGNATURE,
            signature_header_value(&request_signature)?,
        )
        .header(HEADER_TIMESTAMP_MS, timestamp_ms.to_string())
        .header(HEADER_NONCE, nonce)
        .body(body)
        .send()
        .await?;
    let status = response.status();
    let response_bytes = response.bytes().await?;
    if status != StatusCode::OK {
        return Err(eyre!(
            "detached contract verify returned {status}: {}",
            String::from_utf8_lossy(&response_bytes)
        ));
    }
    let actual: norito::json::Value = norito::json::from_slice(&response_bytes)?;
    let root_fields = [
        "ok",
        "submitted",
        "dataspace",
        "contract_address",
        "code_hash_hex",
        "abi_hash_hex",
        "creation_time_ms",
        "transaction_ttl_ms",
        "tx_hash_hex",
        "pipeline_status",
        "entrypoint_hash_hex",
        "transaction_payload_b64",
        "signing_message_b64",
        "entrypoint",
        "operation_receipt",
    ];
    let receipt_fields = [
        "operation_kind",
        "status",
        "transport",
        "dataspace",
        "contract_alias",
        "contract_address",
        "code_hash_hex",
        "abi_hash_hex",
        "tx_hash_hex",
        "entrypoint",
        "entrypoint_hash_hex",
        "gas_limit",
        "gas_used",
        "fee_payment",
        "payload_digest_hex",
    ];
    for (object, fields) in [
        (actual.as_object(), root_fields.as_slice()),
        (
            actual["operation_receipt"].as_object(),
            receipt_fields.as_slice(),
        ),
    ] {
        let object = object
            .ok_or_else(|| eyre!("detached contract response must contain closed objects"))?;
        assert_eq!(object.len(), fields.len());
        for field in fields {
            assert!(
                object.contains_key(*field),
                "missing response field {field}"
            );
        }
    }
    let mut expected = prepared;
    let object = expected
        .as_object_mut()
        .expect("SDK-validated closed prepare response");
    object.insert("submitted".to_owned(), true.into());
    object.insert("tx_hash_hex".to_owned(), tx_hash_hex.clone().into());
    object.insert(
        "entrypoint_hash_hex".to_owned(),
        entrypoint_hash_hex.clone().into(),
    );
    object.insert(
        "transaction_payload_b64".to_owned(),
        norito::json::Value::Null,
    );
    object.insert("signing_message_b64".to_owned(), norito::json::Value::Null);
    object.insert("pipeline_status".to_owned(), norito::json::Value::Null);
    let receipt = object
        .get_mut("operation_receipt")
        .and_then(norito::json::Value::as_object_mut)
        .expect("SDK-validated closed receipt");
    receipt.insert("status".to_owned(), "submitted".into());
    receipt.insert("tx_hash_hex".to_owned(), tx_hash_hex.into());
    receipt.insert("entrypoint_hash_hex".to_owned(), entrypoint_hash_hex.into());
    assert_eq!(
        actual, expected,
        "detached submit must preserve every exact draft binding and only advance submission fields"
    );
    Ok(actual)
}

fn contract_probe_call_observation(
    entrypoint: &str,
    transaction_hash: &str,
    unix_time_ms: u128,
) -> Result<String> {
    if !matches!(entrypoint, "hajimari" | "verify")
        || transaction_hash.len() != 64
        || !transaction_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || unix_time_ms == 0
    {
        return Err(eyre!(
            "contract probe observation requires an exact public stage/hash/timestamp"
        ));
    }
    Ok(format!(
        "KOTODAMA_CONTRACT_CALL stage={entrypoint} hash={transaction_hash} unix_time_ms={unix_time_ms}"
    ))
}

fn contract_probe_genesis_registration(
    artifact: &[u8],
    encoding: &ManifestEncodingBudget,
) -> Result<Vec<InstructionBox>> {
    use iroha_data_model::isi::smart_contract_code::{
        RegisterSmartContractBytes, RegisterSmartContractCode,
    };
    let registrar_key = &iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR;
    let registrar = AccountId::new(registrar_key.public_key().clone());
    let verified = ivm::verify_contract_artifact(artifact)
        .map_err(|error| eyre!("verify genesis contract probe artifact: {error}"))?;
    let manifest = verified
        .manifest
        .try_signed(
            encoding.context(),
            encoding.max_frame_bytes(),
            registrar_key,
        )
        .map_err(|error| eyre!("sign genesis contract probe manifest: {error}"))?;
    let permission: Permission = CanManageSmartContractCode.into();
    Ok(vec![
        Grant::account_permission(permission, registrar).into(),
        RegisterSmartContractBytes {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                verified.code_hash,
            ),
            code: artifact.to_vec(),
        }
        .into(),
        {
            let scoped_manifest = manifest;
            RegisterSmartContractCode {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    scoped_manifest
                        .code_hash
                        .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
                ),
                manifest: scoped_manifest,
            }
        }
        .into(),
    ])
}

fn contract_probe_alias_management_permission() -> CanManageAccountAlias {
    CanManageAccountAlias {
        scope: AccountAliasPermissionScope::Alias(
            iroha_data_model::alias_setup::ResolvedAccountAliasV1::new(
                "contract_state_probe@universal"
                    .parse()
                    .expect("canonical contract probe alias permission"),
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            ),
        ),
    }
}

fn contract_deployment_instructions(
    commit: iroha_data_model::isi::smart_contract_code::CommitContractDeployment,
    hajimari_grantee: Option<&AccountId>,
) -> Vec<InstructionBox> {
    let contract_address = commit.contract_address.clone();
    let mut instructions = vec![InstructionBox::from(commit)];
    if let Some(grantee) = hajimari_grantee {
        // Deployment stages the hook; its caller still needs an exact invocation grant.
        // Keep that grant after Commit in the same ordinary ordered transaction.
        let permission: Permission =
            iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint {
                contract: contract_address,
                entrypoint: "hajimari".to_owned(),
            }
            .into();
        instructions.push(Grant::account_permission(permission, grantee.clone()).into());
    }
    instructions
}

#[test]
fn contract_v1_deployment_grants_only_the_exact_hajimari_invocation() {
    use iroha_data_model::isi::smart_contract_code::CommitContractDeployment;
    use iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint;

    let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"contract-probe-deployment-grant",
    )));
    let address = |nonce| {
        ContractAddress::derive(
            &network,
            &iroha_test_samples::ALICE_ID,
            nonce,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .expect("derive exact fixture address")
    };
    let contract_address = address(0);
    let commit = CommitContractDeployment {
        expected_deploy_nonce: 0,
        contract_address: contract_address.clone(),
        code_hash: Hash::new(b"exact-probe-artifact"),
        contract_alias: iroha_data_model::smart_contract::ContractAlias::from_components(
            "contract_state_probe",
            None,
            "universal",
        )
        .expect("probe alias"),
        lease_expiry_ms: None,
        expected_previous_contract_address: None,
    };
    let exact: Permission = CanInvokeContractEntrypoint {
        contract: contract_address.clone(),
        entrypoint: "hajimari".to_owned(),
    }
    .into();
    let expected: Vec<InstructionBox> = vec![
        commit.clone().into(),
        Grant::account_permission(exact.clone(), iroha_test_samples::ALICE_ID.clone()).into(),
    ];
    let actual =
        contract_deployment_instructions(commit.clone(), Some(&iroha_test_samples::ALICE_ID));
    assert_eq!(
        actual, expected,
        "Commit must precede the exact Alice hook grant"
    );
    assert_eq!(
        contract_deployment_instructions(commit.clone(), None),
        vec![InstructionBox::from(commit)],
        "other deployment fixtures retain their original instructions",
    );
    for (permission, grantee) in [
        (
            CanInvokeContractEntrypoint {
                contract: address(1),
                entrypoint: "hajimari".to_owned(),
            }
            .into(),
            iroha_test_samples::ALICE_ID.clone(),
        ),
        (
            CanInvokeContractEntrypoint {
                contract: contract_address,
                entrypoint: "verify".to_owned(),
            }
            .into(),
            iroha_test_samples::ALICE_ID.clone(),
        ),
        (exact, iroha_test_samples::BOB_ID.clone()),
        (
            Permission::new(
                "CanInvokeContractEntrypoint".to_owned(),
                iroha_primitives::json::Json::new(()),
            ),
            iroha_test_samples::ALICE_ID.clone(),
        ),
    ] {
        let wrong: InstructionBox = Grant::account_permission(permission, grantee).into();
        assert_ne!(
            actual[1], wrong,
            "a different identity or unscoped token is not the hook grant"
        );
    }
    let mut reversed = expected;
    reversed.reverse();
    assert_ne!(
        actual, reversed,
        "grant order is part of the fixture contract"
    );
}

#[test]
fn contract_v1_alias_permission_is_exact() {
    let permission = contract_probe_alias_management_permission();
    let AccountAliasPermissionScope::Alias(alias) = permission.scope else {
        panic!("contract probe must not receive a domain- or dataspace-wide alias grant");
    };
    assert_eq!(alias.canonical_text(), "contract_state_probe@universal");
    assert_eq!(
        alias.dataspace_id,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL
    );
}

#[test]
fn contract_v1_genesis_registration_preserves_artifact_and_registrar() {
    use iroha_data_model::isi::smart_contract_code::{
        RegisterSmartContractBytes, RegisterSmartContractCode,
    };
    let encoding = ManifestEncodingBudget::new().expect("admit fixture manifest budget");
    let artifact = contract_state_probe_artifact();
    let verified = ivm::verify_contract_artifact(&artifact).expect("verify probe artifact");
    let registrar_key = &iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR;
    let registrar = AccountId::new(registrar_key.public_key().clone());
    let permission: Permission = CanManageSmartContractCode.into();
    let expected: Vec<InstructionBox> = vec![
        Grant::account_permission(permission, registrar).into(),
        RegisterSmartContractBytes {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                verified.code_hash,
            ),
            code: artifact.clone(),
        }
        .into(),
        {
            let scoped_manifest = verified
                .manifest
                .try_signed(
                    encoding.context(),
                    encoding.max_frame_bytes(),
                    registrar_key,
                )
                .expect("sign manifest");
            RegisterSmartContractCode {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    scoped_manifest
                        .code_hash
                        .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
                ),
                manifest: scoped_manifest,
            }
        }
        .into(),
    ];
    let actual =
        contract_probe_genesis_registration(&artifact, &encoding).expect("genesis registration");
    assert_eq!(
        actual, expected,
        "permission must precede exact bytes and signed manifest"
    );
    let registered = actual[2]
        .as_any()
        .downcast_ref::<RegisterSmartContractCode>()
        .expect("signed manifest instruction");
    let signed = registered.manifest();
    let provenance = signed.provenance.as_ref().expect("registrar provenance");
    provenance
        .signature
        .verify(
            registrar_key.public_key(),
            &signed
                .signature_payload_bytes(encoding.context(), encoding.max_frame_bytes())
                .expect("bounded canonical signature payload"),
        )
        .expect("canonical manifest signature must verify");
    assert_eq!(signed.code_hash, Some(verified.code_hash));
    assert_eq!(signed.abi_hash, Some(verified.abi_hash));
    assert!(contract_probe_genesis_registration(b"not a contract artifact", &encoding).is_err());
}

#[test]
fn contract_v1_four_validator_probe_compiles_final_syntax() {
    let artifact = contract_state_probe_artifact();
    let parsed = ivm::ProgramMetadata::parse(&artifact).expect("parse V1 network probe");
    let interface = parsed.contract_interface.expect("signed V1 interface");
    assert!(interface.states.iter().any(|state| state.name == "Entries"));
    assert!(
        interface
            .error_types
            .iter()
            .any(|ty| ty.identity == "kotodama::ListError")
    );
    let address = ContractAddress::derive(
        &NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"contract-probe-test-network",
        ))),
        &iroha_test_samples::ALICE_ID,
        0,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("derive probe address");
    let alias = iroha_data_model::smart_contract::ContractAlias::from_components(
        "contract_state_probe",
        None,
        "universal",
    )
    .expect("probe alias");
    for entrypoint in ["hajimari", "verify"] {
        let intent = contract_probe_call_intent(&artifact, &address, &alias, entrypoint)
            .expect("bind exact zero-argument probe call");
        assert_eq!(intent.invocation.contract_address, address);
        assert_eq!(intent.invocation.entrypoint, entrypoint);
        assert!(intent.invocation.arguments.is_none());
        assert_eq!(intent.metadata.iter().count(), 4);
        assert_eq!(
            intent
                .metadata
                .get(&Name::from_str("contract_alias").unwrap()),
            Some(&iroha_primitives::json::Json::new(alias.to_string())),
        );
        assert!(
            intent
                .metadata
                .get(&Name::from_str("contract_payload").unwrap())
                .is_none()
        );
    }
    assert!(contract_probe_call_intent(&artifact, &address, &alias, "missing").is_err());
    let hash = "ab".repeat(32);
    for entrypoint in ["hajimari", "verify"] {
        assert_eq!(
            contract_probe_call_observation(entrypoint, &hash, 123).unwrap(),
            format!("KOTODAMA_CONTRACT_CALL stage={entrypoint} hash={hash} unix_time_ms=123"),
        );
    }
    assert!(contract_probe_call_observation("other", &hash, 123).is_err());
    assert!(contract_probe_call_observation("verify", "abcd", 123).is_err());
    assert!(contract_probe_call_observation("verify", &"AB".repeat(32), 123).is_err());
    assert!(contract_probe_call_observation("verify", &hash, 0).is_err());
}
fn dynamic_access_counter_artifact() -> Vec<u8> {
    let src = r#"
seiyaku DynamicAccessCounter { import permission "CanEnactGovernance" as CanEnactGovernance;
  state StateMap<int, int> Counters;

  fn bump_hidden(int key, int delta) {
    let current = Counters.get(key).unwrap_or(0);
    Counters[key] = current + delta;
  }

  kotoage fn bump_direct(int key, int delta) authorize(CanEnactGovernance) {
    let current = Counters.get(key).unwrap_or(0);
    Counters[key] = current + delta;
  }

  kotoage fn bump_via_helper(int key, int delta) authorize(CanEnactGovernance) {
    bump_hidden(key: key, delta: delta);
  }
}
"#;
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source(src)
        .expect("compile dynamic-access counter program");
    let parsed = ivm::ProgramMetadata::parse(&artifact).expect("parse dynamic-access metadata");
    let interface = parsed
        .contract_interface
        .expect("dynamic-access contract interface");
    for entrypoint_name in ["bump_direct", "bump_via_helper"] {
        let entrypoint = interface
            .entrypoints
            .iter()
            .find(|entrypoint| entrypoint.name == entrypoint_name)
            .unwrap_or_else(|| panic!("missing `{entrypoint_name}` entrypoint"));
        assert!(
            entrypoint.write_keys.iter().any(|key| key == "state:*"),
            "`{entrypoint_name}` must transitively report the dynamic StateMap write: {entrypoint:?}"
        );
        assert_eq!(entrypoint.access_hints_complete, Some(false));
        assert!(
            entrypoint
                .access_hints_skipped
                .iter()
                .any(|reason| reason == "dynamic state path is not compiler-resolved")
        );
    }
    artifact
}
fn typed_core_query_pager_artifact() -> Vec<u8> {
    let source = r#"
seiyaku TypedCoreQueryPager {
  view fn accounts(int offset, int limit) authorize(anyone) -> QueryPage<AccountView> {
    ledger::query::accounts(offset: offset, limit: limit)
  }

  view fn assets(int offset, int limit) authorize(anyone) -> QueryPage<AssetView> {
    ledger::query::assets(offset: offset, limit: limit)
  }

  view fn asset_definitions(int offset, int limit) authorize(anyone) -> QueryPage<AssetDefinitionView> {
    ledger::query::asset_definitions(offset: offset, limit: limit)
  }

  view fn domains(int offset, int limit) authorize(anyone) -> QueryPage<DomainView> {
    ledger::query::domains(offset: offset, limit: limit)
  }

  view fn nfts(int offset, int limit) authorize(anyone) -> QueryPage<NftView> {
    ledger::query::nfts(offset: offset, limit: limit)
  }
}
"#;
    kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .expect("compile typed core-query pager program")
}
fn typed_core_query_page_payload_literals(offset: &str, limit: &str) -> norito::json::Value {
    norito::json::object([
        ("offset", norito::json::Value::from(offset.to_owned())),
        ("limit", norito::json::Value::from(limit.to_owned())),
    ])
    .expect("serialize typed core-query page arguments")
}
fn typed_core_query_page_payload(offset: i64, limit: i64) -> norito::json::Value {
    typed_core_query_page_payload_literals(&offset.to_string(), &limit.to_string())
}
async fn post_typed_core_query_page(
    http: &reqwest::Client,
    torii_url: &reqwest::Url,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    entrypoint: &str,
    payload: norito::json::Value,
) -> Result<(StatusCode, norito::json::Value)> {
    let request = norito::json::object([
        (
            "authority",
            norito::json::Value::from(iroha_test_samples::ALICE_ID.to_string()),
        ),
        (
            "contract_address",
            norito::json::to_value(contract_address)?,
        ),
        (
            "entrypoint",
            norito::json::Value::from(entrypoint.to_owned()),
        ),
        ("payload", payload),
        ("gas_limit", norito::json::Value::from(1_000_000_u64)),
    ])?;
    let response = http
        .post(torii_url.join("v1/contracts/view")?)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .body(norito::json::to_vec(&request)?)
        .send()
        .await?;
    let status = response.status();
    let body = response.bytes().await?;
    let body = norito::json::from_slice(&body)
        .map_err(|error| eyre!("contract view returned {status} with invalid JSON: {error}"))?;
    Ok((status, body))
}
async fn invoke_typed_core_query_page(
    client: iroha::blocking::Client,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    entrypoint: &str,
    offset: i64,
    limit: i64,
) -> Result<norito::json::Value> {
    let contract_address = contract_address.clone();
    let entrypoint = entrypoint.to_owned();
    let payload = typed_core_query_page_payload(offset, limit);
    let response = read_on_dedicated_thread(move || {
        client.client().post_contract_view_json(
            &iroha_test_samples::ALICE_ID,
            Some(&contract_address),
            None,
            &entrypoint,
            Some(&payload),
            1_000_000,
        )
    })
    .await?;
    response
        .get("result")
        .cloned()
        .ok_or_else(|| eyre!("contract view response is missing result: {response:?}"))
}
fn typed_query_page_parts(
    result: &norito::json::Value,
    view_name: &str,
) -> Result<(Vec<String>, Option<i64>)> {
    let result = result
        .as_object()
        .ok_or_else(|| eyre!("typed {view_name} page is not an object: {result:?}"))?;
    if result.len() != 2 || !result.contains_key("items") || !result.contains_key("next_offset") {
        return Err(eyre!(
            "typed {view_name} page must contain exactly items and next_offset: {result:?}"
        ));
    }
    let items = result
        .get("items")
        .and_then(norito::json::Value::as_array)
        .ok_or_else(|| eyre!("typed {view_name} page is missing its items list: {result:?}"))?;
    let ids = items
        .iter()
        .map(|item| {
            item.get("id")
                .and_then(norito::json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| eyre!("typed {view_name} is missing its id: {item:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    if ids.len() > ivm::core_query::QUERY_PAGE_CAPACITY_V1 {
        return Err(eyre!(
            "typed {view_name} page contains {} items; maximum is {}",
            ids.len(),
            ivm::core_query::QUERY_PAGE_CAPACITY_V1,
        ));
    }
    let next_offset = result
        .get("next_offset")
        .and_then(norito::json::Value::as_object)
        .ok_or_else(|| eyre!("typed {view_name} page is missing next_offset: {result:?}"))?;
    if next_offset.len() != 1 {
        return Err(eyre!(
            "typed {view_name} page contains a non-canonical next_offset: {result:?}"
        ));
    }
    let next_offset = if let Some(offset) = next_offset.get("some") {
        let raw = offset.as_str().ok_or_else(|| {
            eyre!("typed {view_name} page contains a non-canonical next_offset Int: {result:?}")
        })?;
        let parsed = raw.parse::<i64>().map_err(|error| {
            eyre!(
                "typed {view_name} page contains an out-of-range next_offset Int: \
                 {result:?}: {error}"
            )
        })?;
        if parsed.to_string() != raw {
            return Err(eyre!(
                "typed {view_name} page contains a non-canonical next_offset Int: {result:?}"
            ));
        }
        if parsed < 0 {
            return Err(eyre!(
                "typed {view_name} page contains a negative next_offset: {result:?}"
            ));
        }
        if ids.is_empty() {
            return Err(eyre!(
                "typed {view_name} page contains next_offset without making progress: {result:?}"
            ));
        }
        let next_offset_usize = usize::try_from(parsed).map_err(|_| {
            eyre!("typed {view_name} page contains an out-of-range next_offset: {result:?}")
        })?;
        if next_offset_usize < ids.len() {
            return Err(eyre!(
                "typed {view_name} page contains next_offset before its returned item count: \
                 {result:?}"
            ));
        }
        Some(parsed)
    } else if next_offset
        .get("none")
        .and_then(norito::json::Value::as_bool)
        == Some(true)
    {
        None
    } else {
        return Err(eyre!(
            "typed {view_name} page contains a non-canonical next_offset: {result:?}"
        ));
    };
    Ok((ids, next_offset))
}
#[test]
fn typed_query_page_parts_require_canonical_active_only_option_int() {
    for (source, expected) in [
        (
            r#"{"items":[{"id":"item"}],"next_offset":{"some":"3"}}"#,
            Some(3),
        ),
        (r#"{"items":[],"next_offset":{"none":true}}"#, None),
    ] {
        let page = norito::json::from_str(source).expect("parse canonical typed query page");
        assert_eq!(
            typed_query_page_parts(&page, "TestView")
                .expect("accept canonical active-only Option<Int>")
                .1,
            expected
        );
    }
    for source in [
        r#"{"items":[],"next_offset":{"some":3}}"#,
        r#"{"items":[],"next_offset":{"some":"03"}}"#,
        r#"{"items":[],"next_offset":{"some":"+3"}}"#,
        r#"{"items":[],"next_offset":{"some":"-0"}}"#,
        r#"{"items":[],"next_offset":{"some":"9223372036854775808"}}"#,
        r#"{"items":[],"next_offset":{"none":false}}"#,
        r#"{"items":[],"next_offset":{"some":"3","none":true}}"#,
        r#"{"items":[],"next_offset":{"unknown":true}}"#,
        r#"{"items":[],"next_offset":{"none":true},"cursor":null}"#,
        r#"{"items":[{"id":"item"}],"next_offset":{"some":"-3"}}"#,
        r#"{"items":[],"next_offset":{"some":"3"}}"#,
        r#"{"items":[{"id":"a"},{"id":"b"}],"next_offset":{"some":"1"}}"#,
    ] {
        let page = norito::json::from_str(source).expect("parse malformed typed query page");
        assert!(
            typed_query_page_parts(&page, "TestView").is_err(),
            "accepted non-canonical active-only Option<Int>: {source}"
        );
    }
    let oversized_items = (0..=ivm::core_query::QUERY_PAGE_CAPACITY_V1)
        .map(|index| format!(r#"{{"id":"item{index}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let oversized = norito::json::from_str(&format!(
        r#"{{"items":[{oversized_items}],"next_offset":{{"none":true}}}}"#
    ))
    .expect("parse oversized typed query page");
    assert!(
        typed_query_page_parts(&oversized, "TestView").is_err(),
        "accepted a typed query page above the V1 capacity"
    );
}
fn assert_typed_query_projection(
    result: &norito::json::Value,
    view_name: &str,
    expected_fields: &[&str],
) -> Result<()> {
    let items = result
        .get("items")
        .and_then(norito::json::Value::as_array)
        .ok_or_else(|| eyre!("typed {view_name} page is missing its items list: {result:?}"))?;
    for item in items {
        let object = item
            .as_object()
            .ok_or_else(|| eyre!("typed {view_name} is not an object: {item:?}"))?;
        if object.len() != expected_fields.len()
            || !expected_fields
                .iter()
                .all(|field| object.contains_key(*field))
        {
            return Err(eyre!(
                "{view_name} must return only fields {expected_fields:?}: {item:?}"
            ));
        }
    }
    Ok(())
}
fn assert_canonical_query_order<T>(ids: &[T], entity_name: &str)
where
    T: Clone + Ord + std::fmt::Debug,
{
    let mut sorted = ids.to_vec();
    sorted.sort();
    assert_eq!(
        ids,
        sorted.as_slice(),
        "the ledger {entity_name} query must expose canonical ID order"
    );
}
fn signed_consensus_handshake(
    network: &sandbox::SerializedNetwork,
) -> Result<ConsensusHandshakeMetadata> {
    let mut handshakes = network
        .genesis_isi()
        .iter()
        .flatten()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
        .filter_map(|set_parameter| match set_parameter.inner() {
            Parameter::Custom(custom)
                if custom.id() == &consensus_metadata::handshake_meta_id() =>
            {
                Some(custom)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if handshakes.len() != 1 {
        return Err(eyre!(
            "genesis must contain exactly one signed consensus handshake; found {}",
            handshakes.len()
        ));
    }
    let custom = handshakes
        .pop()
        .expect("length checked before reading consensus handshake");
    norito::json::from_str(custom.payload().get())
        .map_err(|error| eyre!("decode signed consensus handshake metadata: {error}"))
}
/// Authenticate the original contiguous native chain on every peer and, when
/// selected, join the exact successful transaction to its certified execution.
async fn verify_contract_finality_everywhere(
    network: &sandbox::SerializedNetwork,
    height: u64,
    transaction_hash: Option<Hash>,
) -> Result<()> {
    use iroha_data_model::sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier};
    let genesis = network.genesis().0;
    let validators = iroha_genesis::signed_genesis_validator_pops(&genesis)?
        .into_iter()
        .map(|(public_key, proof_of_possession)| FinalityValidator {
            public_key,
            proof_of_possession,
        })
        .collect();
    let selected =
        SumeragiFinalityVerifier::new(&genesis, &network.chain_id().to_string(), validators)?;
    let deadline = Instant::now() + network.sync_timeout();
    let mut common = None;
    for peer in network.peers() {
        wait_for_contract_applied_height(peer, height, network.sync_timeout()).await?;
        let context = read_on_dedicated_thread({
            let client = peer
                .client()
                .client()
                .clone()
                .with_request_deadline(deadline);
            let mut verifier = selected.clone();
            move || -> Result<Hash> {
                let mut tip = None;
                for current in 1..=height {
                    let proof =
                        client.get_sumeragi_finality_proof(NonZeroU64::new(current).unwrap())?;
                    tip = Some(verifier.verify(&proof)?);
                }
                let tip = tip.ok_or_else(|| eyre!("finality height must be positive"))?;
                if let Some(hash) = transaction_hash {
                    let details =
                        client.get_transaction_details(HashOf::from_untyped_unchecked(hash))?;
                    tip.verify_committed_transaction(client.network_id(), &details.transaction)?;
                }
                Ok(tip.context_id())
            }
        })
        .await?;
        if let Some(expected) = common {
            assert_eq!(
                context, expected,
                "validators disagree on the certified execution context"
            );
        }
        common = Some(context);
    }
    Ok(())
}

fn dynamic_counter_args(key: i64, delta: i64) -> norito::json::Value {
    norito::json::object([
        ("key", norito::json::Value::from(key.to_string())),
        ("delta", norito::json::Value::from(delta.to_string())),
    ])
    .expect("serialize dynamic counter arguments")
}
fn dynamic_counter_call_intent(
    artifact: &[u8],
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    contract_alias: &iroha_data_model::smart_contract::ContractAlias,
    entrypoint: &str,
    payload: &norito::json::Value,
) -> iroha::client::ContractCallDraftIntent {
    use iroha_data_model::transaction::executable::{ContractArgumentRecord, ContractInvocation};

    let verified =
        ivm::verify_contract_artifact(artifact).expect("verify dynamic counter artifact");
    let schema = verified
        .contract_interface
        .entrypoints
        .iter()
        .find(|descriptor| descriptor.name == entrypoint)
        .and_then(|descriptor| descriptor.argument_schema.as_ref())
        .unwrap_or_else(|| panic!("missing argument schema for `{entrypoint}`"));
    let argument_bytes = ivm_abi::arguments::encode_argument_record_from_json(
        schema,
        &iroha_primitives::json::Json::from(payload.clone()),
    )
    .expect("encode dynamic counter argument record");
    let arguments = ContractArgumentRecord::try_new(argument_bytes)
        .expect("bound dynamic counter argument record");

    let mut metadata = Metadata::default();
    for (key, value) in [
        (
            "contract_address",
            iroha_primitives::json::Json::new(contract_address.to_string()),
        ),
        (
            "contract_code_hash",
            iroha_primitives::json::Json::new(verified.code_hash.to_string()),
        ),
        (
            "contract_alias",
            iroha_primitives::json::Json::new(contract_alias.to_string()),
        ),
        (
            "contract_entrypoint",
            iroha_primitives::json::Json::new(entrypoint.to_owned()),
        ),
        (
            "contract_payload",
            iroha_primitives::json::Json::from(payload.clone()),
        ),
    ] {
        metadata.insert(
            Name::from_str(key).expect("static contract metadata key"),
            value,
        );
    }
    iroha::client::ContractCallDraftIntent {
        invocation: ContractInvocation {
            contract_address: contract_address.clone(),
            expected_code_hash: verified.code_hash,
            entrypoint: entrypoint.to_owned(),
            arguments: Some(arguments),
        },
        metadata,
    }
}
fn pipeline_status_kind(payload: &norito::json::Value) -> Option<&str> {
    let status = payload
        .get("content")
        .and_then(|content| content.get("status"))
        .or_else(|| payload.get("status"))?;
    match status {
        norito::json::Value::String(kind) => Some(kind.as_str()),
        norito::json::Value::Object(map) => map.get("kind").and_then(norito::json::Value::as_str),
        _ => None,
    }
}
fn pipeline_status_block_height(payload: &norito::json::Value) -> Option<u64> {
    payload
        .get("content")
        .and_then(|content| content.get("status"))
        .or_else(|| payload.get("status"))?
        .get("block_height")
        .and_then(norito::json::Value::as_u64)
}
async fn wait_for_tx_applied(
    http: &reqwest::Client,
    torii_url: &reqwest::Url,
    tx_hash_hex: &str,
    timeout: Duration,
    stage: &str,
) -> Result<u64> {
    let mut status_url = torii_url.join("v1/pipeline/transactions/status")?;
    status_url
        .query_pairs_mut()
        .append_pair("hash", tx_hash_hex);
    let deadline = Instant::now() + timeout;
    let mut last_kind = String::from("unavailable");
    let mut last_payload = String::new();
    let mut last_error = String::new();
    loop {
        match http
            .get(status_url.clone())
            .header("Accept", "application/json")
            .send()
            .await
        {
            Ok(response)
                if response.status() == reqwest::StatusCode::OK
                    || response.status() == reqwest::StatusCode::ACCEPTED =>
            {
                let status = response.status();
                let bytes = response.bytes().await?;
                if bytes.is_empty() {
                    last_kind = format!("http {status} with empty body");
                } else {
                    let payload: norito::json::Value = norito::json::from_slice(&bytes)?;
                    if let Some(kind) = pipeline_status_kind(&payload) {
                        last_kind = kind.to_string();
                        last_payload = format!("{payload:?}");
                        match kind {
                            "Applied" => {
                                if let Some(block_height) = pipeline_status_block_height(&payload) {
                                    return Ok(block_height);
                                }
                                last_kind = "Applied without block_height".to_owned();
                            }
                            "Rejected" => {
                                return Err(eyre!(
                                    "{stage}: tx `{tx_hash_hex}` rejected; payload={payload:?}"
                                ));
                            }
                            "Expired" => {
                                return Err(eyre!("{stage}: tx `{tx_hash_hex}` expired"));
                            }
                            _ => {}
                        }
                    } else {
                        last_kind = "missing status kind".to_string();
                        last_payload = format!("{payload:?}");
                    }
                }
            }
            Ok(response)
                if response.status() == reqwest::StatusCode::NO_CONTENT
                    || response.status() == reqwest::StatusCode::NOT_FOUND =>
            {
                last_kind = format!("http {}", response.status());
            }
            Ok(response) => {
                last_error = format!(
                    "http {} {}",
                    response.status(),
                    std::str::from_utf8(response.bytes().await?.as_ref()).unwrap_or("")
                );
            }
            Err(err) => {
                last_error = format!("{err}");
            }
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "{stage}: timed out waiting for tx `{tx_hash_hex}` to reach Applied; last_kind={last_kind}, last_payload={last_payload}, last_error={last_error}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
pub(super) fn deploy_contract_locally_signed(
    client: &iroha::blocking::Client,
    artifact: &[u8],
    contract_alias: iroha_data_model::smart_contract::ContractAlias,
) -> Result<(
    iroha_data_model::smart_contract::ContractAddress,
    String,
    String,
    HashOf<iroha_data_model::transaction::SignedTransaction>,
)> {
    deploy_contract_locally_signed_with_registration(client, artifact, contract_alias, false, None)
}

fn deploy_contract_locally_signed_with_registration(
    client: &iroha::blocking::Client,
    artifact: &[u8],
    contract_alias: iroha_data_model::smart_contract::ContractAlias,
    registered_in_genesis: bool,
    hajimari_grantee: Option<&AccountId>,
) -> Result<(
    iroha_data_model::smart_contract::ContractAddress,
    String,
    String,
    HashOf<iroha_data_model::transaction::SignedTransaction>,
)> {
    use iroha_data_model::isi::smart_contract_code::{
        CommitContractDeployment, FinalizeSmartContractCodeUpload, RegisterSmartContractCode,
        SMART_CONTRACT_CODE_CHUNK_BYTES, UploadSmartContractCodeChunk,
    };
    let verified = ivm::verify_contract_artifact(artifact)
        .map_err(|error| eyre!("verify contract artifact: {error}"))?;
    let authority: Account = client
        .client()
        .query_single(FindAccountById::new(client.client().account().clone()))?;
    let nonce_key =
        Name::from_str(iroha_data_model::smart_contract::CONTRACT_DEPLOY_NONCE_METADATA_KEY)?;
    let deploy_nonce = authority
        .metadata()
        .get(&nonce_key)
        .map(|value| {
            value
                .try_into_any_norito::<u64>()
                .map_err(|_| eyre!("contract deployment nonce metadata is not a canonical u64"))
        })
        .transpose()?
        .unwrap_or(0);
    let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
        client.client().network_id(),
        client.client().account(),
        deploy_nonce,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .map_err(|error| eyre!("derive contract address: {error}"))?;
    let mut metadata = Metadata::default();
    for key in ["gov_contract_address", "contract_address"] {
        metadata.insert(
            Name::from_str(key)?,
            iroha_primitives::json::Json::new(contract_address.to_string()),
        );
    }
    if !registered_in_genesis {
        let encoding = ManifestEncodingBudget::new()?;
        let manifest = verified
            .manifest
            .try_signed(
                encoding.context(),
                encoding.max_frame_bytes(),
                client.client().key_pair(),
            )
            .map_err(|error| eyre!("sign contract manifest locally: {error}"))?;
        let total_size = u64::try_from(artifact.len())?;
        let chunk_count = u32::try_from(artifact.len().div_ceil(SMART_CONTRACT_CODE_CHUNK_BYTES))?;
        if chunk_count == 0 {
            return Err(eyre!("contract artifact must not be empty"));
        }
        for (index, chunk) in artifact.chunks(SMART_CONTRACT_CODE_CHUNK_BYTES).enumerate() {
            let chunk_index = u32::try_from(index)?;
            let mut instructions = vec![InstructionBox::from(UploadSmartContractCodeChunk {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    verified.code_hash,
                ),
                total_size,
                chunk_index,
                chunk_count,
                chunk: chunk.to_vec(),
            })];
            if chunk_index + 1 == chunk_count {
                instructions.push(InstructionBox::from(FinalizeSmartContractCodeUpload {
                    artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                        verified.code_hash,
                    ),
                    total_size,
                    chunk_count,
                }));
            }
            client.submit_all_with_metadata(
                instructions,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                metadata.clone(),
            )?;
        }
        client.submit_with_metadata(
            {
                let scoped_manifest = manifest;
                RegisterSmartContractCode {
                    artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                        scoped_manifest.code_hash.unwrap_or_else(|| {
                            iroha_crypto::Hash::new(b"missing test manifest hash")
                        }),
                    ),
                    manifest: scoped_manifest,
                }
            },
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            metadata.clone(),
        )?;
    }
    let deployment_instructions = contract_deployment_instructions(
        CommitContractDeployment {
            expected_deploy_nonce: deploy_nonce,
            contract_address: contract_address.clone(),
            code_hash: verified.code_hash,
            contract_alias,
            lease_expiry_ms: None,
            expected_previous_contract_address: None,
        },
        hajimari_grantee,
    );
    let deployment_tx_hash = client.submit_all_with_metadata(
        deployment_instructions,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        metadata,
    )?;
    Ok((
        contract_address,
        hex::encode(verified.code_hash.as_ref()),
        hex::encode(verified.abi_hash.as_ref()),
        deployment_tx_hash,
    ))
}
async fn deploy_contract_artifact(
    client: &iroha::blocking::Client,
    http: &reqwest::Client,
    artifact: &[u8],
    alias_name: &str,
    stage: &str,
) -> Result<(iroha_data_model::smart_contract::ContractAddress, Hash, u64)> {
    let contract_alias = iroha_data_model::smart_contract::ContractAlias::from_components(
        alias_name,
        None,
        "universal",
    )
    .map_err(|error| eyre!("{stage}: invalid contract alias: {error}"))?;
    let (contract_address, _, _, deployment_tx_hash) = read_on_dedicated_thread({
        let client = client.clone();
        let artifact = artifact.to_vec();
        move || deploy_contract_locally_signed(&client, &artifact, contract_alias)
    })
    .await?;
    let deployment_block_height = wait_for_tx_applied(
        http,
        client.client().endpoint(),
        &hex::encode(deployment_tx_hash.as_ref()),
        Duration::from_secs(60),
        stage,
    )
    .await?;
    Ok((
        contract_address,
        Hash::from(deployment_tx_hash),
        deployment_block_height,
    ))
}
async fn contract_state_json_value(
    http: &reqwest::Client,
    torii_url: &reqwest::Url,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    path: &str,
) -> Result<norito::json::Value> {
    let mut url = torii_url.join("v1/contracts/state")?;
    url.query_pairs_mut()
        .append_pair("contract_address", &contract_address.to_string())
        .append_pair("path", path)
        .append_pair("decode", "json");
    let response = http
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(eyre!("contract state `{path}` returned {status}: {body}"));
    }
    let payload: norito::json::Value = norito::json::from_str(&body)?;
    let entry = payload
        .get("entries")
        .and_then(norito::json::Value::as_array)
        .and_then(|entries| entries.first())
        .ok_or_else(|| eyre!("contract state `{path}` response missing entry: {payload:?}"))?;
    if entry.get("found").and_then(norito::json::Value::as_bool) != Some(true) {
        return Err(eyre!("contract state `{path}` was not found: {payload:?}"));
    }
    entry
        .get("value_json")
        .cloned()
        .ok_or_else(|| eyre!("contract state `{path}` was not decoded: {payload:?}"))
}

async fn contract_view_json_value(
    client: iroha::blocking::Client,
    contract_address: &iroha_data_model::smart_contract::ContractAddress,
    entrypoint: &str,
) -> Result<norito::json::Value> {
    let contract_address = contract_address.clone();
    let entrypoint = entrypoint.to_owned();
    let response = read_on_dedicated_thread(move || {
        client.client().post_contract_view_json(
            &iroha_test_samples::ALICE_ID,
            Some(&contract_address),
            None,
            &entrypoint,
            None,
            CONTRACT_STATE_PROBE_GAS_LIMIT,
        )
    })
    .await?;
    response
        .get("result")
        .cloned()
        .ok_or_else(|| eyre!("contract view response is missing result: {response:?}"))
}

async fn wait_for_contract_applied_height(
    peer: &iroha_test_network::NetworkPeer,
    height: u64,
    timeout: Duration,
) -> Result<()> {
    let mut last_observation = "no applied-state status response".to_owned();
    tokio::time::timeout(timeout, async {
        loop {
            match peer.status().await {
                Ok(status) if status.blocks >= height => return,
                Ok(status) => last_observation = format!("applied height {}", status.blocks),
                Err(error) => last_observation = error.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .map_err(|_| eyre!("contract peer did not apply height {height}: {last_observation}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ContractLifecycleSnapshot {
    version: u64,
    active: bool,
    origin: String,
    origin_account: String,
    owner: String,
    pending_owner: Option<String>,
    parliament_delegated: bool,
    active_code_hash_hex: Option<String>,
    revision: u64,
    emergency_hold_present: bool,
    emergency_hold_active: bool,
}

fn optional_json_string(
    value: Option<&norito::json::Value>,
    field: &str,
) -> Result<Option<String>> {
    match value {
        None => Err(eyre!("governed contract response is missing `{field}`")),
        Some(norito::json::Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_owned()))
            .ok_or_else(|| eyre!("governed contract field `{field}` is not a string or null")),
    }
}

fn contract_lifecycle_snapshot(
    response: &norito::json::Value,
) -> Result<ContractLifecycleSnapshot> {
    if response.get("found").and_then(norito::json::Value::as_bool) != Some(true) {
        return Err(eyre!(
            "governed contract response has no retained lifecycle: {response:?}"
        ));
    }
    let active = response
        .get("active")
        .and_then(norito::json::Value::as_bool)
        .ok_or_else(|| eyre!("governed contract response has no `active` flag: {response:?}"))?;
    let emergency_hold_active = response
        .get("emergency_hold_active")
        .and_then(norito::json::Value::as_bool)
        .ok_or_else(|| eyre!("governed contract response has no hold status: {response:?}"))?;
    let lifecycle = response
        .get("lifecycle")
        .and_then(norito::json::Value::as_object)
        .ok_or_else(|| eyre!("governed contract response has no lifecycle: {response:?}"))?;
    let string_field = |field: &str| -> Result<String> {
        lifecycle
            .get(field)
            .and_then(norito::json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| eyre!("governed contract lifecycle has no `{field}`: {response:?}"))
    };
    let parliament_delegated = lifecycle
        .get("parliament_delegated")
        .and_then(norito::json::Value::as_bool)
        .ok_or_else(|| eyre!("governed contract lifecycle has no delegation flag: {response:?}"))?;
    let revision = lifecycle
        .get("revision")
        .and_then(norito::json::Value::as_u64)
        .ok_or_else(|| eyre!("governed contract lifecycle has no revision: {response:?}"))?;
    let version = lifecycle
        .get("version")
        .and_then(norito::json::Value::as_u64)
        .ok_or_else(|| eyre!("governed contract lifecycle has no version: {response:?}"))?;
    let emergency_hold_present = match lifecycle.get("emergency_hold") {
        None => {
            return Err(eyre!(
                "governed contract lifecycle has no emergency-hold field: {response:?}"
            ));
        }
        Some(norito::json::Value::Null) => false,
        Some(norito::json::Value::Object(_)) => true,
        Some(_) => {
            return Err(eyre!(
                "governed contract lifecycle has malformed emergency-hold state: {response:?}"
            ));
        }
    };
    Ok(ContractLifecycleSnapshot {
        version,
        active,
        origin: string_field("origin")?,
        origin_account: string_field("origin_account")?,
        owner: string_field("owner")?,
        pending_owner: optional_json_string(lifecycle.get("pending_owner"), "pending_owner")?,
        parliament_delegated,
        active_code_hash_hex: optional_json_string(
            lifecycle.get("active_code_hash_hex"),
            "active_code_hash_hex",
        )?,
        revision,
        emergency_hold_present,
        emergency_hold_active,
    })
}

async fn wait_for_contract_lifecycle_on_all_peers(
    network: &iroha_test_network::Network,
    contract_address: &ContractAddress,
    expected: &ContractLifecycleSnapshot,
    stage: &str,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last_observed = Vec::new();
    loop {
        last_observed.clear();
        let mut converged = true;
        for (peer_index, peer) in network.peers().iter().enumerate() {
            let client = peer.client_for(
                &iroha_test_samples::ALICE_ID,
                iroha_test_samples::ALICE_KEYPAIR.private_key().clone(),
            );
            let contract_address = contract_address.clone();
            let observed = read_on_dedicated_thread(move || {
                client
                    .client()
                    .get_gov_contract_json(&contract_address)
                    .and_then(|response| contract_lifecycle_snapshot(&response))
            })
            .await;
            match observed {
                Ok(snapshot) => {
                    converged &= &snapshot == expected;
                    last_observed.push(format!("peer {peer_index}: {snapshot:?}"));
                }
                Err(error) => {
                    converged = false;
                    last_observed.push(format!("peer {peer_index}: error={error:#}"));
                }
            }
        }
        if converged {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "{stage}: four peers did not converge on {expected:?}; last observations: {}",
                last_observed.join("; ")
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn assert_submission_error_contains(error: &eyre::Report, expected: &str, stage: &str) {
    let message = format!("{error:#}");
    assert!(
        message.contains(expected),
        "{stage}: expected rejection containing `{expected}`, got `{message}`"
    );
}

#[tokio::test]
async fn contract_owner_lifecycle_cas_and_transfer_converge_on_four_peers() -> Result<()> {
    let register_permission: Permission = CanManageSmartContractCode.into();
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_block_cadence(Duration::from_secs(4))
        .with_npos_consensus()
        .with_genesis_instruction(Grant::account_permission(
            register_permission,
            iroha_test_samples::ALICE_ID.clone(),
        ));
    let context = stringify!(contract_owner_lifecycle_cas_and_transfer_converge_on_four_peers);
    let network = sandbox::start_network_async_or_skip(builder, context).await?;
    let Some(network) = sandbox::enforce_network_start_requirement(network, context)? else {
        return Ok(());
    };
    assert_eq!(network.peers().len(), 4, "test requires four voting peers");
    let handshake = signed_consensus_handshake(&network)?;
    handshake
        .validate()
        .map_err(|error| eyre!("invalid signed consensus handshake: {error}"))?;
    assert_eq!(handshake.mode, SumeragiConsensusMode::Npos);
    assert_eq!(
        handshake.sumeragi_context.da_layout,
        recommended_data_availability_layout(),
        "contract lifecycle gate requires the signed mandatory DA layout"
    );
    network.ensure_blocks(1).await?;

    let alice = network.peers()[0].client_for(
        &iroha_test_samples::ALICE_ID,
        iroha_test_samples::ALICE_KEYPAIR.private_key().clone(),
    );
    let bob = network.peers()[1].client_for(
        &iroha_test_samples::BOB_ID,
        iroha_test_samples::BOB_KEYPAIR.private_key().clone(),
    );
    let artifact = minimal_contract_artifact();
    let verified = ivm::verify_contract_artifact(&artifact)
        .map_err(|error| eyre!("verify lifecycle test artifact: {error}"))?;
    let code_hash = verified.code_hash;
    let code_hash_hex = hex::encode(code_hash.as_ref());
    let alias = iroha_data_model::smart_contract::ContractAlias::from_components(
        "owner_lifecycle_four_peer",
        None,
        "universal",
    )?;
    let (contract_address, _, _, _) = read_on_dedicated_thread({
        let alice = alice.clone();
        move || deploy_contract_locally_signed(&alice, &artifact, alias)
    })
    .await?;
    let submit = |client: &iroha::blocking::Client, instruction: InstructionBox| {
        let client = client.clone();
        async move {
            read_on_dedicated_thread(move || {
                client.submit(instruction, FeePaymentIntent::authority(Vec::new(), None))
            })
            .await
        }
    };

    let direct_active = ContractLifecycleSnapshot {
        version: 1,
        active: true,
        origin: "direct".to_owned(),
        origin_account: iroha_test_samples::ALICE_ID.to_string(),
        owner: iroha_test_samples::ALICE_ID.to_string(),
        pending_owner: None,
        parliament_delegated: false,
        active_code_hash_hex: Some(code_hash_hex.clone()),
        revision: 1,
        emergency_hold_present: false,
        emergency_hold_active: false,
    };
    wait_for_contract_lifecycle_on_all_peers(
        &network,
        &contract_address,
        &direct_active,
        "direct deployment lifecycle",
    )
    .await?;

    let unauthorized = submit(
        &bob,
        DeactivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 1,
            reason: Some("unauthorized takeover attempt".to_owned()),
        }
        .into(),
    )
    .await
    .expect_err("a non-owner must not deactivate the contract");
    assert_submission_error_contains(
        &unauthorized,
        "only the current account owner may deactivate",
        "non-owner deactivation",
    );
    wait_for_contract_lifecycle_on_all_peers(
        &network,
        &contract_address,
        &direct_active,
        "non-owner deactivation rollback",
    )
    .await?;

    submit(
        &alice,
        DeactivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 1,
            reason: Some("owner maintenance".to_owned()),
        }
        .into(),
    )
    .await?;
    let inactive_revision_2 = ContractLifecycleSnapshot {
        active: false,
        active_code_hash_hex: None,
        revision: 2,
        ..direct_active.clone()
    };
    wait_for_contract_lifecycle_on_all_peers(
        &network,
        &contract_address,
        &inactive_revision_2,
        "owner deactivation",
    )
    .await?;

    let stale_activation = submit(
        &alice,
        ActivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 1,
            code_hash,
        }
        .into(),
    )
    .await
    .expect_err("a consumed lifecycle revision must reject activation");
    assert_submission_error_contains(
        &stale_activation,
        "stale contract lifecycle revision",
        "stale owner activation",
    );

    submit(
        &alice,
        SetContractParliamentDelegation {
            contract_address: contract_address.clone(),
            expected_revision: 2,
            delegated: true,
        }
        .into(),
    )
    .await?;
    let delegated_revision_3 = ContractLifecycleSnapshot {
        parliament_delegated: true,
        revision: 3,
        ..inactive_revision_2.clone()
    };
    wait_for_contract_lifecycle_on_all_peers(
        &network,
        &contract_address,
        &delegated_revision_3,
        "Parliament delegation",
    )
    .await?;

    submit(
        &alice,
        SetContractParliamentDelegation {
            contract_address: contract_address.clone(),
            expected_revision: 3,
            delegated: false,
        }
        .into(),
    )
    .await?;
    let revoked_revision_4 = ContractLifecycleSnapshot {
        parliament_delegated: false,
        revision: 4,
        ..delegated_revision_3
    };
    wait_for_contract_lifecycle_on_all_peers(
        &network,
        &contract_address,
        &revoked_revision_4,
        "Parliament delegation revocation",
    )
    .await?;

    submit(
        &alice,
        OfferContractOwnership {
            contract_address: contract_address.clone(),
            expected_revision: 4,
            new_owner: ContractLifecycleOwnerV1::Account(iroha_test_samples::BOB_ID.clone()),
        }
        .into(),
    )
    .await?;
    let offered_revision_5 = ContractLifecycleSnapshot {
        pending_owner: Some(iroha_test_samples::BOB_ID.to_string()),
        revision: 5,
        ..revoked_revision_4
    };
    wait_for_contract_lifecycle_on_all_peers(
        &network,
        &contract_address,
        &offered_revision_5,
        "two-party ownership offer",
    )
    .await?;

    let wrong_acceptor = submit(
        &alice,
        AcceptContractOwnership {
            contract_address: contract_address.clone(),
            expected_revision: 5,
        }
        .into(),
    )
    .await
    .expect_err("the current owner cannot accept an offer made to another account");
    assert_submission_error_contains(
        &wrong_acceptor,
        "authority is not the pending account owner",
        "wrong ownership acceptor",
    );
    wait_for_contract_lifecycle_on_all_peers(
        &network,
        &contract_address,
        &offered_revision_5,
        "wrong ownership acceptor rollback",
    )
    .await?;

    submit(
        &bob,
        AcceptContractOwnership {
            contract_address: contract_address.clone(),
            expected_revision: 5,
        }
        .into(),
    )
    .await?;
    let transferred_revision_6 = ContractLifecycleSnapshot {
        owner: iroha_test_samples::BOB_ID.to_string(),
        pending_owner: None,
        parliament_delegated: false,
        revision: 6,
        ..offered_revision_5
    };
    wait_for_contract_lifecycle_on_all_peers(
        &network,
        &contract_address,
        &transferred_revision_6,
        "two-party ownership acceptance",
    )
    .await?;

    let former_owner = submit(
        &alice,
        ActivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 6,
            code_hash,
        }
        .into(),
    )
    .await
    .expect_err("the former owner must not reactivate the transferred contract");
    assert_submission_error_contains(
        &former_owner,
        "only the current account owner may activate",
        "former-owner activation",
    );

    submit(
        &bob,
        ActivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 6,
            code_hash,
        }
        .into(),
    )
    .await?;
    let bob_active_revision_7 = ContractLifecycleSnapshot {
        active: true,
        active_code_hash_hex: Some(code_hash_hex),
        revision: 7,
        ..transferred_revision_6
    };
    wait_for_contract_lifecycle_on_all_peers(
        &network,
        &contract_address,
        &bob_active_revision_7,
        "new-owner activation",
    )
    .await?;

    let stale_deactivation = submit(
        &bob,
        DeactivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 6,
            reason: Some("stale replay".to_owned()),
        }
        .into(),
    )
    .await
    .expect_err("the activation revision must not be replayable");
    assert_submission_error_contains(
        &stale_deactivation,
        "stale contract lifecycle revision",
        "stale new-owner deactivation",
    );
    wait_for_contract_lifecycle_on_all_peers(
        &network,
        &contract_address,
        &bob_active_revision_7,
        "stale new-owner deactivation rollback",
    )
    .await
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn deploy_and_get_contract_manifest_via_torii() -> Result<()> {
    // Grant CanManageSmartContractCode to Alice in genesis so she can deploy contracts.
    let permission: Permission = CanManageSmartContractCode.into();
    let builder = NetworkBuilder::new()
        .with_min_peers(4)
        // Keep pipeline timings short to ensure the deploy transaction is flushed promptly.
        .with_block_cadence(std::time::Duration::from_secs(4))
        .with_config_layer(|layer| {
            // Surface more detail if the pipeline stalls while registering the contract.
            layer.write(["logger", "level"], "TRACE").write(
                ["logger", "filter"],
                "iroha_core::sumeragi=trace,iroha_core::queue=trace,iroha_core::smartcontracts=trace,iroha_core::tx=trace",
            );
        })
        .with_genesis_instruction(Grant::account_permission(
            permission,
            iroha_test_samples::ALICE_ID.clone(),
        ));
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(deploy_and_get_contract_manifest_via_torii),
    )
    .await?
    else {
        return Ok(());
    };
    let client = network.client();
    // Wait for genesis to be committed before submitting additional transactions
    network.ensure_blocks(1).await?;
    let code_bytes = minimal_contract_artifact();
    let contract_alias = iroha_data_model::smart_contract::ContractAlias::from_components(
        "deploy_test",
        None,
        "universal",
    )
    .expect("contract alias");
    let (_, code_hash_hex, _, _) = read_on_dedicated_thread({
        let client = client.clone();
        move || deploy_contract_locally_signed(&client, &code_bytes, contract_alias)
    })
    .await?;
    let http = integration_tests::http::client();
    // Poll status until we see the deploy transaction committed
    let deadline = Instant::now() + std::time::Duration::from_secs(120);
    let mut status = None;
    let mut last_status_error: Option<String> = None;
    while Instant::now() < deadline {
        match client.client().status().get().await {
            Ok(current) => {
                let non_empty = current.blocks_non_empty;
                status = Some(current);
                last_status_error = None;
                if non_empty >= 2 {
                    break;
                }
            }
            Err(err) => {
                last_status_error = Some(err.to_string());
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let status = status.ok_or_else(|| {
        eyre!(
            "failed to fetch status before deadline{}",
            last_status_error
                .as_deref()
                .map(|err| format!("; last error: {err}"))
                .unwrap_or_default()
        )
    })?;
    if status.blocks_non_empty < 2 {
        return Err(eyre!(
            "expected blocks_non_empty>=2 after manifest registration, got {} (blocks {}, queue {}, approved {}, rejected {}; last status error: {})",
            status.blocks_non_empty,
            status.blocks,
            status.queue_size,
            status.txs_approved,
            status.txs_rejected,
            last_status_error.as_deref().unwrap_or("none")
        ));
    }
    // GET by code hash
    let get_url = client
        .client()
        .endpoint()
        .join(&format!("/v1/contracts/code/{code_hash_hex}"))
        .unwrap();
    let get_deadline = Instant::now() + std::time::Duration::from_secs(120);
    let mut got_txt = None;
    let mut last_get_error: Option<String> = None;
    while Instant::now() < get_deadline {
        let resp = http
            .get(get_url.clone())
            .header("Accept", "application/json")
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status == StatusCode::NOT_FOUND {
            last_get_error = Some("manifest not found".to_owned());
        } else if !status.is_success() {
            return Err(eyre!(
                "GET /v1/contracts/code/{code_hash_hex} returned {status}: {body}"
            ));
        } else if body.trim().is_empty() {
            last_get_error = Some("empty response body".to_owned());
        } else {
            got_txt = Some(body);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let got_txt = got_txt.ok_or_else(|| {
        eyre!(
            "manifest GET did not return JSON before deadline{}",
            last_get_error
                .as_deref()
                .map(|err| format!("; last error: {err}"))
                .unwrap_or_default()
        )
    })?;
    let got: norito::json::Value = norito::json::from_str(&got_txt)?;
    // Validate manifest present and code_bytes absent
    let (got_manifest, got_bytes) = match &got {
        norito::json::Value::Object(m) => (
            m.get("manifest")
                .cloned()
                .unwrap_or(norito::json::Value::Null),
            m.get("code_bytes")
                .cloned()
                .unwrap_or(norito::json::Value::Null),
        ),
        _ => (norito::json::Value::Null, norito::json::Value::Null),
    };
    let got_code = match &got_manifest {
        norito::json::Value::Object(m) => m.get("code_hash").and_then(|v| v.as_str()),
        _ => None,
    };
    assert_eq!(got_code, Some(code_hash_hex.as_str()));
    assert!(got_bytes.is_null(), "code_bytes must be null/absent");
    Ok(())
}
#[tokio::test]
async fn dynamic_and_helper_hidden_contract_writes_serialize_on_four_peers() -> Result<()> {
    let register_permission: Permission = CanManageSmartContractCode.into();
    let alice_enact_permission: Permission = CanEnactGovernance.into();
    let bob_enact_permission: Permission = CanEnactGovernance.into();
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_block_cadence(Duration::from_secs(4))
        .with_config_layer(|layer| {
            layer
                .write(["pipeline", "parallel_overlay"], true)
                .write(["pipeline", "parallel_apply"], true)
                .write(["pipeline", "workers"], 2_i64);
        })
        .with_genesis_instruction(Grant::account_permission(
            register_permission,
            iroha_test_samples::ALICE_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            alice_enact_permission,
            iroha_test_samples::ALICE_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            bob_enact_permission,
            iroha_test_samples::BOB_ID.clone(),
        ));
    let context = stringify!(dynamic_and_helper_hidden_contract_writes_serialize_on_four_peers);
    let network = sandbox::start_network_async_or_skip(builder, context).await?;
    let Some(network) = sandbox::enforce_network_start_requirement(network, context)? else {
        return Ok(());
    };
    assert_eq!(network.peers().len(), 4, "test requires four voting peers");
    network.ensure_blocks(1).await?;
    let alice_client = network.peers()[0].client();
    let bob_client = network.peers()[1].client_for(
        &iroha_test_samples::BOB_ID,
        iroha_test_samples::BOB_KEYPAIR.private_key().clone(),
    );
    let http = integration_tests::http::client();
    let artifact = dynamic_access_counter_artifact();
    let (contract_address, _, deploy_height) = deploy_contract_artifact(
        &alice_client,
        &http,
        &artifact,
        "dynamic_access_counter",
        "deploy dynamic-access counter",
    )
    .await?;
    let contract_alias = iroha_data_model::smart_contract::ContractAlias::from_components(
        "dynamic_access_counter",
        None,
        "universal",
    )
    .expect("dynamic counter alias");
    network.ensure_blocks(deploy_height).await?;
    let alice_submission = {
        let client = alice_client.clone();
        let contract_address = contract_address.clone();
        let payload = dynamic_counter_args(7, 3);
        let intent = dynamic_counter_call_intent(
            &artifact,
            &contract_address,
            &contract_alias,
            "bump_direct",
            &payload,
        );
        async move {
            client
                .account_client()
                .post_contract_call_json(
                    &iroha_test_samples::ALICE_ID.clone(),
                    Some(iroha_test_samples::ALICE_KEYPAIR.private_key()),
                    Some(&contract_address),
                    None,
                    "bump_direct",
                    Some(&payload),
                    None,
                    None,
                    None,
                    &FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(100_000)),
                    &intent,
                )
                .await
        }
    };
    let bob_submission = {
        let client = bob_client.clone();
        let contract_address = contract_address.clone();
        let payload = dynamic_counter_args(7, 5);
        let intent = dynamic_counter_call_intent(
            &artifact,
            &contract_address,
            &contract_alias,
            "bump_via_helper",
            &payload,
        );
        async move {
            client
                .account_client()
                .post_contract_call_json(
                    &iroha_test_samples::BOB_ID.clone(),
                    Some(iroha_test_samples::BOB_KEYPAIR.private_key()),
                    Some(&contract_address),
                    None,
                    "bump_via_helper",
                    Some(&payload),
                    None,
                    None,
                    None,
                    &FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(100_000)),
                    &intent,
                )
                .await
        }
    };
    let (alice_response, bob_response) = tokio::join!(alice_submission, bob_submission);
    let alice_response = alice_response?;
    let bob_response = bob_response?;
    let alice_tx_hash = alice_response
        .get("tx_hash_hex")
        .and_then(norito::json::Value::as_str)
        .ok_or_else(|| eyre!("direct bump response missing tx_hash_hex: {alice_response:?}"))?
        .to_owned();
    let bob_tx_hash = bob_response
        .get("tx_hash_hex")
        .and_then(norito::json::Value::as_str)
        .ok_or_else(|| eyre!("helper bump response missing tx_hash_hex: {bob_response:?}"))?
        .to_owned();
    let (alice_block_height, bob_block_height) = tokio::try_join!(
        wait_for_tx_applied(
            &http,
            alice_client.client().endpoint(),
            &alice_tx_hash,
            Duration::from_secs(60),
            "direct dynamic bump",
        ),
        wait_for_tx_applied(
            &http,
            bob_client.client().endpoint(),
            &bob_tx_hash,
            Duration::from_secs(60),
            "helper-hidden dynamic bump",
        ),
    )?;
    assert_eq!(
        alice_block_height, bob_block_height,
        "concurrent conflicting calls must be observed in the same committed block"
    );
    network.ensure_blocks(alice_block_height).await?;
    let mut peer_values = Vec::with_capacity(network.peers().len());
    for peer in network.peers() {
        let peer_client = peer.client();
        peer_values.push(
            contract_state_json_value(
                &http,
                peer_client.client().endpoint(),
                &contract_address,
                "Counters/7",
            )
            .await?,
        );
    }
    let expected = norito::json::Value::from("8");
    assert!(
        peer_values.iter().all(|value| value == &expected),
        "conflicting dynamic calls lost an update or peers diverged: {peer_values:?}"
    );
    assert!(
        peer_values.windows(2).all(|pair| pair[0] == pair[1]),
        "contract state differs across voting peers: {peer_values:?}"
    );
    Ok(())
}
#[tokio::test]
async fn typed_core_query_pagination_is_deterministic_on_four_peers() -> Result<()> {
    let seeded_accounts = (0..6)
        .map(|index| {
            KeyPair::try_from_seed(
                format!("typed-core-query-account-{index}").into_bytes(),
                Algorithm::Ed25519,
            )
            .expect("derive deterministic typed-query account keypair")
            .public_key()
            .clone()
        })
        .map(AccountId::new)
        .collect::<Vec<_>>();
    let register_permission: Permission = CanManageSmartContractCode.into();
    let manage_alias_permission: Permission = CanManageAccountAlias {
        scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
    }
    .into();
    let mut builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_block_cadence(Duration::from_secs(4))
        .with_npos_consensus()
        .with_config_layer(|layer| {
            layer
                .write(["nexus", "lane_count"], 1i64)
                // Contract views share the public contract-route limiter with
                // deployments. This gate deliberately walks every typed page
                // on every peer in a tight sequence, so give the semantic test
                // a deterministic budget instead of depending on token refill
                // timing between otherwise single-pass page requests.
                .write(["torii", "deploy_rate_per_origin_per_sec"], 10_000i64)
                .write(["torii", "deploy_burst_per_origin"], 10_000i64);
        })
        .with_genesis_instruction(Grant::account_permission(
            register_permission,
            iroha_test_samples::ALICE_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            manage_alias_permission,
            iroha_test_samples::ALICE_ID.clone(),
        ));
    for account_id in &seeded_accounts {
        builder =
            builder.with_genesis_instruction(Register::account(Account::new(account_id.clone())));
    }
    for index in 0_u64..6 {
        let domain_id = DomainId::try_new(format!("typed-query-{index}"), "universal")?;
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            format!("coin{index}").parse()?,
        );
        let asset_id = AssetId::new(
            asset_definition_id.clone(),
            iroha_test_samples::ALICE_ID.clone(),
        );
        let nft_id = NftId::new(domain_id.clone(), format!("item{index}").parse()?);
        builder = builder
            .with_genesis_instruction(Register::domain(Domain::new(domain_id)))
            .with_genesis_instruction(Register::asset_definition(AssetDefinition::numeric(
                asset_definition_id.clone(),
                format!("Typed query asset {index}"),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )))
            .with_genesis_instruction(Mint::asset_quantity(index + 1, asset_id))
            .with_genesis_instruction(Register::nft(Nft::new(nft_id, Metadata::default())));
    }
    let context = stringify!(typed_core_query_pagination_is_deterministic_on_four_peers);
    let network = sandbox::start_network_async_or_skip(builder, context).await?;
    let Some(network) = sandbox::enforce_network_start_requirement(network, context)? else {
        return Ok(());
    };
    assert_eq!(network.peers().len(), 4, "test requires four voting peers");
    let handshake = signed_consensus_handshake(&network)?;
    handshake
        .validate()
        .map_err(|error| eyre!("invalid signed consensus handshake: {error}"))?;
    assert_eq!(
        handshake.mode,
        SumeragiConsensusMode::Npos,
        "typed-query pagination gate requires the Sora NPoS profile"
    );
    assert_eq!(
        handshake.sumeragi_context.da_layout,
        recommended_data_availability_layout(),
        "typed-query pagination gate requires the signed mandatory DA layout"
    );
    network.ensure_blocks(1).await?;
    let deploy_client = network.peers()[0].client();
    let http = integration_tests::http::client();
    let (contract_address, deployment_tx_hash, deploy_height) = deploy_contract_artifact(
        &deploy_client,
        &http,
        &typed_core_query_pager_artifact(),
        "typed_core_query_pager",
        "deploy typed core-query pager",
    )
    .await?;
    network.ensure_blocks(deploy_height).await?;
    verify_contract_finality_everywhere(&network, deploy_height, Some(deployment_tx_hash)).await?;
    let (account_ids, asset_ids, asset_definition_ids, domain_ids, nft_ids) =
        read_on_dedicated_thread({
            let client = deploy_client.clone();
            move || -> Result<_> {
                let account_ids = client
                    .client()
                    .query(FindAccounts)
                    .execute_all()?
                    .into_iter()
                    .map(|account| account.id().clone())
                    .collect::<Vec<_>>();
                let asset_ids = client
                    .client()
                    .query(FindAssets::new())
                    .execute_all()?
                    .into_iter()
                    .map(|asset| asset.id().clone())
                    .collect::<Vec<_>>();
                let asset_definition_ids = client
                    .client()
                    .query(FindAssetDefinitions::new())
                    .execute_all()?
                    .into_iter()
                    .map(|definition| definition.id().clone())
                    .collect::<Vec<_>>();
                let domain_ids = client
                    .client()
                    .query(FindDomains::new())
                    .execute_all()?
                    .into_iter()
                    .map(|domain| domain.id().clone())
                    .collect::<Vec<_>>();
                let nft_ids = client
                    .client()
                    .query(FindNfts::new())
                    .execute_all()?
                    .into_iter()
                    .map(|nft| nft.id().clone())
                    .collect::<Vec<_>>();
                Ok((
                    account_ids,
                    asset_ids,
                    asset_definition_ids,
                    domain_ids,
                    nft_ids,
                ))
            }
        })
        .await?;
    assert_canonical_query_order(&account_ids, "account");
    assert_canonical_query_order(&asset_ids, "asset");
    assert_canonical_query_order(&asset_definition_ids, "asset-definition");
    assert_canonical_query_order(&domain_ids, "domain");
    assert_canonical_query_order(&nft_ids, "NFT");
    let families: [(&str, &str, Vec<String>, &[&str]); 5] = [
        (
            "accounts",
            "AccountView",
            account_ids.into_iter().map(|id| id.to_string()).collect(),
            &["id", "metadata"],
        ),
        (
            "assets",
            "AssetView",
            asset_ids.into_iter().map(|id| id.to_string()).collect(),
            &["id", "amount"],
        ),
        (
            "asset_definitions",
            "AssetDefinitionView",
            asset_definition_ids
                .into_iter()
                .map(|id| id.to_string())
                .collect(),
            &[
                "id",
                "name",
                "description",
                "owned_by",
                "total_quantity",
                "metadata",
            ],
        ),
        (
            "domains",
            "DomainView",
            domain_ids.into_iter().map(|id| id.to_string()).collect(),
            &["id", "owned_by", "metadata"],
        ),
        (
            "nfts",
            "NftView",
            nft_ids.into_iter().map(|id| id.to_string()).collect(),
            &["id", "owned_by", "content"],
        ),
    ];
    for (entrypoint, _, expected_ids, _) in &families {
        assert!(
            (6..=64).contains(&expected_ids.len()),
            "the {entrypoint} fixture must fit one bounded page and contain two partial pages; \
             found {} entities",
            expected_ids.len()
        );
    }
    const CURSOR_PAGE_LIMIT: i64 = 3;
    let mut peer_results = Vec::with_capacity(network.peers().len());
    for peer in network.peers() {
        let mut family_pages = Vec::with_capacity(families.len());
        for (entrypoint, view_name, expected_ids, _) in &families {
            let expected_cursor_pages = expected_ids
                .len()
                .div_ceil(usize::try_from(CURSOR_PAGE_LIMIT).expect("positive page limit"));
            let mut pages = Vec::with_capacity(expected_cursor_pages + 1);
            let mut offset = 0_i64;
            loop {
                if pages.len() >= expected_cursor_pages {
                    return Err(eyre!(
                        "{entrypoint} cursor walk did not terminate within \
                         {expected_cursor_pages} pages"
                    ));
                }
                let page = invoke_typed_core_query_page(
                    peer.client(),
                    &contract_address,
                    entrypoint,
                    offset,
                    CURSOR_PAGE_LIMIT,
                )
                .await?;
                let (_, next_offset) = typed_query_page_parts(&page, view_name)?;
                pages.push(page);
                let Some(next_offset) = next_offset else {
                    break;
                };
                if next_offset <= offset {
                    return Err(eyre!(
                        "{entrypoint} cursor did not advance strictly: \
                         current={offset}, next={next_offset}"
                    ));
                }
                offset = next_offset;
            }
            pages.push(
                invoke_typed_core_query_page(peer.client(), &contract_address, entrypoint, 0, 64)
                    .await?,
            );
            family_pages.push(pages);
        }
        peer_results.push(family_pages);
    }
    assert!(
        peer_results.windows(2).all(|pair| pair[0] == pair[1]),
        "typed page projections for the five core entity families differ across voting peers: \
         {peer_results:?}"
    );
    let canonical_families = peer_results
        .first()
        .ok_or_else(|| eyre!("four-peer fixture returned no peer results"))?;
    for (family_index, (entrypoint, view_name, expected_ids, expected_fields)) in
        families.iter().enumerate()
    {
        let pages = &canonical_families[family_index];
        let (all_page, cursor_pages) = pages
            .split_last()
            .ok_or_else(|| eyre!("{entrypoint} returned no typed pages"))?;
        let mut walked_ids = Vec::with_capacity(expected_ids.len());
        let mut expected_offset = 0_usize;
        for (page_index, page) in cursor_pages.iter().enumerate() {
            let (page_ids, next_offset) = typed_query_page_parts(page, view_name)?;
            let expected_end = expected_offset
                .saturating_add(
                    usize::try_from(CURSOR_PAGE_LIMIT).expect("positive cursor page limit"),
                )
                .min(expected_ids.len());
            assert_eq!(
                page_ids.as_slice(),
                &expected_ids[expected_offset..expected_end],
                "{entrypoint} cursor page {page_index} must preserve canonical ID order"
            );
            let expected_next = (expected_end < expected_ids.len())
                .then(|| i64::try_from(expected_end).expect("fixture length fits in i64"));
            assert_eq!(
                next_offset, expected_next,
                "{entrypoint} cursor page {page_index} must return its exact continuation"
            );
            assert_typed_query_projection(page, view_name, expected_fields)?;
            walked_ids.extend(page_ids);
            expected_offset = expected_end;
        }
        assert_eq!(
            walked_ids.as_slice(),
            expected_ids.as_slice(),
            "{entrypoint} cursor walk must return every canonical ID exactly once"
        );
        let (all_ids, all_next) = typed_query_page_parts(all_page, view_name)?;
        assert_eq!(
            &all_ids, expected_ids,
            "{entrypoint} maximum bounded page must include the complete fixture"
        );
        assert_eq!(
            all_next, None,
            "{entrypoint} final bounded page must return Option::none"
        );
        assert_typed_query_projection(all_page, view_name, expected_fields)?;
    }
    const INVALID_PAGINATION_BOUNDS: [(&str, &str, &str, &str, &str); 8] = [
        (
            "negative offset",
            "-1",
            "1",
            "DecodeError",
            "instruction decode error",
        ),
        (
            "negative limit",
            "0",
            "-1",
            "AssertionFailed",
            "assertion failed (constraint violation)",
        ),
        (
            "offset-plus-limit overflow",
            "9223372036854775807",
            "1",
            "DecodeError",
            "instruction decode error",
        ),
        (
            "zero limit",
            "0",
            "0",
            "DecodeError",
            "instruction decode error",
        ),
        (
            "limit above the maximum",
            "0",
            "65",
            "DecodeError",
            "instruction decode error",
        ),
        (
            "offset above the signed host range",
            "9223372036854775808",
            "1",
            "AssertionFailed",
            "assertion failed (constraint violation)",
        ),
        (
            "offset above the unsigned host range",
            "18446744073709551616",
            "1",
            "AssertionFailed",
            "assertion failed (constraint violation)",
        ),
        (
            "limit above the unsigned host range",
            "0",
            "18446744073709551616",
            "AssertionFailed",
            "assertion failed (constraint violation)",
        ),
    ];
    for (entrypoint, _, _, _) in &families {
        let entrypoint = *entrypoint;
        for &(bound_class, offset, limit, expected_trap, expected_message) in
            &INVALID_PAGINATION_BOUNDS
        {
            let mut peer_rejections = Vec::with_capacity(network.peers().len());
            for peer in network.peers() {
                let peer_client = peer.client();
                let torii_url = peer_client.client().endpoint().clone();
                let (status, body) = post_typed_core_query_page(
                    &http,
                    &torii_url,
                    &contract_address,
                    entrypoint,
                    typed_core_query_page_payload_literals(offset, limit),
                )
                .await?;
                assert_eq!(
                    status,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "{entrypoint} {bound_class} must be a semantic rejection on every peer: \
                     offset={offset}, limit={limit}, body={body:?}"
                );
                assert_eq!(
                    body.get("ok").and_then(norito::json::Value::as_bool),
                    Some(false),
                    "{entrypoint} {bound_class} rejection must set ok=false: {body:?}"
                );
                let actual_entrypoint = body
                    .get("entrypoint")
                    .and_then(norito::json::Value::as_str)
                    .ok_or_else(|| {
                        eyre!("{entrypoint} {bound_class} rejection has no entrypoint: {body:?}")
                    })?
                    .to_owned();
                assert_eq!(actual_entrypoint, entrypoint);
                let actual_error = body
                    .get("error")
                    .and_then(norito::json::Value::as_str)
                    .ok_or_else(|| {
                        eyre!("{entrypoint} {bound_class} rejection has no error: {body:?}")
                    })?
                    .to_owned();
                assert_eq!(
                    actual_error,
                    format!("contract view execution failed: {expected_message}"),
                    "{entrypoint} {bound_class} returned the wrong semantic fault"
                );
                let diagnostic = body
                    .get("vm_diagnostic")
                    .and_then(norito::json::Value::as_object)
                    .ok_or_else(|| {
                        eyre!("{entrypoint} {bound_class} rejection has no VM diagnostic: {body:?}")
                    })?;
                let actual_trap = diagnostic
                    .get("trap_kind")
                    .and_then(norito::json::Value::as_str)
                    .ok_or_else(|| {
                        eyre!("{entrypoint} {bound_class} rejection has no trap kind: {body:?}")
                    })?
                    .to_owned();
                let actual_message = diagnostic
                    .get("message")
                    .and_then(norito::json::Value::as_str)
                    .ok_or_else(|| {
                        eyre!(
                            "{entrypoint} {bound_class} rejection has no diagnostic message: \
                             {body:?}"
                        )
                    })?
                    .to_owned();
                assert_eq!(actual_trap, expected_trap);
                assert_eq!(actual_message, expected_message);
                peer_rejections.push((
                    status.as_u16(),
                    actual_entrypoint,
                    actual_error,
                    actual_trap,
                    actual_message,
                ));
            }
            assert!(
                peer_rejections.windows(2).all(|pair| pair[0] == pair[1]),
                "{entrypoint} {bound_class} semantic rejection differs across voting peers: \
                 {peer_rejections:?}"
            );
        }
    }
    Ok(())
}
#[test]
fn contract_v1_executes_and_survives_four_peer_native_finality_restart() -> Result<()> {
    run_contract_v1_four_peer_native_finality_restart(
        false,
        stringify!(contract_v1_executes_and_survives_four_peer_native_finality_restart),
    )
}

#[test]
fn contract_v1_genesis_registered_artifact_executes_and_survives_four_peer_native_finality_restart()
-> Result<()> {
    run_contract_v1_four_peer_native_finality_restart(
        true,
        stringify!(
            contract_v1_genesis_registered_artifact_executes_and_survives_four_peer_native_finality_restart
        ),
    )
}

fn run_contract_v1_four_peer_native_finality_restart(
    registered_in_genesis: bool,
    context: &'static str,
) -> Result<()> {
    // Genesis construction needs the same native test stack as the other
    // four-validator corridors. This does not change the IVM stack limit.
    const TEST_STACK_BYTES: usize = 64 * 1024 * 1024;
    let worker = std::thread::Builder::new()
        .name(context.to_owned())
        .stack_size(TEST_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(TEST_STACK_BYTES)
                .enable_all()
                .build()
                .expect("build four-validator contract runtime")
                .block_on(contract_v1_four_peer_native_finality_restart_impl(
                    registered_in_genesis,
                    context,
                ))
        })
        .expect("spawn four-validator contract test");
    match worker.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn contract_v1_four_peer_native_finality_restart_impl(
    registered_in_genesis: bool,
    context: &'static str,
) -> Result<()> {
    let encoding = ManifestEncodingBudget::new()?;
    let register_permission: Permission = CanManageSmartContractCode.into();
    let enact_permission: Permission = CanEnactGovernance.into();
    let mut builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        // Leave one full signed cadence between full-mesh admission and the
        // first genesis QC wave on shared runners. This matches the existing
        // four-validator multi-QC integration envelope.
        .with_block_cadence(Duration::from_secs(8))
        .with_npos_consensus()
        .with_config_layer(|layer| {
            // Nexus is selected by the canonical lane configuration; V1 has
            // no runtime `nexus.enabled` switch.
            layer
                .write(["nexus", "lane_count"], 1i64)
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    1_073_741_824_i64,
                )
                .write(["logger", "level"], "INFO")
                .write(
                    ["logger", "filter"],
                    "iroha_core::sumeragi=trace,iroha_p2p=debug",
                )
                // Keep SoraNet PoW enabled at the
                // production difficulty while bounding full-mesh startup work.
                .write(
                    [
                        "network",
                        "soranet_handshake",
                        "pow",
                        "puzzle",
                        "memory_kib",
                    ],
                    i64::from(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB),
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "time_cost"],
                    1_i64,
                )
                .write(
                    ["network", "soranet_handshake", "pow", "puzzle", "lanes"],
                    1_i64,
                );
        })
        .with_genesis_instruction(SetParameter::new(contract_probe_block_gas_parameter()))
        .with_genesis_instruction(Grant::account_permission(
            register_permission,
            iroha_test_samples::ALICE_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            enact_permission,
            iroha_test_samples::ALICE_ID.clone(),
        ))
        .with_genesis_instruction(Grant::account_permission(
            Permission::from(contract_probe_alias_management_permission()),
            iroha_test_samples::ALICE_ID.clone(),
        ));
    // Genesis can register an artifact without an instance address. Its registrar signs the
    // manifest normally; deployment still waits for the final genesis-derived network identity.
    // This companion leaves the separate upload/register/Commit acceptance gate intact.
    let pre_registered_artifact = if registered_in_genesis {
        let artifact = contract_state_probe_artifact();
        builder = builder
            .with_genesis_keypair(iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone());
        for instruction in contract_probe_genesis_registration(&artifact, &encoding)? {
            builder = builder.with_genesis_instruction(instruction);
        }
        Some(artifact)
    } else {
        None
    };
    let network = sandbox::start_network_async_or_skip(builder, context).await?;
    let Some(network) = sandbox::enforce_network_start_requirement(network, context)? else {
        return Ok(());
    };
    assert_eq!(network.peers().len(), 4, "test requires four voting peers");
    {
        // Both registration modes must carry the exact budget in their signed genesis.
        let genesis = network.genesis();
        let expected = contract_probe_block_gas_parameter();
        let Parameter::Custom(expected_custom) = &expected else {
            unreachable!("fixture helper returns a custom parameter");
        };
        let mut block_gas_parameters = Vec::new();
        for transaction in genesis.0.external_transactions() {
            let iroha_data_model::transaction::Executable::Instructions(instructions) =
                transaction.instructions()
            else {
                panic!("every signed genesis transaction must contain inspectable instructions");
            };
            for instruction in instructions {
                let Some(set_parameter) = instruction.as_any().downcast_ref::<SetParameter>()
                else {
                    continue;
                };
                if let Parameter::Custom(custom) = set_parameter.inner()
                    && custom.id() == expected_custom.id()
                {
                    block_gas_parameters.push(set_parameter.inner().clone());
                }
            }
        }
        assert_eq!(
            block_gas_parameters,
            vec![expected],
            "signed genesis must contain the exact probe block budget once in either scenario",
        );
    }
    let handshake = signed_consensus_handshake(&network)?;
    handshake
        .validate()
        .map_err(|error| eyre!("invalid signed consensus handshake: {error}"))?;
    assert_eq!(
        handshake.mode,
        SumeragiConsensusMode::Npos,
        "contract V1 restart gate requires the Sora NPoS profile"
    );
    assert_eq!(
        handshake.sumeragi_context.da_layout,
        recommended_data_availability_layout(),
        "contract V1 restart gate requires the signed mandatory DA layout"
    );
    let client = network.client();
    let http = integration_tests::http::client();
    network.ensure_blocks(1).await?;
    let code_bytes = pre_registered_artifact.unwrap_or_else(contract_state_probe_artifact);
    if registered_in_genesis {
        let verified = ivm::verify_contract_artifact(&code_bytes)
            .map_err(|error| eyre!("verify pre-registered probe: {error}"))?;
        let expected = verified.manifest.try_signed(
            encoding.context(),
            encoding.max_frame_bytes(),
            &iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
        )?;
        for peer in network.peers() {
            let reader = peer.client();
            let code_hash = verified.code_hash;
            let actual = read_on_dedicated_thread(move || {
                reader.client().query_single(
                    iroha_data_model::query::smart_contract::FindContractManifestByArtifactId::new(
                        iroha_data_model::smart_contract::ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
                    ),
                ).map_err(Into::into)
            })
            .await?;
            assert_eq!(
                actual, expected,
                "genesis must retain the exact signed manifest on every validator"
            );
        }
    }
    let contract_alias = iroha_data_model::smart_contract::ContractAlias::from_components(
        "contract_state_probe",
        None,
        "universal",
    )
    .expect("contract alias");
    let (contract_address, _, _, deployment_tx_hash) = read_on_dedicated_thread({
        let client = client.clone();
        let code_bytes = code_bytes.clone();
        let contract_alias = contract_alias.clone();
        move || {
            deploy_contract_locally_signed_with_registration(
                &client,
                &code_bytes,
                contract_alias,
                registered_in_genesis,
                Some(&iroha_test_samples::ALICE_ID),
            )
        }
    })
    .await?;
    // Observe state application, then authenticate its original native certificate.
    let deployment_height = wait_for_tx_applied(
        &http,
        client.client().endpoint(),
        &hex::encode(deployment_tx_hash.as_ref()),
        network.da_commit_quorum_timeout(),
        "contract V1 deployment",
    )
    .await?;
    network.ensure_blocks(deployment_height).await?;
    let deployment_hash = Hash::from(deployment_tx_hash);
    verify_contract_finality_everywhere(&network, deployment_height, Some(deployment_hash)).await?;
    // CommitContractDeployment already activates the address, binds its alias and stages
    // hajimari; its transaction also grants Alice the exact hook invocation token.
    // Pin the address/code in a trusted intent, then sign the SDK's exact quoted
    // transaction locally. No payload is sent for either zero-parameter hook.
    let mut verification_height = deployment_height;
    for (entrypoint, gas_limit) in [
        ("hajimari", 10_000),
        ("verify", CONTRACT_STATE_PROBE_GAS_LIMIT),
    ] {
        let intent = contract_probe_call_intent(
            &code_bytes,
            &contract_address,
            &contract_alias,
            entrypoint,
        )?;
        let response = if registered_in_genesis && entrypoint == "verify" {
            submit_contract_probe_detached(&client, &contract_alias, &intent, gas_limit).await?
        } else {
            client
                .account_client()
                .post_contract_call_json(
                    &iroha_test_samples::ALICE_ID,
                    Some(iroha_test_samples::ALICE_KEYPAIR.private_key()),
                    None,
                    Some(&contract_alias),
                    entrypoint,
                    None,
                    None,
                    None,
                    None,
                    &FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(gas_limit)),
                    &intent,
                )
                .await?
        };
        if response
            .get("submitted")
            .and_then(norito::json::Value::as_bool)
            != Some(true)
        {
            return Err(eyre!(
                "{entrypoint} was not signed locally and submitted: {response:?}"
            ));
        }
        let tx_hash = response
            .get("tx_hash_hex")
            .and_then(norito::json::Value::as_str)
            .ok_or_else(|| {
                eyre!("{entrypoint} response is missing its exact transaction hash: {response:?}")
            })?;
        // Emit only the locally signed public identity after exact response validation.
        // Observers can follow either submission path without transaction bodies.
        println!(
            "{}",
            contract_probe_call_observation(
                entrypoint,
                tx_hash,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis(),
            )?,
        );
        verification_height = wait_for_tx_applied(
            &http,
            client.client().endpoint(),
            tx_hash,
            network.da_commit_quorum_timeout(),
            entrypoint,
        )
        .await?;
    }
    // Applied is local to the submitting peer. Compare state only after every
    // validator has applied the exact verification transaction height.
    network.ensure_blocks(verification_height).await?;
    let expected_result = norito::json::Value::from("7".to_owned());
    for (index, peer) in network.peers().iter().enumerate() {
        wait_for_contract_applied_height(peer, verification_height, network.sync_timeout()).await?;
        let decoded =
            contract_view_json_value(peer.client(), &contract_address, "readback").await?;
        assert_eq!(
            decoded, expected_result,
            "peer {index} decoded a non-canonical contract V1 result"
        );
        let stored = contract_state_json_value(
            &http,
            peer.client().client().endpoint(),
            &contract_address,
            "probe_readback",
        )
        .await?;
        assert_eq!(
            stored, expected_result,
            "peer {index} read a divergent contract V1 state value"
        );
    }

    verify_contract_finality_everywhere(&network, verification_height, None).await?;
    let restart_index = network.peers().len() - 1;
    let restart_peer = network.peers()[restart_index].clone();
    let config_layers = network.config_layers().collect::<Vec<_>>();
    let mut healthy_heights = Vec::with_capacity(restart_index);
    for peer in network.peers().iter().take(restart_index) {
        healthy_heights.push(peer.status().await?.blocks);
    }
    let recovery_height = healthy_heights
        .into_iter()
        .max()
        .ok_or_else(|| eyre!("contract V1 restart gate has no healthy peer height"))?;
    assert!(
        restart_peer.shutdown_if_started().await,
        "selected contract V1 peer was not running before restart"
    );
    tokio::time::timeout(
        network.peer_startup_timeout(),
        restart_peer.start_checked(config_layers.iter(), None),
    )
    .await
    .map_err(|_| eyre!("contract V1 peer restart exceeded the startup timeout"))??;
    tokio::time::timeout(
        network.sync_timeout(),
        restart_peer.once_block(recovery_height),
    )
    .await
    .map_err(|_| {
        eyre!(
            "restarted contract V1 peer did not recover height {recovery_height} within {:?}",
            network.sync_timeout()
        )
    })?;
    // A durable block journal can satisfy once_block before replay has rebuilt world state.
    // The authoritative status endpoint must confirm applied recovery before contract reads.
    wait_for_contract_applied_height(&restart_peer, recovery_height, network.sync_timeout())
        .await?;
    let restarted_result =
        contract_view_json_value(restart_peer.client(), &contract_address, "readback").await?;
    assert_eq!(
        restarted_result, expected_result,
        "restarted peer decoded a different contract V1 result"
    );
    let restarted_state = contract_state_json_value(
        &http,
        restart_peer.client().client().endpoint(),
        &contract_address,
        "probe_readback",
    )
    .await?;
    assert_eq!(
        restarted_state, expected_result,
        "restarted peer did not recover the contract V1 state value"
    );
    Ok(())
}
