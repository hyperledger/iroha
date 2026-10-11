//! Native deployment instruction and attribution regressions migrated from the CLI helper.
use super::*;
use iroha::data_model::transaction::Executable;
use std::{fs, num::NonZeroU64};
fn test_network_id() -> NetworkId {
    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
        .parse()
        .expect("canonical test network id")
}
fn deployment_key_fixture() -> KeyPair {
    KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::Ed25519)
        .expect("generate checked IVM contract deploy fixture key")
}
fn test_fee_payment() -> FeePaymentIntent {
    FeePaymentIntent::authority(
        Vec::new(),
        Some(NonZeroU64::new(1_000_000).expect("nonzero test gas limit")),
    )
}
#[test]
fn deployment_fixture_uses_checked_ed25519_key_generation() {
    let key_pair = deployment_key_fixture();
    let actual = key_pair
        .public_key()
        .try_algorithm()
        .expect("IVM contract deploy fixture key advertises a valid algorithm");
    assert_eq!(actual, iroha_crypto::Algorithm::Ed25519);
}
#[test]
fn deployment_state_decimal_fields_must_be_canonical() -> Result<()> {
    assert_eq!(canonical_decimal_u64("17", "fixture")?, 17);
    for invalid in ["", "017", "+17", " 17", "17 "] {
        assert!(
            canonical_decimal_u64(invalid, "fixture").is_err(),
            "non-canonical decimal `{invalid}` must fail"
        );
    }
    Ok(())
}
#[test]
fn deployment_state_snapshot_rejects_unknown_fields() {
    let payload = br#"{
            "authority":"authority",
            "contract_alias":"deploy::universal",
            "deploy_nonce":"0",
            "dataspace_alias":"universal",
            "dataspace_id":"0",
            "previous_contract_address":null,
            "observed_block_height":"1",
            "observed_block_hash":"hash",
            "ledger_time_ms":"1",
            "chain_discriminant":"369",
            "retired_hint":"must-fail"
        }"#;
    let result = norito::json::from_slice::<ContractDeploymentStateSnapshot>(payload);
    assert!(
        result.is_err(),
        "deployment-state DTO must reject unknown compatibility fields"
    );
}
#[test]
fn transaction_signing_context_checked_helper_verifies() -> Result<()> {
    let key_pair = deployment_key_fixture();
    let authority = AccountId::of(key_pair.public_key().clone());
    let fee_payment = test_fee_payment();
    let metadata = Metadata::default();
    let signing = TransactionSigningContext {
        network_id: test_network_id(),
        authority: &authority,
        private_key: key_pair.private_key(),
        transaction_ttl: None,
        fee_payment: &fee_payment,
        metadata: &metadata,
    };
    let tx = signing.sign(Vec::<InstructionBox>::new())?;
    tx.verify_signature()
        .wrap_err("verify IVM deploy instruction helper signature")?;
    assert_eq!(tx.authority(), &authority);
    Ok(())
}
#[test]
fn final_deployment_transaction_is_one_native_atomic_commit() -> Result<()> {
    let key_pair = deployment_key_fixture();
    let authority = AccountId::of(key_pair.public_key().clone());
    let network_id = test_network_id();
    let fee_payment = test_fee_payment();
    let metadata = Metadata::default();
    let contract_address = iroha::data_model::smart_contract::ContractAddress::derive(
        &network_id,
        &authority,
        11,
        DataSpaceId::UNIVERSAL,
    )
    .map_err(|error| eyre!(error.to_string()))?;
    let contract_alias: ContractAlias = "atomic_deploy::universal".parse()?;
    let code_hash = Hash::new(b"reviewed-contract-artifact");
    let transaction = build_commit_deployment_transaction(
        &TransactionSigningContext {
            network_id,
            authority: &authority,
            private_key: key_pair.private_key(),
            transaction_ttl: None,
            fee_payment: &fee_payment,
            metadata: &metadata,
        },
        11,
        contract_address.clone(),
        code_hash,
        contract_alias.clone(),
        None,
    )?;
    let Executable::Instructions(instructions) = transaction.instructions() else {
        panic!("native contract deployment commit must use instructions");
    };
    assert_eq!(instructions.len(), 1);
    let commit = instructions[0]
        .as_any()
        .downcast_ref::<CommitContractDeployment>()
        .expect("final deployment transaction must be the native atomic commit");
    assert_eq!(commit.expected_deploy_nonce, 11);
    assert_eq!(commit.contract_address, contract_address);
    assert_eq!(commit.code_hash, code_hash);
    assert_eq!(commit.contract_alias, contract_alias);
    assert!(commit.lease_expiry_ms.is_none());
    assert!(commit.expected_previous_contract_address.is_none());
    assert!(
        instructions[0]
            .as_any()
            .downcast_ref::<iroha::data_model::isi::SetKeyValueBox>()
            .is_none(),
        "generic metadata writes cannot advance the reserved deployment nonce"
    );
    Ok(())
}
#[test]
fn one_chunk_contract_registration_uses_upload_and_finalize() -> Result<()> {
    let key_pair = deployment_key_fixture();
    let authority = AccountId::of(key_pair.public_key().clone());
    let code = vec![1, 2, 3, 4];
    let plan = build_native_upload_transaction_plan(
        &TransactionSigningContext {
            network_id: test_network_id(),
            authority: &authority,
            private_key: key_pair.private_key(),
            transaction_ttl: None,
            fee_payment: &test_fee_payment(),
            metadata: &Metadata::default(),
        },
        ContractArtifactId::new(
            DataSpaceId::new(u64::MAX),
            ivm_abi::metadata::contract_code_hash(&code),
        ),
        &code,
    )?;
    assert_eq!(plan.chunk_count, 1);
    assert!(plan.pre_stage.is_empty());
    assert_eq!(plan.finalize.1, "register-bytes-finalize");
    let Executable::Instructions(instructions) = plan.finalize.2.instructions() else {
        panic!("native upload plan must use instruction transactions");
    };
    assert_eq!(instructions.len(), 2);
    let upload = instructions[0]
        .as_any()
        .downcast_ref::<UploadSmartContractCodeChunk>()
        .expect("first instruction uploads the only chunk");
    assert_eq!(upload.artifact_id.dataspace_id, DataSpaceId::new(u64::MAX));
    assert_eq!(upload.chunk_index, 0);
    assert_eq!(upload.chunk_count, 1);
    assert_eq!(upload.total_size, u64::try_from(code.len())?);
    assert_eq!(
        upload.artifact_id.code_hash,
        ivm_abi::metadata::contract_code_hash(&code)
    );
    assert_eq!(upload.chunk, code);
    let finalize = instructions[1]
        .as_any()
        .downcast_ref::<FinalizeSmartContractCodeUpload>()
        .expect("second instruction finalizes the only chunk");
    assert_eq!(finalize.artifact_id, upload.artifact_id);
    assert_eq!(finalize.total_size, upload.total_size);
    assert_eq!(finalize.chunk_count, upload.chunk_count);
    let report = native_upload_report(&plan, false);
    assert!(
        report["register_bytes_stage_tx_hashes"]
            .as_array()
            .expect("one-chunk stage hashes are an array")
            .is_empty()
    );
    Ok(())
}
#[test]
fn native_upload_plan_rejects_empty_artifact() {
    let key_pair = deployment_key_fixture();
    let authority = AccountId::of(key_pair.public_key().clone());
    let result = build_native_upload_transaction_plan(
        &TransactionSigningContext {
            network_id: test_network_id(),
            authority: &authority,
            private_key: key_pair.private_key(),
            transaction_ttl: None,
            fee_payment: &test_fee_payment(),
            metadata: &Metadata::default(),
        },
        ContractArtifactId::new(DataSpaceId::UNIVERSAL, Hash::new(b"")),
        &[],
    );
    let error = match result {
        Ok(_) => panic!("an empty artifact cannot form a native upload"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("must not be empty"));
}
#[test]
fn native_upload_plan_rejects_noncanonical_code_hash() {
    let key_pair = deployment_key_fixture();
    let authority = AccountId::of(key_pair.public_key().clone());
    let code = [0x01, 0x02, 0x03];
    let result = build_native_upload_transaction_plan(
        &TransactionSigningContext {
            network_id: test_network_id(),
            authority: &authority,
            private_key: key_pair.private_key(),
            transaction_ttl: None,
            fee_payment: &test_fee_payment(),
            metadata: &Metadata::default(),
        },
        ContractArtifactId::new(
            DataSpaceId::UNIVERSAL,
            Hash::new(b"not-the-canonical-artifact-hash"),
        ),
        &code,
    );
    let error = match result {
        Ok(_) => panic!("a mismatched code hash cannot form a native upload"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("canonical artifact hash"));
}
#[test]
fn exact_chunk_boundary_uses_one_final_transaction() -> Result<()> {
    let key_pair = deployment_key_fixture();
    let authority = AccountId::of(key_pair.public_key().clone());
    let code = vec![0x91; SMART_CONTRACT_CODE_CHUNK_BYTES];
    let plan = build_native_upload_transaction_plan(
        &TransactionSigningContext {
            network_id: test_network_id(),
            authority: &authority,
            private_key: key_pair.private_key(),
            transaction_ttl: None,
            fee_payment: &test_fee_payment(),
            metadata: &Metadata::default(),
        },
        ContractArtifactId::new(
            DataSpaceId::UNIVERSAL,
            ivm_abi::metadata::contract_code_hash(&code),
        ),
        &code,
    )?;
    assert_eq!(plan.chunk_count, 1);
    assert!(plan.pre_stage.is_empty());
    let Executable::Instructions(instructions) = plan.finalize.2.instructions() else {
        panic!("native upload plan must use instructions");
    };
    let upload = instructions[0]
        .as_any()
        .downcast_ref::<UploadSmartContractCodeChunk>()
        .expect("final transaction starts with the only upload");
    assert_eq!(upload.chunk.len(), SMART_CONTRACT_CODE_CHUNK_BYTES);
    assert_eq!(upload.total_size, u64::try_from(code.len())?);
    Ok(())
}
#[test]
fn multi_mib_upload_plan_is_bounded_ordered_and_stable() -> Result<()> {
    let key_pair = deployment_key_fixture();
    let authority = AccountId::of(key_pair.public_key().clone());
    // Byte `index` is `index % 251`, produced without a narrowing cast.
    let code = (0..=250_u8)
        .cycle()
        .take(3 * 1024 * 1024 + 17)
        .collect::<Vec<_>>();
    let network_id = test_network_id();
    let contract_address = iroha::data_model::smart_contract::ContractAddress::derive(
        &network_id,
        &authority,
        11,
        DataSpaceId::UNIVERSAL,
    )
    .map_err(|error| eyre!(error.to_string()))?;
    let metadata = deployment_transaction_metadata(&contract_address, &[authority.to_string()])?;
    let plan = build_native_upload_transaction_plan(
        &TransactionSigningContext {
            network_id,
            authority: &authority,
            private_key: key_pair.private_key(),
            transaction_ttl: Some(Duration::from_secs(30)),
            fee_payment: &test_fee_payment(),
            metadata: &metadata,
        },
        ContractArtifactId::new(
            DataSpaceId::UNIVERSAL,
            ivm_abi::metadata::contract_code_hash(&code),
        ),
        &code,
    )?;
    let expected_count = code.len().div_ceil(SMART_CONTRACT_CODE_CHUNK_BYTES);
    assert_eq!(usize::try_from(plan.chunk_count)?, expected_count);
    assert_eq!(plan.pre_stage.len(), expected_count - 1);
    assert_eq!(
        plan.pre_stage.first().map(|(_, slug, _)| slug.as_str()),
        Some("register-bytes-chunk-0001-of-0049")
    );
    assert_eq!(plan.finalize.1, "register-bytes-finalize");
    let transactions = plan
        .pre_stage
        .iter()
        .map(|(_, _, tx)| tx)
        .chain(std::iter::once(&plan.finalize.2))
        .collect::<Vec<_>>();
    let mut rebuilt = Vec::with_capacity(code.len());
    for (expected_index, transaction) in transactions.iter().enumerate() {
        assert_eq!(transaction.metadata(), &metadata);
        assert!(
            transaction.encode_versioned().len()
                < iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_TX_GOSSIP.get(),
            "chunk transaction {expected_index} exceeded the default gossip frame"
        );
        let Executable::Instructions(instructions) = transaction.instructions() else {
            panic!("native upload plan must not emit IVM executables");
        };
        let upload = instructions[0]
            .as_any()
            .downcast_ref::<UploadSmartContractCodeChunk>()
            .expect("every code-bearing transaction starts with one upload");
        assert_eq!(usize::try_from(upload.chunk_index)?, expected_index);
        assert_eq!(upload.chunk_count, plan.chunk_count);
        assert_eq!(upload.total_size, u64::try_from(code.len())?);
        assert_eq!(
            upload.artifact_id.code_hash,
            ivm_abi::metadata::contract_code_hash(&code)
        );
        let expected_chunk_len = code
            .len()
            .saturating_sub(expected_index * SMART_CONTRACT_CODE_CHUNK_BYTES)
            .min(SMART_CONTRACT_CODE_CHUNK_BYTES);
        assert_eq!(upload.chunk.len(), expected_chunk_len);
        assert!(upload.chunk.len() < code.len());
        rebuilt.extend_from_slice(&upload.chunk);
        assert_eq!(
            instructions.len(),
            usize::from(expected_index + 1 == expected_count) + 1
        );
        if expected_index + 1 == expected_count {
            let finalize = instructions[1]
                .as_any()
                .downcast_ref::<FinalizeSmartContractCodeUpload>()
                .expect("last upload transaction must finalize");
            assert_eq!(finalize.artifact_id.code_hash, upload.artifact_id.code_hash);
            assert_eq!(finalize.total_size, upload.total_size);
            assert_eq!(finalize.chunk_count, upload.chunk_count);
        }
    }
    assert_eq!(rebuilt, code);
    Ok(())
}
#[test]
fn native_upload_json_reports_exact_hash_roles_and_skip_semantics() -> Result<()> {
    let key_pair = deployment_key_fixture();
    let authority = AccountId::of(key_pair.public_key().clone());
    let code = vec![0x35; 2 * SMART_CONTRACT_CODE_CHUNK_BYTES + 1];
    let plan = build_native_upload_transaction_plan(
        &TransactionSigningContext {
            network_id: test_network_id(),
            authority: &authority,
            private_key: key_pair.private_key(),
            transaction_ttl: None,
            fee_payment: &test_fee_payment(),
            metadata: &Metadata::default(),
        },
        ContractArtifactId::new(
            DataSpaceId::UNIVERSAL,
            ivm_abi::metadata::contract_code_hash(&code),
        ),
        &code,
    )?;
    let report = native_upload_report(&plan, false);
    let fields = report.as_object().expect("upload report is an object");
    assert_eq!(fields.len(), 5);
    assert!(!fields.contains_key("direct_register_bytes_tx_size"));
    assert_eq!(
        fields["register_bytes_tx_strategy"].as_str(),
        Some("native_chunks")
    );
    assert_eq!(
        fields["register_bytes_chunk_size"].as_u64(),
        Some(u64::try_from(SMART_CONTRACT_CODE_CHUNK_BYTES)?)
    );
    assert_eq!(fields["register_bytes_chunk_count"].as_u64(), Some(3));
    let expected_finalize_hash = plan.finalize.2.hash().to_string();
    assert_eq!(
        fields["register_bytes_tx_hash"].as_str(),
        Some(expected_finalize_hash.as_str())
    );
    let expected_stage_hashes = plan
        .pre_stage
        .iter()
        .map(|(_, _, transaction)| transaction.hash().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        fields["register_bytes_stage_tx_hashes"]
            .as_array()
            .expect("stage hashes are an array")
            .iter()
            .map(|value| value.as_str().expect("stage hash is a string"))
            .collect::<Vec<_>>(),
        expected_stage_hashes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
    let skipped = native_upload_report(&plan, true);
    let skipped = skipped.as_object().expect("skipped report is an object");
    assert_eq!(skipped.len(), 5);
    assert_eq!(
        skipped["register_bytes_tx_strategy"].as_str(),
        Some("native_chunks")
    );
    assert_eq!(skipped["register_bytes_chunk_count"].as_u64(), Some(3));
    assert!(skipped["register_bytes_tx_hash"].is_null());
    assert!(
        skipped["register_bytes_stage_tx_hashes"]
            .as_array()
            .expect("skipped stage hashes are an array")
            .is_empty()
    );
    Ok(())
}
#[test]
fn skip_registration_omits_all_uploads_and_emit_order_is_stable() -> Result<()> {
    let key_pair = deployment_key_fixture();
    let authority = AccountId::of(key_pair.public_key().clone());
    let code = vec![0x7a; SMART_CONTRACT_CODE_CHUNK_BYTES + 1];
    let fee_payment = test_fee_payment();
    let metadata = Metadata::default();
    let signing = TransactionSigningContext {
        network_id: test_network_id(),
        authority: &authority,
        private_key: key_pair.private_key(),
        transaction_ttl: None,
        fee_payment: &fee_payment,
        metadata: &metadata,
    };
    let upload = build_native_upload_transaction_plan(
        &signing,
        ContractArtifactId::new(
            DataSpaceId::UNIVERSAL,
            ivm_abi::metadata::contract_code_hash(&code),
        ),
        &code,
    )?;
    let mut uploads = upload.pre_stage;
    uploads.push(upload.finalize);
    let empty_transaction = || signing.sign(Vec::<InstructionBox>::new());
    let sequence =
        deployment_transaction_sequence(false, uploads, empty_transaction()?, empty_transaction()?);
    assert_eq!(
        sequence
            .iter()
            .map(|(_, slug, _)| slug.as_str())
            .collect::<Vec<_>>(),
        vec![
            "register-bytes-chunk-0001-of-0002",
            "register-bytes-finalize",
            "register-manifest",
            "commit-deployment",
        ]
    );
    let output = tempfile::tempdir()?;
    let written = sequence
        .iter()
        .map(|(_, slug, transaction)| {
            let path = output.path().join(format!("{slug}.norito"));
            let bytes = transaction.encode_versioned();
            fs::write(&path, &bytes)?;
            Ok((path, bytes.len()))
        })
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(
        written
            .iter()
            .map(|(path, _)| path.file_name().and_then(std::ffi::OsStr::to_str).unwrap())
            .collect::<Vec<_>>(),
        vec![
            "register-bytes-chunk-0001-of-0002.norito",
            "register-bytes-finalize.norito",
            "register-manifest.norito",
            "commit-deployment.norito",
        ]
    );
    for ((_, _, transaction), (path, byte_len)) in sequence.iter().zip(&written) {
        let encoded = transaction.encode_versioned();
        assert_eq!(*byte_len, encoded.len());
        assert_eq!(fs::read(path)?, encoded);
    }
    let skipped = deployment_transaction_sequence(
        true,
        sequence.into_iter().take(2).collect(),
        empty_transaction()?,
        empty_transaction()?,
    );
    assert_eq!(
        skipped
            .iter()
            .map(|(_, slug, _)| slug.as_str())
            .collect::<Vec<_>>(),
        vec!["register-manifest", "commit-deployment"]
    );
    Ok(())
}
#[test]
fn every_real_deployment_transaction_carries_identical_governance_metadata() -> Result<()> {
    let key_pair = deployment_key_fixture();
    let authority = AccountId::of(key_pair.public_key().clone());
    let network_id = test_network_id();
    let contract_address = iroha::data_model::smart_contract::ContractAddress::derive(
        &network_id,
        &authority,
        7,
        DataSpaceId::UNIVERSAL,
    )
    .map_err(|error| eyre!(error.to_string()))?;
    let approvers = vec![authority.to_string()];
    let metadata = deployment_transaction_metadata(&contract_address, &approvers)?;
    let fee_payment = test_fee_payment();
    let code = vec![0x44; SMART_CONTRACT_CODE_CHUNK_BYTES + 1];
    let signing = TransactionSigningContext {
        network_id,
        authority: &authority,
        private_key: key_pair.private_key(),
        transaction_ttl: None,
        fee_payment: &fee_payment,
        metadata: &metadata,
    };
    let upload = build_native_upload_transaction_plan(
        &signing,
        ContractArtifactId::new(
            DataSpaceId::UNIVERSAL,
            ivm_abi::metadata::contract_code_hash(&code),
        ),
        &code,
    )?;
    let mut manifest_budget = crate::manifest_encoding::ManifestEncodingBudget::new()?;
    let signer_backing = manifest_budget.reserve_signer(key_pair.public_key())?;
    let mut transactions = upload
        .pre_stage
        .into_iter()
        .map(|(_, _, transaction)| transaction)
        .chain(std::iter::once(upload.finalize.2))
        .collect::<Vec<_>>();
    let code_hash = ivm_abi::metadata::contract_code_hash(&code);
    let manifest = iroha::data_model::smart_contract::manifest::ContractManifest {
        seiyaku_name: None,
        code_hash: Some(code_hash),
        abi_hash: Some(Hash::new(b"metadata-test-abi")),
        compiler_fingerprint: None,
        features_bitmap: Some(0),
        access_set_hints: None,
        permissions: Vec::new(),
        events: Vec::new(),
        enum_types: Vec::new(),
        entrypoints: None,
        states: None,
        error_messages: None,
        error_types: None,
        kotoba: None,
        provenance: None,
    };
    let signing_frame = manifest_budget.reserve_frame(&manifest)?;
    let manifest = manifest
        .try_signed(
            manifest_budget.context(),
            signing_frame.remaining_bytes(),
            &key_pair,
        )
        .wrap_err("sign metadata-test manifest")?;
    drop(signing_frame);
    transactions.push(
        signing.sign([InstructionBox::from(RegisterSmartContractCode {
            artifact_id: ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash),
            manifest,
        })])?,
    );
    transactions.push(build_commit_deployment_transaction(
        &signing,
        7,
        contract_address,
        code_hash,
        "metadata_test::universal".parse()?,
        None,
    )?);
    for transaction in &transactions {
        assert_eq!(transaction.metadata(), &metadata);
        assert_eq!(transaction.fee_payment_intent(), &fee_payment);
        assert!(transaction.metadata().get("gas_limit").is_none());
        assert!(transaction.metadata().get("gas_asset_id").is_none());
        for key in [
            "gov_contract_address",
            "contract_address",
            "gov_manifest_approvers",
        ] {
            assert!(
                transaction.metadata().get(&Name::from_str(key)?).is_some(),
                "missing governance key {key}"
            );
        }
    }
    drop(transactions);
    drop(signer_backing);
    Ok(())
}
#[test]
fn deployment_metadata_rejects_blank_governance_approvers() {
    let key_pair = deployment_key_fixture();
    let authority = AccountId::of(key_pair.public_key().clone());
    let contract_address = iroha::data_model::smart_contract::ContractAddress::derive(
        &test_network_id(),
        &authority,
        0,
        DataSpaceId::UNIVERSAL,
    )
    .expect("derive test address");
    let error = deployment_transaction_metadata(&contract_address, &["  ".to_owned()])
        .expect_err("blank governance approver must fail before signing");
    assert!(error.to_string().contains("must not be blank"));
}
