//! Focused certified absence and append-only recovery gates; no simulated ledger qualification.
use super::*;
use iroha::data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;

fn scan_fixture(fixture: &NativeFinalityFixture, deadline: u64) -> Result<Scan> {
    Ok(Scan {
        verifier: SumeragiFinalityVerifier::new(
            fixture.genesis(),
            fixture.chain_id(),
            fixture.genesis_proof().committee.clone(),
        )?,
        network: fixture.network_id(),
        chain: fixture.chain_id().to_owned(),
        hashes: BTreeSet::new(),
        observed_height: 1,
        observed_hash: fixture.genesis().hash().to_string(),
        deadline,
        bytes: 0,
        proof_digests: Vec::new(),
        previous_time_ms: None,
    })
}

#[test]
fn expiry_complete_native_history_requires_strict_deadline_and_original_observation() -> Result<()>
{
    let fixture = NativeFinalityFixture::new();
    let mut scan = scan_fixture(&fixture, fixture.latest().block_header.creation_time_ms)?;
    let first = RetainedProof::capture(fixture.genesis_proof())?;
    let next = RetainedProof::capture(fixture.latest())?;
    let genesis = scan.accept(&first)?;
    assert!(!scan.finished(&genesis));
    let tip = scan.accept(&next)?;
    assert!(!scan.finished(&tip), "equal deadline remains pending");
    scan.deadline -= 1;
    assert!(scan.finished(&tip));
    assert_eq!(scan.proof_digests.len(), 2);
    let mut wrong = scan_fixture(&fixture, 0)?;
    wrong.observed_hash = Hash::new(b"another preparation observation").to_string();
    assert!(wrong.accept(&first).is_err());
    Ok(())
}

#[test]
fn expiry_rejects_any_original_hash_in_certified_body() -> Result<()> {
    let fixture = NativeFinalityFixture::new();
    let verified = fixture
        .verifier()
        .verify_retained_decision(fixture.latest())?;
    let transaction = verified
        .block()
        .external_transactions()
        .next()
        .expect("nonempty certified work");
    let mut scan = scan_fixture(&fixture, 0)?;
    scan.hashes.insert(transaction.hash());
    scan.accept(&RetainedProof::capture(fixture.genesis_proof())?)?;
    assert!(
        scan.accept(&RetainedProof::capture(fixture.latest())?)
            .is_err()
    );
    Ok(())
}

#[test]
fn expiry_rejects_gaps_duplicates_changed_wire_and_digest() -> Result<()> {
    let fixture = NativeFinalityFixture::new();
    let first = RetainedProof::capture(fixture.genesis_proof())?;
    let second = RetainedProof::capture(fixture.latest())?;
    let mut gap = scan_fixture(&fixture, 0)?;
    assert!(gap.accept(&second).is_err());
    let mut duplicate = scan_fixture(&fixture, 0)?;
    duplicate.accept(&first)?;
    assert!(duplicate.accept(&first).is_err());
    let mut altered = RetainedProof::capture(fixture.latest())?;
    altered.digest = Hash::new(b"changed").to_string();
    assert!(altered.decode().is_err());
    let mut altered = RetainedProof::capture(fixture.latest())?;
    altered.norito_hex.push_str("00");
    assert!(altered.decode().is_err());
    let mut wrong_chain = scan_fixture(&fixture, 0)?;
    wrong_chain.chain = "foreign-chain".into();
    wrong_chain.accept(&first)?;
    assert!(wrong_chain.accept(&second).is_err());
    Ok(())
}

#[test]
fn expiry_refuses_nonincreasing_certified_time_and_total_budget_overflow() -> Result<()> {
    let fixture = NativeFinalityFixture::new();
    let first = RetainedProof::capture(fixture.genesis_proof())?;
    let second = RetainedProof::capture(fixture.latest())?;
    let mut time = scan_fixture(&fixture, 0)?;
    time.accept(&first)?;
    time.previous_time_ms = Some(fixture.latest().block_header.creation_time_ms);
    assert!(time.accept(&second).is_err());
    let mut budget = scan_fixture(&fixture, 0)?;
    budget.bytes = MAX_TOTAL_PROOF_BYTES;
    assert!(budget.accept(&first).is_err());
    Ok(())
}

#[test]
fn expiry_initial_upload_refuses_later_attempts_any_execution_and_unknown_files() -> Result<()> {
    let (_, record) = crate::service_tests::fixture()?;
    let temporary = tempfile::tempdir()?;
    for prohibited in [
        "attempt-0001.json",
        "applied-0000.json",
        "failed-0000.json",
        "receipt.json",
        "cancelled.json",
        "unexpected.json",
    ] {
        let directory = temporary.path().join(prohibited);
        let journal = Journal::persist_plan(&directory, &record)?;
        journal.put_exact(
            "attempt-0000.json",
            &TransactionAttempt {
                name: record.transactions[0].name.clone(),
                hash: record.transactions[0].hash.clone(),
            },
        )?;
        require_initial_upload(&record, &journal)?;
        journal.put_exact(prohibited, &"untrusted")?;
        assert!(
            require_initial_upload(&record, &journal).is_err(),
            "{prohibited}"
        );
    }
    Ok(())
}

#[test]
fn expiry_tampered_marker_cannot_retire_resume_or_inspection() -> Result<()> {
    let (_, record) = crate::service_tests::fixture()?;
    let temporary = tempfile::tempdir()?;
    let journal = Journal::persist_plan(&temporary.path().join("journal"), &record)?;
    journal.put_exact(
        "attempt-0000.json",
        &TransactionAttempt {
            name: record.transactions[0].name.clone(),
            hash: record.transactions[0].hash.clone(),
        },
    )?;
    journal.put_exact(
        MARKER,
        &DeploymentValidityWindowElapsed {
            plan_digest: digest(&record)?,
            root_digest: Hash::new(b"no native proof").to_string(),
            transaction_hashes: record.preflight.transaction_hashes.clone(),
            signed_wire_digests: vec![],
            valid_until_ms: 1,
            finalized_height: 2,
            finalized_block_hash: Hash::new(b"fabricated").to_string(),
            finalized_time_ms: 2,
            proof_digests: vec!["fabricated".into(); 2],
        },
    )?;
    assert!(retained(&record, &journal).is_err());
    assert!(reject_cancelled(&record, &journal).is_err());
    Ok(())
}

#[test]
fn expiry_canonical_hex_and_public_input_bounds() -> Result<()> {
    assert_eq!(canonical_hex("ab00", 2)?, vec![0xab, 0]);
    for invalid in ["AB00", "", "a", "xxxx", "ab0000"] {
        assert!(canonical_hex(invalid, 2).is_err());
    }
    let temporary = tempfile::tempdir()?;
    let input = temporary.path().join("public-root.json");
    std::fs::write(&input, b"abcd")?;
    assert_eq!(read_bounded(&input, 4)?, b"abcd");
    assert!(read_bounded(&input, 3).is_err());
    assert_eq!(proof_name(3), "expiry-proof-0000000003.json");
    Ok(())
}

#[test]
fn expiry_deadlines_bind_every_original_signed_wire() -> Result<()> {
    let (_, record) = crate::service_tests::fixture()?;
    for step in &record.transactions {
        let signed = decode_transaction(step)?;
        assert_eq!(
            signed_deadline(&signed)?,
            u64::try_from((signed.creation_time() + signed.time_to_live().unwrap()).as_millis())?
        );
    }
    let encoded = norito::json::to_vec(&record)?;
    assert_eq!(digest(&record)?, Hash::new(encoded).to_string());
    Ok(())
}

#[test]
fn expiry_certified_public_genesis_retains_inspects_and_blocks_old_resume() -> Result<()> {
    use iroha::data_model::transaction::Executable;
    let mut fixture = NativeFinalityFixture::new_with_explicit_parameters();
    let first = fixture.genesis_proof().clone();
    let second = fixture.latest().clone();
    let third = fixture.certify(fixture.block_with_submitted_work(fixture.next_header()));
    // Retain the original result-bearing certified H1, exactly like public Taira.
    let wire = first.block_wire.clone();
    let genesis_signer = KeyPair::from_seed(vec![41; 32], iroha_crypto::Algorithm::Ed25519);
    let root = RetainedRoot {
        pins: RecoveryRoot {
            chain_id: fixture.chain_id().into(),
            network_id: fixture.network_id(),
            genesis_hash: fixture.genesis().hash(),
            signed_genesis_sha256: hex::encode(iroha_crypto::sha256(&wire)),
            genesis_public_key: genesis_signer.public_key().clone(),
            roster: first
                .committee
                .iter()
                .map(|row| row.public_key.to_string())
                .collect(),
            mode: "permissioned".into(),
        },
        signed_genesis_hex: hex::encode(&wire),
    };
    let (mut config, mut record) = crate::service_tests::fixture()?;
    config.network_id = fixture.network_id();
    config.chain = fixture.chain_id().parse()?;
    record.preflight.network_id = config.network_id;
    record.preflight.chain_id = config.chain.to_string();
    record.preflight.observed_block_hash = fixture.genesis().hash().to_string();
    record.preflight.contract_address = ContractAddress::derive(
        &config.network_id,
        &config.account,
        record.preflight.deploy_nonce,
        DataSpaceId::UNIVERSAL,
    )?;
    let metadata = deployment_transaction_metadata(&record.preflight.contract_address, &[])?;
    let signing = TransactionSigningContext {
        network_id: config.network_id,
        authority: &config.account,
        private_key: config.key_pair.private_key(),
        transaction_ttl: Some(Duration::from_millis(1)),
        fee_payment: &record.requested_fee,
        metadata: &metadata,
    };
    let commit = build_commit_deployment_transaction(
        &signing,
        record.preflight.deploy_nonce,
        record.preflight.contract_address.clone(),
        record.preflight.code_hash,
        record.preflight.contract_alias.clone(),
        None,
    )?;
    for (index, step) in record.transactions.iter_mut().enumerate() {
        let original = if index == 2 {
            commit.clone()
        } else {
            decode_transaction(step)?
        };
        let Executable::Instructions(instructions) = original.instructions() else {
            panic!("native fixture instructions")
        };
        let mut builder = TransactionBuilder::new(
            config.network_id,
            config.account.clone(),
            record.requested_fee.clone(),
        )
        .with_metadata(metadata.clone())
        .with_instructions(instructions.iter().cloned());
        builder.set_creation_time(fixture.genesis().header().creation_time());
        builder.set_ttl(Duration::from_millis(1));
        let signed = builder.try_sign(config.key_pair.private_key())?;
        step.hash = signed.hash().to_string();
        step.norito_hex = hex::encode(signed.encode_versioned());
    }
    record.preflight.transaction_hashes = record
        .transactions
        .iter()
        .map(|step| step.hash.clone())
        .collect();
    validate_plan(&record, &config)?;
    root.authenticate(&record)?;
    let mut wrong = root.clone();
    wrong.pins.signed_genesis_sha256 = "00".repeat(32);
    assert!(wrong.authenticate(&record).is_err());
    let mut wrong = root.clone();
    wrong.pins.mode = "npos".into();
    assert!(wrong.authenticate(&record).is_err());
    let temporary = tempfile::tempdir()?;
    let journal = Journal::persist_plan(&temporary.path().join("journal"), &record)?;
    journal.put_exact(
        "attempt-0000.json",
        &TransactionAttempt {
            name: record.transactions[0].name.clone(),
            hash: record.transactions[0].hash.clone(),
        },
    )?;
    journal.put_exact(ROOT, &root)?;
    let mut scan = Scan::new(&record, &root)?;
    let mut tip = None;
    for proof in [&first, &second, &third] {
        let retained = RetainedProof::capture(proof)?;
        tip = Some(scan.accept(&retained)?);
        journal.put_exact(&proof_name(proof.height()), &retained)?;
    }
    let evidence = scan.evidence(&record, &root, &tip.unwrap())?;
    journal.put_exact(MARKER, &evidence)?;
    assert_eq!(retained(&record, &journal)?, Some(evidence.clone()));
    struct NoTransport;
    impl DeploymentTransport for NoTransport {
        fn submit(&self, _: &SignedTransaction) -> Result<()> {
            panic!("retired journal must not submit")
        }
        fn wait(&self, _: HashOf<SignedTransaction>) -> Result<AppliedEvidence> {
            panic!("retained proof requires no fabricated transaction finality")
        }
    }
    assert!(
        matches!(inspect_read_record(&record, &journal, &DeploymentReadContext::from(&config), &NoTransport)?,
        JournalDisposition::ValidityWindowElapsed(found) if found == evidence)
    );
    assert!(execute_transactions(&record, &journal, &NoTransport, &mut |_| Ok(())).is_err());
    assert!(!journal.exists(RECEIPT_FILE_NAME)?);
    assert!(!journal.exists("failed-0000.json")?);
    Ok(())
}

#[test]
fn expiry_proof_directory_requires_exact_bounded_prefix() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    for bad in [
        "expiry-proof-0000000000.json",
        "expiry-proof-0000100001.json",
        "expiry-proof-0000000002.json",
    ] {
        let journal = Journal::open(&temporary.path().join(bad), true)?;
        journal.put_exact(bad, &"untrusted")?;
        assert!(
            journal
                .require_expiry_recovery_entries(MAX_HEIGHT as usize + 5, None)
                .is_err()
        );
    }
    let journal = Journal::open(&temporary.path().join("valid"), true)?;
    journal.put_exact("expiry-proof-0000000001.json", &"untrusted")?;
    journal.require_expiry_recovery_entries(MAX_HEIGHT as usize + 5, Some(1))?;
    assert!(
        journal
            .require_expiry_recovery_entries(MAX_HEIGHT as usize + 5, Some(2))
            .is_err()
    );
    journal.put_exact("expiry-proof-0000000002.json", &"untrusted")?;
    assert!(
        journal
            .require_expiry_recovery_entries(MAX_HEIGHT as usize + 5, Some(1))
            .is_err()
    );
    Ok(())
}
