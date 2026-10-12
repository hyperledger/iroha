//! Streaming execution identity must equal the sole materialized certificate-free block wire.

use super::*;

/// Construct real nonempty network and time outputs over two originally signed transactions.
fn executed_fixture() -> SignedBlock {
    let mut block = output_test_support::proposal(2);
    let rows = vec![
        output_test_support::network(0, Ok(Vec::new())),
        output_test_support::network(1, Ok(Vec::new())),
        output_test_support::simple_time(&block, 0),
    ];
    output_test_support::install(&mut block, rows, 3).unwrap();
    block
        .validate_execution_outputs(&output_test_support::limits())
        .unwrap();
    assert_eq!(block.network_entrypoint_count(), 2);
    assert_eq!(block.execution_outputs().len(), 3);
    block
}

/// Materialize the independent existing encoder's bytes with exactly the certificate removed.
fn reference_wire(block: &SignedBlock) -> Vec<u8> {
    let mut reference = block.clone();
    reference.set_commit_certificate(None);
    reference.encode_wire().unwrap()
}

/// Compare both streaming APIs with the same complete versioned, framed reference wire.
fn assert_exact_identity(block: &SignedBlock) -> (u64, Hash) {
    let original = block.encode_wire().unwrap();
    let wire = reference_wire(block);
    assert_eq!(wire[0], block.version());
    let frame = norito::core::from_bytes_view(&wire[1..]).unwrap();
    assert_eq!(
        frame.schema(),
        norito::schema::identity::frame_hash::<SignedBlock>()
    );
    assert_eq!(frame.flags(), norito::core::default_encode_flags());
    assert_eq!(
        wire.len(),
        1 + norito::core::Header::SIZE + frame.as_bytes().len()
    );
    let expected = (u64::try_from(wire.len()).unwrap(), Hash::new(&wire));
    assert_eq!(block.executed_block_wire_identity().unwrap(), expected);
    assert_eq!(block.executed_block_wire_hash().unwrap(), expected.1);
    assert_eq!(
        block.encode_wire().unwrap(),
        original,
        "hashing must not mutate its source"
    );
    expected
}

/// Both optional-result layouts preserve the existing exact wire framing and full payload.
#[test]
fn executed_identity_matches_resultless_and_nonempty_executed_wire() {
    let executed = executed_fixture();
    let proposal = executed
        .canonical_resultless_proposal()
        .expect("valid original proposal");
    assert!(!proposal.has_results());
    assert_eq!(proposal.network_entrypoint_count(), 2);
    let proposal_identity = assert_exact_identity(&proposal);
    let executed_identity = assert_exact_identity(&executed);
    assert_eq!(
        proposal_identity.1,
        proposal.canonical_proposal_wire_hash().unwrap()
    );
    assert_ne!(executed_identity.1, proposal_identity.1);
    assert!(executed_identity.0 > proposal_identity.0);
}

/// A genuine complete native certificate is excluded while all executed bytes remain bound.
#[test]
fn executed_identity_excludes_original_complete_certificate_only() {
    let fixture = crate::sumeragi_finality::test_fixtures::NativeFinalityFixture::new();
    let certified = decode_framed_signed_block(&fixture.latest().block_wire).unwrap();
    assert!(certified.has_results());
    assert!(certified.network_entrypoint_count() > 0);
    assert!(!certified.execution_outputs().is_empty());
    let certificate = certified.commit_certificate().unwrap();
    assert!(!certificate.consensus_header().is_empty());
    assert!(!certificate.commit_qc().is_empty());
    assert!(!certificate.result_preimage().is_empty());
    assert!(!certificate.availability().is_empty());
    let identity = assert_exact_identity(&certified);
    let uncertified = certified.clone().with_commit_certificate(None);
    assert_eq!(assert_exact_identity(&uncertified), identity);
    assert!(certified.encode_wire().unwrap().len() > usize::try_from(identity.0).unwrap());
    let commitment = crate::sumeragi_finality::CertifiedResultV1::decode(
        certificate.result_preimage(),
        crate::sumeragi_finality::CertifiedResultScope::TairaGlobal,
    )
    .unwrap();
    let commitment = commitment.commitment();
    assert_eq!(commitment.execution.executed_block_wire_len, identity.0);
    assert_eq!(commitment.execution.executed_block_wire_hash, identity.1);
}

/// A changed result changes executed identity without changing the originally signed proposal.
#[test]
fn executed_identity_binds_post_result_mutations() {
    let original = executed_fixture();
    let before = assert_exact_identity(&original);
    let proposal = original.canonical_proposal_wire_hash().unwrap();
    let mut changed = original.clone();
    changed.result.as_mut().unwrap().committed_fragment_count += 1;
    changed.validate_output_merkle_cache().unwrap();
    assert_eq!(changed.canonical_proposal_wire_hash().unwrap(), proposal);
    let after = assert_exact_identity(&changed);
    assert_ne!(
        after.1, before.1,
        "the fragment count is part of the executed result"
    );
    assert_eq!(assert_exact_identity(&original), before);

    let mut changed = original.clone();
    let rows = vec![
        output_test_support::network(0, Ok(Vec::new())),
        output_test_support::network(1, Ok(Vec::new())),
        output_test_support::simple_time(&changed, 0),
        output_test_support::simple_time(&changed, 1),
    ];
    output_test_support::install(&mut changed, rows, 4).unwrap();
    changed.validate_output_merkle_cache().unwrap();
    assert_eq!(changed.canonical_proposal_wire_hash().unwrap(), proposal);
    let after = assert_exact_identity(&changed);
    assert_ne!(
        after.1, before.1,
        "every typed output is part of the executed result"
    );
    assert!(after.0 > before.0);
}

/// Ambient decode selection cannot change canonical wire identity or leak from either API.
#[test]
fn executed_identity_preserves_ambient_flags() {
    let block = executed_fixture();
    let expected = assert_exact_identity(&block);
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(block.executed_block_wire_identity().unwrap(), expected);
        assert_eq!(norito::core::get_decode_flags(), flags);
        assert_eq!(block.executed_block_wire_hash().unwrap(), expected.1);
        assert_eq!(norito::core::get_decode_flags(), flags);
    }
}

/// The original archive cap still applies to payload bytes and error exits restore flags.
#[test]
fn executed_identity_rejects_archive_cap_in_isolated_process() {
    /// Restore the process ceiling even when an assertion fails in this isolated child.
    struct RestoreCap(u64);
    impl Drop for RestoreCap {
        fn drop(&mut self) {
            norito::core::set_max_archive_len(self.0);
        }
    }
    const CHILD: &str = "IROHA_DATA_MODEL_EXECUTED_IDENTITY_CAP_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("executed_identity_rejects_archive_cap_in_isolated_process")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(CHILD, "1")
            .output()
            .expect("run archive-cap mutation without sharing another test's process");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let _restore = RestoreCap(norito::core::max_archive_len());
    let block = executed_fixture();
    let expected = assert_exact_identity(&block);
    let payload_len = expected.0 - 1 - norito::core::Header::SIZE as u64;
    assert!(payload_len > 1);
    let _ambient = norito::core::DecodeFlagsGuard::enter(0);
    norito::core::set_max_archive_len(payload_len);
    assert_eq!(block.executed_block_wire_identity().unwrap(), expected);
    assert_eq!(block.executed_block_wire_hash().unwrap(), expected.1);
    assert_eq!(norito::core::get_decode_flags(), 0);
    norito::core::set_max_archive_len(payload_len - 1);
    assert!(matches!(block.executed_block_wire_identity(),
        Err(NoritoFrameError::ArchiveLengthExceeded { length, limit })
            if length == payload_len && limit == payload_len - 1));
    assert_eq!(norito::core::get_decode_flags(), 0);
    assert!(matches!(block.executed_block_wire_hash(),
        Err(NoritoFrameError::ArchiveLengthExceeded { length, limit })
            if length == payload_len && limit == payload_len - 1));
    assert_eq!(norito::core::get_decode_flags(), 0);
}
