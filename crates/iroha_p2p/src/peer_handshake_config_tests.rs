// SoraNet handshake configuration regressions included from `peer`.
use super::*;
use rand::{
    RngCore, SeedableRng,
    rand_core::{TryCryptoRng, TryRngCore},
    rngs::StdRng,
};
use std::{
    fmt,
    num::{NonZeroU32, NonZeroUsize},
};
use tempfile::tempdir;
fn test_admission_transcript() -> [u8; 32] {
    pow::derive_admission_transcript(b"soranet-test-client-hello")
}
fn test_puzzle_parameters(
    difficulty: u8,
    max_future_skew: Duration,
    min_ticket_ttl: Duration,
) -> PuzzleParameters {
    PuzzleParameters::try_new(
        NonZeroU32::new(puzzle::MIN_MEMORY_KIB).expect("minimum puzzle memory is non-zero"),
        NonZeroU32::new(1).expect("one Argon2 iteration is non-zero"),
        NonZeroU32::new(1).expect("one Argon2 lane is non-zero"),
        difficulty,
        max_future_skew,
        min_ticket_ttl,
    )
    .expect("test puzzle parameters must be valid")
}
fn minimal_puzzle_config(
    ticket_ttl: Duration,
    max_future_skew: Duration,
    min_ticket_ttl: Duration,
) -> Arc<SoranetHandshakeConfig> {
    let puzzle_params = test_puzzle_parameters(1, max_future_skew, min_ticket_ttl);
    Arc::new(
        SoranetHandshakeConfig::new(
            SoranetHandshakeParams {
                descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT
                    .to_vec(),
                client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                    .to_vec(),
                relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                    .to_vec(),
                trust_gossip: true,
                kem_id: 1,
                sig_id: 1,
                resume_hash: None,
                puzzle_params,
                ticket_ttl,
            },
            test_ticket_revocation_store(),
        )
        .expect("test SoraNet handshake config must be valid"),
    )
}
fn in_memory_puzzle_replay_config() -> Arc<SoranetHandshakeConfig> {
    let puzzle_params =
        test_puzzle_parameters(1, Duration::from_secs(300), Duration::from_secs(60));
    let limits =
        TicketRevocationStoreLimits::new(16, Duration::from_secs(900)).expect("valid limits");
    let store =
        TicketRevocationStore::in_memory(limits).expect("in-memory revocation store should open");
    Arc::new(
        SoranetHandshakeConfig::new(
            SoranetHandshakeParams {
                descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT
                    .to_vec(),
                client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                    .to_vec(),
                relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                    .to_vec(),
                trust_gossip: true,
                kem_id: 1,
                sig_id: 1,
                resume_hash: None,
                puzzle_params,
                ticket_ttl: Duration::from_secs(120),
            },
            Arc::new(Mutex::new(store)),
        )
        .expect("test SoraNet handshake config must be valid"),
    )
}
fn mint_test_admission_ticket(
    config: &SoranetHandshakeConfig,
    transcript_hash: &[u8; 32],
    seed: [u8; 32],
) -> Vec<u8> {
    let mut minted = config
        .mint_challenge_ticket(transcript_hash, &mut StdRng::from_seed(seed))
        .expect("test admission should mint");
    std::mem::take(&mut minted.credential)
}
struct FailingTryRng;
struct ZeroTryRng;
struct RepeatedTryRng;
#[derive(Debug)]
struct FailingTryRngError;
impl fmt::Display for FailingTryRngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("failing p2p ticket RNG")
    }
}
impl TryRngCore for FailingTryRng {
    type Error = FailingTryRngError;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(FailingTryRngError)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(FailingTryRngError)
    }
    fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
        Err(FailingTryRngError)
    }
}
impl TryCryptoRng for FailingTryRng {}
impl TryRngCore for ZeroTryRng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.fill(0);
        Ok(())
    }
}
impl TryCryptoRng for ZeroTryRng {}
impl TryRngCore for RepeatedTryRng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_le_bytes([0xA5; 4]))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_le_bytes([0xA5; 8]))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.fill(0xA5);
        Ok(())
    }
}
impl TryCryptoRng for RepeatedTryRng {}
#[test]
fn soranet_handshake_rng_reads_os_entropy() {
    let mut rng = soranet_handshake_rng().expect("OS RNG should seed SoraNet handshake RNG");
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
}
#[test]
fn soranet_transport_delegation_challenge_rng_failure_is_fail_closed() {
    let error = generate_soranet_transport_delegation_challenge(&mut FailingTryRng)
        .expect_err("challenge entropy failure must stop the handshake");
    assert!(matches!(
        error,
        Error::HandshakeSoranet(message)
            if message == "SoraNet delegation challenge RNG failed: failing p2p ticket RNG"
    ));
}
#[test]
fn soranet_transport_delegation_challenge_rejects_all_zero_entropy() {
    let error = generate_soranet_transport_delegation_challenge(&mut ZeroTryRng)
        .expect_err("an all-zero challenge must stop the handshake");
    assert!(matches!(
        error,
        Error::HandshakeSoranet(message)
            if message == "SoraNet delegation challenge RNG returned an all-zero value"
    ));

    let error = generate_soranet_transport_delegation_challenge(&mut RepeatedTryRng)
        .expect_err("an all-identical-byte challenge must stop the handshake");
    assert!(matches!(
        error,
        Error::HandshakeSoranet(message)
            if message == "SoraNet delegation challenge RNG returned all-identical-byte material"
    ));
}
#[test]
fn rejects_invalid_kem_and_signature_ids() {
    let params = test_puzzle_parameters(1, Duration::from_secs(300), Duration::from_secs(30));
    let kem_error = SoranetHandshakeConfig::new(
        SoranetHandshakeParams {
            descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
            client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                .to_vec(),
            relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                .to_vec(),
            trust_gossip: true,
            kem_id: 42,
            sig_id: 1,
            resume_hash: None,
            puzzle_params: params,
            ticket_ttl: Duration::from_secs(60),
        },
        test_ticket_revocation_store(),
    )
    .expect_err("unsupported KEM identifiers must fail closed");
    assert!(matches!(
        kem_error,
        Error::HandshakeSoranet(message)
            if message == "unsupported SoraNet ML-KEM identifier 42"
    ));
    let signature_error = SoranetHandshakeConfig::new(
        SoranetHandshakeParams {
            descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
            client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                .to_vec(),
            relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                .to_vec(),
            trust_gossip: true,
            kem_id: 1,
            sig_id: 99,
            resume_hash: None,
            puzzle_params: params,
            ticket_ttl: Duration::from_secs(60),
        },
        test_ticket_revocation_store(),
    )
    .expect_err("unsupported signature identifiers must fail closed");
    assert!(matches!(
        signature_error,
        Error::HandshakeSoranet(message)
            if message == "unsupported SoraNet signature identifier 99"
    ));

    for suite in MlKemSuite::ALL {
        let mut client_capabilities =
            iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES.to_vec();
        let mut relay_capabilities =
            iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES.to_vec();
        client_capabilities[4] = suite.kem_id();
        relay_capabilities[4] = suite.kem_id();
        SoranetHandshakeConfig::new(
            SoranetHandshakeParams {
                descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT
                    .to_vec(),
                client_capabilities,
                relay_capabilities,
                trust_gossip: true,
                kem_id: suite.kem_id(),
                sig_id: 1,
                resume_hash: None,
                puzzle_params: params,
                ticket_ttl: Duration::from_secs(60),
            },
            test_ticket_revocation_store(),
        )
        .expect("every advertised ML-KEM suite in the first-release registry must be accepted");
    }
}

#[test]
fn rejects_selected_kem_missing_from_capability_vectors() {
    let error = SoranetHandshakeConfig::new(
        SoranetHandshakeParams {
            descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
            client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                .to_vec(),
            relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                .to_vec(),
            trust_gossip: true,
            kem_id: MlKemSuite::MlKem512.kem_id(),
            sig_id: 1,
            resume_hash: None,
            puzzle_params: test_puzzle_parameters(
                1,
                Duration::from_secs(300),
                Duration::from_secs(30),
            ),
            ticket_ttl: Duration::from_secs(60),
        },
        test_ticket_revocation_store(),
    )
    .expect_err("an unadvertised selected KEM must fail at construction");
    assert!(matches!(
        error,
        Error::HandshakeSoranet(message)
            if message.contains("does not advertise selected id 0x00")
    ));
}

fn insert_strict_constant_rate_tlv(mut capabilities: Vec<u8>) -> Vec<u8> {
    const STRICT_CONSTANT_RATE_TLV: [u8; 8] = [0x02, 0x03, 0x00, 0x04, 0x01, 0x01, 0x00, 0x04];
    let grease_offset = capabilities
        .windows(2)
        .position(|window| window[0] == 0x7f)
        .expect("default capabilities contain a trailing GREASE entry");
    capabilities.splice(grease_offset..grease_offset, STRICT_CONSTANT_RATE_TLV);
    capabilities
}

#[test]
fn rejects_strict_constant_rate_claim_while_p2p_payload_bypasses_mux() {
    let client_capabilities = insert_strict_constant_rate_tlv(
        iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES.to_vec(),
    );
    let relay_capabilities = insert_strict_constant_rate_tlv(
        iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES.to_vec(),
    );
    let error = SoranetHandshakeConfig::new(
        SoranetHandshakeParams {
            descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
            client_capabilities,
            relay_capabilities,
            trust_gossip: true,
            kem_id: 1,
            sig_id: 1,
            resume_hash: None,
            puzzle_params: test_puzzle_parameters(
                1,
                Duration::from_secs(300),
                Duration::from_secs(30),
            ),
            ticket_ttl: Duration::from_secs(60),
        },
        test_ticket_revocation_store(),
    )
    .expect_err("strict traffic-shape claims must fail before peer payload is scheduler-bound");
    assert!(matches!(
        error,
        Error::HandshakeSoranet(message)
            if message.contains("strict SoraNet constant-rate capability is unavailable for iroha_p2p")
    ));
}

#[test]
fn rejects_descriptor_commitment_mismatching_relay_capability() {
    let error = SoranetHandshakeConfig::new(
        SoranetHandshakeParams {
            descriptor_commit: vec![0xA5; iroha_crypto::Hash::LENGTH],
            client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                .to_vec(),
            relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                .to_vec(),
            trust_gossip: true,
            kem_id: 1,
            sig_id: 1,
            resume_hash: None,
            puzzle_params: test_puzzle_parameters(
                1,
                Duration::from_secs(300),
                Duration::from_secs(30),
            ),
            ticket_ttl: Duration::from_secs(60),
        },
        test_ticket_revocation_store(),
    )
    .expect_err("the advertised and configured descriptor commitments must agree");
    assert!(matches!(
        error,
        Error::HandshakeSoranet(message)
            if message.contains("snnet.transcript_commit does not match")
    ));
}
#[test]
fn admission_config_retains_the_mandatory_replay_store() {
    let replay_store = test_ticket_revocation_store();
    let config = SoranetHandshakeConfig::new(
        SoranetHandshakeParams {
            descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
            client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                .to_vec(),
            relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                .to_vec(),
            trust_gossip: true,
            kem_id: 1,
            sig_id: 1,
            resume_hash: None,
            puzzle_params: test_puzzle_parameters(
                1,
                Duration::from_secs(300),
                Duration::from_secs(30),
            ),
            ticket_ttl: Duration::from_secs(60),
        },
        Arc::clone(&replay_store),
    )
    .expect("admission config should retain its required replay store");

    assert!(Arc::ptr_eq(&config.revocation_store, &replay_store));
}
#[test]
fn rejects_noncanonical_transcript_fields_and_capability_vectors_at_construction() {
    let params = test_puzzle_parameters(1, Duration::from_secs(300), Duration::from_secs(30));
    let build =
        |descriptor_commit: Vec<u8>, client_capabilities: Vec<u8>, resume_hash: Option<Vec<u8>>| {
            SoranetHandshakeConfig::new(
                SoranetHandshakeParams {
                    descriptor_commit,
                    client_capabilities,
                    relay_capabilities:
                        iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES.to_vec(),
                    trust_gossip: true,
                    kem_id: 1,
                    sig_id: 1,
                    resume_hash,
                    puzzle_params: params,
                    ticket_ttl: Duration::from_secs(60),
                },
                test_ticket_revocation_store(),
            )
        };
    for (error, expected) in [
        (
            build(
                vec![0; iroha_crypto::Hash::LENGTH - 1],
                iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES.to_vec(),
                None,
            )
            .expect_err("short descriptor commitment must fail"),
            "descriptor commitment must be 32 bytes",
        ),
        (
            build(
                iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
                iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES.to_vec(),
                Some(vec![0; iroha_crypto::Hash::LENGTH - 1]),
            )
            .expect_err("short resume hash must fail"),
            "resume hash must be 32 bytes",
        ),
        (
            build(
                iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
                vec![0x01],
                None,
            )
            .expect_err("malformed capabilities must fail"),
            "invalid SoraNet client capability vector",
        ),
        (
            build(
                iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
                vec![
                    0x01, 0x02, 0x00, 0x02, 0x01, 0x01, // signature
                    0x01, 0x01, 0x00, 0x02, 0x01, 0x01, // KEM
                ],
                None,
            )
            .expect_err("decreasing client capability types must fail at construction"),
            "nondecreasing order",
        ),
        (
            build(
                iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
                vec![0; iroha_crypto::soranet::handshake::MAX_CAPABILITY_VECTOR_LEN + 1],
                None,
            )
            .expect_err("oversized client capability vector must fail at the shared bound"),
            "first-release maximum is 4096 bytes",
        ),
    ] {
        assert!(
            matches!(error, Error::HandshakeSoranet(message) if message.contains(expected)),
            "unexpected error for {expected}"
        );
    }
}
#[test]
fn admission_transcript_binds_resumption_presence_and_value() {
    let absent = RuntimeParams::soranet_defaults();
    let resume_a = [0xA1; 32];
    let resume_b = [0xB2; 32];
    let mut present_a = absent.clone();
    present_a.resume_hash = Some(&resume_a);
    let mut present_b = absent.clone();
    present_b.resume_hash = Some(&resume_b);
    let seed = [0x73; 32];
    let (hello_absent, _) =
        build_client_hello(&absent, &mut StdRng::from_seed(seed)).expect("client hello");
    let (hello_a, _) =
        build_client_hello(&present_a, &mut StdRng::from_seed(seed)).expect("resumed hello a");
    let (hello_b, _) =
        build_client_hello(&present_b, &mut StdRng::from_seed(seed)).expect("resumed hello b");
    assert_ne!(hello_absent, hello_a);
    assert_ne!(hello_absent, hello_b);
    assert_ne!(hello_a, hello_b);
    assert!(
        hello_a
            .windows(resume_a.len())
            .any(|window| window == resume_a.as_slice())
    );
    assert!(
        hello_b
            .windows(resume_b.len())
            .any(|window| window == resume_b.as_slice())
    );
    let transcript_absent = pow::derive_admission_transcript(&hello_absent);
    let transcript_a = pow::derive_admission_transcript(&hello_a);
    let transcript_b = pow::derive_admission_transcript(&hello_b);
    assert_ne!(transcript_absent, transcript_a);
    assert_ne!(transcript_absent, transcript_b);
    assert_ne!(transcript_a, transcript_b);
}
#[test]
fn puzzle_ticket_mints_and_verifies() {
    let puzzle_params = puzzle::Parameters::try_new(
        NonZeroU32::new(64 * 1024).expect("memory"),
        NonZeroU32::new(2).expect("time"),
        NonZeroU32::new(1).expect("lanes"),
        2,
        Duration::from_secs(900),
        Duration::from_secs(120),
    )
    .expect("test puzzle parameters must be valid");
    let config = SoranetHandshakeConfig::new(
        SoranetHandshakeParams {
            descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
            client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                .to_vec(),
            relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                .to_vec(),
            trust_gossip: true,
            kem_id: 1,
            sig_id: 1,
            resume_hash: None,
            puzzle_params,
            ticket_ttl: Duration::from_secs(240),
        },
        test_ticket_revocation_store(),
    )
    .expect("test SoraNet handshake config must be valid");
    assert_eq!(config.ticket_ttl(), Duration::from_secs(240));
    let configured_puzzle = config.puzzle_parameters();
    assert_eq!(configured_puzzle.memory_kib().get(), 64 * 1024);
    let admission = config.admission_summary();
    assert_eq!(admission.puzzle.difficulty(), 2);
    assert_eq!(admission.ticket_ttl, Duration::from_secs(240));
    let mut rng = StdRng::from_seed([7u8; 32]);
    let transcript = test_admission_transcript();
    let mut minted = config
        .mint_challenge_ticket(&transcript, &mut rng)
        .expect("mint ticket");
    assert_eq!(
        minted.admission.puzzle.difficulty(),
        puzzle_params.difficulty()
    );
    let verification = config
        .verify_challenge_ticket(&minted.credential, &transcript)
        .expect("verify ticket");
    assert_eq!(verification.puzzle.difficulty(), puzzle_params.difficulty());
    let mut corrupted = std::mem::take(&mut minted.credential);
    // Corrupt the version byte to guarantee a parse/verify failure.
    // Flipping solution bytes is probabilistic for low difficulties (it may still satisfy
    // the leading-zero predicate), so do not rely on it in tests.
    corrupted[0] ^= 0xFF;
    assert!(
        config
            .verify_challenge_ticket(&corrupted, &transcript)
            .is_err()
    );
}
#[test]
fn minted_challenge_explicitly_clears_sensitive_bytes() {
    let mut minted = MintedChallenge {
        credential: vec![0xA5; 32],
        admission: ChallengeAdmission {
            ticket_ttl: Duration::from_secs(60),
            puzzle: test_puzzle_parameters(1, Duration::from_secs(300), Duration::from_secs(30)),
        },
    };
    minted.clear_sensitive_bytes();
    assert!(minted.credential.is_empty());
    assert!(std::mem::needs_drop::<MintedChallenge>());
}
#[test]
fn inbound_challenge_owner_redacts_and_scrubs_sensitive_bytes() {
    let mut frame = SensitiveHandshakeFrame::from(vec![0xA5; 32]);
    assert!(std::mem::needs_drop::<SensitiveHandshakeFrame>());
    let rendered = format!("{frame:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains("165"));
    frame.clear();
    assert!(frame.is_empty());
}
#[test]
fn mint_challenge_ticket_reports_rng_failure() {
    let puzzle_params =
        test_puzzle_parameters(5, Duration::from_secs(900), Duration::from_secs(120));
    let config = SoranetHandshakeConfig::new(
        SoranetHandshakeParams {
            descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
            client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                .to_vec(),
            relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                .to_vec(),
            trust_gossip: true,
            kem_id: 1,
            sig_id: 1,
            resume_hash: None,
            puzzle_params,
            ticket_ttl: Duration::from_secs(240),
        },
        test_ticket_revocation_store(),
    )
    .expect("test SoraNet handshake config must be valid");
    let mut rng = FailingTryRng;
    let transcript = test_admission_transcript();
    let err = config
        .mint_challenge_ticket(&transcript, &mut rng)
        .expect_err("failing RNG must abort challenge minting");
    match err {
        puzzle::MintError::RandomBytes { operation, message } => {
            assert_eq!(operation, "minting puzzle solution nonce");
            assert!(
                message.contains("failing p2p ticket RNG"),
                "unexpected message: {message}"
            );
        }
        other => panic!("expected puzzle RNG failure, got {other:?}"),
    }
}
#[test]
fn puzzle_ticket_replay_rejected_and_persisted() {
    let puzzle_params =
        test_puzzle_parameters(1, Duration::from_secs(900), Duration::from_secs(120));
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("revocations.norito");
    let limits = TicketRevocationStoreLimits::new(4, Duration::from_secs(900)).expect("limits");
    let store = TicketRevocationStore::load(&path, limits, SystemTime::now()).expect("store");
    let config = SoranetHandshakeConfig::new(
        SoranetHandshakeParams {
            descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
            client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                .to_vec(),
            relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                .to_vec(),
            trust_gossip: true,
            kem_id: 1,
            sig_id: 1,
            resume_hash: None,
            puzzle_params,
            ticket_ttl: Duration::from_secs(240),
        },
        Arc::new(Mutex::new(store)),
    )
    .expect("test SoraNet handshake config must be valid");
    let mut rng = StdRng::from_seed([0x21; 32]);
    let transcript = test_admission_transcript();
    let mut minted = config
        .mint_challenge_ticket(&transcript, &mut rng)
        .expect("mint");
    let ticket = std::mem::take(&mut minted.credential);
    config
        .verify_challenge_ticket(&ticket, &transcript)
        .expect("first verify");
    let err = config
        .verify_challenge_ticket(&ticket, &transcript)
        .expect_err("replay must fail");
    assert!(matches!(err, ChallengeVerifyError::Replay));
    drop(config);
    let reloaded =
        TicketRevocationStore::load(&path, limits, SystemTime::now()).expect("reload store");
    let config_reloaded = SoranetHandshakeConfig::new(
        SoranetHandshakeParams {
            descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
            client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                .to_vec(),
            relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                .to_vec(),
            trust_gossip: true,
            kem_id: 1,
            sig_id: 1,
            resume_hash: None,
            puzzle_params,
            ticket_ttl: Duration::from_secs(240),
        },
        Arc::new(Mutex::new(reloaded)),
    )
    .expect("test SoraNet handshake config must be valid");
    let err = config_reloaded
        .verify_challenge_ticket(&ticket, &transcript)
        .expect_err("replay after reload must fail");
    assert!(matches!(err, ChallengeVerifyError::Replay));
}
#[test]
fn pending_replay_reservations_release_the_store_lock_and_roll_back_on_drop() {
    let config = in_memory_puzzle_replay_config();
    let transcript = test_admission_transcript();
    let first_bytes = mint_test_admission_ticket(&config, &transcript, [0x22; 32]);
    let second_bytes = mint_test_admission_ticket(&config, &transcript, [0x23; 32]);
    let first = PowTicket::parse(&first_bytes).expect("first ticket should parse");
    let second = PowTicket::parse(&second_bytes).expect("second ticket should parse");
    let now = SystemTime::now();

    let first_reservation = config
        .reserve_ticket_replay(&first, now)
        .expect("first replay preflight should succeed");
    let store_guard = config
        .revocation_store
        .try_lock()
        .expect("reservation must not retain the revocation-store mutex");
    drop(store_guard);

    let second_reservation = config
        .reserve_ticket_replay(&second, now)
        .expect("a distinct ticket should reserve concurrently");
    let duplicate = config
        .reserve_ticket_replay(&first, now)
        .expect_err("the same canonical ticket identity must reserve only once");
    assert!(matches!(duplicate, ChallengeVerifyError::Replay));

    drop(first_reservation);
    drop(second_reservation);
    config
        .reserve_ticket_replay(&first, now)
        .expect("dropping an unfinished reservation should roll it back");
}
#[test]
fn concurrent_duplicate_ticket_verification_has_exactly_one_success() {
    let config = in_memory_puzzle_replay_config();
    let transcript = test_admission_transcript();
    let ticket = mint_test_admission_ticket(&config, &transcript, [0x24; 32]);
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::with_capacity(2);
    for _ in 0..2 {
        let config = Arc::clone(&config);
        let barrier = Arc::clone(&barrier);
        let ticket = ticket.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            config.verify_challenge_ticket(&ticket, &transcript)
        }));
    }
    barrier.wait();

    let mut successes = 0;
    let mut replays = 0;
    for worker in workers {
        match worker.join().expect("verification worker should not panic") {
            Ok(_) => successes += 1,
            Err(ChallengeVerifyError::Replay) => replays += 1,
            other => panic!("unexpected concurrent verification result: {other:?}"),
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(replays, 1);
}
#[test]
fn revocation_store_capacity_fails_closed_without_forgetting_replays() {
    let puzzle_params =
        test_puzzle_parameters(1, Duration::from_secs(300), Duration::from_secs(60));
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("revocations.norito");
    let limits = TicketRevocationStoreLimits::new(1, Duration::from_secs(900)).expect("limits");
    let store = TicketRevocationStore::load(&path, limits, SystemTime::now()).expect("store");
    let config = SoranetHandshakeConfig::new(
        SoranetHandshakeParams {
            descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
            client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                .to_vec(),
            relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                .to_vec(),
            trust_gossip: true,
            kem_id: 1,
            sig_id: 1,
            resume_hash: None,
            puzzle_params,
            ticket_ttl: Duration::from_secs(120),
        },
        Arc::new(Mutex::new(store)),
    )
    .expect("test SoraNet handshake config must be valid");
    let mut rng = StdRng::from_seed([0x31; 32]);
    let transcript = test_admission_transcript();
    let first = config
        .mint_challenge_ticket(&transcript, &mut rng)
        .expect("mint");
    let second = config
        .mint_challenge_ticket(&transcript, &mut rng)
        .expect("mint second");
    config
        .verify_challenge_ticket(&first.credential, &transcript)
        .expect("first verify");
    assert_eq!(config.active_revocations().expect("active count"), 1);
    let capacity_err = config
        .verify_challenge_ticket(&second.credential, &transcript)
        .expect_err("full store must fail closed");
    assert!(matches!(
        capacity_err,
        ChallengeVerifyError::RevocationStore(_)
    ));
    assert_eq!(
        config.active_revocations().expect("active count"),
        1,
        "capacity-one store must retain the first consumption record"
    );
    let replay_err = config
        .verify_challenge_ticket(&first.credential, &transcript)
        .expect_err("first ticket must remain consumed");
    assert!(matches!(replay_err, ChallengeVerifyError::Replay));
    config.purge_expired_revocations().expect("purge succeeds");
    assert_eq!(
        config.active_revocations().expect("active count"),
        1,
        "purge should not drop non-expired entries"
    );
}
#[test]
fn revocation_store_ttl_overflow_surfaces_store_error() {
    let puzzle_params =
        test_puzzle_parameters(1, Duration::from_secs(300), Duration::from_secs(60));
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("revocations.norito");
    let limits = TicketRevocationStoreLimits::new(8, Duration::from_secs(10)).expect("limits");
    let store = TicketRevocationStore::load(&path, limits, SystemTime::now()).expect("store");
    let config = SoranetHandshakeConfig::new(
        SoranetHandshakeParams {
            descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT.to_vec(),
            client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                .to_vec(),
            relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                .to_vec(),
            trust_gossip: true,
            kem_id: 1,
            sig_id: 1,
            resume_hash: None,
            puzzle_params,
            ticket_ttl: Duration::from_secs(120),
        },
        Arc::new(Mutex::new(store)),
    )
    .expect("test SoraNet handshake config must be valid");
    let mut rng = StdRng::from_seed([0x41; 32]);
    let transcript = test_admission_transcript();
    let minted = config
        .mint_challenge_ticket(&transcript, &mut rng)
        .expect("mint");
    let err = config
        .verify_challenge_ticket(&minted.credential, &transcript)
        .expect_err("revocation store ttl cap should reject ticket");
    assert!(matches!(err, ChallengeVerifyError::RevocationStore(_)));
}
#[tokio::test(flavor = "current_thread")]
async fn outbound_search_mints_canonical_transcript_bound_replay_protected_tickets() {
    for capacity in [1, 3] {
        let mut config = in_memory_puzzle_replay_config();
        Arc::get_mut(&mut config)
            .expect("test owns its configuration")
            .puzzle_work_admission = Arc::new(SoranetPuzzleWorkAdmission::new(
            NonZeroUsize::new(capacity).expect("nonzero capacity"),
            NonZeroUsize::new(1).expect("nonzero verification capacity"),
        ));
        let transcript = test_admission_transcript();
        let minted = mint_handshake_challenge(
            Arc::clone(&config),
            transcript,
            StdRng::from_seed([0x64; 32]),
        )
        .await
        .expect("bounded searches mint a valid ticket");
        assert_eq!(minted.admission.puzzle, *config.puzzle_params);
        assert_eq!(minted.admission.ticket_ttl, config.effective_ticket_ttl());
        let ticket = PowTicket::parse(&minted.credential).expect("canonical ticket bytes");
        assert!(
            puzzle::verify_at(
                &ticket,
                &config.puzzle_binding(&[0x99; 32]),
                config.puzzle_params.as_ref(),
                SystemTime::now(),
            )
            .is_err()
        );
        verify_handshake_challenge(
            Arc::clone(&config),
            SensitiveHandshakeFrame::from(minted.credential.clone()),
            transcript,
        )
        .await
        .expect("unchanged verifier accepts the exact transcript");
        assert!(matches!(
            config.verify_challenge_ticket(&minted.credential, &transcript),
            Err(ChallengeVerifyError::Replay)
        ));
        let gate = config.puzzle_work_admission.outbound_mint_gate();
        let all = tokio::time::timeout(
            Duration::from_secs(5),
            gate.acquire_many(u32::try_from(capacity).expect("test capacity")),
        )
        .await
        .expect("losing evaluations exit")
        .expect("open gate");
        drop(all);
    }
}
#[tokio::test(flavor = "current_thread")]
async fn puzzle_work_is_offloaded_serialized_and_remains_bounded_after_cancellation() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc,
    };
    let gate = Arc::new(Semaphore::new(1));
    let first_started = Arc::new(AtomicBool::new(false));
    let second_started = Arc::new(AtomicBool::new(false));
    let (release_first, wait_for_release) = std_mpsc::channel();
    let first_started_by_work = Arc::clone(&first_started);
    let first = tokio::spawn(run_soranet_admission_work(
        Arc::clone(&gate),
        move |cancellation| {
            first_started_by_work.store(true, Ordering::Release);
            wait_for_release
                .recv_timeout(Duration::from_secs(2))
                .map_err(|error| Error::HandshakeSoranet(error.to_string()))?;
            assert!(
                cancellation.is_cancelled(),
                "aborting the owner must stop further evaluations"
            );
            Ok(1_u8)
        },
    ));
    tokio::time::timeout(Duration::from_secs(1), async {
        while !first_started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("blocking puzzle work must not stall the current-thread async executor");
    // Dropping the handshake future cannot cancel spawn_blocking. The
    // blocking task must therefore retain the sole permit until it really
    // exits, or a reconnect would recreate the original puzzle storm.
    first.abort();
    let _ = first.await;
    let cancelled_waiter_started = Arc::new(AtomicBool::new(false));
    let cancelled_waiter_started_by_work = Arc::clone(&cancelled_waiter_started);
    let cancelled_waiter = tokio::spawn(run_soranet_admission_work(
        Arc::clone(&gate),
        move |_cancellation| {
            cancelled_waiter_started_by_work.store(true, Ordering::Release);
            Ok(3_u8)
        },
    ));
    tokio::task::yield_now().await;
    assert!(
        !cancelled_waiter_started.load(Ordering::Acquire),
        "a queued handshake must apply backpressure before blocking work starts"
    );
    cancelled_waiter.abort();
    let _ = cancelled_waiter.await;
    let second_started_by_work = Arc::clone(&second_started);
    let second = tokio::spawn(run_soranet_admission_work(
        Arc::clone(&gate),
        move |_cancellation| {
            second_started_by_work.store(true, Ordering::Release);
            Ok(2_u8)
        },
    ));
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(
        !second_started.load(Ordering::Acquire),
        "a retry cannot overlap uncancellable blocking puzzle work"
    );
    release_first.send(()).expect("release first puzzle work");
    let result = tokio::time::timeout(Duration::from_secs(1), second)
        .await
        .expect("serialized retry should start after the first task exits")
        .expect("retry task should not panic")
        .expect("retry puzzle work should succeed");
    assert_eq!(result, 2);
    assert!(second_started.load(Ordering::Acquire));
    assert!(
        !cancelled_waiter_started.load(Ordering::Acquire),
        "disconnecting while queued must remove work before it reaches Argon2"
    );
}
#[tokio::test(start_paused = true)]
async fn authentication_deadline_cancels_puzzle_work_without_releasing_inflight_memory() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc,
    };

    let gate = Arc::new(Semaphore::new(1));
    let started = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let (release, evaluation) = std_mpsc::channel();
    let deadline = PreauthDeadline::from_now(Duration::from_secs(35)).expect("auth deadline");
    let work_gate = Arc::clone(&gate);
    let work_started = Arc::clone(&started);
    let work_cancelled = Arc::clone(&cancelled);
    let handshake = tokio::spawn(async move {
        deadline
            .run(
                None,
                run_soranet_admission_work(work_gate, move |cancellation| {
                    work_started.store(true, Ordering::Release);
                    evaluation
                        .recv_timeout(Duration::from_secs(2))
                        .map_err(|error| Error::HandshakeSoranet(error.to_string()))?;
                    work_cancelled.store(cancellation.is_cancelled(), Ordering::Release);
                    Ok(())
                }),
            )
            .await
    });
    while !started.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(35)).await;
    assert!(handshake.await.expect("handshake task").is_err());
    assert_eq!(
        gate.available_permits(),
        0,
        "the current evaluation still owns its memory"
    );
    tokio::time::resume();
    release.send(()).expect("complete the current evaluation");
    let permit = tokio::time::timeout(Duration::from_secs(2), gate.acquire())
        .await
        .expect("cancelled evaluation must release its permit")
        .expect("open gate");
    assert!(
        cancelled.load(Ordering::Acquire),
        "deadline expiry must cancel further evaluations"
    );
    drop(permit);
}
#[tokio::test(flavor = "current_thread")]
async fn puzzle_work_gate_bounds_concurrency_and_keeps_the_async_runtime_responsive() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    const WORKERS: usize = 8;
    let gate = Arc::new(Semaphore::new(1));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::with_capacity(WORKERS);
    for value in 0..WORKERS {
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        workers.push(tokio::spawn(run_soranet_admission_work(
            Arc::clone(&gate),
            move |_cancellation| {
                let current = active.fetch_add(1, Ordering::AcqRel) + 1;
                peak.fetch_max(current, Ordering::AcqRel);
                std::thread::sleep(Duration::from_millis(10));
                active.fetch_sub(1, Ordering::AcqRel);
                Ok(value)
            },
        )));
    }
    let heartbeat = tokio::spawn(async {
        for _ in 0..WORKERS {
            tokio::task::yield_now().await;
        }
    });
    tokio::time::timeout(Duration::from_secs(2), heartbeat)
        .await
        .expect("blocking puzzle work must not starve the async executor")
        .expect("heartbeat task must not panic");
    let completed = tokio::time::timeout(Duration::from_secs(2), async {
        let mut values = Vec::with_capacity(WORKERS);
        for worker in workers {
            values.push(
                worker
                    .await
                    .expect("puzzle worker task must not panic")
                    .expect("puzzle worker must succeed"),
            );
        }
        values
    })
    .await
    .expect("backpressured workers should eventually complete");
    assert_eq!(completed.len(), WORKERS);
    assert_eq!(peak.load(Ordering::Acquire), 1);
    assert_eq!(active.load(Ordering::Acquire), 0);
    assert_eq!(gate.available_permits(), 1);
}
#[tokio::test(flavor = "current_thread")]
async fn inbound_puzzle_pressure_cannot_consume_outbound_recovery_capacity() {
    let admission = SoranetPuzzleWorkAdmission::new(
        NonZeroUsize::new(1).expect("non-zero outbound capacity"),
        NonZeroUsize::new(1).expect("non-zero inbound capacity"),
    );
    let inbound_gate = admission.inbound_verify_gate();
    let held_inbound = inbound_gate
        .clone()
        .acquire_owned()
        .await
        .expect("inbound gate open");
    assert!(inbound_gate.try_acquire_owned().is_err());
    let outbound = admission
        .outbound_mint_gate()
        .try_acquire_owned()
        .expect("inbound verification cannot starve outbound ticket minting");
    drop(outbound);
    drop(held_inbound);
    assert_eq!(admission.inbound_verify_gate().available_permits(), 1);
    assert_eq!(admission.outbound_mint_gate().available_permits(), 1);
}
#[tokio::test(flavor = "current_thread")]
async fn closed_puzzle_work_gate_fails_closed_without_running_work() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let gate = Arc::new(Semaphore::new(1));
    gate.close();
    let started = Arc::new(AtomicBool::new(false));
    let started_by_work = Arc::clone(&started);
    let error = run_soranet_admission_work(gate, move |_cancellation| {
        started_by_work.store(true, Ordering::Release);
        Ok(())
    })
    .await
    .expect_err("a closed puzzle gate must reject work");
    assert!(matches!(
        error,
        Error::HandshakeSoranet(message)
            if message.starts_with("SoraNet admission work gate closed:")
    ));
    assert!(!started.load(Ordering::Acquire));
}
#[tokio::test(flavor = "current_thread")]
async fn inbound_puzzle_verification_accepts_a_fresh_valid_ticket() {
    let config = minimal_puzzle_config(
        Duration::from_secs(5),
        Duration::from_secs(30),
        Duration::from_secs(1),
    );
    let transcript_hash = test_admission_transcript();
    let ticket = mint_test_admission_ticket(&config, &transcript_hash, [0x31; 32]);
    let admission = tokio::time::timeout(
        Duration::from_secs(2),
        verify_handshake_challenge_with_gate(
            config,
            ticket.into(),
            transcript_hash,
            Arc::new(Semaphore::new(1)),
        ),
    )
    .await
    .expect("inbound verification should complete")
    .expect("fresh valid puzzle ticket should verify");
    assert_eq!(admission.puzzle.difficulty(), 1);
}
#[tokio::test(flavor = "current_thread")]
async fn inbound_puzzle_verification_rejects_an_invalid_ticket() {
    let config = minimal_puzzle_config(
        Duration::from_secs(5),
        Duration::from_secs(30),
        Duration::from_secs(1),
    );
    let transcript_hash = test_admission_transcript();
    let mut ticket = mint_test_admission_ticket(&config, &transcript_hash, [0x32; 32]);
    ticket[0] ^= 0xFF;
    let error = verify_handshake_challenge_with_gate(
        config,
        ticket.into(),
        transcript_hash,
        Arc::new(Semaphore::new(1)),
    )
    .await
    .expect_err("malformed inbound puzzle ticket must be rejected");
    assert!(matches!(
        error,
        Error::HandshakeSoranet(message)
            if message.contains("unsupported pow ticket version")
    ));
}
#[tokio::test(flavor = "current_thread")]
async fn inbound_puzzle_ticket_expiring_while_queued_is_rejected() {
    let config = minimal_puzzle_config(
        Duration::from_secs(3),
        Duration::from_secs(10),
        Duration::from_secs(1),
    );
    let transcript_hash = test_admission_transcript();
    let ticket = mint_test_admission_ticket(&config, &transcript_hash, [0x33; 32]);
    config
        .verify_challenge_ticket(&ticket, &transcript_hash)
        .expect("ticket must be valid before it enters the work queue");
    let expires_at = PowTicket::parse(&ticket)
        .expect("minted ticket must parse")
        .expires_at;
    let gate = Arc::new(Semaphore::new(1));
    let occupied = Arc::clone(&gate)
        .acquire_owned()
        .await
        .expect("test gate must be open");
    let queued = tokio::spawn(verify_handshake_challenge_with_gate(
        config,
        ticket.into(),
        transcript_hash,
        Arc::clone(&gate),
    ));
    tokio::task::yield_now().await;
    assert_eq!(gate.available_permits(), 0);
    let now_secs = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_secs();
    tokio::time::sleep(Duration::from_secs(
        expires_at.saturating_sub(now_secs).saturating_add(1),
    ))
    .await;
    drop(occupied);
    let error = tokio::time::timeout(Duration::from_secs(1), queued)
        .await
        .expect("expired queued verification should finish promptly")
        .expect("queued verification task must not panic")
        .expect_err("ticket freshness must be checked after queue admission");
    assert!(matches!(
        error,
        Error::HandshakeSoranet(message) if message.contains("puzzle ticket expired")
    ));
}
