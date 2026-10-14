// Peer transport regressions are included at module scope to preserve private-item access.
#[cfg(test)]
mod tests {
    use super::{
        Connection, SoranetHandshakeConfig, cryptographer::Cryptographer, state::*, test_network_id,
    };
    use crate::{ConfidentialHandshakeCaps, ConsensusConfigCaps, ConsensusMode, RelayRole};
    use iroha_crypto::{Algorithm, KeyPair, Signature, encryption::ChaCha20Poly1305};
    use iroha_primitives::addr::SocketAddr;
    use norito::codec::{DecodeAll, Encode};
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };
    use tokio::io::AsyncWrite;
    const TEST_SORANET_TRANSPORT_BINDING: [u8; iroha_crypto::Hash::LENGTH] =
        [0xD7; iroha_crypto::Hash::LENGTH];
    #[test]
    fn first_release_frame_aead_uses_iroha3_domain() {
        assert_eq!(super::DEFAULT_AAD, b"Iroha3 AAD");
    }
    fn delegation_test_key(seed: u8, algorithm: Algorithm) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], algorithm).expect("valid deterministic test key")
    }
    fn delegation_test_challenge(byte: u8) -> super::SoranetTransportDelegationChallenge {
        let mut challenge = [byte; super::SORANET_TRANSPORT_DELEGATION_CHALLENGE_BYTES];
        challenge[super::SORANET_TRANSPORT_DELEGATION_CHALLENGE_BYTES - 1] ^= 0xA5;
        challenge
    }
    fn transport_certificate(
        node: &KeyPair,
        transport: &Arc<KeyPair>,
        relay_authentication: &Arc<KeyPair>,
        network_id: &iroha_data_model::NetworkId,
    ) -> Arc<super::LocalSoranetTransportCertificateV5> {
        super::create_soranet_transport_certificate_v5(
            node,
            Arc::clone(transport),
            Arc::clone(relay_authentication),
            network_id,
        )
        .expect("valid roles must create a certificate")
    }
    fn signed_delegation(
        certificate: &super::LocalSoranetTransportCertificateV5,
        transport: &KeyPair,
        challenge: super::SoranetTransportDelegationChallenge,
        transport_binding: Option<super::TransportBinding>,
    ) -> super::LocalSoranetTransportDelegationV5 {
        super::sign_soranet_transport_delegation_v5(
            certificate,
            transport,
            challenge,
            transport_binding,
        )
        .expect("valid roles must sign a proof")
    }
    fn decode_delegation(frame: &[u8]) -> super::SignedSoranetTransportDelegationV5 {
        norito::decode_canonical(frame).expect("canonical v5 delegation")
    }
    fn encode_delegation(frame: &super::SignedSoranetTransportDelegationV5) -> Vec<u8> {
        norito::encode_canonical(frame).expect("canonical v5 delegation")
    }
    fn unwrap_delegation_error(error: crate::Error) -> crate::SoranetTransportDelegationError {
        match error {
            crate::Error::HandshakeSoranetDelegation(error) => error,
            other => panic!("expected delegation error, got {other:?}"),
        }
    }
    #[test]
    fn soranet_transport_v5_caches_certificate_and_authenticates_exact_dual_identity() {
        assert_eq!(super::PRE_VERSION, 5);
        let network_id = test_network_id("v5-canonical");
        let node = delegation_test_key(0x11, Algorithm::BlsNormal);
        let node_id = iroha_model_base::peer::PeerId::from(node.public_key().clone());
        let transport = Arc::new(delegation_test_key(0x22, Algorithm::Ed25519));
        let relay_authentication = Arc::new(delegation_test_key(0x23, Algorithm::MlDsa));
        let certificate =
            transport_certificate(&node, &transport, &relay_authentication, &network_id);
        let first = signed_delegation(
            &certificate,
            &transport,
            delegation_test_challenge(0x31),
            None,
        );
        let second = signed_delegation(
            &certificate,
            &transport,
            delegation_test_challenge(0x32),
            Some(TEST_SORANET_TRANSPORT_BINDING),
        );
        assert_eq!(
            first.canonical_signed_frame.len(),
            4_459,
            "the absent channel binding defines the exact unbound V5 frame size"
        );
        assert_eq!(
            second.canonical_signed_frame.len(),
            super::MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES,
            "the current signed V5 layout and present channel binding define the exact cap"
        );
        let first_decoded = decode_delegation(&first.canonical_signed_frame);
        let second_decoded = decode_delegation(&second.canonical_signed_frame);
        assert_eq!(first_decoded.certificate, second_decoded.certificate);
        assert_ne!(first_decoded.proof, second_decoded.proof);
        assert_ne!(first.binding, second.binding);
        let verified = super::verify_soranet_transport_delegation_v5(
            &second.canonical_signed_frame,
            &network_id,
            &node_id,
            &delegation_test_challenge(0x32),
            Some(TEST_SORANET_TRANSPORT_BINDING),
        )
        .expect("exact maximum-size v5 frame");
        assert_eq!(
            verified.relay_authentication_verifier.ed25519_public_key(),
            transport.public_key()
        );
        assert_eq!(
            verified.relay_authentication_verifier.mldsa65_public_key(),
            relay_authentication.public_key()
        );
        assert_eq!(
            verified
                .relay_authentication_verifier
                .authenticated_binding_digest(),
            &certificate.digest
        );
        assert_eq!(verified.binding, second.binding);

        let mut oversized = second.canonical_signed_frame.clone();
        oversized.push(0);
        assert!(matches!(
            super::verify_soranet_transport_delegation_v5(
                &oversized,
                &network_id,
                &node_id,
                &delegation_test_challenge(0x32),
                Some(TEST_SORANET_TRANSPORT_BINDING),
            )
            .map_err(unwrap_delegation_error),
            Err(crate::SoranetTransportDelegationError::FrameTooLarge {
                found: 4_526,
                max: 4_525,
            })
        ));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn soranet_transport_v5_rejects_oversized_declared_frame_before_payload_read() {
        use tokio::io::AsyncWriteExt as _;

        let network_id = test_network_id("v5-oversized");
        let node = delegation_test_key(0x38, Algorithm::BlsNormal);
        let node_id = iroha_model_base::peer::PeerId::from(node.public_key().clone());
        let challenge = delegation_test_challenge(0x39);
        let oversized_len = u16::try_from(
            super::MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES
                .checked_add(1)
                .expect("bounded frame cap"),
        )
        .expect("V5 frame cap fits the two-byte length prefix");
        let (mut sender, mut receiver) = tokio::io::duplex(2);
        sender
            .write_all(&oversized_len.to_be_bytes())
            .await
            .expect("write only the rejected length prefix");

        let error = super::read_and_verify_soranet_transport_delegation_v5(
            &mut receiver,
            &network_id,
            &node_id,
            &challenge,
            Some(TEST_SORANET_TRANSPORT_BINDING),
        )
        .await
        .expect_err("oversized declaration must fail before reading a payload");
        assert!(matches!(
            unwrap_delegation_error(error),
            crate::SoranetTransportDelegationError::FrameTooLarge { found, max }
                if found == usize::from(oversized_len)
                    && max == super::MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES
        ));
    }
    #[test]
    fn soranet_transport_v5_rejects_identity_nonce_binding_and_signature_substitution() {
        let network_id = test_network_id("v5-attacks");
        let node = delegation_test_key(0x41, Algorithm::BlsNormal);
        let other_node = delegation_test_key(0x42, Algorithm::BlsNormal);
        let node_id = iroha_model_base::peer::PeerId::from(node.public_key().clone());
        let other_id = iroha_model_base::peer::PeerId::from(other_node.public_key().clone());
        let transport = Arc::new(delegation_test_key(0x43, Algorithm::Ed25519));
        let relay_authentication = Arc::new(delegation_test_key(0x46, Algorithm::MlDsa));
        let challenge = delegation_test_challenge(0x44);
        let certificate =
            transport_certificate(&node, &transport, &relay_authentication, &network_id);
        let local = signed_delegation(
            &certificate,
            &transport,
            challenge,
            Some(TEST_SORANET_TRANSPORT_BINDING),
        );
        assert!(matches!(
            super::verify_soranet_transport_delegation_v5(
                &local.canonical_signed_frame,
                &network_id,
                &other_id,
                &challenge,
                Some(TEST_SORANET_TRANSPORT_BINDING),
            )
            .map_err(unwrap_delegation_error),
            Err(crate::SoranetTransportDelegationError::PeerMismatch { .. })
        ));
        assert!(matches!(
            super::verify_soranet_transport_delegation_v5(
                &local.canonical_signed_frame,
                &network_id,
                &node_id,
                &delegation_test_challenge(0x45),
                Some(TEST_SORANET_TRANSPORT_BINDING),
            )
            .map_err(unwrap_delegation_error),
            Err(crate::SoranetTransportDelegationError::ChallengeMismatch { .. })
        ));
        assert!(matches!(
            super::verify_soranet_transport_delegation_v5(
                &local.canonical_signed_frame,
                &network_id,
                &node_id,
                &challenge,
                None,
            ),
            Err(crate::Error::HandshakeSoranet(message)) if message.contains("binding mismatch")
        ));
        let mut tampered = decode_delegation(&local.canonical_signed_frame);
        tampered.proof.transport_signature[0] ^= 1;
        assert!(matches!(
            super::verify_soranet_transport_delegation_v5(
                &encode_delegation(&tampered),
                &network_id,
                &node_id,
                &challenge,
                Some(TEST_SORANET_TRANSPORT_BINDING),
            ),
            Err(crate::Error::HandshakeSoranet(message))
                if message.contains("proof signature verification failed")
        ));
        let mut tampered = decode_delegation(&local.canonical_signed_frame);
        tampered
            .certificate
            .certificate
            .relay_authentication_mldsa65_public_key = delegation_test_key(0x47, Algorithm::MlDsa)
            .public_key()
            .clone();
        assert!(matches!(
            super::verify_soranet_transport_delegation_v5(
                &encode_delegation(&tampered),
                &network_id,
                &node_id,
                &challenge,
                Some(TEST_SORANET_TRANSPORT_BINDING),
            )
            .map_err(unwrap_delegation_error),
            Err(crate::SoranetTransportDelegationError::InvalidNodeSignature)
        ));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn soranet_transport_v5_preface_carries_exact_optional_binding_and_rejects_v4() {
        use tokio::io::AsyncWriteExt as _;
        let challenge = delegation_test_challenge(0x51);
        let (mut sender, mut receiver) = tokio::io::duplex(128);
        super::write_client_pre_handshake_header(
            &mut sender,
            &challenge,
            Some(TEST_SORANET_TRANSPORT_BINDING),
        )
        .await
        .expect("write preface");
        let observed = super::read_and_verify_client_pre_handshake_header(&mut receiver)
            .await
            .expect("read preface");
        assert_eq!(observed.challenge, challenge);
        assert_eq!(
            observed.transport_binding,
            Some(TEST_SORANET_TRANSPORT_BINDING)
        );

        for invalid_challenge in [
            [0; super::SORANET_TRANSPORT_DELEGATION_CHALLENGE_BYTES],
            [0xA5; super::SORANET_TRANSPORT_DELEGATION_CHALLENGE_BYTES],
        ] {
            let mut invalid = Vec::from(super::PRE_MAGIC.as_slice());
            invalid.push(super::PRE_VERSION);
            invalid.extend_from_slice(&invalid_challenge);
            invalid.push(0);
            let (mut sender, mut receiver) = tokio::io::duplex(64);
            sender
                .write_all(&invalid)
                .await
                .expect("degenerate preface");
            assert_eq!(
                super::read_and_verify_client_pre_handshake_header(&mut receiver)
                    .await
                    .expect_err("degenerate challenge must fail before signing")
                    .kind(),
                std::io::ErrorKind::InvalidData
            );
        }

        let mut malformed = Vec::from(super::PRE_MAGIC.as_slice());
        malformed.push(super::PRE_VERSION);
        malformed.extend_from_slice(&challenge);
        malformed.push(2);
        let (mut sender, mut receiver) = tokio::io::duplex(64);
        sender
            .write_all(&malformed)
            .await
            .expect("malformed preface");
        assert_eq!(
            super::read_and_verify_client_pre_handshake_header(&mut receiver)
                .await
                .expect_err("invalid option tag")
                .kind(),
            std::io::ErrorKind::InvalidData
        );

        let mut legacy = Vec::from(super::PRE_MAGIC.as_slice());
        legacy.push(4);
        legacy.extend_from_slice(&challenge);
        legacy.push(0);
        let (mut sender, mut receiver) = tokio::io::duplex(64);
        sender.write_all(&legacy).await.expect("legacy v4 preface");
        assert_eq!(
            super::read_and_verify_client_pre_handshake_header(&mut receiver)
                .await
                .expect_err("v4 must not remain compatible")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }
    #[test]
    fn external_plaintext_stream_rejects_client_claimed_transport_binding() {
        let exact = Connection::from_split(7, tokio::io::empty(), tokio::io::sink());
        assert!(
            exact
                .validate_client_transport_binding(Some(TEST_SORANET_TRANSPORT_BINDING))
                .is_err()
        );
        assert_eq!(
            exact
                .validate_client_transport_binding(None)
                .expect("plaintext stream has no transport binding"),
            None
        );
    }
    #[test]
    fn admission_transcript_rejects_two_nodes_sharing_one_descriptor() {
        use rand::SeedableRng as _;
        let network_id = test_network_id("shared-descriptor");
        let challenge = delegation_test_challenge(0x61);
        let node_a = delegation_test_key(0x62, Algorithm::BlsNormal);
        let node_b = delegation_test_key(0x63, Algorithm::BlsNormal);
        let transport_a = Arc::new(delegation_test_key(0x64, Algorithm::Ed25519));
        let transport_b = Arc::new(delegation_test_key(0x65, Algorithm::Ed25519));
        let relay_authentication_a = Arc::new(delegation_test_key(0x67, Algorithm::MlDsa));
        let relay_authentication_b = Arc::new(delegation_test_key(0x68, Algorithm::MlDsa));
        let frame_a = signed_delegation(
            &transport_certificate(&node_a, &transport_a, &relay_authentication_a, &network_id),
            &transport_a,
            challenge,
            Some(TEST_SORANET_TRANSPORT_BINDING),
        );
        let frame_b = signed_delegation(
            &transport_certificate(&node_b, &transport_b, &relay_authentication_b, &network_id),
            &transport_b,
            challenge,
            Some(TEST_SORANET_TRANSPORT_BINDING),
        );
        let hello = b"same-final-client-hello";
        let transcript_a = super::soranet_admission_transcript(hello, &frame_a.binding);
        let transcript_b = super::soranet_admission_transcript(hello, &frame_b.binding);
        assert_ne!(transcript_a, transcript_b);
        let binding_config = SoranetHandshakeConfig::defaults();
        assert_ne!(
            binding_config.puzzle_binding(&transcript_a),
            binding_config.puzzle_binding(&transcript_b)
        );
        let config = SoranetHandshakeConfig::defaults;
        let relay_a = config();
        let relay_b = config();
        let mut rng = rand::rngs::StdRng::from_seed([0x66; 32]);
        let mut minted = relay_a
            .mint_challenge_ticket(&transcript_a, &mut rng)
            .expect("mint ticket");
        let mut ticket = std::mem::take(&mut minted.credential);
        let result = relay_b.verify_challenge_ticket(&ticket, &transcript_b);
        super::clear_sensitive_vec(&mut ticket);
        result.expect_err("one presentation must not verify for a second server identity");
    }
    #[test]
    fn final_identity_payload_binds_complete_v5_frame() {
        let network_id = test_network_id("v5-final-binding");
        let node = delegation_test_key(0x71, Algorithm::BlsNormal);
        let transport = Arc::new(delegation_test_key(0x72, Algorithm::Ed25519));
        let relay_authentication = Arc::new(delegation_test_key(0x75, Algorithm::MlDsa));
        let frame = signed_delegation(
            &transport_certificate(&node, &transport, &relay_authentication, &network_id),
            &transport,
            delegation_test_challenge(0x73),
            None,
        );
        let cryptographer = Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[0x74; 32])
            .expect("valid session key");
        let hello = unsigned_handshake_hello(&node, "127.0.0.1:1337".parse().expect("address"));
        let canonical = handshake_signature_payload::<ChaCha20Poly1305>(
            &cryptographer,
            &hello,
            &frame.binding,
            None,
        );
        let mut mutated = frame.canonical_signed_frame.clone();
        *mutated.last_mut().expect("frame byte") ^= 1;
        let mutated_binding = super::soranet_transport_delegation_binding_v5(&mutated);
        assert_ne!(frame.binding, mutated_binding);
        assert_ne!(
            canonical,
            handshake_signature_payload::<ChaCha20Poly1305>(
                &cryptographer,
                &hello,
                &mutated_binding,
                None,
            )
        );
    }
    fn sample_consensus_config_caps() -> ConsensusConfigCaps {
        ConsensusConfigCaps {
            execution_policy_hash: [0xB4; 32],
            nexus_policy_digest: [0xA5; 32],
            native_config_fingerprint: [0xC3; 32],
            ivm_gas_schedule_hash: [0xE7; 32],
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn soranet_handshake_accepts_bls_delegated_dual_online_authentication() {
        let soranet = Arc::new(SoranetHandshakeConfig::defaults());
        let outbound_keys = KeyPair::try_from_seed(vec![0x81; 32], Algorithm::BlsNormal)
            .expect("derive outbound BLS peer identity");
        let inbound_keys = KeyPair::try_from_seed(vec![0x82; 32], Algorithm::BlsNormal)
            .expect("derive inbound BLS peer identity");
        let inbound_transport_keys = Arc::new(
            KeyPair::try_from_seed(vec![0x83; 32], Algorithm::Ed25519)
                .expect("derive inbound Ed25519 SoraNet transport identity"),
        );
        let inbound_relay_authentication = Arc::new(
            KeyPair::try_from_seed(vec![0x84; 32], Algorithm::MlDsa)
                .expect("derive inbound ML-DSA-65 SoraNet authentication identity"),
        );
        let network_id = test_network_id("bls-soranet-test-chain");
        let inbound_transport_certificate = transport_certificate(
            &inbound_keys,
            &inbound_transport_keys,
            &inbound_relay_authentication,
            &network_id,
        );
        let outbound_addr: SocketAddr = "127.0.0.1:10011".parse().unwrap();
        let inbound_addr: SocketAddr = "127.0.0.1:10012".parse().unwrap();
        let expected_inbound_id =
            iroha_model_base::peer::PeerId::from(inbound_keys.public_key().clone());
        let (outbound_stream, inbound_stream) = tokio::io::duplex(64 * 1024);
        let (outbound_read, outbound_write) = tokio::io::split(outbound_stream);
        let (inbound_read, inbound_write) = tokio::io::split(inbound_stream);
        let outbound = ConnectedTo::for_transport_delegation_test(
            outbound_addr,
            expected_inbound_id,
            Arc::new(outbound_keys),
            Connection::from_split_with_binding(
                101,
                outbound_read,
                outbound_write,
                TEST_SORANET_TRANSPORT_BINDING,
            ),
            network_id,
            soranet.clone(),
        );
        let inbound = ConnectedFrom {
            our_public_address: inbound_addr,
            key_pair: Arc::new(inbound_keys),
            soranet_transport_key_pair: inbound_transport_keys,
            soranet_transport_certificate: inbound_transport_certificate,
            connection: Connection::from_split_with_binding(
                102,
                inbound_read,
                inbound_write,
                TEST_SORANET_TRANSPORT_BINDING,
            ),
            network_id,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            soranet_handshake: soranet,
            local_scion_supported: true,
            trust_gossip: true,
            relay_role: RelayRole::Disabled,
        };
        let (outbound_result, inbound_result) = tokio::join!(
            ConnectedTo::send_client_hello::<ChaCha20Poly1305>(outbound),
            ConnectedFrom::read_client_hello::<ChaCha20Poly1305>(inbound),
        );
        outbound_result.expect("outbound BLS SoraNet handshake");
        inbound_result.expect("inbound BLS SoraNet handshake");
    }
    #[tokio::test(flavor = "current_thread")]
    async fn soranet_admission_rejects_plain_unbound_transport_before_ticket() {
        let config = Arc::new(SoranetHandshakeConfig::defaults());
        let network_id = test_network_id("plain-admission-rejected");
        let outbound_keys = delegation_test_key(0x91, Algorithm::BlsNormal);
        let inbound_keys = delegation_test_key(0x92, Algorithm::BlsNormal);
        let inbound_transport_keys = Arc::new(delegation_test_key(0x93, Algorithm::Ed25519));
        let inbound_relay_authentication = Arc::new(delegation_test_key(0x94, Algorithm::MlDsa));
        let inbound_transport_certificate = transport_certificate(
            &inbound_keys,
            &inbound_transport_keys,
            &inbound_relay_authentication,
            &network_id,
        );
        let expected_inbound_id =
            iroha_model_base::peer::PeerId::from(inbound_keys.public_key().clone());
        let (outbound_stream, inbound_stream) = tokio::io::duplex(4096);
        let (outbound_read, outbound_write) = tokio::io::split(outbound_stream);
        let (inbound_read, inbound_write) = tokio::io::split(inbound_stream);
        let outbound = ConnectedTo::for_transport_delegation_test(
            "127.0.0.1:10021".parse().expect("address"),
            expected_inbound_id,
            Arc::new(outbound_keys),
            Connection::from_split(201, outbound_read, outbound_write),
            network_id,
            Arc::clone(&config),
        );
        let inbound = ConnectedFrom {
            our_public_address: "127.0.0.1:10022".parse().expect("address"),
            key_pair: Arc::new(inbound_keys),
            soranet_transport_key_pair: inbound_transport_keys,
            soranet_transport_certificate: inbound_transport_certificate,
            connection: Connection::from_split(202, inbound_read, inbound_write),
            network_id,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            soranet_handshake: config,
            local_scion_supported: true,
            trust_gossip: true,
            relay_role: RelayRole::Disabled,
        };
        let (_outbound_result, inbound_result) = tokio::join!(
            ConnectedTo::send_client_hello::<ChaCha20Poly1305>(outbound),
            ConnectedFrom::read_client_hello::<ChaCha20Poly1305>(inbound),
        );
        assert!(matches!(
            inbound_result,
            Err(crate::Error::HandshakeSoranet(message))
                if message.contains("requires TLS or QUIC channel binding")
        ));
    }
    #[test]
    fn consensus_config_mismatch_rejects_execution_policy_drift() {
        let expected = sample_consensus_config_caps();
        let mut got = expected;
        got.execution_policy_hash[0] ^= 1;
        let reason = consensus_config_mismatch(&expected, &got)
            .expect("one-bit execution-policy drift must fail the handshake");
        assert!(reason.starts_with("execution_policy_hash mismatch"));
    }
    #[test]
    fn consensus_config_mismatch_rejects_nexus_policy_digest_drift() {
        let expected = sample_consensus_config_caps();
        let mut got = expected;
        got.nexus_policy_digest[0] ^= 1;
        let reason = consensus_config_mismatch(&expected, &got)
            .expect("one-bit Nexus policy drift must fail the handshake");
        assert!(reason.starts_with("nexus_policy_digest mismatch"));
    }
    #[test]
    fn consensus_config_mismatch_rejects_ivm_gas_schedule_drift() {
        let expected = sample_consensus_config_caps();
        let mut got = expected;
        got.ivm_gas_schedule_hash[0] ^= 1;
        let reason = consensus_config_mismatch(&expected, &got)
            .expect("one-bit IVM gas-schedule drift must fail the handshake");
        assert!(reason.starts_with("ivm_gas_schedule_hash mismatch"));
        assert!(reason.contains(&hex_bytes(&expected.ivm_gas_schedule_hash)));
        assert!(reason.contains(&hex_bytes(&got.ivm_gas_schedule_hash)));
    }
    struct TrackingWrite {
        buffer: Vec<u8>,
        flushes: usize,
    }
    impl TrackingWrite {
        fn new() -> Self {
            Self {
                buffer: Vec::new(),
                flushes: 0,
            }
        }
    }
    impl AsyncWrite for TrackingWrite {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.buffer.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flushes = self.flushes.saturating_add(1);
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    fn random_node_key_pair() -> KeyPair {
        KeyPair::random_with_algorithm(Algorithm::BlsNormal)
    }
    fn unsigned_handshake_hello(key_pair: &KeyPair, addr: SocketAddr) -> HandshakeHello {
        let (_, public_key) = key_pair
            .public_key()
            .try_to_bytes()
            .expect("fixture public key must be valid");
        HandshakeHello {
            network_id: test_network_id("test-chain"),
            public_key: public_key.to_vec(),
            signature: Vec::new(),
            addr,
            relay: RelayRole::Disabled,
            consensus: HandshakeConsensusMeta {
                mode: None,
                proto_version: None,
                consensus_fingerprint: None,
                config: None,
            },
            confidential: HandshakeConfidentialMeta {
                enabled: None,
                assume_valid: None,
                verifier_backend: None,
                features: None,
            },
            crypto: HandshakeCryptoMeta {
                sm_enabled: None,
                sm_openssl_preview: None,
            },
            trust: HandshakeTrustMeta {
                trust_gossip: true,
                scion_supported: false,
            },
        }
    }
    async fn read_crafted_handshake_hello(
        hello: HandshakeHello,
        cryptographer: Cryptographer<ChaCha20Poly1305>,
    ) -> Result<Ready<ChaCha20Poly1305>, crate::Error> {
        use tokio::io::AsyncWriteExt;
        let encoded =
            encode_handshake_message(&cryptographer, &hello).expect("encode crafted hello");
        let hello_len = u16::try_from(encoded.len()).expect("crafted hello fits handshake frame");
        let (stream_a, stream_b) = tokio::io::duplex(encoded.len() + 2);
        let (_sender_read, mut sender_write) = tokio::io::split(stream_a);
        let (receiver_read, receiver_write) = tokio::io::split(stream_b);
        sender_write
            .write_u16(hello_len)
            .await
            .expect("write hello length");
        sender_write
            .write_all(&encoded)
            .await
            .expect("write hello bytes");
        let get_key = GetKey::<ChaCha20Poly1305> {
            local_peer_id: super::PeerId::from(random_node_key_pair().public_key().clone()),
            connection: Connection::from_split(15, receiver_read, receiver_write),
            expected_peer_id: None,
            cryptographer,
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        };
        GetKey::read_their_public_key(get_key).await
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_writes_flush_frames() {
        let mut writer = TrackingWrite::new();
        let challenge = delegation_test_challenge(0xC7);
        super::write_client_pre_handshake_header(&mut writer, &challenge, None)
            .await
            .expect("preface write");
        assert_eq!(writer.flushes, 1, "preface should flush once");
        let payload = b"hello";
        super::write_handshake_frame(&mut writer, payload)
            .await
            .expect("handshake frame write");
        assert_eq!(writer.flushes, 2, "handshake frame should flush once");
        let mut expected = Vec::from(&super::PRE_MAGIC[..]);
        expected.push(super::PRE_VERSION);
        expected.extend_from_slice(&challenge);
        expected.push(0);
        assert_eq!(
            &writer.buffer[..expected.len()],
            expected.as_slice(),
            "preface bytes should be written first"
        );
        let frame = &writer.buffer[expected.len()..];
        assert_eq!(frame.len(), 2 + payload.len());
        let len = u16::from_be_bytes([frame[0], frame[1]]);
        assert_eq!(len as usize, payload.len());
        assert_eq!(&frame[2..], payload);
    }
    #[test]
    fn handshake_signature_payload_is_consistent_between_sides() {
        let cryptographer = Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[0xA5; 32])
            .expect("valid key length");
        let addr: SocketAddr = "127.0.0.1:1337".parse().unwrap();
        let hello = unsigned_handshake_hello(&random_node_key_pair(), addr);
        let sender_payload = handshake_signature_payload::<ChaCha20Poly1305>(
            &cryptographer,
            &hello,
            &TEST_SORANET_TRANSPORT_BINDING,
            None,
        );
        let receiver_payload = handshake_signature_payload::<ChaCha20Poly1305>(
            &cryptographer,
            &hello,
            &TEST_SORANET_TRANSPORT_BINDING,
            None,
        );
        assert_eq!(sender_payload, receiver_payload);
    }
    #[test]
    fn handshake_signature_payload_rejects_same_name_different_genesis() {
        let addr: SocketAddr = "127.0.0.1:1337".parse().unwrap();
        let mut hello_a = unsigned_handshake_hello(&random_node_key_pair(), addr);
        let cryptographer = Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[0x5A; 32])
            .expect("valid key length");
        let display_name = iroha_model_base::chain::ChainId::from("shared-display-name");
        let network_a = test_network_id("handshake-genesis-a");
        let network_b = test_network_id("handshake-genesis-b");
        hello_a.network_id = network_a;
        let mut hello_b = hello_a.clone();
        hello_b.network_id = network_b;
        let payload_a = handshake_signature_payload::<ChaCha20Poly1305>(
            &cryptographer,
            &hello_a,
            &TEST_SORANET_TRANSPORT_BINDING,
            None,
        );
        let payload_b = handshake_signature_payload::<ChaCha20Poly1305>(
            &cryptographer,
            &hello_b,
            &TEST_SORANET_TRANSPORT_BINDING,
            None,
        );
        assert_ne!(payload_a, payload_b);
        assert_eq!(display_name.as_str(), "shared-display-name");
    }
    #[test]
    fn handshake_signature_payload_binds_the_full_session_hash() {
        let addr: SocketAddr = "127.0.0.1:1337".parse().unwrap();
        let hello = unsigned_handshake_hello(&random_node_key_pair(), addr);
        let cryptographer = Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[0x3C; 32])
            .expect("valid key length");
        let mut same_compact_prefix = cryptographer.clone();
        same_compact_prefix.session_binding[iroha_crypto::Hash::LENGTH - 1] ^= 1;
        assert_eq!(
            cryptographer.disambiguator, same_compact_prefix.disambiguator,
            "fixture must preserve the 64-bit operational tie-breaker"
        );
        let expected = handshake_signature_payload::<ChaCha20Poly1305>(
            &cryptographer,
            &hello,
            &TEST_SORANET_TRANSPORT_BINDING,
            None,
        );
        let changed = handshake_signature_payload::<ChaCha20Poly1305>(
            &same_compact_prefix,
            &hello,
            &TEST_SORANET_TRANSPORT_BINDING,
            None,
        );
        assert_ne!(
            expected, changed,
            "identity authentication must bind all 256 session-binding bits"
        );
    }
    #[test]
    fn handshake_signature_payload_binds_all_advertised_capabilities() {
        let cryptographer = Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[0x6D; 32])
            .expect("valid key length");
        let addr: SocketAddr = "127.0.0.1:1337".parse().unwrap();
        let mut hello = unsigned_handshake_hello(&random_node_key_pair(), addr);
        hello.consensus.mode = Some(ConsensusMode::Permissioned);
        hello.confidential.enabled = Some(true);
        hello.crypto.sm_enabled = Some(false);
        let expected = handshake_signature_payload::<ChaCha20Poly1305>(
            &cryptographer,
            &hello,
            &TEST_SORANET_TRANSPORT_BINDING,
            None,
        );
        let mut changed = hello.clone();
        changed.relay = RelayRole::Hub;
        assert_ne!(
            expected,
            handshake_signature_payload::<ChaCha20Poly1305>(
                &cryptographer,
                &changed,
                &TEST_SORANET_TRANSPORT_BINDING,
                None,
            ),
            "relay capability must be authenticated"
        );
        let mut changed = hello.clone();
        changed.consensus.mode = Some(ConsensusMode::Npos);
        assert_ne!(
            expected,
            handshake_signature_payload::<ChaCha20Poly1305>(
                &cryptographer,
                &changed,
                &TEST_SORANET_TRANSPORT_BINDING,
                None,
            ),
            "consensus capabilities must be authenticated"
        );
        let mut changed = hello.clone();
        changed.confidential.enabled = Some(false);
        assert_ne!(
            expected,
            handshake_signature_payload::<ChaCha20Poly1305>(
                &cryptographer,
                &changed,
                &TEST_SORANET_TRANSPORT_BINDING,
                None,
            ),
            "confidential capabilities must be authenticated"
        );
        let mut changed = hello.clone();
        changed.crypto.sm_enabled = Some(true);
        assert_ne!(
            expected,
            handshake_signature_payload::<ChaCha20Poly1305>(
                &cryptographer,
                &changed,
                &TEST_SORANET_TRANSPORT_BINDING,
                None,
            ),
            "cryptographic capabilities must be authenticated"
        );
        let mut changed = hello;
        changed.trust.scion_supported = true;
        assert_ne!(
            expected,
            handshake_signature_payload::<ChaCha20Poly1305>(
                &cryptographer,
                &changed,
                &TEST_SORANET_TRANSPORT_BINDING,
                None,
            ),
            "trust and transport capabilities must be authenticated"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_capabilities_changed_after_signing() {
        let key_pair = random_node_key_pair();
        let addr: SocketAddr = "127.0.0.1:1337".parse().unwrap();
        let cryptographer = Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[0x4E; 32])
            .expect("valid key length");
        let mut hello = unsigned_handshake_hello(&key_pair, addr);
        let payload = handshake_signature_payload::<ChaCha20Poly1305>(
            &cryptographer,
            &hello,
            &TEST_SORANET_TRANSPORT_BINDING,
            None,
        );
        hello.signature = Signature::try_new(key_pair.private_key(), &payload)
            .expect("sign canonical handshake claims")
            .payload()
            .to_vec();
        hello.trust.scion_supported = true;
        let error = match read_crafted_handshake_hello(hello, cryptographer).await {
            Ok(_) => panic!("capabilities changed after signing must fail authentication"),
            Err(error) => error,
        };
        assert!(
            matches!(error, crate::Error::Keys(_)),
            "expected signature verification failure, got {error:?}"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_same_name_peer_from_a_different_genesis() {
        let addr: SocketAddr = "127.0.0.1:1337".parse().unwrap();
        let display_name = iroha_model_base::chain::ChainId::from("shared-display-name");
        let key_pair = random_node_key_pair();
        let cryptographer = Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[0x7C; 32])
            .expect("valid key length");
        let (stream_a, stream_b) = tokio::io::duplex(512);
        let (sender_read, sender_write) = tokio::io::split(stream_a);
        let (receiver_read, receiver_write) = tokio::io::split(stream_b);
        let send_key = SendKey::<ChaCha20Poly1305>::new(SendKeyInit {
            our_public_address: addr,
            expected_peer_id: None,
            key_pair,
            connection: Connection::from_split(1, sender_read, sender_write),
            cryptographer: cryptographer.clone(),
            network_id: test_network_id("genesis-a"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        });
        let get_key = GetKey::<ChaCha20Poly1305> {
            local_peer_id: super::PeerId::from(random_node_key_pair().public_key().clone()),
            connection: Connection::from_split(2, receiver_read, receiver_write),
            expected_peer_id: None,
            cryptographer,
            network_id: test_network_id("genesis-b"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        };
        let sender = tokio::spawn(async move {
            let _ = SendKey::send_our_public_key(send_key).await?;
            Result::<(), crate::Error>::Ok(())
        });
        let error = match GetKey::read_their_public_key(get_key).await {
            Ok(_) => panic!("a handshake from a different genesis must be rejected"),
            Err(error) => error,
        };
        sender
            .await
            .expect("sender task panicked")
            .expect("sending handshake should succeed");
        assert!(matches!(
            error,
            crate::Error::HandshakeNetworkMismatch { expected, found }
                if expected == test_network_id("genesis-b")
                    && found == test_network_id("genesis-a")
        ));
        assert_eq!(display_name.as_str(), "shared-display-name");
    }
    #[test]
    fn confidential_digest_roundtrip_preserves_zk_policy_hash() {
        let digest = crate::ConfidentialFeatureDigest::new(
            Some([0x11; 32]),
            Some(7),
            Some(11),
            Some(13),
            Some([0xA5; 32]),
        );
        let handshake = HandshakeConfidentialDigest::from(&digest);
        let encoded = handshake.encode();
        let mut slice = encoded.as_slice();
        let decoded = HandshakeConfidentialDigest::decode_all(&mut slice)
            .expect("decode confidential handshake digest");
        assert!(slice.is_empty(), "digest decode should consume all bytes");
        let roundtrip = crate::ConfidentialFeatureDigest::from(decoded);
        assert_eq!(roundtrip, digest);
        assert_eq!(roundtrip.zk_policy_hash, Some([0xA5; 32]));
    }
    fn confidential_feature_digest(
        policy_hash_byte: Option<u8>,
    ) -> crate::ConfidentialFeatureDigest {
        confidential_feature_digest_with_rules(
            Some(iroha_data_model::confidential::CONFIDENTIAL_RULES_VERSION),
            policy_hash_byte,
        )
    }
    fn confidential_feature_digest_with_rules(
        rules_version: Option<u32>,
        policy_hash_byte: Option<u8>,
    ) -> crate::ConfidentialFeatureDigest {
        confidential_feature_digest_full(None, None, None, rules_version, policy_hash_byte)
    }
    fn confidential_feature_digest_full(
        vk_set_hash_byte: Option<u8>,
        poseidon_params_id: Option<u32>,
        pedersen_params_id: Option<u32>,
        rules_version: Option<u32>,
        policy_hash_byte: Option<u8>,
    ) -> crate::ConfidentialFeatureDigest {
        crate::ConfidentialFeatureDigest::new(
            vk_set_hash_byte.map(|byte| [byte; 32]),
            poseidon_params_id,
            pedersen_params_id,
            rules_version,
            policy_hash_byte.map(|byte| [byte; 32]),
        )
    }
    fn confidential_zk_caps(
        features: Option<crate::ConfidentialFeatureDigest>,
    ) -> ConfidentialHandshakeCaps {
        ConfidentialHandshakeCaps {
            enabled: true,
            assume_valid: false,
            verifier_backend: "halo2-ipa-pallas".to_string(),
            features,
        }
    }
    fn confidential_zk_caps_with_flags(
        assume_valid: bool,
        verifier_backend: &str,
        features: Option<crate::ConfidentialFeatureDigest>,
    ) -> ConfidentialHandshakeCaps {
        confidential_zk_caps_full(true, assume_valid, verifier_backend, features)
    }
    fn confidential_zk_caps_full(
        enabled: bool,
        assume_valid: bool,
        verifier_backend: &str,
        features: Option<crate::ConfidentialFeatureDigest>,
    ) -> ConfidentialHandshakeCaps {
        ConfidentialHandshakeCaps {
            enabled,
            assume_valid,
            verifier_backend: verifier_backend.to_string(),
            features,
        }
    }
    async fn confidential_handshake_error(
        sender_caps: ConfidentialHandshakeCaps,
        receiver_caps: ConfidentialHandshakeCaps,
    ) -> crate::Error {
        confidential_handshake_error_with_caps(Some(sender_caps), Some(receiver_caps)).await
    }
    async fn confidential_handshake_error_with_caps(
        sender_caps: Option<ConfidentialHandshakeCaps>,
        receiver_caps: Option<ConfidentialHandshakeCaps>,
    ) -> crate::Error {
        let addr: SocketAddr = "127.0.0.1:1338".parse().unwrap();
        let key_pair = random_node_key_pair();
        let cryptographer =
            Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[12u8; 32]).unwrap();
        let (stream_a, stream_b) = tokio::io::duplex(1024);
        let (sender_read, sender_write) = tokio::io::split(stream_a);
        let (receiver_read, receiver_write) = tokio::io::split(stream_b);
        let send_key = SendKey::<ChaCha20Poly1305>::new(SendKeyInit {
            our_public_address: addr.clone(),
            expected_peer_id: None,
            key_pair,
            connection: Connection::from_split(21, sender_read, sender_write),
            cryptographer: cryptographer.clone(),
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: sender_caps,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        });
        let get_key = GetKey::<ChaCha20Poly1305> {
            local_peer_id: super::PeerId::from(random_node_key_pair().public_key().clone()),
            connection: Connection::from_split(22, receiver_read, receiver_write),
            expected_peer_id: None,
            cryptographer,
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: receiver_caps,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        };
        let sender = tokio::spawn(async move {
            let _ = SendKey::send_our_public_key(send_key).await?;
            Result::<(), crate::Error>::Ok(())
        });
        let err = match GetKey::read_their_public_key(get_key).await {
            Ok(_) => panic!("confidential capability mismatch must reject handshake"),
            Err(err) => err,
        };
        sender
            .await
            .expect("sender task panicked")
            .expect("sending handshake should succeed");
        err
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_confidential_zk_policy_hash_mismatch() {
        let err = confidential_handshake_error(
            confidential_zk_caps(Some(confidential_feature_digest(Some(0xAA)))),
            confidential_zk_caps(Some(confidential_feature_digest(Some(0xBB)))),
        )
        .await;
        assert!(
            matches!(err, crate::Error::HandshakeConfidentialMismatch),
            "expected confidential mismatch, got {err:?}"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_missing_confidential_feature_digest_when_expected() {
        let err = confidential_handshake_error(
            confidential_zk_caps(None),
            confidential_zk_caps(Some(confidential_feature_digest(Some(0xAA)))),
        )
        .await;
        assert!(
            matches!(err, crate::Error::HandshakeConfidentialMismatch),
            "expected confidential mismatch, got {err:?}"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_missing_confidential_meta_when_expected() {
        let err = confidential_handshake_error_with_caps(
            None,
            Some(confidential_zk_caps(Some(confidential_feature_digest(
                Some(0xAA),
            )))),
        )
        .await;
        assert!(
            matches!(err, crate::Error::HandshakeConfidentialMismatch),
            "expected confidential mismatch, got {err:?}"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_missing_zk_policy_hash_when_expected() {
        let err = confidential_handshake_error(
            confidential_zk_caps(Some(confidential_feature_digest(None))),
            confidential_zk_caps(Some(confidential_feature_digest(Some(0xAA)))),
        )
        .await;
        assert!(
            matches!(err, crate::Error::HandshakeConfidentialMismatch),
            "expected confidential mismatch, got {err:?}"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_missing_confidential_rules_version_when_expected() {
        let err = confidential_handshake_error(
            confidential_zk_caps(Some(confidential_feature_digest_with_rules(
                None,
                Some(0xAA),
            ))),
            confidential_zk_caps(Some(confidential_feature_digest(Some(0xAA)))),
        )
        .await;
        assert!(
            matches!(err, crate::Error::HandshakeConfidentialMismatch),
            "expected confidential mismatch, got {err:?}"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_confidential_rules_version_mismatch() {
        let err = confidential_handshake_error(
            confidential_zk_caps(Some(confidential_feature_digest_with_rules(
                Some(iroha_data_model::confidential::CONFIDENTIAL_RULES_VERSION + 1),
                Some(0xAA),
            ))),
            confidential_zk_caps(Some(confidential_feature_digest(Some(0xAA)))),
        )
        .await;
        assert!(
            matches!(err, crate::Error::HandshakeConfidentialMismatch),
            "expected confidential mismatch, got {err:?}"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_confidential_feature_material_mismatches() {
        for (label, sender_features, receiver_features) in [
            (
                "vk_set_hash",
                confidential_feature_digest_full(Some(0x10), None, None, Some(1), Some(0xAA)),
                confidential_feature_digest_full(Some(0x20), None, None, Some(1), Some(0xAA)),
            ),
            (
                "poseidon_params_id",
                confidential_feature_digest_full(None, Some(1), None, Some(1), Some(0xAA)),
                confidential_feature_digest_full(None, Some(2), None, Some(1), Some(0xAA)),
            ),
            (
                "pedersen_params_id",
                confidential_feature_digest_full(None, None, Some(1), Some(1), Some(0xAA)),
                confidential_feature_digest_full(None, None, Some(2), Some(1), Some(0xAA)),
            ),
            (
                "missing_poseidon_params_id",
                confidential_feature_digest_full(None, None, None, Some(1), Some(0xAA)),
                confidential_feature_digest_full(None, Some(1), None, Some(1), Some(0xAA)),
            ),
        ] {
            let err = confidential_handshake_error(
                confidential_zk_caps(Some(sender_features)),
                confidential_zk_caps(Some(receiver_features)),
            )
            .await;
            assert!(
                matches!(err, crate::Error::HandshakeConfidentialMismatch),
                "{label} should produce confidential mismatch, got {err:?}"
            );
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_confidential_assume_valid_mismatch() {
        let features = Some(confidential_feature_digest(Some(0xAA)));
        let err = confidential_handshake_error(
            confidential_zk_caps_with_flags(true, "halo2-ipa-pallas", features),
            confidential_zk_caps_with_flags(false, "halo2-ipa-pallas", features),
        )
        .await;
        assert!(
            matches!(err, crate::Error::HandshakeConfidentialMismatch),
            "expected confidential mismatch, got {err:?}"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_confidential_enabled_mismatch() {
        let features = Some(confidential_feature_digest(Some(0xAA)));
        let err = confidential_handshake_error(
            confidential_zk_caps_full(false, false, "halo2-ipa-pallas", features),
            confidential_zk_caps_full(true, false, "halo2-ipa-pallas", features),
        )
        .await;
        assert!(
            matches!(err, crate::Error::HandshakeConfidentialMismatch),
            "expected confidential mismatch, got {err:?}"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_confidential_verifier_backend_mismatch() {
        let features = Some(confidential_feature_digest(Some(0xAA)));
        let err = confidential_handshake_error(
            confidential_zk_caps_with_flags(false, "halo2-ipa-pallas-alt", features),
            confidential_zk_caps_with_flags(false, "halo2-ipa-pallas", features),
        )
        .await;
        assert!(
            matches!(err, crate::Error::HandshakeConfidentialMismatch),
            "expected confidential mismatch, got {err:?}"
        );
    }
    #[test]
    fn untagged_handshake_is_rejected() {
        let cryptographer =
            Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[9u8; 32]).unwrap();
        let key_pair = random_node_key_pair();
        let (_, pk_bytes) = key_pair
            .public_key()
            .try_to_bytes()
            .expect("fixture public key must be valid");
        let addr: SocketAddr = "127.0.0.1:1337".parse().unwrap();
        let hello = HandshakeHello {
            network_id: test_network_id("test-chain"),
            public_key: pk_bytes.to_vec(),
            signature: vec![0u8; 64],
            addr: addr.clone(),
            relay: RelayRole::Disabled,
            consensus: HandshakeConsensusMeta {
                mode: None,
                proto_version: None,
                consensus_fingerprint: None,
                config: None,
            },
            confidential: HandshakeConfidentialMeta {
                enabled: None,
                assume_valid: None,
                verifier_backend: None,
                features: None,
            },
            crypto: HandshakeCryptoMeta {
                sm_enabled: None,
                sm_openssl_preview: None,
            },
            trust: HandshakeTrustMeta {
                trust_gossip: true,
                scion_supported: false,
            },
        };
        let raw = hello.encode();
        let encrypted = cryptographer.encrypt(&raw).expect("encrypt raw handshake");
        let decoded = decode_handshake_message(&cryptographer, &encrypted);
        assert!(
            matches!(decoded, Err(crate::Error::Format)),
            "untagged handshake must be rejected"
        );
    }
    #[test]
    fn versioned_handshake_preserves_trust_flag() {
        let cryptographer =
            Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[11u8; 32]).unwrap();
        let key_pair = random_node_key_pair();
        let (_, pk_bytes) = key_pair
            .public_key()
            .try_to_bytes()
            .expect("fixture public key must be valid");
        let addr: SocketAddr = "127.0.0.1:1444".parse().unwrap();
        let hello = HandshakeHello {
            network_id: test_network_id("test-chain"),
            public_key: pk_bytes.to_vec(),
            signature: vec![1u8; 64],
            addr: addr.clone(),
            relay: RelayRole::Hub,
            consensus: HandshakeConsensusMeta {
                mode: Some(ConsensusMode::Permissioned),
                proto_version: Some(1),
                consensus_fingerprint: Some([7u8; 32]),
                config: None,
            },
            confidential: HandshakeConfidentialMeta {
                enabled: Some(true),
                assume_valid: Some(false),
                verifier_backend: Some("backend".to_string()),
                features: None,
            },
            crypto: HandshakeCryptoMeta {
                sm_enabled: Some(false),
                sm_openssl_preview: Some(false),
            },
            trust: HandshakeTrustMeta {
                trust_gossip: true,
                scion_supported: true,
            },
        };
        let encrypted =
            encode_handshake_message(&cryptographer, &hello).expect("encode v1 handshake");
        let decoded =
            decode_handshake_message(&cryptographer, &encrypted).expect("decode v1 handshake");
        assert_eq!(decoded.addr, addr);
        assert!(decoded.trust.trust_gossip);
    }
    #[test]
    fn handshake_decode_honors_its_pre_auth_resource_budget() {
        let key_pair = random_node_key_pair();
        let addr: SocketAddr = "127.0.0.1:1444".parse().unwrap();
        let hello = unsigned_handshake_hello(&key_pair, addr);
        let body = hello.encode();
        let no_sequence_budget = norito::DecodeLimits::new(0, body.len(), 0, body.len(), 16);
        let error = decode_handshake_body_with_limits(&body, no_sequence_budget)
            .expect_err("the handshake decoder must not widen its caller's resource budget");
        assert!(
            matches!(
                error,
                crate::Error::NoritoCodec(
                    norito::core::Error::SequenceLengthExceeded { .. }
                        | norito::core::Error::TotalElementsExceeded { .. }
                        | norito::core::Error::TotalAllocationExceeded { .. }
                )
            ),
            "expected a decode-budget rejection, got {error:?}"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_fails_when_metadata_exceeds_limit() {
        let addr: SocketAddr = "127.0.0.1:1337".parse().unwrap();
        let key_pair = random_node_key_pair();
        let connection = Connection::from_split(7, tokio::io::empty(), tokio::io::sink());
        let cryptographer =
            super::cryptographer::Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(
                &[42u8; 32],
            )
            .expect("valid key length");
        let caps = ConfidentialHandshakeCaps {
            enabled: true,
            assume_valid: false,
            verifier_backend: "halo2-ipa-".repeat(7000),
            features: None,
        };
        let send_key = SendKey::<ChaCha20Poly1305>::new(SendKeyInit {
            our_public_address: addr,
            expected_peer_id: None,
            key_pair,
            connection,
            cryptographer,
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: Some(caps),
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        });
        let err = match SendKey::<ChaCha20Poly1305>::send_our_public_key(send_key).await {
            Ok(_) => panic!("expected HandshakeMessageTooLarge error"),
            Err(err) => err,
        };
        assert!(
            matches!(err, crate::Error::HandshakeMessageTooLarge),
            "expected HandshakeMessageTooLarge, got {err:?}"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn outbound_handshake_rejects_non_bls_node_identity() {
        let key_pair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let send_key = SendKey::<ChaCha20Poly1305>::new(SendKeyInit {
            our_public_address: "127.0.0.1:1337".parse().expect("address"),
            expected_peer_id: None,
            key_pair,
            connection: Connection::from_split(7, tokio::io::empty(), tokio::io::sink()),
            cryptographer: Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[42u8; 32])
                .expect("valid key length"),
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        });
        let error = match SendKey::send_our_public_key(send_key).await {
            Ok(_) => panic!("only BLS-normal node identities may initiate a handshake"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            crate::Error::HandshakeNodeAlgorithmMismatch {
                found: Algorithm::Ed25519
            }
        ));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_v1_propagates_trust_and_scion_capabilities() {
        let addr: SocketAddr = "127.0.0.1:1337".parse().unwrap();
        let key_pair = random_node_key_pair();
        let cryptographer =
            Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[7u8; 32]).unwrap();
        let (stream_a, stream_b) = tokio::io::duplex(256);
        let (sender_read, sender_write) = tokio::io::split(stream_a);
        let (receiver_read, receiver_write) = tokio::io::split(stream_b);
        let send_key = SendKey::<ChaCha20Poly1305>::new(SendKeyInit {
            our_public_address: addr.clone(),
            expected_peer_id: None,
            key_pair,
            connection: Connection::from_split(1, sender_read, sender_write),
            cryptographer: cryptographer.clone(),
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        });
        let get_key = GetKey::<ChaCha20Poly1305> {
            local_peer_id: super::PeerId::from(random_node_key_pair().public_key().clone()),
            connection: Connection::from_split(2, receiver_read, receiver_write),
            expected_peer_id: None,
            cryptographer,
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        };
        let sender = tokio::spawn(async move {
            let _ = SendKey::send_our_public_key(send_key).await?;
            Result::<(), crate::Error>::Ok(())
        });
        let ready = GetKey::read_their_public_key(get_key)
            .await
            .expect("handshake should succeed");
        sender
            .await
            .expect("sender task panicked")
            .expect("sending handshake should succeed");
        assert!(ready.trust_gossip, "handshake should enable trust gossip");
        assert!(
            ready.scion_supported,
            "handshake should propagate SCION support flag"
        );
    }
    async fn write_framed_handshake<W>(writer: &mut W, encoded: &[u8])
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        let len = u16::try_from(encoded.len()).expect("fixture handshake message length fits u16");
        writer.write_u16(len).await.expect("write hello length");
        writer.write_all(encoded).await.expect("write hello bytes");
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_all_zero_signature_material() {
        let addr: SocketAddr = "127.0.0.1:1443".parse().unwrap();
        let key_pair = random_node_key_pair();
        let (_, public_key) = key_pair
            .public_key()
            .try_to_bytes()
            .expect("fixture public key must be valid");
        let cryptographer =
            Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[13u8; 32]).unwrap();
        let hello = HandshakeHello {
            network_id: test_network_id("test-chain"),
            public_key: public_key.to_vec(),
            signature: vec![0u8; 64],
            addr,
            relay: RelayRole::Disabled,
            consensus: HandshakeConsensusMeta {
                mode: None,
                proto_version: None,
                consensus_fingerprint: None,
                config: None,
            },
            confidential: HandshakeConfidentialMeta {
                enabled: None,
                assume_valid: None,
                verifier_backend: None,
                features: None,
            },
            crypto: HandshakeCryptoMeta {
                sm_enabled: None,
                sm_openssl_preview: None,
            },
            trust: HandshakeTrustMeta {
                trust_gossip: true,
                scion_supported: false,
            },
        };
        let encoded =
            encode_handshake_message(&cryptographer, &hello).expect("encode crafted hello");
        let (stream_a, stream_b) = tokio::io::duplex(4096);
        let (_sender_read, mut sender_write) = tokio::io::split(stream_a);
        let (receiver_read, receiver_write) = tokio::io::split(stream_b);
        write_framed_handshake(&mut sender_write, &encoded).await;
        let get_key = GetKey::<ChaCha20Poly1305> {
            local_peer_id: super::PeerId::from(random_node_key_pair().public_key().clone()),
            connection: Connection::from_split(15, receiver_read, receiver_write),
            expected_peer_id: None,
            cryptographer,
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        };
        let err = match GetKey::read_their_public_key(get_key).await {
            Ok(_) => panic!("all-zero handshake signature material must be rejected"),
            Err(err) => err,
        };
        assert!(
            matches!(err, crate::Error::Keys(_)),
            "expected signature parse failure, got {err:?}"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_non_bls_node_identity() {
        for algorithm in [Algorithm::Ed25519, Algorithm::MlDsa] {
            let addr: SocketAddr = "127.0.0.1:1443".parse().unwrap();
            let key_pair = KeyPair::random_with_algorithm(algorithm);
            let cryptographer =
                Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[13u8; 32]).unwrap();
            let mut hello = unsigned_handshake_hello(&key_pair, addr);
            let payload = handshake_signature_payload::<ChaCha20Poly1305>(
                &cryptographer,
                &hello,
                &TEST_SORANET_TRANSPORT_BINDING,
                None,
            );
            hello.signature = Signature::try_new(key_pair.private_key(), &payload)
                .expect("sign non-BLS rejection fixture")
                .payload()
                .to_vec();
            let err = match read_crafted_handshake_hello(hello, cryptographer).await {
                Ok(_) => panic!("only BLS-normal node identities are admitted"),
                Err(error) => error,
            };
            assert!(
                matches!(err, crate::Error::Keys(_)),
                "expected {algorithm:?} public-key rejection, got {err:?}"
            );
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_accepts_matching_transport_binding() {
        let addr: SocketAddr = "127.0.0.1:1444".parse().unwrap();
        let key_pair = random_node_key_pair();
        let cryptographer =
            Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[9u8; 32]).unwrap();
        let transport_binding = [0x5Au8; iroha_crypto::Hash::LENGTH];
        let (stream_a, stream_b) = tokio::io::duplex(256);
        let (sender_read, sender_write) = tokio::io::split(stream_a);
        let (receiver_read, receiver_write) = tokio::io::split(stream_b);
        let send_key = SendKey::<ChaCha20Poly1305>::new(SendKeyInit {
            our_public_address: addr,
            expected_peer_id: None,
            key_pair,
            connection: Connection::from_split_with_binding(
                11,
                sender_read,
                sender_write,
                transport_binding,
            ),
            cryptographer: cryptographer.clone(),
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        });
        let get_key = GetKey::<ChaCha20Poly1305> {
            local_peer_id: super::PeerId::from(random_node_key_pair().public_key().clone()),
            connection: Connection::from_split_with_binding(
                12,
                receiver_read,
                receiver_write,
                transport_binding,
            ),
            expected_peer_id: None,
            cryptographer,
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        };
        let sender = tokio::spawn(async move {
            let _ = SendKey::send_our_public_key(send_key).await?;
            Result::<(), crate::Error>::Ok(())
        });
        let ready = GetKey::read_their_public_key(get_key)
            .await
            .expect("handshake should succeed with matching transport binding");
        sender
            .await
            .expect("sender task panicked")
            .expect("sending handshake should succeed");
        assert_eq!(ready.connection.transport_binding, Some(transport_binding));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn handshake_rejects_mismatched_transport_binding() {
        let addr: SocketAddr = "127.0.0.1:1446".parse().unwrap();
        let key_pair = random_node_key_pair();
        let cryptographer =
            Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[10u8; 32]).unwrap();
        let (stream_a, stream_b) = tokio::io::duplex(256);
        let (sender_read, sender_write) = tokio::io::split(stream_a);
        let (receiver_read, receiver_write) = tokio::io::split(stream_b);
        let send_key = SendKey::<ChaCha20Poly1305>::new(SendKeyInit {
            our_public_address: addr,
            expected_peer_id: None,
            key_pair,
            connection: Connection::from_split_with_binding(
                13,
                sender_read,
                sender_write,
                [0x11u8; iroha_crypto::Hash::LENGTH],
            ),
            cryptographer: cryptographer.clone(),
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        });
        let get_key = GetKey::<ChaCha20Poly1305> {
            local_peer_id: super::PeerId::from(random_node_key_pair().public_key().clone()),
            connection: Connection::from_split_with_binding(
                14,
                receiver_read,
                receiver_write,
                [0x22u8; iroha_crypto::Hash::LENGTH],
            ),
            expected_peer_id: None,
            cryptographer,
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        };
        let sender = tokio::spawn(async move {
            let _ = SendKey::send_our_public_key(send_key).await?;
            Result::<(), crate::Error>::Ok(())
        });
        let err = match GetKey::read_their_public_key(get_key).await {
            Ok(_) => panic!("mismatched transport binding must be rejected"),
            Err(err) => err,
        };
        sender
            .await
            .expect("sender task panicked")
            .expect("sending handshake should succeed");
        assert!(
            matches!(err, crate::Error::Keys(_)),
            "expected signature verification failure, got {err:?}"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn outgoing_handshake_rejects_unexpected_peer_identity() {
        let addr: SocketAddr = "127.0.0.1:1445".parse().unwrap();
        let actual_key_pair = random_node_key_pair();
        let expected_peer_id =
            iroha_model_base::peer::PeerId::from(random_node_key_pair().public_key().clone());
        let cryptographer =
            Cryptographer::<ChaCha20Poly1305>::new_with_raw_key_bytes(&[8u8; 32]).unwrap();
        let (stream_a, stream_b) = tokio::io::duplex(256);
        let (sender_read, sender_write) = tokio::io::split(stream_a);
        let (receiver_read, receiver_write) = tokio::io::split(stream_b);
        let send_key = SendKey::<ChaCha20Poly1305>::new(SendKeyInit {
            our_public_address: addr.clone(),
            expected_peer_id: None,
            key_pair: actual_key_pair,
            connection: Connection::from_split(3, sender_read, sender_write),
            cryptographer: cryptographer.clone(),
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        });
        let get_key = GetKey::<ChaCha20Poly1305> {
            local_peer_id: super::PeerId::from(random_node_key_pair().public_key().clone()),
            connection: Connection::from_split(4, receiver_read, receiver_write),
            expected_peer_id: Some(expected_peer_id.clone()),
            cryptographer,
            network_id: test_network_id("test-chain"),
            soranet_transport_binding: TEST_SORANET_TRANSPORT_BINDING,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            relay_role: RelayRole::Disabled,
            local_scion_supported: true,
            trust_gossip: true,
        };
        let sender = tokio::spawn(async move {
            let _ = SendKey::send_our_public_key(send_key).await?;
            Result::<(), crate::Error>::Ok(())
        });
        let err = match GetKey::read_their_public_key(get_key).await {
            Ok(_) => panic!("unexpected peer identity must be rejected"),
            Err(err) => err,
        };
        sender
            .await
            .expect("sender task panicked")
            .expect("sending handshake should succeed");
        match err {
            crate::Error::HandshakePeerMismatch { expected, found } => {
                assert_eq!(expected, expected_peer_id);
                assert_ne!(expected, found);
            }
            other => panic!("expected HandshakePeerMismatch, got {other:?}"),
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn pre_handshake_header_rejects_garbage() {
        // Build a duplex to simulate a remote sending garbage preface
        let (a, mut b) = tokio::io::duplex(64);
        // Writer side: send wrong 5 bytes then close
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = b.write_all(b"BAD!!").await;
        });
        // ConnectedFrom will attempt to read the preface and should error out
        let key_pair = KeyPair::try_from_seed(vec![0xD4; 32], Algorithm::BlsNormal)
            .expect("test BLS-normal node key");
        let soranet_transport_key_pair = Arc::new(
            KeyPair::try_from_seed(vec![0xE5; 32], Algorithm::Ed25519)
                .expect("test Ed25519 transport key"),
        );
        let relay_authentication_key_pair = Arc::new(
            KeyPair::try_from_seed(vec![0xE6; 32], Algorithm::MlDsa)
                .expect("test ML-DSA-65 relay-authentication key"),
        );
        let network_id = test_network_id("test-chain");
        let soranet_transport_certificate = transport_certificate(
            &key_pair,
            &soranet_transport_key_pair,
            &relay_authentication_key_pair,
            &network_id,
        );
        let our_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (r, w) = tokio::io::split(a);
        let conn = Connection::from_split(1, r, w);
        let soranet = Arc::new(SoranetHandshakeConfig::defaults());
        let cf = ConnectedFrom {
            our_public_address: our_addr,
            key_pair: Arc::new(key_pair),
            soranet_transport_key_pair,
            soranet_transport_certificate,
            connection: conn,
            network_id,
            consensus_caps: None,
            confidential_caps: None,
            crypto_caps: None,
            soranet_handshake: soranet,
            local_scion_supported: true,
            trust_gossip: true,
            relay_role: RelayRole::Disabled,
        };
        let err =
            ConnectedFrom::read_client_hello::<iroha_crypto::encryption::ChaCha20Poly1305>(cf)
                .await
                .err()
                .expect("expected error on bad preface");
        assert!(matches!(err, crate::Error::HandshakeBadPreface));
    }

    #[test]
    fn captured_original_p2p_signed_transport_frames() {
        use crate::frame_identity_tests::{preimage, shapes};
        let network_id = test_network_id("v5-canonical");
        let node = delegation_test_key(0x11, Algorithm::BlsNormal);
        let node_id = iroha_model_base::peer::PeerId::from(node.public_key().clone());
        let transport = Arc::new(delegation_test_key(0x22, Algorithm::Ed25519));
        let relay_authentication = Arc::new(delegation_test_key(0x23, Algorithm::MlDsa));
        let certificate =
            transport_certificate(&node, &transport, &relay_authentication, &network_id);
        shapes(
            "signed_certificate_v5",
            "canonical",
            &certificate.signed_certificate,
        );
        let signed_bytes = super::soranet_transport_certificate_signature_payload_v5(
            &certificate.signed_certificate.certificate,
        );
        Signature::try_from_bytes(&certificate.signed_certificate.node_signature)
            .unwrap()
            .verify(node.public_key(), &signed_bytes)
            .unwrap();
        preimage("signed_certificate_v5", "canonical", &signed_bytes);
        for (variant, byte, binding, expected_len) in [
            ("unbound", 0x31, None, 4459),
            ("bound", 0x32, Some(TEST_SORANET_TRANSPORT_BINDING), 4525),
        ] {
            let challenge = delegation_test_challenge(byte);
            let signed = signed_delegation(&certificate, &transport, challenge, binding);
            assert_eq!(signed.canonical_signed_frame.len(), expected_len);
            let verified = super::verify_soranet_transport_delegation_v5(
                &signed.canonical_signed_frame,
                &network_id,
                &node_id,
                &challenge,
                binding,
            )
            .unwrap();
            assert_eq!(verified.binding, signed.binding);
            let decoded = decode_delegation(&signed.canonical_signed_frame);
            assert_eq!(encode_delegation(&decoded), signed.canonical_signed_frame);
            shapes("signed_delegation_v5", variant, &decoded);
            let signed_bytes =
                super::soranet_transport_proof_signature_payload_v5(&decoded.proof.statement);
            Signature::try_from_bytes(&decoded.proof.transport_signature)
                .unwrap()
                .verify(transport.public_key(), &signed_bytes)
                .unwrap();
            preimage("signed_delegation_v5", variant, &signed_bytes);
        }
    }
}
// handshake payload is encoded/decoded as a tuple to avoid extra type definitions
