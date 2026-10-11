// Publisher-side transport and immutable original-set controls. Signed specimens here are
// transport fixtures; native completion, admission and publication qualification remain separate.
fn serve_inventory_once(
    original: Option<MusubiProviderBundleVerificationAttestationV1>,
) -> (Url, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "inventory request never arrived"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("inventory accept failed: {error}"),
            }
        };
        // Accepted sockets inherit the listener's non-blocking mode on BSD-derived platforms;
        // reads below must block (bounded by the timeout) instead of failing with WouldBlock.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 2048];
        let (start, length) = loop {
            let count = stream.read(&mut buffer).unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&buffer[..count]);
            assert!(request.len() <= 8192);
            if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..end]).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                break (end + 4, length);
            }
        };
        while request.len() < start + length {
            let count = stream.read(&mut buffer).unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&buffer[..count]);
            assert!(request.len() <= 8192);
        }
        let (status, body) = match original {
            Some(original) => ("200 OK", norito::encode_canonical(&original).unwrap()),
            None => ("204 No Content", Vec::new()),
        };
        write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/x-norito\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
        stream.write_all(&body).unwrap();
        request
    });
    (url, server)
}

fn bind_inventory_fixture(fixture: &mut RebaseFixture, root: &Path) {
    fs::create_dir(root.join("publication-v1")).unwrap();
    fixture.runtime.bind_publication_state_root(root).unwrap();
    fixture.runtime.provider_gateways.clear();
    for attestation in &fixture.attestations {
        fixture.runtime.provider_gateways.insert(
            attestation.key().provider_id,
            ProviderPublicationEndpointsV1 {
                readback: "https://shared-private.example/".parse().unwrap(),
                attestation: "http://127.0.0.1:9/".parse().unwrap(),
            },
        );
    }
}

#[test]
fn provider_inventory_origin_is_required_canonical_and_separate_from_shared_readback() {
    use provider_inventory::parse_attestation_origin;
    for valid in [
        "https://provider.example:9443/",
        "http://127.0.0.1:8180/",
        "http://[::1]:8181/",
    ] {
        assert_eq!(parse_attestation_origin(valid).unwrap().as_str(), valid);
    }
    for invalid in [
        "",
        "http://provider.example/",
        "http://localhost/",
        "http://10.0.0.1/",
        "https://provider.example",
        "https://PROVIDER.example/",
        "https://user@provider.example/",
        "https://provider.example:0/",
        "https://provider.example/path",
        "https://provider.example/?",
        "https://provider.example/#",
    ] {
        assert!(parse_attestation_origin(invalid).is_err(), "{invalid:?}");
    }
    let state = tempdir().unwrap();
    let path = state.path().join("client.toml");
    let (_, mut config) = write_client_config(&path, "");
    for endpoint in &mut config.provider_gateways {
        endpoint.url = "https://shared-private.example/".into();
    }
    let parsed = parse_provider_gateways(&config.provider_gateways).unwrap();
    assert_eq!(parsed.len(), 3);
    assert!(
        parsed
            .values()
            .all(|value| value.readback.as_str() == "https://shared-private.example/")
    );
    config.provider_gateways[1].attestation_url =
        config.provider_gateways[0].attestation_url.clone();
    assert!(parse_provider_gateways(&config.provider_gateways).is_err());
    let original = fs::read_to_string(&path).unwrap();
    let missing = original.replace(", attestation_url = \"https://inventory-a.example/\"", "");
    assert_ne!(missing, original);
    fs::write(&path, missing).unwrap();
    assert!(RegistrySigningClientV1::load(Some(&path)).is_err());
}

#[test]
fn publisher_inventory_acquires_exact_three_with_manager_identity_and_reuses_full_originals() {
    let mut fixture = rebase_fixture();
    let state = tempdir().unwrap();
    bind_inventory_fixture(&mut fixture, state.path());
    let mut servers = Vec::new();
    for attestation in &fixture.attestations {
        let (url, server) = serve_inventory_once(Some(attestation.clone()));
        fixture
            .runtime
            .provider_gateways
            .get_mut(&attestation.key().provider_id)
            .unwrap()
            .attestation = url;
        servers.push(server);
    }
    fixture
        .runtime
        .signing
        .with_unrelated_listener_headers_for_test();
    let operation = fixture.request.operation_id();
    let retained = fixture
        .runtime
        .acquire_provider_attestation_set(operation, 1, &fixture.request, &fixture.response, None)
        .unwrap();
    assert_eq!(retained.attestations, fixture.attestations);
    let expected_actor = fixture.request.publisher.to_canonical_hex().unwrap();
    for (server, attestation) in servers.into_iter().zip(&fixture.attestations) {
        let raw = server.join().unwrap();
        let end = raw
            .windows(4)
            .position(|value| value == b"\r\n\r\n")
            .unwrap();
        let headers = std::str::from_utf8(&raw[..end])
            .unwrap()
            .to_ascii_lowercase();
        assert!(headers.starts_with("post /v1/sorafs/provider/attestation http/1.1\r\n"));
        assert!(headers.contains(&format!(
            "x-iroha-account: {}",
            expected_actor.to_ascii_lowercase()
        )));
        assert!(headers.contains("x-iroha-signature: "));
        assert!(headers.contains("x-iroha-timestamp-ms: "));
        assert!(headers.contains("x-iroha-nonce: "));
        assert!(!headers.contains("authorization:"));
        assert!(!headers.contains("x-api-token:"));
        assert_eq!(
            &raw[end + 4..],
            &norito::encode_canonical(&attestation.key()).unwrap()
        );
    }
    let bytes = fs::read(
        state
            .path()
            .join(provider_attestation_set_checkpoint_relative_path(
                operation, 1,
            )),
    )
    .unwrap();
    let listeners: Vec<_> = fixture
        .attestations
        .iter()
        .map(|attestation| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            fixture
                .runtime
                .provider_gateways
                .get_mut(&attestation.key().provider_id)
                .unwrap()
                .attestation = format!("http://{}/", listener.local_addr().unwrap())
                .parse()
                .unwrap();
            listener
        })
        .collect();
    let anchored = PublicationProviderRegistrationCheckpointV1 {
        generation: 1,
        archive_id: retained.archive_id,
        replication_order: retained.replication_order,
        provider_attestation_set_digest: retained.set_digest,
        set_sidecar_hash: provider_attestation_sidecar_hash(&bytes),
        transactions: Vec::new(),
    };
    assert_eq!(
        fixture
            .runtime
            .acquire_provider_attestation_set(
                operation,
                1,
                &fixture.request,
                &fixture.response,
                Some(&anchored)
            )
            .unwrap(),
        retained
    );
    assert_eq!(
        fs::read(
            state
                .path()
                .join(provider_attestation_set_checkpoint_relative_path(
                    operation, 1
                ))
        )
        .unwrap(),
        bytes
    );
    for listener in &listeners {
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    fs::remove_file(
        state
            .path()
            .join(provider_attestation_set_checkpoint_relative_path(
                operation, 1,
            )),
    )
    .unwrap();
    assert_eq!(
        fixture
            .runtime
            .acquire_provider_attestation_set(
                operation,
                1,
                &fixture.request,
                &fixture.response,
                Some(&anchored)
            )
            .unwrap_err()
            .code(),
        "PROVIDER_ATTESTATION_SET_CHECKPOINT_MISSING"
    );
    for listener in &listeners {
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn publisher_inventory_retains_no_partial_set_and_refuses_unknown_provider_before_http() {
    let mut fixture = rebase_fixture();
    let state = tempdir().unwrap();
    bind_inventory_fixture(&mut fixture, state.path());
    let (first, first_server) = serve_inventory_once(Some(fixture.attestations[0].clone()));
    let (second, second_server) = serve_inventory_once(None);
    fixture
        .runtime
        .provider_gateways
        .get_mut(&fixture.attestations[0].key().provider_id)
        .unwrap()
        .attestation = first;
    fixture
        .runtime
        .provider_gateways
        .get_mut(&fixture.attestations[1].key().provider_id)
        .unwrap()
        .attestation = second;
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    unused.set_nonblocking(true).unwrap();
    fixture
        .runtime
        .provider_gateways
        .get_mut(&fixture.attestations[2].key().provider_id)
        .unwrap()
        .attestation = format!("http://{}/", unused.local_addr().unwrap())
        .parse()
        .unwrap();
    let operation = fixture.request.operation_id();
    assert_eq!(
        fixture
            .runtime
            .acquire_provider_attestation_set(
                operation,
                1,
                &fixture.request,
                &fixture.response,
                None
            )
            .unwrap_err()
            .code(),
        "PROVIDER_ATTESTATION_INVENTORY_PENDING"
    );
    first_server.join().unwrap();
    second_server.join().unwrap();
    assert!(
        !state
            .path()
            .join(provider_attestation_set_checkpoint_relative_path(
                operation, 1
            ))
            .exists()
    );
    assert_eq!(
        unused.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let MusubiStorageLocationDispositionV1::NeedsRegistration {
        completed_providers,
        ..
    } = &mut fixture.response.disposition
    else {
        unreachable!()
    };
    completed_providers[2] = ProviderId::new([0xff; 32]);
    assert!(
        fixture
            .runtime
            .acquire_provider_attestation_set(
                operation,
                1,
                &fixture.request,
                &fixture.response,
                None
            )
            .is_err()
    );
    assert_eq!(
        unused.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn publisher_inventory_rejects_every_signed_original_binding_substitution() {
    let fixture = rebase_fixture();
    provider_inventory::validate_original_attestations(
        &fixture.request,
        &fixture.response,
        &fixture.attestations,
    )
    .unwrap();
    for case in 0..9 {
        let mut originals = fixture.attestations.clone();
        let binding = &mut originals[0].payload.binding;
        match case {
            0 => binding.network_id = test_network_id(0xdd),
            1 => binding.archive_id = ArchiveId::new([0xdd; 32]),
            2 => binding.replication_order = ReplicationOrderId::new([0xdd; 32]),
            3 => binding.provider_id = ProviderId::new([0xdd; 32]),
            4 => binding.bundle_digest = MusubiContentDigestV1::new([0xdd; 32]),
            5 => binding.descriptor_digest = MusubiContentDigestV1::new([0xdd; 32]),
            6 => binding.source_tree_digest = MusubiContentDigestV1::new([0xdd; 32]),
            7 => {
                binding.semantic_release_manifest_digest =
                    iroha_data_model::musubi::MusubiSemanticReleaseDigestV1::new([0xdd; 32])
            }
            8 => {
                binding.verification_lock_digest =
                    iroha_data_model::musubi::MusubiVerificationLockDigestV1::new([0xdd; 32])
            }
            _ => unreachable!(),
        }
        let key = KeyPair::try_from_seed(vec![0x88; 32], Algorithm::Ed25519).unwrap();
        originals[0].approvals[0].signature =
            SignatureOf::try_from_hash(key.private_key(), originals[0].payload.signing_hash())
                .unwrap();
        originals[0].verify(&originals[0].payload.binding).unwrap();
        assert!(
            provider_inventory::validate_original_attestations(
                &fixture.request,
                &fixture.response,
                &originals
            )
            .is_err(),
            "binding {case}"
        );
    }
    let mut reordered = fixture.attestations.clone();
    reordered.reverse();
    assert!(
        provider_inventory::validate_original_attestations(
            &fixture.request,
            &fixture.response,
            &reordered
        )
        .is_err()
    );
}

#[test]
fn retired_daemon_inventory_controls_use_the_sole_publisher_selection_owner() {
    use provider_inventory::parse_attestation_origin;
    let original = parse_attestation_origin("http://127.0.0.1:8182/").unwrap();
    assert_eq!(original.port(), Some(8182));
    assert_eq!(
        parse_attestation_origin("https://provider.example:9443/")
            .unwrap()
            .port(),
        Some(9443)
    );
    for raw in [
        "http://provider.example/",
        "http://localhost/",
        "http://10.0.0.1/",
        "https://provider.example:0/",
        "https://user:secret@provider.example/",
        "https://provider.example/other",
        "https://provider.example/?q=1",
        "https://provider.example/#f",
    ] {
        assert!(parse_attestation_origin(raw).is_err(), "{raw}");
    }
    let root = tempdir().unwrap();
    let (_, mut config) = write_client_config(&root.path().join("client.toml"), "");
    assert_eq!(
        parse_provider_gateways(&config.provider_gateways)
            .unwrap()
            .len(),
        3
    );
    let selected = config.provider_gateways[2].provider_id.clone();
    config.provider_gateways[2].provider_id = config.provider_gateways[0].provider_id.clone();
    assert!(parse_provider_gateways(&config.provider_gateways).is_err());
    config.provider_gateways[2].provider_id = "00".repeat(32);
    assert!(parse_provider_gateways(&config.provider_gateways).is_err());
    config.provider_gateways[2].provider_id = selected;
    assert_eq!(
        parse_provider_gateways(&config.provider_gateways)
            .unwrap()
            .len(),
        3
    );
}
