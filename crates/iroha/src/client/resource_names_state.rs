//! Canonical signed provider transport for complete native resource-name originals.

use super::*;
use iroha_torii_shared::resource_names_state::{
    NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1, NATIVE_RESOURCE_NAMES_STATE_ROUTE_PREFIX_V1,
    NativeResourceNamesStateV1,
};

impl Client {
    /// Fetch canonical complete native alias/SNS wire using this client's exact account signer.
    ///
    /// Torii requires that account's existing native `CanReadAllLedgerData` permission;
    /// owning an API token or an ordinary query signer does not establish that grant.
    /// The configured provider path prefix is preserved in the signed final GET URI.
    /// The fresh challenge is signed in that URI and echoed in the singleton
    /// finality header. Owner-held listener credentials and the bounded no-redirect
    /// transport come from this client's admitted context. This is unverified data:
    /// consumers must still authenticate four current independently selected native
    /// statements, the exact complete World cut and the independent release catalog.
    ///
    /// # Errors
    /// Zero challenge, failed canonical signing/transport, denied read root, non-success,
    /// wrong media type, oversized/noncanonical wire, changed network or challenge.
    pub fn get_native_resource_names_state_wire(&self, challenge: [u8; 32]) -> Result<Vec<u8>> {
        if challenge == [0; 32] {
            return Err(eyre!("native resource names challenge must be nonzero"));
        }
        if self.torii_url.scheme() != "https"
            || !self.torii_url.path().ends_with('/')
            || self.torii_url.query().is_some()
            || self.torii_url.fragment().is_some()
            || !self.torii_url.username().is_empty()
            || self.torii_url.password().is_some()
        {
            return Err(eyre!(
                "native private resource names provider requires a canonical HTTPS root ending in a slash"
            ));
        }
        let mut names = std::collections::HashSet::new();
        for name in self.headers.keys() {
            if !names.insert(name.to_ascii_lowercase()) {
                return Err(eyre!(
                    "native private resource names provider rejects duplicate default headers"
                ));
            }
            if ![
                "x-api-token",
                "x-dataspace-id",
                "user-agent",
                "accept",
                "content-type",
                "cache-control",
            ]
            .iter()
            .any(|allowed| name.eq_ignore_ascii_case(allowed))
            {
                return Err(eyre!(
                    "native private resource names provider rejects non-native default credential/header context"
                ));
            }
        }
        let challenge_hex = hex::encode(challenge);
        let path = format!("{NATIVE_RESOURCE_NAMES_STATE_ROUTE_PREFIX_V1}{challenge_hex}");
        let url = join_torii_url(&self.torii_url, &path);
        let mut native_client = self.clone();
        native_client.headers.retain(|name, _| {
            !name.eq_ignore_ascii_case("accept") && !name.eq_ignore_ascii_case("content-type")
        });
        let response = native_client.send_builder(
            native_client
                .account_signed_request(HttpMethod::GET, url, Vec::new())?
                .header("Accept", APPLICATION_NORITO)
                .header("X-Iroha-Finality-Challenge", &challenge_hex)
                .max_response_bytes(NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1),
        )?;
        // Never follow a non-success carrier or reinterpret an HTTP error as absence.
        if response.status() != StatusCode::OK {
            // Private provider bodies and any echoed credentials never enter an error/log.
            return Err(eyre!(
                "native resource names read returned HTTP {}",
                response.status()
            ));
        }
        let media_type = Self::response_content_type(&response)
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if !media_type.eq_ignore_ascii_case(APPLICATION_NORITO) {
            return Err(eyre!(
                "native resource names response requires canonical Norito content type"
            ));
        }
        let wire = response.into_body();
        if wire.is_empty() || wire.len() > NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1 {
            return Err(eyre!("native resource names response exceeds reader bound"));
        }
        let original: NativeResourceNamesStateV1 = norito::decode_canonical_with_limits(
            &wire,
            norito::canonical_decode_limits(wire.len()),
        )
        .map_err(|_| eyre!("native resource names response is not exact bounded canonical data"))?;
        if original.attestation.body.network_id != self.network_id
            || original.attestation.body.challenge != challenge
        {
            return Err(eyre!(
                "native resource names response changed exact network or fresh signed challenge"
            ));
        }
        // Structural/node signature checking grants no installed-node or finality authority.
        original.attestation.verify().map_err(|_| {
            eyre!("native resource names node statement has invalid structure/signature")
        })?;
        Ok(wire)
    }
}

#[cfg(test)]
mod tests {
    use super::super::evidence_http_tests::{capture_requests, client_with_base_url};
    use super::super::tests::assert_canonical_account_signed_request;
    use super::*;

    #[test]
    fn native_names_provider_dispatches_exact_signed_get_with_fresh_uri_challenge() {
        let client = client_with_base_url(Url::parse("https://mock.local/").unwrap());
        let response = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(b"private-sentinel-never-log".to_vec())
            .unwrap();
        let (result, snapshots) = capture_requests(response, |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .get_native_resource_names_state_wire([0xab; 32])
        });
        assert!(!format!("{:#}", result.unwrap_err()).contains("private-sentinel-never-log"));
        assert_eq!(snapshots.len(), 1);
        let request = &snapshots[0];
        assert_eq!(request.method, HttpMethod::GET);
        assert_eq!(
            request.url.path(),
            format!(
                "{NATIVE_RESOURCE_NAMES_STATE_ROUTE_PREFIX_V1}{}",
                "ab".repeat(32)
            )
        );
        assert!(request.url.query().is_none());
        assert!(request.body.is_empty());
        assert_eq!(
            request.max_response_bytes,
            NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1
        );
        let headers = request
            .headers
            .iter()
            .map(|(key, value)| (key.to_ascii_lowercase(), value))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            headers.get("x-iroha-finality-challenge").unwrap().as_str(),
            "ab".repeat(32)
        );
        assert_canonical_account_signed_request(&client, request);
        let mut changed = request.clone();
        changed.url.set_path(&format!(
            "{NATIVE_RESOURCE_NAMES_STATE_ROUTE_PREFIX_V1}{}",
            "ac".repeat(32)
        ));
        let timestamp: u64 = headers
            .get("x-iroha-timestamp-ms")
            .unwrap()
            .parse()
            .unwrap();
        let nonce = headers.get("x-iroha-nonce").unwrap();
        let message = Client::exact_network_request_message(
            &client.network_id,
            &changed.method,
            &changed.url,
            &[],
            timestamp,
            nonce,
        )
        .unwrap();
        let signature = base64::engine::general_purpose::STANDARD
            .decode(headers.get("x-iroha-signature").unwrap())
            .unwrap();
        assert!(
            iroha_crypto::Signature::from_bytes(&signature)
                .verify(client.key_pair.public_key(), &message)
                .is_err()
        );
    }
    #[test]
    fn native_names_provider_preserves_exact_peer_prefix_in_signed_get() {
        for prefix in [
            "native-peer-2/",
            "native-peer-3/",
            "native-peer-4/",
            "private/nested/",
        ] {
            let client =
                client_with_base_url(Url::parse(&format!("https://mock.local/{prefix}")).unwrap());
            let response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Vec::new())
                .unwrap();
            let (result, snapshots) = capture_requests(response, |transport| {
                client
                    .clone()
                    .with_test_http_transport(transport)
                    .get_native_resource_names_state_wire([0xab; 32])
            });
            assert!(result.is_err());
            assert_eq!(snapshots.len(), 1);
            let request = &snapshots[0];
            let suffix = format!(
                "{NATIVE_RESOURCE_NAMES_STATE_ROUTE_PREFIX_V1}{}",
                "ab".repeat(32)
            );
            assert_eq!(
                request.url.path(),
                format!("/{prefix}{}", suffix.trim_start_matches('/'))
            );
            assert!(request.url.query().is_none());
            assert_canonical_account_signed_request(&client, request);
            let headers = request
                .headers
                .iter()
                .map(|(key, value)| (key.to_ascii_lowercase(), value))
                .collect::<std::collections::HashMap<_, _>>();
            let mut stripped = request.url.clone();
            stripped.set_path(&suffix);
            let message = Client::exact_network_request_message(
                &client.network_id,
                &request.method,
                &stripped,
                &[],
                headers["x-iroha-timestamp-ms"].parse::<u64>().unwrap(),
                headers["x-iroha-nonce"],
            )
            .unwrap();
            let signature = base64::engine::general_purpose::STANDARD
                .decode(headers["x-iroha-signature"])
                .unwrap();
            assert!(
                iroha_crypto::Signature::from_bytes(&signature)
                    .verify(client.key_pair.public_key(), &message)
                    .is_err()
            );
        }
    }
    #[test]
    fn native_names_provider_rejects_fi_bearer_and_cleartext_before_dispatch() {
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Vec::new())
            .unwrap();
        let mut client = client_with_base_url(Url::parse("https://mock.local/").unwrap());
        client.headers.insert(
            "Authorization".into(),
            "Bearer synthetic-fi-application-credential".into(),
        );
        let (result, snapshots) = capture_requests(response.clone(), |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .get_native_resource_names_state_wire([1; 32])
        });
        let error = format!("{:#}", result.unwrap_err());
        assert!(!error.contains("synthetic-fi-application-credential"));
        assert!(snapshots.is_empty());
        let client = client_with_base_url(Url::parse("http://mock.local/").unwrap());
        let (result, snapshots) = capture_requests(response, |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .get_native_resource_names_state_wire([1; 32])
        });
        assert!(result.is_err());
        assert!(snapshots.is_empty());
    }
    #[test]
    fn native_names_provider_zero_challenge_never_reaches_transport() {
        let client = client_with_base_url(Url::parse("https://mock.local/").unwrap());
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Vec::new())
            .unwrap();
        let (result, snapshots) = capture_requests(response, |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .get_native_resource_names_state_wire([0; 32])
        });
        assert!(result.is_err());
        assert!(snapshots.is_empty());
    }
    #[test]
    fn native_names_provider_rejects_redirect_and_noncanonical_success_body() {
        let client = client_with_base_url(Url::parse("https://mock.local/").unwrap());
        for status in [StatusCode::TEMPORARY_REDIRECT, StatusCode::OK] {
            let response = Response::builder()
                .status(status)
                .header("Content-Type", APPLICATION_NORITO)
                .body(vec![0, 1, 2])
                .unwrap();
            let (result, snapshots) = capture_requests(response, |transport| {
                client
                    .clone()
                    .with_test_http_transport(transport)
                    .get_native_resource_names_state_wire([1; 32])
            });
            assert!(result.is_err());
            assert_eq!(snapshots.len(), 1);
        }
    }
    #[test]
    fn native_names_provider_preserves_admitted_listener_token_and_normalizes_accept() {
        let fixture = client_with_base_url(Url::parse("https://mock.local/").unwrap());
        let token = "synthetic-native-listener-token";
        let config = Config {
            chain: fixture.chain.clone(),
            network_id: fixture.network_id,
            key_pair: fixture.key_pair.clone(),
            account: fixture.account.clone(),
            account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
            torii_api_url: fixture.torii_url.clone(),
            torii_request_timeout: crate::config::DEFAULT_TORII_REQUEST_TIMEOUT,
            basic_auth: None,
            api_token: Some(crate::secrecy::SecretString::new(token.to_owned())),
            transaction_add_nonce: false,
            transaction_ttl: std::time::Duration::from_secs(5),
            transaction_status_timeout: std::time::Duration::from_secs(10),
            sorafs_alias_cache: default_alias_policy(),
            sorafs_anonymity_policy: AnonymityPolicy::GuardPq,
            sorafs_rollout_phase: RolloutPhase::Canary,
        };
        let mut client = Client::builder(config).build().unwrap();
        client
            .headers
            .insert("AcCePt".into(), APPLICATION_JSON.into());
        client
            .headers
            .insert("CONTENT-TYPE".into(), APPLICATION_JSON.into());
        let response = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Vec::new())
            .unwrap();
        let (result, snapshots) = capture_requests(response, |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .get_native_resource_names_state_wire([2; 32])
        });
        assert!(result.is_err());
        assert_eq!(snapshots.len(), 1);
        let headers = &snapshots[0].headers;
        let only = |name: &str| {
            headers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(only("x-api-token"), vec![token]);
        assert_eq!(only("accept"), vec![APPLICATION_NORITO]);
        assert!(only("content-type").is_empty());
        assert_eq!(
            only("x-iroha-finality-challenge"),
            vec!["02".repeat(32).as_str()]
        );
    }
    #[test]
    fn native_names_provider_rejects_incomplete_root_and_foreign_or_duplicate_headers() {
        for root in [
            "https://mock.local/peer1",
            "https://mock.local/?query=1",
            "https://mock.local/#fragment",
            "https://user:secret@mock.local/",
        ] {
            let client = client_with_base_url(Url::parse("https://mock.local/").unwrap());
            let target = Url::parse(root).unwrap();
            let response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Vec::new())
                .unwrap();
            let (result, snapshots) = capture_requests(response, |transport| {
                let mut configured = client.clone().with_test_http_transport(transport);
                configured.torii_url = target;
                configured.get_native_resource_names_state_wire([3; 32])
            });
            assert!(result.is_err());
            assert!(snapshots.is_empty());
        }
        for additions in [
            vec![("Proxy-Authorization", "secret")],
            vec![("Cookie", "secret")],
            vec![("X-Iroha-Finality-Challenge", "00")],
            vec![("Accept", "a"), ("accept", "b")],
            vec![("x-api-token", "a"), ("X-API-TOKEN", "b")],
        ] {
            let client = client_with_base_url(Url::parse("https://mock.local/").unwrap());
            let response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Vec::new())
                .unwrap();
            let (result, snapshots) = capture_requests(response, |transport| {
                let mut configured = client.clone().with_test_http_transport(transport);
                for (key, value) in additions {
                    configured.headers.insert(key.into(), value.into());
                }
                configured.get_native_resource_names_state_wire([3; 32])
            });
            assert!(result.is_err());
            assert!(snapshots.is_empty());
        }
    }
    #[test]
    fn native_names_provider_returns_exact_canonical_signed_native_wire_without_admitting_authority()
     {
        use iroha_crypto::{Algorithm, Hash, KeyPair, SignatureOf};
        use iroha_data_model::{
            sumeragi::SumeragiStatus,
            sumeragi_finality::{
                SumeragiFinalityAttestation, SumeragiFinalityAttestationBody, WorldStateSnapshotV1,
                test_fixtures::NativeFinalityFixture,
            },
        };
        use iroha_model_base::peer::PeerId;
        use norito::codec::Encode as _;
        // Genuine native certificate/signature mechanics over deliberately synthetic
        // wire-only World data. Neither the mock HTTP response nor this schema grants
        // installed-node, completeness, full-read permission or release authority.
        let snapshot = WorldStateSnapshotV1 {
            schema_hash: Hash::new(b"SDK HTTP fixture unqualified World schema"),
            entries: Vec::new(),
        };
        let mut native = NativeFinalityFixture::start("SDK native names canonical HTTP fixture");
        let block = native.block_with_submitted_work(native.next_header());
        let proof = native.certify_with_world_root(block, snapshot.root().unwrap());
        let verified = native
            .verifier()
            .verify_retained_decision(native.latest())
            .unwrap();
        snapshot.authenticate(&verified).unwrap();
        let node = KeyPair::from_seed(vec![0x57; 32], Algorithm::BlsNormal);
        let node_id = PeerId::new(node.public_key().clone());
        let config = Hash::new(b"explicitly synthetic node HTTP fixture configuration");
        let body = SumeragiFinalityAttestationBody {
            observed_at_unix_ms: 1_000_000,
            challenge: [0x58; 32],
            network_id: native.network_id(),
            node_fingerprint: Hash::new(node_id.encode()),
            node_id,
            build_fingerprint: Hash::new(b"unqualified SDK transport fixture build"),
            config_fingerprint: config,
            genesis_block_hash: native.genesis().hash(),
            genesis_finality_proof: native.genesis_proof().clone(),
            status: SumeragiStatus {
                protocol_version: 1,
                config_fingerprint: config,
                beacon_horizon: None,
                instance: native.verifier().instance().0,
                height: 3,
                view: 0,
                stage: 0,
                leader: None,
                proxy_tail: None,
                high_qc_view: None,
                level: 0,
                start_level: 0,
                t_retx_ms: 100,
                committed_height: 2,
                applied_height: 2,
                awaiting: false,
                signer: Some(node.public_key().clone()),
                unanchored: false,
                abstaining: false,
                halted: None,
                footprint: iroha_data_model::sumeragi::SumeragiFootprint::default(),
            },
            finality_proof: proof,
        };
        let attestation = SumeragiFinalityAttestation {
            signature: SignatureOf::try_from_hash(node.private_key(), body.signing_hash()).unwrap(),
            body,
        };
        attestation.verify().unwrap();
        let original = NativeResourceNamesStateV1 {
            attestation,
            world_snapshot: snapshot,
            asset_alias_bindings: Vec::new(),
            smart_contract_keys: Vec::new(),
            dataspace_names: Vec::new(),
        };
        let wire = norito::encode_canonical(&original).unwrap();
        let mut client = client_with_base_url(Url::parse("https://mock.local/").unwrap());
        let other_network = client.network_id;
        assert_ne!(other_network, native.network_id());
        client.network_id = native.network_id();
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", APPLICATION_NORITO)
            .body(wire.clone())
            .unwrap();
        let (result, snapshots) = capture_requests(response.clone(), |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .get_native_resource_names_state_wire([0x58; 32])
        });
        let returned: Vec<u8> = result.unwrap();
        assert_eq!(returned, wire);
        assert_eq!(snapshots.len(), 1);
        assert_canonical_account_signed_request(&client, &snapshots[0]);
        // Valid node-signed carrier is still tied to this exact fresh request.
        let (result, snapshots) = capture_requests(response.clone(), |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .get_native_resource_names_state_wire([0x59; 32])
        });
        assert!(result.is_err());
        assert_eq!(snapshots.len(), 1);
        client.network_id = other_network;
        let (result, snapshots) = capture_requests(response, |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .get_native_resource_names_state_wire([0x58; 32])
        });
        assert!(result.is_err());
        assert_eq!(snapshots.len(), 1);
    }
}
