//! SDK provenance, raw-source admission and independent finality-placement regressions.

use super::*;
use crate::verify::http::HttpFinalitySource;
use iroha::{
    client::Client,
    config::Config,
    http::{HttpTransport, Response, TransportFuture, TransportRequest},
};
use std::sync::Mutex;

#[derive(Debug)]
struct StatementTransport {
    statement: SumeragiFinalityAttestation,
    requests: Mutex<Vec<String>>,
}

impl HttpTransport for StatementTransport {
    fn send_blocking(
        &self,
        request: TransportRequest,
    ) -> color_eyre::eyre::Result<Response<Vec<u8>>> {
        assert_eq!(request.method, iroha::http::Method::GET);
        assert!(request.body.is_empty());
        assert!(request.timeout.is_some());
        let path = request.url.path().to_owned();
        self.requests.lock().unwrap().push(path.clone());
        let (media, body) = if path == "/v1/node/capabilities" {
            (
                "application/json",
                norito::json::to_vec(&norito::json!({
                    "data_model_version": (iroha_data_model::DATA_MODEL_VERSION),
                    "signed_transaction_schema_hash_hex":
                        (hex::encode(norito::schema::identity::frame_hash::<iroha_data_model::transaction::SignedTransaction>()))
                }))?,
            )
        } else {
            assert_eq!(
                path,
                format!(
                    "/v1/bridge/finality/attestation/{}",
                    self.statement.body.status.committed_height
                )
            );
            let challenges = request
                .headers
                .iter()
                .filter(|(name, _)| name.as_str() == "x-iroha-finality-challenge")
                .map(|(_, value)| value.to_str().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(challenges, vec![hex::encode(self.statement.body.challenge)]);
            (
                "application/x-norito",
                norito::encode_canonical(&self.statement)?,
            )
        };
        assert!(body.len() <= request.max_response_bytes);
        Ok(Response::builder()
            .header("content-type", media)
            .body(body)?)
    }

    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}

// Only real SDK response admission can produce the opaque carrier, even with an injected
// transport. The native adapter does not construct one from the fixture's raw DTO itself.
fn native_read(statement: SumeragiFinalityAttestation) -> FinalityAttestation {
    let network = statement.body.network_id;
    let identity = statement.body.node_id.clone();
    let height = nz(statement.body.status.committed_height);
    let challenge = statement.body.challenge;
    let transport = Arc::new(StatementTransport {
        statement,
        requests: Mutex::new(Vec::new()),
    });
    let key = KeyPair::from_seed(vec![83; 32], Algorithm::Ed25519);
    let table = toml::toml! {
        chain = CHAIN
        network_id = (network.to_string())
        torii_url = "http://127.0.0.1:18080/"
        [account]
        chain_discriminant = 753
        public_key = (key.public_key().to_string())
        private_key = (iroha_crypto::ExposedPrivateKey(key.private_key().clone()).to_string())
    };
    let client = Client::builder(Config::load_table("carrier-tests.toml", table).unwrap())
        .http_transport(transport.clone())
        .build()
        .unwrap();
    let source = HttpFinalitySource::new(
        network,
        height,
        vec![client.clone()],
        vec![(identity.clone(), client)],
        std::time::Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    let mut reads = source.latest_attestations(&[identity], &challenge);
    assert_eq!(reads.len(), 1);
    let read = reads.pop().unwrap().unwrap();
    assert!(matches!(&read, FinalityAttestation::Authenticated(_)));
    assert_eq!(
        *transport.requests.lock().unwrap(),
        vec![
            "/v1/node/capabilities".to_owned(),
            format!("/v1/bridge/finality/attestation/{height}"),
        ]
    );
    read
}

#[test]
fn authenticated_carrier_rechecks_the_observations_exact_bindings() {
    let chain = Chain::constant(4, 1);
    let statement = chain.attest(&chain.epoch(1).keys[0], 1);
    let identity = statement.body.node_id.clone();
    let network = chain.anchor.network_id;
    assert!(matches!(
        Read::new(
            Ok(native_read(statement.clone())),
            &identity,
            &CHALLENGE,
            network
        ),
        Read::Claim(_)
    ));
    for challenge in [[0; 32], [8; 32]] {
        let Read::Invalid(error) = Read::new(
            Ok(native_read(statement.clone())),
            &identity,
            &challenge,
            network,
        ) else {
            panic!("an authenticated carrier cannot change its observation challenge")
        };
        assert!(matches!(
            *error,
            FinalityError::ZeroChallenge | FinalityError::StaleChallenge
        ));
    }
    let foreign = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign carrier consumer",
    )));
    let Read::Invalid(error) = Read::new(
        Ok(native_read(statement.clone())),
        &identity,
        &CHALLENGE,
        foreign,
    ) else {
        panic!("an authenticated carrier cannot change its observation network")
    };
    assert!(
        matches!(*error, FinalityError::WrongNetwork { expected, actual } if expected == foreign && actual == network)
    );
    let other = peer(&chain.epoch(1).keys[1]);
    let Read::Substituted(actual) =
        Read::new(Ok(native_read(statement)), &other, &CHALLENGE, network)
    else {
        panic!("an authenticated carrier cannot substitute another selected peer")
    };
    assert_eq!(*actual, identity);
}

#[test]
fn raw_conversion_and_default_batch_cannot_forge_sdk_provenance() {
    let chain = Chain::constant(4, 1);
    let key = &chain.epoch(1).keys[0];
    let identity = peer(key);
    for mutation in 0..2 {
        let mut source = Source::new(&chain);
        let mut statement = chain.attest(key, 1);
        if mutation == 0 {
            statement.body.config_fingerprint =
                Hash::new(b"unsigned substitution after raw conversion");
        } else {
            statement.body.status.applied_height = 0;
            resign(&mut statement, key);
        }
        source
            .attestation_overrides
            .insert(identity.clone(), statement);
        let mut reads = source.latest_attestations(std::slice::from_ref(&identity), &CHALLENGE);
        let raw = reads.pop().unwrap().unwrap();
        assert!(matches!(&raw, FinalityAttestation::Raw(_)));
        let Read::Invalid(error) =
            Read::new(Ok(raw), &identity, &CHALLENGE, chain.anchor.network_id)
        else {
            panic!("default raw-source adapter must fully authenticate structure and signature")
        };
        assert!(matches!(*error, FinalityError::Native(_)));
    }
}

#[test]
fn consuming_sdk_provenance_cannot_authenticate_a_mutated_raw_statement() {
    let chain = Chain::constant(4, 1);
    let statement = chain.attest(&chain.epoch(1).keys[0], 1);
    let identity = statement.body.node_id.clone();
    let FinalityAttestation::Authenticated(authenticated) = native_read(statement.clone()) else {
        unreachable!()
    };
    assert_eq!(authenticated.attestation(), &statement);
    let mut raw = authenticated.into_attestation();
    raw.body.build_fingerprint = Hash::new(b"changed after discarding SDK provenance");
    assert!(matches!(
        Read::new(
            Ok(raw.into()),
            &identity,
            &CHALLENGE,
            chain.anchor.network_id
        ),
        Read::Invalid(_)
    ));
}

#[test]
fn sdk_authenticated_conflicting_decision_still_fails_trusted_prefix_placement() {
    let chain = Chain::constant(4, 3);
    let verifier = chain.verifier_at(3);
    let prefix = Prefix::new(verifier.checkpoint()).unwrap();
    let member = &chain.epoch(3).keys[0];
    let identity = peer(member);
    let statement = chain.attest(member, 3);
    let Read::Claim(valid) = Read::new(
        Ok(native_read(statement)),
        &identity,
        &CHALLENGE,
        chain.anchor.network_id,
    ) else {
        panic!("original SDK-authenticated statement must be admitted")
    };
    let epoch = prefix
        .verified
        .commitment()
        .schedule
        .current
        .authorization
        .epoch;
    prefix
        .place(&valid.body.finality_proof, epoch, None)
        .unwrap();

    let mut proof = chain.proof(3).clone();
    let header = core(&proof);
    let mut commitment = result(&proof);
    commitment.execution.parent_state_root = Hash::new(b"conflicting certified execution");
    let mut qc = commit_qc(&proof);
    qc.result = commitment.result().unwrap();
    sign_qc(&mut qc, &chain.epoch(3).keys, &[0, 1, 2]);
    replace_certificate(&mut proof, &header, &qc, &commitment);
    let mut conflict = chain.attest(member, 3);
    conflict.body.finality_proof = proof;
    resign(&mut conflict, member);
    let Read::Claim(conflict) = Read::new(
        Ok(native_read(conflict)),
        &identity,
        &CHALLENGE,
        chain.anchor.network_id,
    ) else {
        panic!("SDK authentication intentionally does not select a trusted chain")
    };
    assert!(
        prefix
            .place(&conflict.body.finality_proof, epoch, None)
            .is_err()
    );
}

#[test]
fn sdk_authenticated_outsider_cannot_count_as_a_selected_committee_member() {
    struct Outsider<'a>(&'a Chain);
    impl FinalitySource for Outsider<'_> {
        type Error = std::io::Error;
        fn finality_proof(&self, height: NonZeroU64) -> Result<SumeragiFinalityProof, Self::Error> {
            Ok(self.0.proof(height.get()).clone())
        }
        fn latest_attestation(
            &self,
            _: &PeerId,
            challenge: &[u8; 32],
        ) -> Result<FinalityAttestation, Self::Error> {
            assert_eq!(challenge, &CHALLENGE);
            // A custom source may forward a real authenticated carrier for another reader.
            // It cannot turn that selected outsider into any member requested by observe().
            Ok(native_read(self.0.attest(&key(100), 1)))
        }
    }
    let chain = Chain::constant(4, 1);
    let mut verifier = chain.verifier();
    let before = verifier.checkpoint().clone();
    let Err(FinalityError::InsufficientAttestations(quorum)) =
        verifier.observe(&Outsider(&chain), &CHALLENGE)
    else {
        panic!("SDK node authentication must never mint committee membership")
    };
    assert_eq!(quorum.verified(), 0);
    assert!(quorum.peers.iter().all(|(_, outcome)| matches!(
        outcome,
        AttestationOutcome::Rejected(FinalityError::UnexpectedPeer { .. })
    )));
    assert_eq!(verifier.checkpoint(), &before);
}
