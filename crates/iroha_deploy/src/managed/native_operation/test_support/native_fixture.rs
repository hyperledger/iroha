//! Sole generated-genesis execution fixture and actual native fee/funding HTTP reader.
//! Exact original validator custody signs component certificates; no four-process consensus
//! or full coordinator HTTP success is inferred. Ordinary stacks remain unchanged.

use crate::{
    genesis::staging::{
        configured_initial_genesis_state, ensure_peer_config_matches_manifest,
        staged_genesis_chain_discriminant,
    },
    managed::{
        PreparedLocalnet,
        native_operation::{
            now_ms,
            test_support::wallet_http::{WalletHttpRequest, wallet_request},
        },
        service_authority::ServiceAuthority,
    },
    verify::finality::{FinalitySource, FinalityVerifier},
};
use iroha::config::Config;
use iroha_core::{
    smartcontracts::{
        ValidSingularQuery,
        isi::query::{QueryLimits, validate_fresh_query_for_client_world_parts},
    },
    state::{AllocationBudget, State, StateReadOnly},
    sumeragi::{
        finality::{FinalityProofReader, build_attestation, build_proof, with_proof_reader},
        lanes::merge::NoLanes,
        node::NodeIdentity,
        test_chain::{CertifiedTestChain, PreparedTestChainConfig},
    },
};
use iroha_crypto::{Hash, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    isi::InstructionBox,
    query::{
        QueryRequest, QueryResponse, SignedQuery, SingularQueryBox, SingularQueryOutputBox,
        asset::FindAssetById,
    },
    sorafs::{
        capacity::ProviderId,
        reserve::{
            RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveAuthorityPolicyV1, ReservePolicyV1,
            account_proof::{ReserveAccountProofRefV1, ReserveAccountProofV1},
            proof::{ReservePolicyProofRefV1, ReservePolicyProofV1},
        },
    },
    sumeragi::{SumeragiFootprint, SumeragiStatus},
    sumeragi_finality::SumeragiFinalityProof,
    transaction::{
        FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionDomain,
        TransactionPayload,
    },
};
use iroha_fs::PrivateDirectory;
use iroha_genesis::{GenesisBlock, RawGenesisTransaction};
use iroha_model_base::{peer::PeerId, topology::DataSpaceId};
use iroha_primitives::numeric::Quantity;
use iroha_torii_shared::{
    FeeQuoteCapacity, FeeQuoteComponent, FeeQuoteDecision, FeeQuoteObservation, FeeQuoteRequest,
    FeeQuoteResponse,
};
use iroha_version::codec::DecodeVersioned as _;
use sorafs_manifest::deal::XorQuantity;
use std::{
    cell::RefCell,
    io::{self, Write as _},
    net::{Ipv4Addr, TcpListener},
    num::NonZeroU64,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub(in crate::managed) struct NativeFixture {
    pub(in crate::managed) chain: CertifiedTestChain,
    validators: Vec<(KeyPair, Hash)>,
}
// Exact prepared inputs cross the phase boundary; parsed configuration temporaries do not.
struct PreparedNativeFixture {
    chain: PreparedTestChainConfig,
    validators: Vec<(KeyPair, Hash)>,
    signed: zeroize::Zeroizing<Vec<u8>>,
    _discriminant: iroha_data_model::account::address::ChainDiscriminantGuard,
    _root: PrivateDirectory,
}

impl NativeFixture {
    pub(in crate::managed) fn from_generated(
        prepared: &PreparedLocalnet,
        authority: &ServiceAuthority,
    ) -> Self {
        let prepared = Self::prepare_generated(prepared, authority);
        let chain = CertifiedTestChain::from_prepared(prepared.chain).unwrap();
        assert_eq!(
            chain.genesis().encode_wire().unwrap().as_slice(),
            prepared.signed.as_slice()
        );
        assert_eq!(chain.network_id(), authority.config.network_id);
        assert_eq!(chain.state().chain_id_ref(), &authority.config.chain);
        assert!(
            !chain
                .state()
                .view()
                .nexus()
                .fees
                .per_instruction_fee
                .is_zero(),
            "retain the actual charged generated policy"
        );
        Self {
            chain,
            validators: prepared.validators,
        }
    }
    // End canonical configuration/state preparation before genesis executes. The returned
    // owner retains every chain input and the original directory custody across that execution.
    #[inline(never)]
    fn prepare_generated(
        prepared: &PreparedLocalnet,
        authority: &ServiceAuthority,
    ) -> PreparedNativeFixture {
        let root =
            PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
        let manifest_bytes = root
            .read(
                "genesis.json",
                iroha_genesis::GENESIS_MANIFEST_JSON_MAX_BYTES_V1,
            )
            .unwrap();
        iroha_genesis::validate_genesis_manifest_json(&manifest_bytes).unwrap();
        let manifest = RawGenesisTransaction::from_json_slice_at_path(
            &manifest_bytes,
            root.path().join("genesis.json"),
        )
        .unwrap();
        let _discriminant = staged_genesis_chain_discriminant(&manifest);
        let signed = root
            .read(
                "genesis.signed.nrt",
                iroha_genesis::SIGNED_GENESIS_MAX_BYTES_V1,
            )
            .unwrap();
        let mut peers = Vec::new();
        let mut selected_config = None;
        for (index, peer) in prepared.peers.iter().enumerate() {
            let bytes = iroha_fs::read_private(&peer.config_path, 1024 * 1024).unwrap();
            let table = crate::secret_toml::parse_table(
                std::str::from_utf8(&bytes).unwrap(),
                "native reserve fixture peer",
            )
            .unwrap();
            let reader = iroha_config::node_config::open_node_config(
                iroha_config::node_config::NodeFile::Verified {
                    path: peer.config_path.clone(),
                    table,
                },
                iroha_config::node_config::NodeConfigOptions::default(),
            )
            .unwrap();
            let (user, _) = reader.read().unwrap();
            let config = user.parse().unwrap();
            ensure_peer_config_matches_manifest(&config, &manifest).unwrap();
            assert_eq!(
                config.genesis.expected_hash,
                authority.genesis.genesis.hash()
            );
            let node = root
                .open_child("nodes")
                .unwrap()
                .open_child(format!("peer{index}"))
                .unwrap();
            node.revalidate().unwrap();
            peers.push((config.common.key_pair.clone(), Hash::new(bytes.as_slice())));
            if selected_config.is_none() {
                selected_config = Some(config);
            }
        }
        peers.sort_by_key(|(key, _)| PeerId::new(key.public_key().clone()));
        let config = selected_config.unwrap();
        let genesis = iroha_genesis::validate_prepared_genesis_bundle(
            &signed,
            &manifest,
            &config.genesis.public_key,
            config.genesis.expected_hash,
        )
        .unwrap();
        assert_eq!(genesis.canonical_wire(), signed.as_slice());
        let (state, kura, _) = configured_initial_genesis_state(
            &manifest,
            Some(&config),
            &GenesisBlock(genesis.block().clone()),
        )
        .unwrap();
        let validators = peers
            .iter()
            .map(|(key, fingerprint)| (key.clone(), *fingerprint))
            .collect();
        let keys = peers.into_iter().map(|(key, _)| key).collect();
        let chain = PreparedTestChainConfig {
            genesis,
            manifest,
            state: Arc::new(state),
            kura,
            validator_keys: keys,
            clock: authority.config.key_pair.clone(),
            lane_blocks: Arc::new(NoLanes),
        };
        PreparedNativeFixture {
            chain,
            validators,
            signed,
            _discriminant,
            _root: root,
        }
    }
    pub(in crate::managed) fn observe(&self, authority: &ServiceAuthority) -> FinalityVerifier {
        let genesis = self.finality_proof(NonZeroU64::new(1).unwrap()).unwrap();
        let mut verifier = FinalityVerifier::from_genesis(&authority.genesis, &genesis).unwrap();
        // The original standalone genesis producer has returned before this lazy
        // source exists. All four fresh attesters still use their independent native
        // producers; only the later intermediate source reads share this immutable cut.
        let view = self.chain.state().view();
        with_proof_reader(&view, |reader| {
            let source = NativeObservationSource {
                native: self,
                reader: RefCell::new(reader),
            };
            assert_eq!(
                verifier
                    .observe(&source, &rand::random())
                    .unwrap()
                    .verified(),
                4
            );
        });
        assert_eq!(verifier.checkpoint().height(), self.chain.height());
        verifier
    }
    pub(in crate::managed) fn policy_proof(&self, manager: &AccountId) -> ReservePolicyProofV1 {
        let tip = self.chain.committed(self.chain.height());
        let budget = AllocationBudget::new(32 * 1024 * 1024);
        let (bytes, charge) = self
            .chain
            .state()
            .with_native_reserve_policy_snapshot_v1(
                &tip,
                manager,
                &budget,
                |world, permissions, current| {
                    assert_eq!(
                        world.root().unwrap(),
                        tip.commitment().execution.world_state_root
                    );
                    let borrowed = ReservePolicyProofRefV1::new(world, permissions, current);
                    let size = norito::canonical_frame_len(&borrowed)
                        .map_err(|error| error.to_string())?;
                    let charge = budget
                        .try_reserve_bytes(size)
                        .map_err(|error| error.to_string())?;
                    Ok((
                        norito::encode_canonical(&borrowed).map_err(|error| error.to_string())?,
                        charge,
                    ))
                },
            )
            .unwrap();
        let proof = ReservePolicyProofV1::decode_frame(&bytes).unwrap();
        drop(bytes);
        drop(charge);
        assert_eq!(budget.reserved_bytes(), 0);
        proof
    }
}
impl NativeFixture {
    /// Borrow the exact original account facts from this same genuinely executed State.
    pub(in crate::managed) fn account_proof(
        &self,
        operator: &AccountId,
        provider: ProviderId,
    ) -> ReserveAccountProofV1 {
        let tip = self.chain.committed(self.chain.height());
        let budget = AllocationBudget::new(32 * 1024 * 1024);
        let (bytes, charge) = self
            .chain
            .state()
            .with_native_reserve_account_snapshot_v1(
                &tip,
                operator,
                provider,
                &budget,
                |world, owner, policy, current, credit, capacity, pricing| {
                    assert_eq!(
                        world.root().unwrap(),
                        tip.commitment().execution.world_state_root
                    );
                    let borrowed = ReserveAccountProofRefV1::new(
                        world, owner, policy, current, credit, capacity, pricing,
                    );
                    let size = norito::canonical_frame_len(&borrowed)
                        .map_err(|error| error.to_string())?;
                    let charge = budget
                        .try_reserve_bytes(size)
                        .map_err(|error| error.to_string())?;
                    Ok((
                        norito::encode_canonical(&borrowed).map_err(|error| error.to_string())?,
                        charge,
                    ))
                },
            )
            .unwrap();
        let proof = ReserveAccountProofV1::decode_frame(&bytes).unwrap();
        drop(bytes);
        drop(charge);
        assert_eq!(budget.reserved_bytes(), 0);
        proof
    }
}

// This transport borrows one callback-owned producer. It neither owns a second
// history graph nor changes any attester's original status, signer or source checks.
struct NativeObservationSource<'a, 'v, V: StateReadOnly> {
    native: &'a NativeFixture,
    reader: RefCell<&'a mut FinalityProofReader<'v, V>>,
}

impl<V: StateReadOnly> FinalitySource for NativeObservationSource<'_, '_, V> {
    type Error = io::Error;

    fn finality_proof(&self, height: NonZeroU64) -> io::Result<SumeragiFinalityProof> {
        self.reader
            .borrow_mut()
            .proof(height.get())
            .map_err(|error| io::Error::other(error.to_string()))
    }

    fn latest_attestation(
        &self,
        peer: &PeerId,
        challenge: &[u8; 32],
    ) -> io::Result<crate::verify::finality::FinalityAttestation> {
        self.native.latest_attestation(peer, challenge)
    }
}

impl FinalitySource for NativeFixture {
    type Error = io::Error;
    fn finality_proof(&self, height: NonZeroU64) -> io::Result<SumeragiFinalityProof> {
        build_proof(&self.chain.state().view(), height.get())
            .map_err(|error| io::Error::other(error.to_string()))
    }
    fn latest_attestation(
        &self,
        peer: &PeerId,
        challenge: &[u8; 32],
    ) -> io::Result<crate::verify::finality::FinalityAttestation> {
        let (key, fingerprint) = self
            .validators
            .iter()
            .find(|(key, _)| key.public_key() == peer.public_key())
            .ok_or_else(|| io::Error::other("peer is outside generated genesis"))?;
        let height = self.chain.height();
        let identity = NodeIdentity {
            node_id: peer.clone(),
            config_fingerprint: *fingerprint,
        };
        // A fixture status derived from this actual committed State, not a running node-driver
        // assertion. The production attestation owner checks the instance, proof and durable tip.
        let status = SumeragiStatus {
            protocol_version: iroha_data_model::sumeragi::PROTOCOL_VERSION,
            config_fingerprint: *fingerprint,
            beacon_horizon: None,
            instance: self.chain.instance().0,
            height: height + 1,
            view: 0,
            stage: 0,
            leader: None,
            proxy_tail: None,
            high_qc_view: None,
            level: 0,
            start_level: 0,
            t_retx_ms: 100,
            committed_height: height,
            applied_height: height,
            awaiting: false,
            signer: Some(key.public_key().clone()),
            unanchored: false,
            abstaining: false,
            halted: None,
            footprint: SumeragiFootprint::default(),
        };
        build_attestation(
            &self.chain.state().view(),
            status,
            &identity,
            Hash::new(b"generated-native-reserve-component-test"),
            height,
            *challenge,
            key,
        )
        .map(crate::verify::finality::FinalityAttestation::Raw)
        .map_err(|error| io::Error::other(error.to_string()))
    }
}

fn native_quote(state: &State, payload: &TransactionPayload) -> FeeQuoteResponse {
    let header = state.latest_block_header_fast().unwrap();
    let view = state.view();
    let draft = iroha_core::executor::quote_nexus_fee_admission_draft(
        view.world(),
        view.nexus(),
        view.pipeline(),
        &view.zk().gas,
        payload,
        header.creation_time_ms,
        iroha_core::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
            .expect("original native quote time"),
        header.height().get() + 1,
        Some(DataSpaceId::UNIVERSAL),
    )
    .unwrap();
    let quote = draft.quote;
    FeeQuoteResponse {
        intent: draft.recommended_intent,
        observation: FeeQuoteObservation {
            ledger_time_ms: header.creation_time_ms,
            next_block_height: header.height().get() + 1,
            route_dataspace_id: DataSpaceId::UNIVERSAL,
        },
        components: quote
            .charges
            .into_iter()
            .map(|charge| FeeQuoteComponent {
                kind: charge.kind,
                asset_definition_id: charge.asset_definition_id,
                max_amount: charge.max_bound,
            })
            .collect(),
        capacities: quote
            .capacities
            .into_iter()
            .map(|(asset_definition_id, capacity)| FeeQuoteCapacity {
                asset_definition_id,
                vault_balance: capacity.vault_balance,
                reserve_floor: capacity.reserve_floor,
                block_remaining: capacity.block_remaining,
                program_epoch_remaining: capacity.program_epoch_remaining,
                beneficiary_epoch_remaining: capacity.beneficiary_epoch_remaining,
            })
            .collect(),
        decision: FeeQuoteDecision::Accepted {
            debit_source: quote.debit_source,
            program_revision: quote.program_revision,
        },
    }
}
pub(in crate::managed) fn balance(state: &State, asset: &AssetId) -> Quantity {
    FindAssetById::new(asset.clone())
        .execute(&state.view())
        .unwrap()
        .value
}
pub(in crate::managed) fn quote_instructions(
    fixture: &NativeFixture,
    config: &Config,
    instructions: impl IntoIterator<Item = InstructionBox>,
) -> SignedTransaction {
    let key = &config.key_pair;
    let mut builder = TransactionBuilder::new(
        fixture.chain.network_id(),
        config.account.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(
        now_ms()
            .unwrap()
            .max(fixture.chain.genesis().header().creation_time_ms + 1),
    ));
    builder.set_ttl(Duration::from_secs(600));
    let builder = builder.with_instructions(instructions);
    let draft = builder.clone().sign(key.private_key());
    let quote = native_quote(fixture.chain.state(), draft.payload());
    assert!(!quote.components.is_empty());
    builder
        .with_fee_payment_intent(quote.intent)
        .sign(key.private_key())
}

pub(in crate::managed) struct NativeReadHttp {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<()>>>,
    pub(in crate::managed) requests: Arc<Mutex<Vec<(String, String)>>>,
    pub(in crate::managed) quote: Arc<Mutex<Option<FeeQuoteResponse>>>,
}
impl NativeReadHttp {
    pub(in crate::managed) fn start_config(config: &Config, state: Arc<State>) -> Self {
        let endpoint = &config.torii_api_url;
        assert_eq!(endpoint.host_str(), Some("127.0.0.1"));
        assert_eq!(endpoint.scheme(), "http");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, endpoint.port().unwrap())).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let quote = Arc::new(Mutex::new(None));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&requests);
        let thread_quote = Arc::clone(&quote);
        let manager = config.account.clone();
        let worker = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        // macOS inherits the listener's nonblocking flag on accepted streams.
                        // wallet_request owns bounded blocking reads/writes for this connection.
                        socket.set_nonblocking(false)?;
                        let request = wallet_request(&mut socket)?;
                        let (content_type, bytes) =
                            read_response(&request, &state, &manager, &thread_quote);
                        let mut seen = thread_requests.lock().unwrap();
                        if seen.len() >= 16 {
                            return Err(io::Error::other("native read request cap exceeded"));
                        }
                        seen.push((request.method, request.target.path().to_owned()));
                        drop(seen);
                        write!(
                            socket,
                            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            bytes.len()
                        )?;
                        socket.write_all(&bytes)?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        Self {
            stop,
            worker: Some(worker),
            requests,
            quote,
        }
    }
    pub(in crate::managed) fn finish(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap().unwrap();
    }
}
impl Drop for NativeReadHttp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn read_response(
    request: &WalletHttpRequest,
    state: &State,
    manager: &AccountId,
    quote: &Mutex<Option<FeeQuoteResponse>>,
) -> (&'static str, Vec<u8>) {
    match (request.method.as_str(), request.target.path()) {
        ("GET", "/v1/node/capabilities") => ("application/json", norito::json::to_vec(&norito::json!({
            "data_model_version": (iroha_data_model::DATA_MODEL_VERSION),
            "signed_transaction_schema_hash_hex": (hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>()))
        })).unwrap()),
        ("POST", "/v1/fees/quote") => {
            let request: FeeQuoteRequest = norito::json::from_slice(&request.body).unwrap();
            assert_eq!(&request.payload.authority, manager);
            assert_eq!(request.payload.domain, TransactionDomain::Network(*state.network_id_ref()));
            let response = native_quote(state, &request.payload);
            let bytes = norito::json::to_vec(&response).unwrap();
            assert!(quote.lock().unwrap().replace(response).is_none(), "one actual native quote");
            ("application/json", bytes)
        }
        ("POST", "/v1/query") => {
            let signed = SignedQuery::decode_all_versioned(&request.body).unwrap();
            signed.verify_signature().unwrap();
            assert_eq!(signed.authority(), manager);
            assert_eq!(signed.payload.network_id(), *state.network_id_ref());
            let view = state.view();
            validate_fresh_query_for_client_world_parts(
                signed.payload.into_parts().1, manager, view.world(), state.latest_block_header_fast(),
                QueryLimits::from_pipeline(view.pipeline()), &state.ivm_execution_budget(),
            ).unwrap();
            // Validation consumes the request. Execute the same bounded original bytes.
            let signed = SignedQuery::decode_all_versioned(&request.body).unwrap();
            let output = match signed.request() {
                QueryRequest::Singular(SingularQueryBox::FindAccountById(query)) => SingularQueryOutputBox::Account(query.execute(&view).unwrap()),
                QueryRequest::Singular(SingularQueryBox::FindAssetDefinitionById(query)) => SingularQueryOutputBox::AssetDefinition(query.execute(&view).unwrap()),
                QueryRequest::Singular(SingularQueryBox::FindAssetById(query)) => SingularQueryOutputBox::Asset(query.execute(&view).unwrap()),
                _ => panic!("unexpected funding query"),
            };
            ("application/x-norito", norito::to_bytes(&QueryResponse::Singular(output)).unwrap())
        }
        _ => panic!("native fixture permits actual quote/funding reads only"),
    }
}

pub(in crate::managed) fn policy(authority: &ServiceAuthority) -> ReserveAuthorityPolicyV1 {
    ReserveAuthorityPolicyV1 {
        version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
        revision: 1,
        predecessor_policy_digest: None,
        economics: ReservePolicyV1::default(),
        asset_definition: AssetDefinitionId::parse_address_literal(
            crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
        )
        .unwrap(),
        custody_account: authority.manifest.network.reserve_accounts.custody.clone(),
        treasury_account: authority.manifest.network.reserve_accounts.treasury.clone(),
        operations_authority: authority
            .network_role(crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReserveOperations)
            .unwrap()
            .clone(),
        decision_authority: authority.config.account.clone(),
        grace_period_days: 7,
        default_after_days: 30,
        max_provider_debt: XorQuantity::try_from_micro(1_000_000_000).unwrap(),
        max_pending_movements_per_provider: 4,
        max_open_appeals_per_provider: 2,
    }
}

#[cfg(test)]
#[path = "native_fixture/proof_reader_tests.rs"]
mod proof_reader_tests;
