//! Real independent root construction and explicit software custody for the native AMX service.

use super::*;
use iroha_config::base::toml::WriteExt as _;
use iroha_data_model::{
    block::consensus::{RootFeePolicy, SumeragiGenesisContextParameters},
    isi::{Grant, Mint, Register},
    parameter::Parameter,
    sns::{DATASPACE_ALIAS_SUFFIX_ID, NameSelectorV1},
    sumeragi_finality::authenticated_genesis,
};
use iroha_genesis::GenesisBuilder;
use std::{borrow::Cow, io::Write as _, path::Path, sync::LazyLock};
use toml::{Table, Value};

pub(crate) const CADENCE_MS: u64 = 1_000;
pub(crate) const PRINCIPAL: u32 = 1_000;
// Match the private-root authoring owner: the canonical SNS dataspace selector
// supplies the stable catalog manifest_hash, independently of signed child genesis.
// This is not an inline lane-governance or public Space Directory manifest digest.
const BANK_ALIASES: [&str; 2] = ["bank-a", "bank-b"];
static DATASPACE_MANIFEST_HASHES: LazyLock<[[u8; 32]; 2]> = LazyLock::new(|| {
    BANK_ALIASES.map(|alias| {
        let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, alias)
            .expect("canonical private-root dataspace selector");
        assert_eq!(selector.normalized_label(), alias);
        selector.name_hash()
    })
});
pub(crate) static DATASPACES: LazyLock<[DataSpaceId; 2]> =
    LazyLock::new(|| DATASPACE_MANIFEST_HASHES.map(|hash| DataSpaceId::from_hash(&hash)));

fn private_root_catalog(bank: usize) -> Table {
    let alias = BANK_ALIASES[bank];
    Table::new()
        .write(
            "lane_catalog",
            vec![Value::Table(
                Table::new()
                    .write("index", 0_i64)
                    .write("alias", "private-root")
                    .write("dataspace", alias)
                    .write("visibility", "restricted")
                    .write("storage", "full_replica"),
            )],
        )
        .write(
            "dataspace_catalog",
            vec![Value::Table(
                Table::new()
                    .write("alias", alias)
                    .write(
                        "manifest_hash",
                        hex::encode(DATASPACE_MANIFEST_HASHES[bank]),
                    )
                    .write("fault_tolerance", 1_i64),
            )],
        )
        .write(["routing_policy", "default_lane"], 0_i64)
        .write(["routing_policy", "default_dataspace"], alias)
}

#[test]
fn private_root_catalog_uses_one_manifest_derived_identity_everywhere() {
    use iroha_config::base::{read::ConfigReader, toml::TomlSource, util::Emitter};
    use iroha_config::parameters::user::Nexus;

    assert!(DATASPACES[0] < DATASPACES[1]);
    for bank in 0..2 {
        assert_ne!(DATASPACES[bank], DataSpaceId::UNIVERSAL);
        let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, BANK_ALIASES[bank])
            .expect("same private-root authoring selector");
        assert_eq!(selector.normalized_label(), BANK_ALIASES[bank]);
        assert_eq!(selector.name_hash(), DATASPACE_MANIFEST_HASHES[bank]);
        let table = private_root_catalog(bank);
        let encoded = toml::to_string(&table).unwrap();
        let user = ConfigReader::new()
            .without_env()
            .with_toml_source(TomlSource::inline(encoded.parse::<Table>().unwrap()))
            .read_and_complete::<Nexus>()
            .expect("exact authored private catalog must decode");
        let mut errors = Emitter::new();
        let actual = user.clone().parse(&mut errors);
        errors
            .into_result()
            .expect("manifest-derived catalog must validate");
        let actual = actual.expect("validated private catalog");
        assert_eq!(actual.dataspace_catalog.entries().len(), 1);
        assert_eq!(actual.dataspace_catalog.entries()[0].id, DATASPACES[bank]);
        assert_eq!(
            actual.lane_catalog.lanes()[0].dataspace_id,
            DATASPACES[bank]
        );
        assert_eq!(actual.routing_policy.default_dataspace, DATASPACES[bank]);
        assert!(
            user.dataspace_catalog[0].id.is_none(),
            "no numeric identity alias"
        );
        assert_eq!(
            DataSpaceId::from_hash(&DATASPACE_MANIFEST_HASHES[bank]),
            DATASPACES[bank],
        );
        let mut missing_manifest = user;
        missing_manifest.dataspace_catalog[0].manifest_hash = None;
        let mut errors = Emitter::new();
        assert!(missing_manifest.parse(&mut errors).is_none());
        assert!(
            format!("{:?}", errors.into_result().unwrap_err())
                .contains("must specify `manifest_hash`")
        );
    }
}

#[test]
fn private_root_catalog_is_restricted_full_replica_in_exact_signed_dataspace() {
    use iroha_config::base::{read::ConfigReader, toml::TomlSource, util::Emitter};
    use iroha_config::parameters::{actual, user};
    use iroha_data_model::nexus::{LaneStorageProfile, LaneVisibility};
    use iroha_model_base::topology::LaneId;

    let parse = |table: Table| -> actual::Nexus {
        let user = ConfigReader::new()
            .without_env()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<user::Nexus>()
            .expect("actual authored private catalog must decode");
        let mut errors = Emitter::new();
        let actual = user.parse(&mut errors);
        errors.into_result().expect("authored catalog must parse");
        actual.expect("parsed catalog")
    };
    for bank in 0..2 {
        let actual = parse(private_root_catalog(bank));
        actual
            .validate_private_root_geometry(DATASPACES[bank])
            .expect("each bank must satisfy the real private-root startup owner");
        let [lane] = actual.lane_catalog.lanes() else {
            panic!("one private physical lane")
        };
        assert_eq!(lane.id, LaneId::SINGLE);
        assert_eq!(lane.dataspace_id, DATASPACES[bank]);
        assert_eq!(lane.visibility, LaneVisibility::Restricted);
        assert_eq!(lane.storage, LaneStorageProfile::FullReplica);
        assert_eq!(actual.lane_catalog, actual.configured_lane_catalog);
        assert!(actual.lane_config.matches_catalog(&actual.lane_catalog));
        assert_eq!(actual.routing_policy.default_dataspace, DATASPACES[bank]);
        assert!(actual.routing_policy.rules.is_empty());
        assert_eq!(
            actual.validate_private_root_geometry(DATASPACES[1 - bank]),
            Err("private root requires exactly its signed dataspace in the physical catalog")
        );

        for (field, value) in [("visibility", "public"), ("storage", "commitment_only")] {
            let mut table = private_root_catalog(bank);
            let lane = table
                .get_mut("lane_catalog")
                .unwrap()
                .as_array_mut()
                .unwrap()[0]
                .as_table_mut()
                .unwrap();
            lane.insert(field.to_owned(), Value::String(value.to_owned()));
            let invalid = parse(table);
            assert_eq!(
                invalid.validate_private_root_geometry(DATASPACES[bank]),
                Err(
                    "private root requires its own restricted, fully replicated physical lane zero"
                ),
                "the fixture must retain the actual private-root {field} guard"
            );
        }
    }
}

pub(crate) fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}
pub(crate) fn account(key: &KeyPair) -> AccountId {
    AccountId::new(key.public_key().clone())
}
pub(crate) fn genesis_key(index: usize) -> KeyPair {
    key(0x70 + index as u8)
}
pub(crate) fn payer(index: usize) -> KeyPair {
    key(0x81 + index as u8)
}
pub(crate) fn relay(index: usize) -> KeyPair {
    key(0x91 + index as u8)
}
pub(crate) fn fee_asset() -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap()
}
pub(crate) fn currency(index: usize) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("money", BANK_ALIASES[index]).unwrap(),
        ["usd", "eur"][index].parse().unwrap(),
    )
}
pub(crate) fn fee_intent() -> FeePaymentIntent {
    // All three signed genesis policies select Nexus-only charging. Global
    // commits no accepted PipelineGas asset; banks include gas in Nexus.
    FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            fee_asset(),
            Quantity::from(512_u32),
        )],
        None,
    )
}

pub(crate) fn service_read_role() -> iroha_data_model::role::RoleId {
    "native_amx_service_read".parse().expect("authored role ID")
}
pub(crate) fn service_admin_role() -> iroha_data_model::role::RoleId {
    "native_amx_service_admin"
        .parse()
        .expect("authored role ID")
}

#[derive(Clone, Copy)]
pub(crate) enum BankFeeProfile {
    Metered,
    UnfundedRelay,
}
pub(crate) struct Root {
    pub network: Network,
    pub scope: SumeragiRootScope,
    pub pins: SignedGenesisPinsV1,
    pub genesis_wire: Vec<u8>,
    pub instance: [u8; 32],
    pub index: usize,
    pub relay_layer: Table,
    api_token: iroha::secrecy::SecretString,
    clients: std::collections::BTreeMap<AccountId, iroha::blocking::Client>,
}
impl Root {
    pub fn new(index: usize, parent: Option<(&Root, Vec<u8>, Vec<u8>)>) -> Result<Self> {
        Self::new_with_fee_profile(index, parent, BankFeeProfile::Metered)
    }
    pub fn new_with_fee_profile(
        index: usize,
        parent: Option<(&Root, Vec<u8>, Vec<u8>)>,
        fees: BankFeeProfile,
    ) -> Result<Self> {
        let chain = ChainId::try_from(format!("native-amx-independent-root-{index}"))?;
        let scope = parent
            .as_ref()
            .map_or(SumeragiRootScope::Global, |(parent, _, _)| {
                SumeragiRootScope::Dataspace {
                    parent_network_id: parent.network.network_id(),
                    dataspace_id: DATASPACES[index - 1],
                }
            });
        let bank = index.checked_sub(1);
        let alias = bank.map_or("universal", |bank| BANK_ALIASES[bank]);
        let domain = DomainId::try_new("money", alias)?;
        let balance_policy = if bank.is_some() {
            AssetBalancePolicy::DataspaceRestricted
        } else {
            AssetBalancePolicy::Global
        };
        let balance_scope = bank.map_or(AssetBalanceScope::Global, |bank| {
            AssetBalanceScope::Dataspace(DATASPACES[bank])
        });
        let mut instructions: Vec<InstructionBox> = vec![
            Register::account(Account::new(account(&relay(index)))).into(),
            Register::domain(Domain::new(domain.clone())).into(),
            Register::asset_definition(AssetDefinition::numeric(
                fee_asset(),
                "Native AMX carrier fees",
                balance_policy,
                Some(domain.clone()),
            ))
            .into(),
            Grant::account_permission(
                iroha_executor_data_model::permission::parameter::CanSetParameters,
                account(&genesis_key(index)),
            )
            .into(),
            Grant::account_permission(
                iroha_executor_data_model::permission::query::CanReadAllLedgerData,
                account(&genesis_key(index)),
            )
            .into(),
        ];
        for owner in [account(&genesis_key(index)), account(&relay(index))] {
            if matches!(fees, BankFeeProfile::UnfundedRelay) && owner == account(&relay(index)) {
                continue;
            }
            instructions.push(
                Mint::asset_quantity(
                    1_000_000_u32,
                    AssetId::with_scope(fee_asset(), owner, balance_scope.clone()),
                )
                .into(),
            );
        }
        if let Some(bank) = bank {
            // Explicit privileged full-bank disclosure, isolated from debit consent
            // and listener credentials. Genesis-only capabilities are revocable by
            // deleting their dedicated local role, never by reissuing a token.
            instructions.extend([
                // The fee audit's ordinary asset-definition query crosses this
                // restricted route. Full-ledger disclosure and route access are
                // distinct grants; the audit authority needs both for this bank.
                Grant::account_permission(
                    iroha_executor_data_model::permission::query::CanReadRestrictedDataspace {
                        dataspace: DATASPACES[bank],
                    },
                    account(&genesis_key(index)),
                )
                .into(),
                Register::role(
                    iroha_data_model::role::Role::new(service_read_role(), account(&relay(index)))
                        .add_permission(
                            iroha_executor_data_model::permission::query::CanReadAllLedgerData,
                        ),
                )
                .into(),
                Register::role(
                    iroha_data_model::role::Role::new(
                        service_admin_role(),
                        account(&genesis_key(index)),
                    )
                    .add_permission(iroha_executor_data_model::permission::role::CanManageRoles),
                )
                .into(),
            ]);
            for bank_payer in [payer(0), payer(1)] {
                instructions.push(Register::account(Account::new(account(&bank_payer))).into());
                instructions.push(
                    Mint::asset_quantity(
                        1_000_000_u32,
                        AssetId::with_scope(
                            fee_asset(),
                            account(&bank_payer),
                            balance_scope.clone(),
                        ),
                    )
                    .into(),
                );
            }
            instructions.push(
                Register::asset_definition(AssetDefinition::numeric(
                    currency(bank),
                    ["Bank A USD", "Bank B EUR"][bank],
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(domain),
                ))
                .into(),
            );
            instructions.push(
                Mint::asset_quantity(
                    PRINCIPAL,
                    AssetId::with_scope(currency(bank), account(&payer(bank)), balance_scope),
                )
                .into(),
            );
            let (global, executed_genesis, successor) = parent.as_ref().unwrap();
            instructions.push(
                RegisterAmxParticipantV1 {
                    dataspace: DATASPACES[bank],
                    global_chain_id: global.network.chain_id().clone(),
                    global_genesis: executed_genesis.clone(),
                    global_successor: successor.clone(),
                }
                .into(),
            );
        }
        let mut context = SumeragiGenesisContextParameters::recommended();
        context.root_scope = scope;
        let mut parameters = Vec::new();
        parameters.push(Parameter::Custom(
            iroha_data_model::block::consensus::RootFeePolicy {
                fee_asset_id: fee_asset(),
                fee_sink_account_id: account(&genesis_key(index)),
                sponsor_vault_custody_account_id: account(&genesis_key(index)),
                successful_claim_fee_exempt_authorities: Default::default(),
                base_fee: Quantity::one(),
                per_byte_fee: Quantity::zero(),
                per_instruction_fee: if bank.is_some() {
                    Quantity::one()
                } else {
                    Quantity::zero()
                },
                per_gas_unit_fee: if bank.is_some() {
                    Quantity::one()
                } else {
                    Quantity::zero()
                },
            }
            .into_custom_parameter()?,
        ));
        // Author fee projection as signed genesis state, never a node-local override.
        for (name, value) in [
            (
                "ivm_gas_tech_account_id",
                norito::json!(account(&genesis_key(index)).to_string()),
            ),
            (
                "ivm_gas_accepted_assets",
                norito::json::Value::Array(if bank.is_some() {
                    vec![norito::json!(fee_asset().canonical_address())]
                } else {
                    vec![]
                }),
            ),
            (
                "ivm_gas_units_per_gas",
                norito::json::Value::Array(if bank.is_some() {
                    vec![norito::json!({
                        "asset": (fee_asset().canonical_address()), "units_per_gas": 1,
                        "twap_local_per_xor": "1", "liquidity_profile": "tier2", "volatility_class": "stable"
                    })]
                } else {
                    vec![]
                }),
            ),
        ] {
            parameters.push(Parameter::Custom(
                iroha_data_model::parameter::CustomParameter::new(
                    name.parse()?,
                    iroha_primitives::json::Json::new(value),
                ),
            ));
        }
        // This listener credential exists only in this test run's private custody.
        // It is independent of both the ledger account keys and the other roots.
        let api_token = listener_credential()?;
        let selected_chain = chain.clone();
        let selected_key = genesis_key(index);
        let selected_staking = iroha_test_network::genesis_support::staking_policy(
            fee_asset(),
            account(&selected_key),
            account(&selected_key),
        );
        let network = NetworkBuilder::new()
            .with_api_token(api_token.clone())
            .with_peers(4)
            .with_permissioned_consensus()
            .with_auto_populated_trusted_peers()
            .with_base_seed(format!("native-amx-independent-processes-{index}"))
            .with_genesis_keypair(selected_key.clone())
            .with_block_cadence(Duration::from_millis(CADENCE_MS))
            .with_peer_startup_timeout(Duration::from_secs(20 * 60))
            .with_genesis_block(move |_, entries| {
                let builder = GenesisBuilder::new_without_executor(
                    selected_chain.clone(),
                    ".",
                    iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                        iroha_crypto::Algorithm::Ed25519,
                        iroha_crypto::Algorithm::Secp256k1,
                        iroha_crypto::Algorithm::BlsNormal,
                    ])
                    .expect("explicit fixture account and validator controller policy"),
                )
                .with_staking_policy(selected_staking.clone())
                .expect("explicit fixture staking policy")
                .with_block_cadence_ms(NonZeroU64::new(CADENCE_MS).unwrap())
                .set_topology(entries)
                .with_sumeragi_context_parameters(context.clone());
                let builder = parameters
                    .clone()
                    .into_iter()
                    .fold(builder, GenesisBuilder::append_parameter)
                    .next_transaction();
                instructions
                    .clone()
                    .into_iter()
                    .fold(builder, GenesisBuilder::append_instruction)
                    .build_raw()
                    .unwrap()
                    .with_consensus_mode(ConsensusMode::Permissioned.into())
                    .with_consensus_meta()
                    .unwrap()
                    .build_and_sign(&selected_key)
                    .unwrap()
            })
            .with_config_layer(move |layer| {
                layer.write("chain", chain.to_string()).write(
                    ["nexus", "storage", "local_budget_bytes"],
                    1024_i64 * 1024 * 1024,
                );

                if let Some(bank) = bank {
                    let mut catalog = private_root_catalog(bank);
                    for name in ["lane_catalog", "dataspace_catalog", "routing_policy"] {
                        layer.write(
                            ["nexus", name],
                            catalog
                                .remove(name)
                                .expect("authored private catalog field"),
                        );
                    }
                }
            })
            .build();
        Self::from_network(index, network, ConsensusMode::Permissioned, api_token)
    }
    pub fn from_network(
        index: usize,
        network: Network,
        mode: ConsensusMode,
        api_token: iroha::secrecy::SecretString,
    ) -> Result<Self> {
        let scope = iroha_genesis::signed_genesis_consensus_metadata(&network.genesis().0)?
            .sumeragi_context
            .root_scope;
        let genesis_wire = network.genesis().0.encode_wire()?;
        let mut roster = network
            .topology_entries()
            .iter()
            .map(|entry| entry.peer.clone())
            .collect::<Vec<_>>();
        roster.sort();
        let pins = SignedGenesisPinsV1 {
            chain_id: network.chain_id().to_string(),
            network_id: network.network_id(),
            genesis_hash: network.genesis().0.hash(),
            signed_genesis_sha256: Sha256::digest(&genesis_wire).into(),
            genesis_public_key: genesis_key(index).public_key().clone(),
            roster,
            mode,
        };
        authenticate_signed_genesis_v1(&genesis_wire, &pins)?;
        let instance = scope
            .instance_id(
                &iroha_core::sumeragi::crypto::BlsCrypto::new(),
                network.network_id(),
                network.chain_id().as_str(),
            )?
            .0;
        let clients = [genesis_key(index), relay(index), payer(0), payer(1)]
            .into_iter()
            .map(|key| {
                (
                    account(&key),
                    network.validators()[0].client_for(&account(&key), key.private_key().clone()),
                )
            })
            .collect();
        Ok(Self {
            clients,
            api_token,
            network,
            scope,
            pins,
            genesis_wire,
            instance,
            index,
            relay_layer: Table::new(),
        })
    }
    pub fn authenticate_http(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.header("X-API-Token", self.api_token.expose_secret())
    }
    pub async fn assert_listener_authentication(&self, foreign: &Root) -> Result<()> {
        ensure!(
            self.api_token.expose_secret() != foreign.api_token.expose_secret(),
            "independent roots require distinct runtime listener credentials"
        );
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        for route in ["status", "v1/sumeragi/status"] {
            let url = format!(
                "{}/{route}",
                self.network.validators()[0]
                    .torii_url()
                    .trim_end_matches('/')
            );
            for credential in [
                None,
                Some("deliberately-wrong-listener-credential"),
                Some(foreign.api_token.expose_secret()),
            ] {
                let mut request = http
                    .get(&url)
                    .header("Accept", "application/json")
                    .timeout(Duration::from_secs(10));
                if let Some(credential) = credential {
                    request = request.header("X-API-Token", credential);
                }
                let response = request.send().await?;
                ensure!(
                    response.status() == reqwest::StatusCode::UNAUTHORIZED,
                    "root {} {route} must refuse missing, wrong and other-root credentials",
                    self.index
                );
                ensure!(
                    response
                        .headers()
                        .get("www-authenticate")
                        .and_then(|value| value.to_str().ok())
                        == Some("IrohaApiToken realm=\"torii\"")
                );
                let bytes = response.bytes().await?;
                let body: norito::json::Value = norito::json::from_slice(&bytes)?;
                ensure!(
                    body.get("code").and_then(norito::json::Value::as_str)
                        == Some("api_token_required")
                );
            }
        }
        // These are the actual retained readiness/diagnostic clients, including
        // the operator signature needed by the consensus-status endpoint.
        for peer in self.network.validators() {
            let client = peer.client();
            let status =
                status_poll::read_once(client.client().torii_request_timeout(), || peer.status())
                    .await?;
            ensure!(status.blocks >= 1);
        }
        let client = self.network.validators()[0].client();
        iroha_test_network::read_on_dedicated_thread(move || client.client().get_sumeragi_status())
            .await?;
        Ok(())
    }
    pub fn client(&self, signer: &KeyPair) -> iroha::blocking::Client {
        self.clients
            .get(&account(signer))
            .expect("fixture signer was constructed outside the async runtime")
            .clone()
    }
    pub fn verifier(&self) -> Result<SumeragiFinalityVerifier> {
        let selected = authenticate_signed_genesis_v1(&self.genesis_wire, &self.pins)?;
        Ok(SumeragiFinalityVerifier::new(
            selected.block(),
            &self.pins.chain_id,
            selected.validators().to_vec(),
        )?)
    }
    pub fn registry(&self) -> Result<RegisterAmxDataspaceV1> {
        let SumeragiRootScope::Dataspace { dataspace_id, .. } = self.scope else {
            return Err(eyre!(
                "only an independently signed bank root has a participant registration"
            ));
        };
        Ok(RegisterAmxDataspaceV1 {
            dataspace: dataspace_id,
            instance: self.instance,
            anchor: norito::encode_canonical(
                &authenticated_genesis(&self.network.genesis().0)?
                    .into_parts()
                    .0,
            )?,
        })
    }
    async fn restart_peer_until(
        &self,
        with_relay: bool,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        let peer = &self.network.validators()[0];
        tokio::time::timeout_at(deadline, async {
            peer.shutdown().await;
            // Spawn completion is not HTTP readiness. With no genesis argument,
            // this existing owner requires ServerStarted for the current run;
            // its Kura bootstrap fallback cannot authorize a restart.
            peer.start_checked(
                self.network
                    .config_layers_for_peer(peer)
                    .chain(with_relay.then(|| Cow::Borrowed(&self.relay_layer))),
                None,
            )
            .await
        })
        .await
        .map_err(|error| {
            eyre!(
                "root {} peer did not reach HTTP readiness within the restart phase: {error}",
                self.index
            )
        })?
    }
    pub async fn restart_service(&self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        self.restart_peer_until(true, deadline).await
    }
    pub async fn pause_service(&self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        self.restart_peer_until(false, deadline).await
    }
    pub async fn restart_all(&self) -> Result<()> {
        let client = self.client(&relay(self.index));
        let height = status_poll::read_once(client.client().torii_request_timeout(), || async {
            client.client().status().get().await.map_err(Into::into)
        })
        .await?
        .blocks;
        self.network.shutdown().await;
        self.network.start_all().await?;
        // Readiness and replay publication share this original finite phase.
        // A completed relay restart does not grant a fresh polling deadline.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        self.restart_peer_until(true, deadline).await?;
        // Startup can expose Kura before replay publishes the applied State. This
        // locator only schedules proof reads; the independent verifier remains authority.
        tokio::time::timeout_at(deadline, async {
            loop {
                let mut ready = true;
                for peer in self.network.validators() {
                    let status = status_poll::read_until(deadline, || peer.status()).await?;
                    ready &= status.blocks >= height;
                }
                if ready {
                    return Ok::<(), eyre::Report>(());
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .map_err(|error| {
            eyre!(
                "root {} failed to publish original State height {height} after restart: {error}",
                self.index
            )
        })??;
        Ok(())
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn route_with_ttl(root: &Root, directory: &Path, ttl_ms: i64) -> Result<Table> {
    let signer = relay(root.index);
    let key_path = directory.join(format!("relay-{}.key", root.index));
    write_private(
        &key_path,
        iroha_crypto::ExposedPrivateKey(signer.private_key().clone())
            .to_string()
            .as_bytes(),
    )?;
    let account_path = directory.join(format!("relay-{}.toml", root.index));
    let account_config = Table::new()
        .write("api_token", root.api_token.expose_secret())
        .write("chain", root.network.chain_id().to_string())
        .write("network_id", root.network.network_id().to_string())
        .write("torii_url", root.network.validators()[0].torii_url())
        .write(
            ["account", "chain_discriminant"],
            i64::from(iroha_data_model::account::address::chain_discriminant()),
        )
        .write(["account", "public_key"], signer.public_key().to_string())
        .write(
            ["account", "private_key_file"],
            key_path.to_string_lossy().into_owned(),
        )
        .write(["transaction", "time_to_live_ms"], ttl_ms)
        .write(["transaction", "status_timeout_ms"], 120_000_i64)
        .write("torii_request_timeout_ms", 60_000_i64);
    write_private(&account_path, toml::to_string(&account_config)?.as_bytes())?;
    let genesis_path = directory.join(format!("root-{}.nrt", root.index));
    write_private(&genesis_path, &root.genesis_wire)?;
    let mut route = Table::new()
        .write("network_id", root.network.network_id().to_string())
        .write("chain_id", root.network.chain_id().to_string())
        .write("authority", account(&signer).to_string())
        .write(
            "account_config",
            account_path.to_string_lossy().into_owned(),
        )
        .write(
            "signed_genesis",
            genesis_path.to_string_lossy().into_owned(),
        )
        .write(
            "signed_genesis_sha256",
            hex::encode(root.pins.signed_genesis_sha256),
        )
        .write(
            "genesis_public_key",
            root.pins.genesis_public_key.to_string(),
        )
        .write("fee_payment_json", norito::json::to_json(&fee_intent())?);
    route = route.write("scope_json", norito::json::to_json(&root.scope)?);
    Ok(route)
}

pub(crate) fn service(directory: &Path, index: usize, routes: Vec<Table>) -> Table {
    Table::new()
        .write(
            ["amx_relay", "journal_dir"],
            directory
                .join(format!("workflow-{index}"))
                .to_string_lossy()
                .into_owned(),
        )
        .write(["amx_relay", "poll_interval_ms"], 200_i64)
        .write(["amx_relay", "max_source_heights_per_pass"], 32_i64)
        .write(["amx_relay", "max_finality_proof_reads"], 64_i64)
        .write(
            ["amx_relay", "routes"],
            routes.into_iter().map(Value::Table).collect::<Vec<_>>(),
        )
}

// Listener admission is runtime-only, independent of account and consensus keys.
pub(crate) fn listener_credential() -> Result<iroha::secrecy::SecretString> {
    Ok(iroha::secrecy::SecretString::new(hex::encode(
        Sha256::digest(
            KeyPair::try_random_with_algorithm(Algorithm::Ed25519)?
                .public_key()
                .to_string()
                .as_bytes(),
        ),
    )))
}
