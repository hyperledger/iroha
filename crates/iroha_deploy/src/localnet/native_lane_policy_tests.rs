//! The native lane policy signed into generated multi-lane localnet genesis.
use super::*;
use iroha_data_model::{
    block::SignedBlock,
    isi::SetParameter,
    nexus::LaneVisibility,
    parameter::{Parameter, system::ConsensusMode},
    sns::dataspace_id_for_alias,
    sumeragi_finality::{
        GenesisDataspaceSelectorV1, SignedGenesisPinsV1, authenticate_signed_genesis_v1,
        verify_genesis_dataspace_v1,
    },
    sumeragi_lanes::{SumeragiLanePolicy, SumeragiLaneRoute},
    transaction::Executable,
};

/// The public BPNG dataspace of fresh Taira: SNS identity of `bpng`, lane 5, no account route.
const TAIRA_BPNG_DATASPACE_ID: u64 = 8_648_377_547_929_788_715;

fn generate(
    seed: &str,
    sora_profile: Option<SoraProfile>,
    consensus_mode: SumeragiConsensusMode,
    chain: Option<&str>,
) -> crate::localnet::localnet_test_helpers::PrivateTempDir {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir()
        .expect("temporary localnet directory");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile,
        perf_profile: None,
        peers: NonZeroU16::new(TAIRA_TESTNET_PEERS).expect("four peers"),
        seed: Some(seed.to_owned()),
        bind_host: "127.0.0.1".to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 18_880,
        base_p2p_port: 18_970,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode,
    };
    generate_localnet_with_chain(&opts, &mut BufWriter::new(Vec::new()), chain, None)
        .expect("generate localnet");
    temp
}

fn taira() -> crate::localnet::localnet_test_helpers::PrivateTempDir {
    generate(
        "taira-native-lane-policy",
        Some(SoraProfile::Nexus),
        SumeragiConsensusMode::Npos,
        Some(PUBLIC_TAIRA_CHAIN_ID),
    )
}

fn lane_policy(manifest: &RawGenesisTransaction) -> Option<SumeragiLanePolicy> {
    manifest
        .effective_parameters()
        .expect("one structured parameter block")
        .custom()
        .get(&SumeragiLanePolicy::parameter_id())
        .map(|custom| {
            SumeragiLanePolicy::from_custom_parameter(custom)
                .expect("lane policy identity")
                .expect("valid lane policy")
        })
}

fn signed_lane_policies(block: &SignedBlock) -> Vec<SumeragiLanePolicy> {
    block
        .external_transactions()
        .flat_map(|transaction| match transaction.instructions() {
            Executable::Instructions(instructions) => instructions.iter().collect::<Vec<_>>(),
            _ => Vec::new(),
        })
        .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
        .filter_map(|set| match set.inner() {
            Parameter::Custom(custom) => SumeragiLanePolicy::from_custom_parameter(custom),
            _ => None,
        })
        .map(|policy| policy.expect("valid signed lane policy"))
        .collect()
}

#[test]
fn generated_taira_genesis_signs_one_lane_policy_for_every_catalog_lane() {
    let _chain_discriminant = ChainDiscriminantGuard::enter(369);
    let temp = taira();
    let manifest = RawGenesisTransaction::from_path(temp.path().join("genesis.json"))
        .expect("bound Taira genesis");
    let policy = lane_policy(&manifest).expect("Taira genesis sets the native lane policy");
    let config = parse_localnet_peer_config(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("peer0 config"),
        Some(&temp.path().join("peer0.toml")),
    )
    .expect("generated peer0 config");
    let catalog = config
        .nexus
        .lane_catalog
        .lanes()
        .iter()
        .filter(|lane| lane.id != LaneId::new(0))
        .map(|lane| (lane.id, lane.dataspace_id))
        .collect::<Vec<_>>();
    assert_eq!(
        catalog.len(),
        7,
        "fresh Taira has lanes 1..=7 besides lane 0"
    );
    assert_eq!(
        policy
            .fixed
            .iter()
            .map(|fixed| (fixed.lane, fixed.dataspace))
            .collect::<Vec<_>>(),
        catalog,
        "every non-zero catalog lane is a fixed native lane of its catalog dataspace"
    );
    let topology = manifest
        .transactions()
        .iter()
        .flat_map(|tx| tx.topology())
        .map(|entry| {
            (
                entry.peer.clone(),
                entry.pop_bytes().expect("PoP hex").expect("genesis PoP"),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(topology.len(), 4);
    let canonical = iroha_core::sumeragi::schedule::canonical_committee(topology.keys().cloned())
        .expect("BLS topology");
    for fixed in &policy.fixed {
        assert_eq!(
            fixed
                .committee
                .iter()
                .map(|member| member.peer.clone())
                .collect::<Vec<_>>(),
            canonical,
            "lane {} is served by the whole genesis topology in canonical order",
            fixed.lane
        );
        for member in &fixed.committee {
            assert_eq!(Some(&member.pop), topology.get(&member.peer));
        }
    }
    iroha_core::sumeragi::lanes::step::validate_policy(&policy).expect("core admits the policy");
    let account_routes = config
        .nexus
        .routing_policy
        .rules
        .iter()
        .filter(|rule| rule.matcher.account.is_some())
        .map(|rule| SumeragiLaneRoute {
            lane: rule.lane,
            account: rule.matcher.account.clone(),
            instruction: rule.matcher.instruction.clone(),
        })
        .collect::<Vec<_>>();
    assert_eq!(policy.routes, account_routes);
    assert_eq!(
        policy
            .routes
            .iter()
            .map(|route| (route.lane.as_u32(), route.account.as_deref()))
            .collect::<Vec<_>>(),
        vec![
            (3, Some("*@dpn")),
            (4, Some("*@is2")),
            (6, Some("*@cbsi")),
            (7, Some("*@is")),
        ],
        "only account routes are native; Public BPNG routes by target dataspace"
    );
    assert!(policy.autoscale.is_none());
    let parameters = manifest.effective_parameters().expect("parameters");
    assert_eq!(policy.lane_params, parameters.sumeragi);
    assert_eq!(
        policy.da_layout,
        manifest.sumeragi_context_parameters().da_layout
    );
    assert!(
        !manifest
            .instructions()
            .any(|instruction| instruction.as_any().is::<SetParameter>()),
        "the policy is a structured parameter, never an authored SetParameter"
    );
    let signed =
        read_signed_genesis(&temp.path().join("genesis.signed.nrt")).expect("signed Taira genesis");
    assert_eq!(
        signed_lane_policies(&signed),
        vec![policy],
        "signed genesis sets exactly one lane policy"
    );
}

#[test]
fn generated_taira_genesis_admits_the_public_bpng_dataspace() {
    let _chain_discriminant = ChainDiscriminantGuard::enter(369);
    let temp = taira();
    let executed =
        read_signed_genesis(&temp.path().join("genesis.signed.nrt")).expect("signed Taira genesis");
    // Light clients authenticate the canonical resultless proposal of the executed genesis.
    let wire = executed
        .canonical_resultless_proposal()
        .and_then(|proposal| proposal.encode_wire())
        .expect("canonical resultless genesis");
    // Independently selected pins: the generated topology in ascending order.
    let mut roster = RawGenesisTransaction::from_path(temp.path().join("genesis.json"))
        .expect("bound Taira genesis")
        .transactions()
        .iter()
        .flat_map(|tx| tx.topology())
        .map(|entry| entry.peer.clone())
        .collect::<Vec<_>>();
    roster.sort();
    let genesis_public_key = fs::read_to_string(temp.path().join(GENESIS_PUBLIC_KEY_FILE))
        .expect("genesis public key")
        .trim()
        .parse()
        .expect("canonical genesis public key");
    let pins = SignedGenesisPinsV1 {
        chain_id: PUBLIC_TAIRA_CHAIN_ID.to_owned(),
        network_id: NetworkId::from_genesis_hash(executed.hash()),
        genesis_hash: executed.hash(),
        signed_genesis_sha256: iroha_crypto::sha256(&wire),
        genesis_public_key,
        roster,
        mode: ConsensusMode::Npos,
    };
    let genesis = authenticate_signed_genesis_v1(&wire, &pins).expect("authenticated genesis");
    let context =
        fs::read(temp.path().join("nexus-amx-context.v1.bin")).expect("Nexus AMX context");
    let dataspace = DataSpaceId::new(TAIRA_BPNG_DATASPACE_ID);
    assert_eq!(dataspace_id_for_alias("bpng"), Some(dataspace));
    let selector = GenesisDataspaceSelectorV1 {
        alias: "bpng".to_owned(),
        dataspace_id: dataspace,
        lane_id: LaneId::new(5),
        lane_alias: "bpng".to_owned(),
        visibility: LaneVisibility::Public,
        account_routes: Vec::new(),
    };
    let authority =
        verify_genesis_dataspace_v1(&genesis, &context, &selector).expect("BPNG dataspace");
    assert_eq!(authority.dataspace_id(), dataspace);
    assert_eq!(authority.lane_id(), LaneId::new(5));
}

#[test]
fn single_lane_localnet_genesis_has_no_lane_policy() {
    let temp = generate(
        "single-lane-no-native-lane-policy",
        None,
        SumeragiConsensusMode::Permissioned,
        None,
    );
    let manifest =
        RawGenesisTransaction::from_path(temp.path().join("genesis.json")).expect("bound genesis");
    assert!(lane_policy(&manifest).is_none());
}
