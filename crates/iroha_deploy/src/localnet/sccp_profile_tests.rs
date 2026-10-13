// Canonical Taira SCCP initialization and durable reset identity regressions.

fn assert_sccp_localnet_profile(
    directory: &Path,
    history: &Path,
) -> ([u8; 32], [u8; 32], Vec<PeerId>) {
    use iroha_data_model::{
        isi::{governance::ProposeSccpRouteGovernance, sccp::InitializeSccpV1},
        sccp::params::{SCCP_MIN_EPOCH_MS_V1, SccpParametersV1},
    };

    let manifest = RawGenesisTransaction::from_path(directory.join("genesis.json"))
        .expect("canonical Taira manifest");
    let initializers = manifest
        .transactions()
        .iter()
        .enumerate()
        .flat_map(|(position, batch)| {
            batch.instructions().iter().filter_map(move |instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<InitializeSccpV1>()
                    .map(|initializer| (position, initializer))
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(initializers.len(), 1, "SCCP initializes exactly once");
    let (position, initializer) = initializers[0];
    assert_eq!(manifest.transactions()[position].instructions().len(), 1);
    assert_eq!(initializer.parameters, SccpParametersV1::taira_default());
    assert_ne!(initializer.reset_nonce, [0; 32]);
    assert!(
        !manifest
            .instructions()
            .any(|instruction| { instruction.as_any().is::<ProposeSccpRouteGovernance>() }),
        "genesis installs no routes or substitute Parliament decisions"
    );

    let registrations = manifest.transactions()[..position]
        .iter()
        .flat_map(iroha_genesis::RawGenesisTx::instructions)
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
        })
        .filter(|registration| registration.lane_id == LaneId::SINGLE)
        .collect::<Vec<_>>();
    assert_eq!(
        registrations.len(),
        4,
        "four global stake registrations precede SCCP"
    );
    for registration in &registrations {
        assert_eq!(registration.validator, registration.stake_account);
        assert!(!registration.initial_stake.is_zero());
        assert_eq!(
            registration.peer_id.public_key().algorithm(),
            iroha_crypto::Algorithm::BlsNormal
        );
    }
    let mut registered = registrations
        .iter()
        .map(|registration| registration.peer_id.clone())
        .collect::<Vec<_>>();
    registered.sort();
    assert!(registered.windows(2).all(|pair| pair[0] != pair[1]));
    let signed = read_signed_genesis(&directory.join("genesis.signed.nrt"))
        .expect("native executed signed genesis");
    let (epoch, _) = iroha_data_model::sumeragi_finality::authenticated_genesis(&signed)
        .expect("original signed native committee")
        .into_parts();
    assert_eq!(
        epoch
            .committee
            .iter()
            .map(|member| member.validator.clone())
            .collect::<Vec<_>>(),
        registered
    );
    assert!(
        signed
            .output_results()
            .all(|result| result.as_ref().is_ok())
    );

    let parameters = manifest.effective_parameters().unwrap();
    let npos = SumeragiNposParameters::from_custom_parameter(
        parameters
            .custom()
            .get(&SumeragiNposParameters::parameter_id())
            .unwrap(),
    )
    .unwrap()
    .unwrap();
    let timing = parameters.sumeragi();
    assert_eq!(timing.epoch_length_blocks, npos.epoch_length_blocks);
    assert!(
        timing.epoch_length_blocks.get() * timing.block_cadence_ms().get() >= SCCP_MIN_EPOCH_MS_V1
    );
    for index in 0..4 {
        let config: toml::Value = toml::from_str(
            &fs::read_to_string(directory.join(format!("peer{index}.toml"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            config["nexus"]["staking"]["unbonding_delay_ms"].as_integer(),
            Some(1_814_400_000)
        );
        assert_eq!(
            config["nexus"]["staking"]["max_slash_bps"].as_integer(),
            Some(10_000)
        );
    }
    let nonce = initializer.reset_nonce;
    let hash: [u8; 32] = *signed.hash().as_ref();
    assert_eq!(
        fs::read(history.join(format!("nonce-{}", hex::encode(nonce)))).unwrap(),
        b"sccp-reset-v1\n"
    );
    assert_eq!(
        fs::read_to_string(history.join(format!("consumed-nonce-{}", hex::encode(nonce)))).unwrap(),
        hex::encode(hash)
    );
    assert_eq!(
        fs::read_to_string(history.join(format!("network-{}", hex::encode(hash)))).unwrap(),
        hex::encode(nonce)
    );
    (nonce, hash, registered)
}

#[test]
fn sccp_canonical_taira_resets_keep_native_stake_authority_and_fresh_consumed_nonces() {
    // This generator writes ephemeral signing keys. Use the same private, RAII-owned
    // external runtime directory as the other native Taira generator tests.
    let temporary = crate::localnet::localnet_test_helpers::private_tempdir()
        .expect("private runtime outside the checkout");
    let history = temporary.path().join("sccp-reset-history");
    let _chain_discriminant = ChainDiscriminantGuard::enter(
        known_chain_discriminant_for_chain_id(PUBLIC_TAIRA_CHAIN_ID).unwrap(),
    );
    let mut identities = Vec::new();
    for name in ["first", "second"] {
        let directory = iroha_fs::PrivateDirectory::open_or_create(temporary.path().join(name))
            .expect("private reset output");
        let options = canonical_taira_options(directory.path(), "sccp-same-seed-reset");
        generate_localnet_with_chain(
            &options,
            &mut BufWriter::new(Vec::new()),
            Some(PUBLIC_TAIRA_CHAIN_ID),
            None,
        )
        .expect("canonical SCCP Taira reset");
        identities.push(assert_sccp_localnet_profile(directory.path(), &history));
    }
    assert_ne!(
        identities[0].0, identities[1].0,
        "seed reuse must not reuse the nonce"
    );
    assert_ne!(
        identities[0].1, identities[1].1,
        "each reset has a new signed network identity"
    );
    assert_eq!(
        identities[0].2, identities[1].2,
        "both resets retain the same seeded native validators"
    );
    assert_eq!(
        fs::read_dir(history).unwrap().count(),
        6,
        "both resets keep reservation, consumption and identity markers"
    );
}
