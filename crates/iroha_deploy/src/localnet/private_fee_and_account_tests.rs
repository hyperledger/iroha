#[test]
fn private_profile_fee_policy_is_signed_and_absent_from_node_config() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    for (profile, label, base_port) in [
        (SoraProfile::PrivateSbp, "sbp", 28_080_u16),
        (SoraProfile::PrivateCbuae, "cbuae", 29_080_u16),
        (SoraProfile::PrivateBpng, "bpng", 30_080_u16),
    ] {
        let out_dir = temp.path().join(label);
        let opts = LocalnetOptions {
            service_profile: crate::localnet::LocalnetServiceProfile::Standard,
            sora_profile: Some(profile),
            perf_profile: None,
            peers: NonZeroU16::new(4).expect("non-zero"),
            seed: Some(format!("private-direct-settlement-{label}")),
            bind_host: DEFAULT_BIND_HOST.to_owned(),
            public_host: DEFAULT_PUBLIC_HOST.to_owned(),
            base_api_port: base_port,
            base_p2p_port: base_port.saturating_add(257),
            out_dir: out_dir.clone(),
            extra_accounts: 0,
            assets: Vec::new(),
            block_cadence_ms: None,
            consensus_mode: SumeragiConsensusMode::Npos,
        };
        generate_localnet(&opts, &mut BufWriter::new(Vec::new()))
            .unwrap_or_else(|error| panic!("generate {label} localnet: {error:#}"));
        let signed = read_signed_genesis(&out_dir.join("genesis.signed.nrt"))
            .expect("canonical generated signed genesis");
        let expected: NetworkId = fs::read_to_string(out_dir.join("genesis.expected_hash"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(signed.hash(), expected.into_genesis_hash());
        let fees = iroha_genesis::signed_genesis_root_fee_policy(&signed)
            .expect("complete authenticated root fee policy");
        let generated_custody = localnet_gas_account_id(
            signed
                .external_transactions()
                .next()
                .unwrap()
                .authority()
                .try_signatory()
                .unwrap(),
        );
        assert_eq!(fees.fee_asset_id, localnet_xor_asset_definition_id());
        assert_eq!(fees.fee_sink_account_id, generated_custody);
        assert_eq!(fees.sponsor_vault_custody_account_id, generated_custody);
        assert!(fees.successful_claim_fee_exempt_authorities.is_empty());
        assert_eq!(fees.base_fee, Quantity::zero());
        assert_eq!(fees.per_byte_fee, Quantity::zero());
        assert_eq!(fees.per_instruction_fee, "0.001".parse().unwrap());
        assert_eq!(fees.per_gas_unit_fee, "0.00005".parse().unwrap());
        for peer in 0..4 {
            let peer_cfg: toml::Value = toml::from_str(
                &fs::read_to_string(out_dir.join(format!("peer{peer}.toml")))
                    .expect("read generated peer config"),
            )
            .expect("parse peer config");
            assert!(
                peer_cfg
                    .get("nexus")
                    .and_then(|nexus| nexus.get("fees"))
                    .is_none(),
                "private {label} peer {peer} cannot author monetary terms"
            );
        }
    }
}
#[test]
fn account_id_raw_string_parses_as_account_id() {
    let seed_bytes = Some(b"localnet-gas-parse".as_slice());
    let (genesis_public_key, _) = generate_genesis_key_pair(seed_bytes, GENESIS_SEED)
        .expect("test localnet genesis key generation should succeed");
    let gas_account_id = localnet_gas_account_id(&genesis_public_key);
    let encoded = account_id_raw_string(&gas_account_id);
    let parsed = AccountId::parse_encoded(&encoded).expect("account id parse");
    assert_eq!(parsed, gas_account_id);
}
