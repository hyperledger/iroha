#[test]
fn localnet_uses_a_durable_fsync_policy() {
    assert_eq!(
        LOCALNET_KURA_FSYNC_MODE.parse::<FsyncMode>().unwrap(),
        FsyncMode::Batched
    );
    assert!("off".parse::<FsyncMode>().is_err());
}
#[cfg(unix)]
#[test]
fn owner_only_localnet_writer_sets_mode_before_write_and_refuses_overwrite() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir()
        .expect("make private writer temp dir");
    let path = crate::localnet::custody::prepare_empty_private_directory(temp.path())
        .expect("prepare private writer directory")
        .join("peer0.toml");
    write_owner_only_localnet_file(&path, b"private_key = 'secret'\n")
        .expect("write owner-only config");
    let mode = fs::metadata(&path)
        .expect("owner-only config metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    let error = write_owner_only_localnet_file(&path, b"private_key = 'replacement'\n")
        .expect_err("owner-only writer must not overwrite an existing config");
    assert!(error.to_string().contains("write owner-only localnet file"));
    assert_eq!(
        fs::read_to_string(path).expect("read preserved owner-only config"),
        "private_key = 'secret'\n"
    );
}
#[test]
fn genesis_key_files_are_canonical_consistent_and_non_overwriting() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir()
        .expect("make genesis key temp dir");
    let custody = crate::localnet::custody::prepare_empty_private_directory(
        &temp.path().join("genesis-custody"),
    )
    .expect("prepare genesis key custody directory");
    let public_path = custody.join(GENESIS_PUBLIC_KEY_FILE);
    let private_path = custody.join(GENESIS_PRIVATE_KEY_FILE);
    let (public_key, private_key) =
        KeyPair::try_from_seed(vec![41_u8; 32], iroha_crypto::Algorithm::Ed25519)
            .expect("derive fixture genesis key")
            .into_parts();
    let private_key = ExposedPrivateKey(private_key);
    write_genesis_key_files(&public_path, &private_path, &public_key, &private_key)
        .expect("write genesis key files");
    let public_record = fs::read_to_string(&public_path).expect("read public key file");
    assert_eq!(public_record, format!("{public_key}\n"));
    let private_record = fs::read_to_string(&private_path).expect("read private key file");
    assert_eq!(
        private_record,
        format!(
            "{}\n",
            private_key
                .try_to_multihash_string()
                .expect("canonical private key")
        )
    );
    let reconstructed = KeyPair::from_private_key(private_key.0.clone())
        .expect("derive public key from private file");
    assert_eq!(reconstructed.public_key(), &public_key);
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&private_path)
            .expect("private key metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(
        write_genesis_key_files(&public_path, &private_path, &public_key, &private_key).is_err(),
        "existing genesis key custody must never be overwritten"
    );
}
#[test]
fn raw_npos_genesis_receives_the_chain_bound_localnet_epoch_seed() {
    let chain_id = ChainId::from("pk3");
    let genesis = generate_raw_genesis(
        REAL_GENESIS_ACCOUNT_KEYPAIR.public_key(),
        SumeragiConsensusMode::Npos,
        chain_id.as_str(),
    )
    .expect("generate NPoS localnet genesis");
    let parameters = genesis
        .effective_parameters()
        .expect("generated NPoS genesis parameters");
    let npos = parameters
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()
        .expect("valid fixture NPoS parameters")
        .flatten()
        .expect("generated NPoS parameters");
    assert_eq!(npos.epoch_seed(), localnet_npos_epoch_seed(&chain_id));
    assert_ne!(npos.epoch_seed(), [0; 32]);
}
