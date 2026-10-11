//! Canonical configuration parsing consumes exact supplied references and bounded private files.

use super::*;
use std::{
    cell::RefCell,
    sync::atomic::{AtomicUsize, Ordering},
};

struct Files {
    values: BTreeMap<PathBuf, (ConfigFileAccess, zeroize::Zeroizing<Vec<u8>>)>,
    reads: RefCell<Vec<PathBuf>>,
}
impl ConfigFileSource for Files {
    fn read(
        &self,
        path: &Path,
        request: ConfigFileRequest,
    ) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
        self.reads.borrow_mut().push(path.to_path_buf());
        let (access, bytes) = self.values.get(path).ok_or(io::ErrorKind::NotFound)?;
        if request.access != *access {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // The parser itself must enforce the caller-owned bound.
        Ok(zeroize::Zeroizing::new(bytes.to_vec()))
    }
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "iroha-config-source-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&path).unwrap();
        Self(path)
    }
    fn write(&self, path: &Path, bytes: &[u8]) {
        use std::io::Write as _;
        assert_eq!(path.parent(), Some(self.0.as_path()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options.open(path).unwrap().write_all(bytes).unwrap();
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fixture(path: &Path) -> (toml::Table, Files) {
    let mut table: toml::Table = include_str!("../../../tests/fixtures/base.toml")
        .parse()
        .unwrap();
    let root = path.parent().unwrap();
    let mut values = BTreeMap::new();
    for (inline, file, name) in [
        ("private_key", "private_key_file", "validator.key"),
        (
            "soranet_transport_private_key",
            "soranet_transport_private_key_file",
            "transport.key",
        ),
    ] {
        let bytes = table.remove(inline).unwrap().as_str().unwrap().to_owned();
        values.insert(
            root.join(name),
            (
                ConfigFileAccess::Private,
                zeroize::Zeroizing::new(format!("{bytes}\n").into_bytes()),
            ),
        );
        table.insert(file.into(), toml::Value::String(name.into()));
    }
    let genesis = table.get_mut("genesis").unwrap().as_table_mut().unwrap();
    let identity = genesis
        .remove("expected_hash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    genesis.insert(
        "expected_hash_file".into(),
        toml::Value::String("genesis.expected_hash".into()),
    );
    values.insert(
        root.join("genesis.expected_hash"),
        (
            ConfigFileAccess::Public,
            zeroize::Zeroizing::new(format!("{identity}\n").into_bytes()),
        ),
    );
    let streaming = table.get_mut("streaming").unwrap().as_table_mut().unwrap();
    let key = streaming
        .remove("identity_private_key")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    streaming.insert(
        "identity_private_key_file".into(),
        toml::Value::String("stream.key".into()),
    );
    values.insert(
        root.join("stream.key"),
        (
            ConfigFileAccess::Private,
            zeroize::Zeroizing::new(format!("{key}\n").into_bytes()),
        ),
    );
    // This nested value uses the canonical JSON shape, whose fields are explicit.
    let mut codec = toml::toml! {
        cabac_mode = "disabled"
        trellis_blocks = []
    };
    // Inner JSON WithOrigin values are inline; generated profiles name this table absolutely.
    codec.insert(
        "rans_tables_path".into(),
        toml::Value::String(root.join("tables.toml").to_string_lossy().into_owned()),
    );
    codec.insert(
        "entropy_mode".into(),
        toml::Value::String(defaults::streaming::codec::entropy_mode()),
    );
    codec.insert(
        "bundle_width".into(),
        toml::Value::Integer(i64::from(defaults::streaming::codec::bundle_width())),
    );
    codec.insert(
        "bundle_accel".into(),
        toml::Value::String(defaults::streaming::codec::bundle_accel()),
    );
    streaming.insert("codec".into(), toml::Value::Table(codec));
    values.insert(
        root.join("tables.toml"),
        (
            ConfigFileAccess::Public,
            zeroize::Zeroizing::new(
                include_bytes!("../../../../../codec/rans/tables/rans_seed0.toml").to_vec(),
            ),
        ),
    );
    let public: PublicKey = streaming["identity_public_key"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let authority = AccountId::new(public).to_string();
    let torii = table.get_mut("torii").unwrap().as_table_mut().unwrap();
    let onboarding_path = root.join("onboarding.key").to_string_lossy().into_owned();
    let faucet_path = root.join("faucet.key").to_string_lossy().into_owned();
    let mut onboarding = toml::toml! {
        credentials = [{ id = "test", scope = { dataspace = "universal" }, token_hash = "blake3:1111111111111111111111111111111111111111111111111111111111111111" }]
    };
    onboarding.insert("authority".into(), toml::Value::String(authority.clone()));
    onboarding.insert(
        "private_key_file".into(),
        toml::Value::String(onboarding_path),
    );
    torii.insert("account_onboarding".into(), toml::Value::Table(onboarding));
    let mut faucet = toml::toml! {
        enabled = true
        asset_definition_id = "xor#universal"
        amount = "1"
    };
    for (name, value) in [
        (
            "pow_difficulty_bits",
            u64::from(defaults::torii::faucet::POW_DIFFICULTY_BITS),
        ),
        (
            "pow_scrypt_log_n",
            u64::from(defaults::torii::faucet::POW_SCRYPT_LOG_N),
        ),
        (
            "pow_scrypt_r",
            u64::from(defaults::torii::faucet::POW_SCRYPT_R),
        ),
        (
            "pow_scrypt_p",
            u64::from(defaults::torii::faucet::POW_SCRYPT_P),
        ),
        (
            "pow_max_anchor_age_blocks",
            defaults::torii::faucet::POW_MAX_ANCHOR_AGE_BLOCKS.get(),
        ),
        (
            "pow_adaptive_lookback_blocks",
            defaults::torii::faucet::POW_ADAPTIVE_LOOKBACK_BLOCKS,
        ),
        (
            "pow_adaptive_claims_per_extra_bit",
            defaults::torii::faucet::POW_ADAPTIVE_CLAIMS_PER_EXTRA_BIT,
        ),
        (
            "pow_adaptive_max_extra_bits",
            u64::from(defaults::torii::faucet::POW_ADAPTIVE_MAX_EXTRA_BITS),
        ),
    ] {
        faucet.insert(
            name.into(),
            toml::Value::Integer(i64::try_from(value).unwrap()),
        );
    }
    faucet.insert(
        "pow_beacon_seed_enabled".into(),
        toml::Value::Boolean(defaults::torii::faucet::POW_BEACON_SEED_ENABLED),
    );
    faucet.insert("authority".into(), toml::Value::String(authority));
    faucet.insert("private_key_file".into(), toml::Value::String(faucet_path));
    torii.insert("faucet".into(), toml::Value::Table(faucet));
    for name in ["onboarding.key", "faucet.key"] {
        values.insert(
            root.join(name),
            (
                ConfigFileAccess::Private,
                zeroize::Zeroizing::new(format!("{key}\n").into_bytes()),
            ),
        );
    }
    (
        table,
        Files {
            values,
            reads: RefCell::new(Vec::new()),
        },
    )
}

fn user(table: toml::Table, path: &Path) -> Root {
    ConfigReader::new()
        .without_env()
        .with_toml_source(iroha_config_base::toml::TomlSource::new(
            path.to_path_buf(),
            table,
        ))
        .read_and_complete::<Root>()
        .unwrap()
}

#[test]
fn complete_node_parser_reads_every_reference_from_supplied_bytes_and_preserves_origins() {
    let directory = Directory::new();
    let path = directory.0.join("not-created/peer.toml");
    let (table, files) = fixture(&path);
    let parsed = user(table, &path).parse_with_file_source(&files).unwrap();
    assert_eq!(
        files
            .reads
            .borrow()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        files.values.keys().cloned().collect()
    );
    assert_eq!(
        parsed.streaming.codec.rans_tables_path,
        path.with_file_name("tables.toml")
    );
    assert!(parsed.torii.account_onboarding.is_some());
    assert!(parsed.torii.faucet.is_some());
    assert!(!path.parent().unwrap().exists());
}

#[test]
fn supplied_node_files_match_native_inputs_and_never_fall_back_to_existing_files() {
    let directory = Directory::new();
    let path = directory.0.join("peer.toml");
    let (mut table, mut files) = fixture(&path);
    // Native codec path selection is unchanged; an explicit absolute path names the same input.
    table
        .get_mut("streaming")
        .unwrap()
        .get_mut("codec")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert(
            "rans_tables_path".into(),
            toml::Value::String(
                directory
                    .0
                    .join("tables.toml")
                    .to_string_lossy()
                    .into_owned(),
            ),
        );
    for (path, (_, bytes)) in &files.values {
        directory.write(path, bytes);
    }
    let native = user(table.clone(), &path).parse().unwrap();
    let supplied = user(table.clone(), &path)
        .parse_with_file_source(&files)
        .unwrap();
    assert!(native.common.key_pair == supplied.common.key_pair);
    assert!(native.common.soranet_transport_key_pair == supplied.common.soranet_transport_key_pair);
    assert_eq!(native.genesis.expected_hash, supplied.genesis.expected_hash);
    assert_eq!(
        native.streaming.codec.rans_tables_path,
        supplied.streaming.codec.rans_tables_path
    );
    let mut oversized_key = files.values[&directory.0.join("onboarding.key")].1.to_vec();
    oversized_key.resize(4097, b'\n');
    assert!(
        std::str::from_utf8(&oversized_key)
            .unwrap()
            .trim_end_matches(['\r', '\n'])
            .parse::<PrivateKey>()
            .is_ok()
    );
    for (name, bad) in [
        ("genesis.expected_hash", vec![b'x'; 513]),
        ("onboarding.key", oversized_key),
        ("faucet.key", b"invalid key\n".to_vec()),
        ("tables.toml", vec![b' '; 64 * 1024 + 1]),
    ] {
        let key = directory.0.join(name);
        let before = std::mem::replace(
            &mut files.values.get_mut(&key).unwrap().1,
            zeroize::Zeroizing::new(bad),
        );
        let error = user(table.clone(), &path)
            .parse_with_file_source(&files)
            .unwrap_err();
        if name == "onboarding.key" {
            assert!(
                format!("{error:?}").contains("configuration file exceeds the parser byte bound")
            );
        }

        files.values.get_mut(&key).unwrap().1 = before;
    }
    let mut conflicting = table.clone();
    conflicting.insert(
        "private_key".into(),
        toml::Value::String(
            "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F".into(),
        ),
    );
    let error = user(conflicting, &path)
        .parse_with_file_source(&files)
        .unwrap_err();
    assert!(format!("{error:?}").contains("mutually exclusive"));
    let onboarding_path = directory.0.join("onboarding.key");
    let faucet_path = directory.0.join("faucet.key");
    let original_onboarding = std::mem::replace(
        &mut files.values.get_mut(&onboarding_path).unwrap().1,
        zeroize::Zeroizing::new(b"private-sentinel-onboarding".to_vec()),
    );
    let original_faucet = std::mem::replace(
        &mut files.values.get_mut(&faucet_path).unwrap().1,
        zeroize::Zeroizing::new(b"private-sentinel-faucet".to_vec()),
    );
    let error = user(table.clone(), &path)
        .parse_with_file_source(&files)
        .unwrap_err();
    let diagnostic = format!("{error:?}");
    assert!(diagnostic.contains("torii.account_onboarding.private_key_file"));
    assert!(diagnostic.contains("torii.faucet.private_key_file"));
    assert!(!diagnostic.contains("private-sentinel"));
    files.values.get_mut(&onboarding_path).unwrap().1 = original_onboarding;
    files.values.get_mut(&faucet_path).unwrap().1 = original_faucet;
    let tables_path = directory.0.join("tables.toml");
    let mut padded = files.values[&tables_path].1.to_vec();
    padded.extend_from_slice(format!("\n#{}\n", "x".repeat(64 * 1024)).as_bytes());
    fs::write(&tables_path, &padded).unwrap();
    assert!(user(table.clone(), &path).parse().is_ok());
    let original_tables = std::mem::replace(
        &mut files.values.get_mut(&tables_path).unwrap().1,
        zeroize::Zeroizing::new(padded),
    );
    assert!(
        user(table.clone(), &path)
            .parse_with_file_source(&files)
            .is_err()
    );
    files.values.get_mut(&tables_path).unwrap().1 = original_tables;
    fs::write(&tables_path, files.values[&tables_path].1.as_slice()).unwrap();
    user(table.clone(), &path)
        .parse()
        .expect("all disk inputs remain valid before one-at-a-time source refusals");
    let references: Vec<_> = files.values.keys().cloned().collect();
    assert_eq!(references.len(), 7);
    for missing in references {
        user(table.clone(), &path)
            .parse_with_file_source(&files)
            .expect("every supplied input is valid immediately before removing one");
        let input = files.values.remove(&missing).unwrap();
        files.reads.borrow_mut().clear();
        let error = user(table.clone(), &path)
            .parse_with_file_source(&files)
            .expect_err("valid disk bytes must not replace one absent supplied input");
        assert!(files.reads.borrow().contains(&missing));
        let name = missing.file_name().unwrap().to_str().unwrap();
        if name == "tables.toml" {
            // Nested codec values have Inline origins; their canonical diagnostic does not
            // display the stored path. Validate the typed refusal and field instead.
            assert!(error.frames().any(|frame| matches!(
                frame.downcast_ref::<ParseError>(),
                Some(ParseError::InvalidStreamingConfig)
            )));
            assert!(error.frames().any(|frame| matches!(
                frame.downcast_ref::<norito::streaming::BundleTableError>(),
                Some(norito::streaming::BundleTableError::Io(error))
                    if error.kind() == io::ErrorKind::NotFound
            )));
            assert!(format!("{error:?}").contains("streaming.codec.rans_tables_path"));
        } else {
            assert!(
                format!("{error:?}").contains(name),
                "missing {name} must identify its source"
            );
        }
        files.values.insert(missing, input);
    }
}

#[test]
fn default_onboarding_and_faucet_key_readers_refuse_oversize_and_unsafe_permissions() {
    let directory = Directory::new();
    let path = directory.0.join("key");
    let key = "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F\n";
    directory.write(&path, key.as_bytes());
    for reader in [
        AccountOnboarding::load_private_key,
        ToriiFaucet::load_private_key,
    ] {
        let mut emitter = Emitter::new();
        assert!(reader(&path, &mut emitter, &ConfigFiles::Native).is_some());
        assert!(emitter.into_result().is_ok());
    }
    let mut oversized_key = key.as_bytes().to_vec();
    oversized_key.resize(4097, b'\n');
    assert!(
        std::str::from_utf8(&oversized_key)
            .unwrap()
            .trim_end_matches(['\r', '\n'])
            .parse::<PrivateKey>()
            .is_ok()
    );
    fs::write(&path, &oversized_key).unwrap();
    for reader in [
        AccountOnboarding::load_private_key,
        ToriiFaucet::load_private_key,
    ] {
        let mut emitter = Emitter::new();
        assert!(reader(&path, &mut emitter, &ConfigFiles::Native).is_none());
        let error = emitter.into_result().unwrap_err();
        assert!(format!("{error:?}").contains("configuration file exceeds the parser byte bound"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::write(&path, key).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        for reader in [
            AccountOnboarding::load_private_key,
            ToriiFaucet::load_private_key,
        ] {
            let mut emitter = Emitter::new();
            assert!(reader(&path, &mut emitter, &ConfigFiles::Native).is_none());
            assert!(emitter.into_result().is_err());
        }
    }
}

#[test]
fn vpn_operator_key_reference_uses_supplied_bytes_and_native_defaults_without_fallback() {
    let directory = Directory::new();
    let path = directory.0.join("peer.toml");
    let (mut table, mut files) = fixture(&path);
    table
        .get_mut("streaming")
        .unwrap()
        .get_mut("codec")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert(
            "rans_tables_path".into(),
            toml::Value::String(
                directory
                    .0
                    .join("tables.toml")
                    .to_string_lossy()
                    .into_owned(),
            ),
        );
    let operator = KeyPair::try_from_seed(vec![0xD1; 32], Algorithm::Ed25519)
        .expect("valid VPN operator fixture");
    let operator_path = directory.0.join("vpn-operator.key");
    let mut vpn = toml::toml! {
        enabled = true
        operator_private_key_file = "vpn-operator.key"
        relay_id_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        guard_directory_path = "guard-directory.to"
    };
    vpn.insert(
        "operator_account_id".into(),
        toml::Value::String(AccountId::new(operator.public_key().clone()).to_string()),
    );
    vpn.insert(
        "guard_directory_digest_hex".into(),
        toml::Value::String("cd".repeat(32)),
    );
    table
        .get_mut("network")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert("soranet_vpn".into(), toml::Value::Table(vpn));
    files.values.insert(
        operator_path.clone(),
        (
            ConfigFileAccess::Private,
            zeroize::Zeroizing::new(
                format!(
                    "{}\n",
                    iroha_crypto::ExposedPrivateKey(operator.private_key().clone())
                )
                .into_bytes(),
            ),
        ),
    );
    let supplied = user(table.clone(), &path)
        .parse_with_file_source(&files)
        .expect("supplied VPN key must parse without any disk files");
    assert!(supplied.network.soranet_vpn.operator_key_pair.as_ref() == Some(&operator));
    assert!(files.reads.borrow().contains(&operator_path));
    assert!(!operator_path.exists());
    for (input, (_, bytes)) in &files.values {
        directory.write(input, bytes);
    }
    let native = user(table.clone(), &path)
        .parse()
        .expect("valid native VPN key");
    assert!(
        native.network.soranet_vpn.operator_key_pair
            == supplied.network.soranet_vpn.operator_key_pair
    );
    user(table.clone(), &path)
        .parse_with_file_source(&files)
        .expect("all supplied references are valid immediately before removing only VPN key");
    files.values.remove(&operator_path).unwrap();
    files.reads.borrow_mut().clear();
    // VPN configuration errors retain the existing canonical parser's panic policy.
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        user(table.clone(), &path).parse_with_file_source(&files)
    }))
    .expect_err("a valid native VPN key must not replace absent supplied bytes");
    let diagnostic = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("VPN parse diagnostic");
    assert!(diagnostic.contains("network.soranet_vpn.operator_private_key_file"));
    assert!(diagnostic.contains("vpn-operator.key"));
    assert!(files.reads.borrow().contains(&operator_path));
}
