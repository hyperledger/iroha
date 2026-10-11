// Repository-fixture coverage for deterministic bundled rANS tables.
#[test]
fn load_bundle_tables_accepts_repo_fixture() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../codec/rans/tables/rans_seed0.toml");
    let tables = load_bundle_tables_from_toml(&path)
        .unwrap_or_else(|err| panic!("failed to load {}: {err}", path.display()));
    assert!(
        tables.max_width() >= 2,
        "expected deterministic tables fixture to expose bundled widths"
    );
}

#[test]
fn supplied_bundle_tables_share_file_validation_without_opening_a_path() {
    let text = include_str!("../../../../codec/rans/tables/rans_seed0.toml");
    let supplied = parse_bundle_tables_from_toml(text).expect("canonical supplied tables");
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../codec/rans/tables/rans_seed0.toml");
    let file = load_bundle_tables_from_toml(path).expect("same ordinary file tables");
    assert_eq!(supplied.checksum(), file.checksum());
    assert_eq!(supplied.precision_bits(), file.precision_bits());
    assert_eq!(supplied.max_width(), file.max_width());
    struct InputFile(std::path::PathBuf);
    impl Drop for InputFile {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).unwrap();
        }
    }
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let input_path = std::env::temp_dir().join(format!(
        "norito-rans-source-{}-{}.toml",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&input_path)
        .unwrap();
    let input = InputFile(input_path);
    for invalid in [
        "invalid TOML".to_owned(),
        text.replacen("[payload]\n", "[payload]\nretired_selector = true\n", 1),
        text.replace("[payload]\n", ""),
    ] {
        std::fs::write(&input.0, &invalid).unwrap();
        let supplied = parse_bundle_tables_from_toml(&invalid).unwrap_err();
        let native = load_bundle_tables_from_toml(&input.0).unwrap_err();
        assert_eq!(native.to_string(), supplied.to_string());
    }
    // The ordinary parser accepts valid TOML regardless of nonsemantic comment padding.
    let padded = format!("{text}\n#{}\n", "x".repeat(64 * 1024));
    std::fs::write(&input.0, &padded).unwrap();
    let supplied = parse_bundle_tables_from_toml(&padded).unwrap();
    let native = load_bundle_tables_from_toml(&input.0).unwrap();
    assert_eq!(supplied.checksum(), native.checksum());
    assert_eq!(supplied.precision_bits(), native.precision_bits());
    assert_eq!(supplied.max_width(), native.max_width());
}
