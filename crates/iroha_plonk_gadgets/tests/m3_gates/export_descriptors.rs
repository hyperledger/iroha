//! Export exact current M3 workload descriptors for isolated evaluator diagnostics.
//! Exports exact source-fingerprint descriptors, no commitment generation or keys.
use super::*;
use std::io::Write as _;

fn export<C, Ci>(root: &Path, name: &str, circuit: &Ci) -> norito::json::Value
where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    Ci: Circuit<C::ScalarExt>,
{
    let (params, _) = pinned_params::<C>(K);
    let source = iroha_plonk::keys::source_fingerprint_v2(
        &params,
        &circuit.without_witnesses(),
        &measurement_key_config(),
        None,
    )
    .unwrap();
    let bytes = source.binding().encoded();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(name))
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    norito::json!({
        "name": name, "bytes": (bytes.len()), "sha256": (hex(&Sha256::digest(bytes))),
        "descriptor_digest": (hex(source.binding().digest())),
        "lookup_only_fingerprint": (hex(source.digest())),
    })
}

#[test]
#[ignore = "explicit source descriptor export for DAG experiment; no proof or key qualification"]
fn actual_m3_source_descriptors_for_dag_experiment() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let output = PathBuf::from(std::env::var_os("DAG_DESCRIPTOR_OUTPUT").unwrap());
    assert!(output.is_absolute());
    let parent = output.parent().unwrap();
    assert_eq!(parent.canonicalize().unwrap(), parent);
    assert!(parent.starts_with(repo.join("target")));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(&output).unwrap();
    let q = export::<Pallas, _>(
        &output,
        "q-chips.descriptor",
        &q_leaf(Q_VARIABLE, Q_FIXED, 60),
    );
    let a = export::<Vesta, _>(&output, "a-chips.descriptor", &a_load(70));
    let manifest = norito::json!({
        "scope": "Exact current source descriptor DATA; not keys, source qualification, satisfying witness or timing evidence",
        "descriptors": [q, a],
    });
    let bytes = norito::json::to_json(&manifest).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("manifest.json"))
        .unwrap();
    file.write_all(bytes.as_bytes()).unwrap();
    file.sync_all().unwrap();
    std::fs::File::open(output).unwrap().sync_all().unwrap();
}
