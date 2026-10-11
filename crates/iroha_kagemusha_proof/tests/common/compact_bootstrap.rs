//! Real compact Bootstrap with its actual immutable outer key in every signed
//! object and source proof. The catalog contains one terminal only; broader
//! catalog, operation and performance qualification remain separate gates.

include!("proof_fixtures/compact_bootstrap_body.rs");

#[test]
#[ignore = "actual authenticated source chain rebuilt under its compact outer key; run optimized"]
fn compact_bootstrap_binds_its_actual_immutable_outer_key() {
    let artifact = rooted_compact_bootstrap();
    assert_eq!(artifact.proof.len() + 1088, 4800);
    assert_eq!(
        artifact.source.state.lineage[17],
        artifact.key.kagemusha_digest(&artifact.binding).unwrap(),
    );
}

#[path = "proof_fixtures/omega_hard_fixture_export.rs"]
mod omega_hard_fixture_export;

/// Retain the existing current Bootstrap success without proving a successor.
#[test]
#[ignore = "genuine current Bootstrap; explicit fresh export and source/binary receipt required; run optimized"]
fn compact_bootstrap_exports_native_hard_fixture() {
    use omega_hard_fixture_export::{ExportRequest, NativeBundle};
    let request = ExportRequest::from_env();
    let artifact = rooted_compact_bootstrap();
    request.export(NativeBundle {
        descriptor: artifact.binding.encoded(),
        key: &artifact.key.to_bytes(),
        proof: &artifact.proof,
        public: &artifact.source.state.lineage,
        pallas: &artifact.source.pallas,
        vesta: &artifact.vesta,
        instances: &artifact.instances,
    });
}
