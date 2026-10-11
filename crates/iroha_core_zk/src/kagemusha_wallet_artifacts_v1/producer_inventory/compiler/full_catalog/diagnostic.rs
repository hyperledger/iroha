//! Read-only source-shape diagnosis from partial engineering metadata, never admission.

use super::*;

fn metadata<C: PastaCurve>(root: &Path, name: &str) -> KeyArtifact<C> {
    // The PK prefix only locates independently hash-checked D/V files. It is not
    // a PK import, source qualification or authority to open a wallet.
    assert_eq!(name.len(), 64);
    assert!(name.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let mut reader = File::open(root.join(name)).unwrap();
    let mut header = [0; 44];
    reader.read_exact(&mut header).unwrap();
    assert_eq!(&header[..8], b"PIPAPK01");
    let length = u32::from_le_bytes(header[40..44].try_into().unwrap()) as usize;
    assert!(length <= VERIFYING_KEY_MAX_BYTES_V1);
    let mut vk = vec![0; length];
    reader.read_exact(&mut vk).unwrap();
    let identity = BlobV1::of(&vk);
    assert_eq!(
        pinned_file(
            &root.join(hex::encode(identity.sha256)),
            length,
            identity.sha256
        )
        .unwrap(),
        vk
    );
    let mut matching = None;
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.metadata().unwrap().len() > DESCRIPTOR_MAX_BYTES_V1 as u64 {
            continue;
        }
        let bytes = bounded_file(&entry.path(), DESCRIPTOR_MAX_BYTES_V1).unwrap();
        if let Ok(binding) = DescriptorBinding::decode_v2(&bytes) {
            assert_eq!(
                entry.file_name().to_str().unwrap(),
                hex::encode(BlobV1::of(&bytes).sha256)
            );
            if binding.digest() == &header[8..40] {
                assert!(matching.replace(binding).is_none());
            }
        }
    }
    let binding = matching.expect("retained exact descriptor");
    let key = VerifyingKey::read(&vk, &binding).unwrap();
    KeyArtifact::new(binding, key).unwrap()
}

#[test]
#[ignore = "explicit partial-original paths; source-shape diagnosis only"]
fn renewed_receive_first_source_from_retained_metadata() {
    let directory = PathBuf::from(std::env::var("KAGEMUSHA_DIAGNOSTIC_ORIGINALS").unwrap());
    let input = PathBuf::from(std::env::var("KAGEMUSHA_DIAGNOSTIC_INPUT").unwrap());
    let bytes = bounded_file(&input, 16_384).unwrap();
    let input: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    let sigmas: [KeyArtifact<Eq>; 16] =
        core::array::from_fn(|index| metadata(&directory, input["sigma"][index].as_str().unwrap()));
    let policy = bounded_file(
        &directory.parent().unwrap().join("source-policy.norito"),
        4_096,
    )
    .unwrap();
    let (provider, x, y): ([u128; 2], [u64; 4], [u64; 4]) = norito::decode_canonical_with_limits(
        &policy,
        norito::canonical_decode_limits(policy.len()),
    )
    .unwrap();
    let scope = SourceScopeV1::new(provider, Affine { x, y }).unwrap();
    let (source, signatures) =
        q_source_recipe(scope, Variant::ReceiveRenewed, &[10], &[2, 6], &sigmas).unwrap();
    let keys = (0..3)
        .map(|index| metadata(&directory, input["q"][index].as_str().unwrap()))
        .collect();
    let recipe = QProgramRecipeV1::from_metadata(source.plan().clone(), signatures, keys).unwrap();
    let omega = metadata(&directory, input["omega"].as_str().unwrap());
    let route = OperationRoute {
        variant: Variant::ReceiveRenewed,
        own: 10,
        incoming: Some(2),
    };
    let operation::Plan::Receive(plan) = operation::plan(route, scope, &recipe, &omega).unwrap()
    else {
        panic!("fixed Receive route");
    };
    let circuit = plan.source_circuit(0, None).unwrap();
    // This is the same public source factory and k as actual compilation. No
    // proof, PK, signed inventory or wallet grant is published by this test.
    match iroha_plonk::frontend::synthesize(&circuit, 16, None) {
        Ok(_) => eprintln!("SOURCE_DIAGNOSTIC route={route:?} stage=0 k=16 synthesis=ok"),
        Err(error) => panic!("SOURCE_DIAGNOSTIC route={route:?} stage=0 k=16 synthesis={error:?}"),
    }
    let read = ReadConfig {
        maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let params = PinnedParams::<Eq>::derive(16).unwrap();
    match keygen_pk_v2(
        &params,
        &circuit,
        &config(vec![InstanceType::Bounded], false, read),
    ) {
        Ok(_) => eprintln!("SOURCE_DIAGNOSTIC route={route:?} stage=0 k=16 key_generation=ok"),
        Err(error) => {
            panic!("SOURCE_DIAGNOSTIC route={route:?} stage=0 k=16 key_generation={error:?}")
        }
    }
}

#[test]
fn key_failure_preserves_typed_stage_and_resource_cause() {
    let route = OperationRoute {
        variant: Variant::ReceiveRenewed,
        own: 10,
        incoming: Some(2),
    };
    let source = KeyError::Synthesis(iroha_plonk::frontend::Error::BoundsFailure);
    let error = stage_error(
        CompilationErrorV1::KeyGeneration(source.clone()),
        route,
        3,
        true,
    );
    assert!(
        matches!(error, CompilationErrorV1::OperationKeyGeneration { route: actual, stage: 3, wrapper: true, source: actual_source } if actual == route && actual_source == source)
    );
    assert!(matches!(
        stage_error(CompilationErrorV1::Closure, route, 0, false),
        CompilationErrorV1::Closure
    ));
}
