use super::*;
use iroha_core::{
    state::World,
    sumeragi::{
        finality::build_checkpoint,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;

fn fixture() -> (SumeragiFinalityCheckpoint, Vec<u8>, [u8; 32], [u8; 32]) {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    let checkpoint = build_checkpoint(&chain.state().view(), 2).unwrap();
    let bytes = checkpoint.encode_canonical().unwrap();
    let (_, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
        &checkpoint,
        &chain.network_id(),
        checkpoint.chain_id(),
    )
    .unwrap();
    let sha = sha256(&bytes).into();
    let context = *tip.context_id().as_ref();
    (checkpoint, bytes, sha, context)
}

#[test]
fn selected_checkpoint_authenticates_actual_native_tip() {
    let (checkpoint, bytes, sha, context) = fixture();
    let result = verify_fi_checkpoint_selection(
        &bytes,
        checkpoint.network_id(),
        checkpoint.chain_id(),
        sha,
        2,
        context,
    )
    .unwrap();
    assert_eq!(result.height, 2);
    assert_eq!(result.context_id, context);
    assert_eq!(result.block_hash, *checkpoint.block_hash().as_ref());
    let json: norito::json::Value = norito::json::from_slice(&result.to_json()).unwrap();
    assert_eq!(json["height"].as_str(), Some("2"));
    assert_ne!(result.context_id, result.block_hash);
}

#[test]
fn checkpoint_selection_refuses_foreign_pins_network_chain_and_bytes() {
    let (checkpoint, bytes, sha, context) = fixture();
    let verify = |wire: &[u8], digest, height, ctx, network, chain| {
        verify_fi_checkpoint_selection(wire, network, chain, digest, height, ctx)
    };
    let network = checkpoint.network_id();
    let chain = checkpoint.chain_id();
    for height in [0, 1, 3, u64::MAX] {
        assert!(verify(&bytes, sha, height, context, network, chain).is_err());
    }
    assert!(verify(&bytes, [1; 32], 2, context, network, chain).is_err());
    assert!(verify(&bytes, sha, 2, [1; 32], network, chain).is_err());
    assert!(verify(&bytes, sha, 2, context, network, "foreign").is_err());
    let other = NativeFinalityFixture::start_with_explicit_parameters("foreign");
    assert!(verify(&bytes, sha, 2, context, other.network_id(), chain).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(
        verify(
            &trailing,
            sha256(&trailing).into(),
            2,
            context,
            network,
            chain
        )
        .is_err()
    );
    assert!(verify(&[], sha256([]).into(), 2, context, network, chain).is_err());
    let malformed = b"not a canonical checkpoint";
    assert!(
        verify(
            malformed,
            sha256(malformed).into(),
            2,
            context,
            network,
            chain
        )
        .is_err()
    );
}

#[test]
fn checkpoint_selection_refuses_authenticated_private_root() {
    let parent = NativeFinalityFixture::new();
    let private = NativeFinalityFixture::start_with_scope(
        "private-checkpoint",
        SumeragiRootScope::Dataspace {
            parent_network_id: parent.network_id(),
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(9),
        },
    );
    let checkpoint = private.checkpoint();
    let bytes = checkpoint.encode_canonical().unwrap();
    let (_, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
        &checkpoint,
        &private.network_id(),
        private.chain_id(),
    )
    .unwrap();
    assert_ne!(tip.root_scope(), SumeragiRootScope::Global);
    assert!(
        verify_fi_checkpoint_selection(
            &bytes,
            private.network_id(),
            private.chain_id(),
            sha256(&bytes).into(),
            tip.height(),
            *tip.context_id().as_ref()
        )
        .is_err()
    );
}

#[test]
fn checkpoint_ffi_clears_outputs_and_rejects_noncanonical_height() {
    let (checkpoint, bytes, sha, context) = fixture();
    let network = checkpoint.network_id().to_string();
    let chain = checkpoint.chain_id();
    let mut output = std::ptr::dangling_mut::<u8>();
    let mut length = 99;
    let oversized_status = unsafe {
        connect_norito_verify_fi_checkpoint_selection_v1(
            bytes.as_ptr(),
            (MAX_FINALITY_CHECKPOINT_BYTES + 1) as c_ulong,
            network.as_ptr(),
            network.len() as c_ulong,
            chain.as_ptr(),
            chain.len() as c_ulong,
            sha.as_ptr(),
            32,
            b"2".as_ptr(),
            1,
            context.as_ptr(),
            32,
            &mut output,
            &mut length,
        )
    };
    assert_ne!(oversized_status, 0);
    assert!(output.is_null());
    assert_eq!(length, 0);
    for height in ["", "02", "+2", "-2", "18446744073709551616"] {
        let mut output = std::ptr::dangling_mut::<u8>();
        let mut length = 99;
        let status = unsafe {
            connect_norito_verify_fi_checkpoint_selection_v1(
                bytes.as_ptr(),
                bytes.len() as c_ulong,
                network.as_ptr(),
                network.len() as c_ulong,
                chain.as_ptr(),
                chain.len() as c_ulong,
                sha.as_ptr(),
                32,
                height.as_ptr(),
                height.len() as c_ulong,
                context.as_ptr(),
                32,
                &mut output,
                &mut length,
            )
        };
        assert_ne!(status, 0);
        assert!(output.is_null());
        assert_eq!(length, 0);
    }
    let mut output = std::ptr::null_mut();
    let mut length = 0;
    let status = unsafe {
        connect_norito_verify_fi_checkpoint_selection_v1(
            bytes.as_ptr(),
            bytes.len() as c_ulong,
            network.as_ptr(),
            network.len() as c_ulong,
            chain.as_ptr(),
            chain.len() as c_ulong,
            sha.as_ptr(),
            32,
            b"2".as_ptr(),
            1,
            context.as_ptr(),
            32,
            &mut output,
            &mut length,
        )
    };
    assert_eq!(status, 0);
    assert!(!output.is_null());
    assert!(length > 0 && length < 1024);
    crate::connect_norito_free(output);
}
