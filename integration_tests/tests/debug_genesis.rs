#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Inspect genesis encoding/decoding behaviour for troubleshooting.
use integration_tests::sandbox;
use iroha_data_model::{
    block::{decode_framed_signed_block, deframe_versioned_signed_block_bytes},
    transaction::Executable,
};
use iroha_test_network::{NetworkBuilder, init_instruction_registry};
use norito::codec::{encode_adaptive, encode_with_header_flags};
#[test]
fn genesis_roundtrip_inspection() {
    init_instruction_registry();
    let Some(network) = sandbox::build_network_or_skip(
        NetworkBuilder::new()
            .with_peers(4)
            .with_auto_populated_trusted_peers(),
        stringify!(genesis_roundtrip_inspection),
    ) else {
        return;
    };
    let genesis = network.genesis();
    let sanity_wire = genesis.0.canonical_wire().expect("canonical genesis wire");
    assert_eq!(
        sanity_wire.payload(),
        encode_adaptive(&genesis.0).as_slice(),
        "the canonical wire carries the adaptive payload"
    );
    decode_framed_signed_block(sanity_wire.as_framed()).expect("sanity decode");
    for (tx_idx, tx) in genesis.0.external_transactions().enumerate() {
        if let Executable::Instructions(step) = tx.instructions() {
            eprintln!("tx#{tx_idx} instruction_count={}", step.len());
            for (inst_idx, inst) in step.iter().enumerate() {
                let (bytes, flags) = encode_with_header_flags(inst);
                eprintln!(
                    "tx#{tx_idx} inst#{inst_idx} len={} flags=0x{flags:02x} debug={:?}",
                    bytes.len(),
                    inst
                );
            }
        } else {
            eprintln!("tx#{tx_idx} carries non-instruction executable");
        }
    }
    let (_probe_payload, probe_flags) = encode_with_header_flags(&genesis.0);
    eprintln!("explicit flags before frame: 0x{probe_flags:02x}");
    let payload_1 = encode_adaptive(&genesis.0);
    let mut versioned_1 = Vec::with_capacity(1 + payload_1.len());
    versioned_1.push(1);
    versioned_1.extend_from_slice(&payload_1);
    eprintln!("payload_1 len={}", payload_1.len());
    let wire = genesis.0.canonical_wire().expect("canonical genesis wire");
    let framed = wire.as_framed();
    let header_flags = framed[1 + norito::core::Header::SIZE - 1];
    eprintln!("header_flags stored: 0x{header_flags:02x}");
    let deframed = deframe_versioned_signed_block_bytes(framed).expect("deframe genesis");
    let bare = deframed.bare_versioned.into_owned();
    assert_eq!(bare, versioned_1, "bare payload mismatch");
    let payload_2 = encode_adaptive(&genesis.0);
    eprintln!("payload_2 len={}", payload_2.len());
    let mut versioned_2 = Vec::with_capacity(1 + payload_2.len());
    versioned_2.push(1);
    versioned_2.extend_from_slice(&payload_2);
    assert_eq!(bare, versioned_2, "bare payload mismatch");
    decode_framed_signed_block(framed).expect("decode versioned genesis");
}
