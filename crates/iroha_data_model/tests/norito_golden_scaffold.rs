//! Norito golden scaffolding for data-model types.
//!
//! These tests pin stable encodings for core data-model types so future changes
//! surface deterministic diffs instead of silent codec drift.
use hex_literal::hex;
use iroha_data_model::block::BlockHeader;
use nonzero_ext::nonzero;
use norito::codec::{DecodeAll, Encode};
#[test]
fn block_header_roundtrip() {
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 12345, 0);
    let bytes = norito::to_bytes(&header).expect("encode");
    let decoded: BlockHeader = norito::decode_from_bytes(&bytes).expect("decode");
    assert_eq!(decoded, header);
}
#[test]
fn block_header_golden_bytes() {
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 12345, 0);
    let bytes = header.encode();
    // The default policy is pinned against Core's compiled ZK/SCCP inputs.
    // The current layout includes the execution-context and beacon commitment slots.
    let expected: &[u8] = &hex!(
        "0801000000000000000100010001000100010001000839300000000000000800000000000000005201500100010001000601040100000042014001640105015001fb01590127011d011001c001b2018d0191011d014a013101660192018801ce013f01eb01a7015601370179011a012e01de011d0129011f010601000100"
    );
    assert_eq!(bytes.as_slice(), expected);
    let mut cursor = expected;
    assert_eq!(
        BlockHeader::decode_all(&mut cursor).expect("decode complete header golden"),
        header,
    );
    let mut without_beacon = &expected[..expected.len() - 2];
    assert!(
        BlockHeader::decode_all(&mut without_beacon).is_err(),
        "a header without the required beacon commitment slot must be rejected",
    );
}
