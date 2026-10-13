//! Public synthetic carrier bytes test only local equality serialization, never finality.

use super::*;
use iroha_data_model::{
    isi::sumeragi_amx::{RelayAmxHandoffV1, RelayGlobalAmxHandoffV1},
    sumeragi_amx::{AmxCertifiedBlockV1, AmxHandoffProofV1},
};
use iroha_model_base::topology::DataSpaceId;
use norito::core::{DecodeFlagsGuard, default_encode_flags, serialize_to_buffer};

fn carrier(
    global: bool,
    dataspace: DataSpaceId,
    header: &[u8],
    result: &[u8],
    qc: &[u8],
) -> InstructionBox {
    let proof = AmxHandoffProofV1 {
        block: AmxCertifiedBlockV1 {
            consensus_header: header.to_vec(),
            commit_qc: qc.to_vec(),
            result_preimage: result.to_vec(),
        },
    };
    if global {
        RelayGlobalAmxHandoffV1 { dataspace, proof }.into()
    } else {
        RelayAmxHandoffV1 { dataspace, proof }.into()
    }
}

#[test]
fn handoff_effect_preserves_borrowed_payload_and_its_canonical_hash_domain() {
    let long_header = [0x7b; 127];
    let long_result = [0x80; 128];
    let cases = [
        (b"".as_slice(), b"".as_slice()),
        (b"public header".as_slice(), b"public result".as_slice()),
        (long_header.as_slice(), long_result.as_slice()),
    ];
    let dataspace = DataSpaceId::new((1_u64 << 40) + 117);
    for (header, result) in cases {
        let original = HandoffEffect {
            direction: 1,
            dataspace,
            consensus_header: header,
            result_preimage: result,
        };
        assert!(std::ptr::eq(original.consensus_header, header));
        assert!(std::ptr::eq(original.result_preimage, result));
        // The public test-only owned tuple checks field payload parity, not a
        // parallel production frame or a compatibility alias for this local key.
        let owned = (1_u8, dataspace, header.to_vec(), result.to_vec());
        let canonical = norito::encode_canonical(&original).unwrap();
        let expected_hash = Hash::new(&canonical);
        let tuple_frame = norito::encode_canonical(&owned).unwrap();
        assert_ne!(canonical, tuple_frame);
        assert_ne!(expected_hash, Hash::new(&tuple_frame));
        let instruction = carrier(true, dataspace, header, result, b"public QC");
        for flags in [
            0,
            default_encode_flags(),
            default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN,
        ] {
            let _ambient = DecodeFlagsGuard::enter(flags);
            let mut borrowed_payload = Vec::new();
            let mut owned_payload = Vec::new();
            serialize_to_buffer(&original, &mut borrowed_payload).unwrap();
            serialize_to_buffer(&owned, &mut owned_payload).unwrap();
            assert_eq!(borrowed_payload, owned_payload);
            let mut streamed = Vec::new();
            norito::core::write_canonical_to_writer(&original, &mut streamed).unwrap();
            assert_eq!(streamed, canonical);
            assert_eq!(handoff_effect(&instruction).unwrap(), Some(expected_hash));
            assert_eq!(norito::core::get_decode_flags(), flags);
        }
    }
}

#[test]
fn handoff_effect_binds_each_original_field_and_excludes_only_the_qc() {
    let dataspace = DataSpaceId::new((1_u64 << 40) + 117);
    let original = carrier(false, dataspace, b"header", b"result", b"first QC");
    let expected = handoff_effect(&original).unwrap().unwrap();
    let changed = [
        carrier(true, dataspace, b"header", b"result", b"first QC"),
        carrier(
            false,
            DataSpaceId::new(dataspace.as_u64() + 1),
            b"header",
            b"result",
            b"first QC",
        ),
        carrier(false, dataspace, b"changed header", b"result", b"first QC"),
        carrier(false, dataspace, b"header", b"changed result", b"first QC"),
        // Field boundaries distinguish the same raw concatenated bytes.
        carrier(false, dataspace, b"head", b"erresult", b"first QC"),
    ];
    for instruction in changed {
        assert_ne!(handoff_effect(&instruction).unwrap().unwrap(), expected);
    }
    let other_qc = carrier(false, dataspace, b"header", b"result", b"another QC");
    assert_eq!(handoff_effect(&other_qc).unwrap(), Some(expected));
    // This equality is deliberately not evidence that either synthetic QC is valid.
    // successful_handoff still independently authenticates the candidate and its execution.
}
