//! Parity with the canonical decoder at the allocation-free keeper boundary.

use super::*;
use crate::{
    ethereum_source::*,
    light_client::{
        bsc::{BscAdvanceStepV1, BscFinalityV1, BscLcAdvanceV1},
        ethereum::{EthereumHeaderSegmentV1, EthereumLcAdvanceV1},
        proof::SccpLcSegmentV1,
        ton::{TonKeyBlockHopV1, TonLcAdvanceV1, TonSignedBlockV1},
    },
    ton_native::{
        TonBlockIdExtV1, TonBlockSignaturesV1, TonOrdinaryBlockSignaturesV1,
        TonSimplexBlockSignaturesV1, TonValidatorSignatureV1,
    },
};
use norito::{
    NoritoSchema,
    core::{Encoder, SerializePayload},
};

struct RawPayload<'a>(&'a [u8]);
impl SerializePayload for RawPayload<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        std::io::Write::write_all(writer, self.0).map_err(Into::into)
    }
}
impl NoritoSchema for RawPayload<'_> {
    fn nominal_name() -> String {
        SccpLcAdvanceV1::nominal_name()
    }
    fn static_nominal_name() -> Option<&'static str> {
        SccpLcAdvanceV1::static_nominal_name()
    }
    fn frame_name() -> String {
        SccpLcAdvanceV1::frame_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        SccpLcAdvanceV1::static_frame_name()
    }
}

fn expected(bytes: &[u8]) -> Option<SccpNetworkV1> {
    SccpLcAdvanceV1::from_frame(bytes).ok().and_then(|value| {
        if matches!(value, SccpLcAdvanceV1::Backfill { .. }) {
            None
        } else {
            Some(value.network())
        }
    })
}
fn frame(payload: &[u8]) -> Vec<u8> {
    {
        let mut bytes = norito::encode_canonical(&RawPayload(payload)).unwrap();
        // Raw copying emits no field-length operations, so supply the known compact layout.
        bytes[norito::core::Header::SIZE - 1] = norito::core::default_encode_flags();
        bytes
    }
}
fn assert_parity(bytes: &[u8]) {
    assert_eq!(keeper_network(bytes), expected(bytes));
}

fn fixtures() -> Vec<SccpLcAdvanceV1> {
    let capella = EthereumNativeCapellaExecutionHeaderV1 {
        parent_hash: [1; 32],
        fee_recipient: vec![2; 20],
        state_root: [3; 32],
        receipts_root: [4; 32],
        logs_bloom: vec![5; 7],
        prev_randao: [6; 32],
        block_number: 7,
        gas_limit: 8,
        gas_used: 9,
        timestamp: 10,
        extra_data: vec![11; 3],
        base_fee_per_gas: [12; 32],
        block_hash: [13; 32],
        transactions_root: [14; 32],
        withdrawals_root: [15; 32],
    };
    let forks = [
        EthereumNativeForkV1::Altair,
        EthereumNativeForkV1::Bellatrix,
        EthereumNativeForkV1::Capella,
        EthereumNativeForkV1::Deneb,
        EthereumNativeForkV1::Electra,
        EthereumNativeForkV1::Fulu,
    ];
    let mut values = vec![
        SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 { updates: vec![] }),
        SccpLcAdvanceV1::Bsc(BscLcAdvanceV1 { steps: vec![] }),
        SccpLcAdvanceV1::Ton(TonLcAdvanceV1 { hops: vec![] }),
        SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Ethereum(EthereumHeaderSegmentV1 {
                headers: vec![vec![1, 2, 3], vec![]],
            }),
        },
    ];
    for (index, fork) in forks.into_iter().enumerate() {
        let header = EthereumNativeLightClientHeaderV1 {
            fork,
            beacon: EthereumNativeBeaconHeaderV1 {
                slot: 1,
                proposer_index: 2,
                parent_root: [3; 32],
                state_root: [4; 32],
                body_root: [5; 32],
            },
            execution: match index {
                0 | 1 => None,
                2 => Some(EthereumNativeExecutionHeaderV1::Capella(capella.clone())),
                _ => Some(EthereumNativeExecutionHeaderV1::Deneb(
                    EthereumNativeDenebExecutionHeaderV1 {
                        base: capella.clone(),
                        blob_gas_used: 8,
                        excess_blob_gas: 9,
                    },
                )),
            },
            execution_branch: vec![vec![6; 32], vec![]],
        };
        values.push(SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
            updates: vec![EthereumNativeLightClientUpdateV1 {
                attested_header: header.clone(),
                finalized_header: header,
                next_sync_committee: (index % 2 == 0).then(|| EthereumNativeNextSyncCommitteeV1 {
                    committee: EthereumNativeSyncCommitteeV1 {
                        public_keys: vec![vec![], vec![7; 48]],
                        aggregate_public_key: vec![8; 48],
                    },
                    branch: vec![vec![9; 32]],
                }),
                finality_branch: vec![vec![10; 32]],
                sync_committee_bits: vec![11; 64],
                sync_committee_signature: vec![12; 96],
                signature_slot: 13,
            }],
        }));
    }
    for successor_set_id in [None, Some(18)] {
        values.push(SccpLcAdvanceV1::Bsc(BscLcAdvanceV1 {
            steps: vec![BscAdvanceStepV1 {
                headers: vec![vec![1, 2], vec![]],
                finality: BscFinalityV1 {
                    set_id: 17,
                    successor_set_id,
                    attestation: vec![3, 4],
                },
            }],
        }));
    }
    let signatures = vec![TonValidatorSignatureV1 {
        node_id_short: [7; 32],
        signature: vec![8; 64],
    }];
    for signatures in [
        TonBlockSignaturesV1::Ordinary(TonOrdinaryBlockSignaturesV1 {
            catchain_seqno: 1,
            validator_list_hash_short: 2,
            signatures: signatures.clone(),
        }),
        TonBlockSignaturesV1::Simplex(TonSimplexBlockSignaturesV1 {
            catchain_seqno: 1,
            validator_list_hash_short: 2,
            session_id: [3; 32],
            slot: 4,
            candidate_data: vec![5; 4],
            signatures,
        }),
    ] {
        values.push(SccpLcAdvanceV1::Ton(TonLcAdvanceV1 {
            hops: vec![TonKeyBlockHopV1 {
                block: TonSignedBlockV1 {
                    block_id: TonBlockIdExtV1 {
                        workchain: -1,
                        shard: 1 << 63,
                        seqno: 1,
                        root_hash: [2; 32],
                        file_hash: [3; 32],
                    },
                    header_proof: vec![4, 5],
                    signatures,
                },
                config_proof: vec![6, 7],
            }],
        }));
    }
    values
}

#[test]
fn every_advance_variant_and_nested_option_matches_the_canonical_decoder() {
    for value in fixtures() {
        let bytes = value.to_frame().unwrap();
        assert_parity(&bytes);
        let payload = norito::canonical_frame_payload::<SccpLcAdvanceV1>(
            &bytes,
            norito::core::default_encode_flags(),
        )
        .unwrap();
        assert_eq!(
            frame(payload),
            bytes,
            "mutation framing must preserve the real archive layout"
        );
    }
}

#[test]
fn truncated_mutated_and_nonminimal_payloads_match_the_canonical_decoder() {
    for value in fixtures() {
        let bytes = value.to_frame().unwrap();
        for end in 0..bytes.len() {
            assert_eq!(keeper_network(&bytes[..end]), None);
        }
        let payload = norito::canonical_frame_payload::<SccpLcAdvanceV1>(
            &bytes,
            norito::core::default_encode_flags(),
        )
        .unwrap();
        // Rebuild the checksum after each mutation so the structural checker, not CRC,
        // decides parity. Includes every length/tag/count byte in these closed fixtures.
        for index in 0..payload.len() {
            let mut changed = payload.to_vec();
            changed[index] ^= 0x80;
            assert_parity(&frame(&changed));
        }
        let mut suffix = payload.to_vec();
        suffix.push(0);
        assert_parity(&frame(&suffix));
    }
    let minimal = SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 { updates: vec![] })
        .to_frame()
        .unwrap();
    let mut payload = norito::canonical_frame_payload::<SccpLcAdvanceV1>(
        &minimal,
        norito::core::default_encode_flags(),
    )
    .unwrap()
    .to_vec();
    assert!(payload[4] < 128);
    payload[4] |= 0x80;
    payload.insert(5, 0);
    let nonminimal = frame(&payload);
    assert_eq!(keeper_network(&nonminimal), None);
    assert_parity(&nonminimal);
    // A huge nested sequence count cannot trigger a heap allocation or a wire-sized loop.
    let mut payload = norito::canonical_frame_payload::<SccpLcAdvanceV1>(
        &minimal,
        norito::core::default_encode_flags(),
    )
    .unwrap()
    .to_vec();
    payload[6..14].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(keeper_network(&frame(&payload)), None);
    assert_parity(&frame(&payload));
}

#[test]
fn envelope_flags_schema_padding_and_unknown_tags_are_not_keeper_eligible() {
    for value in fixtures() {
        let bytes = value.to_frame().unwrap();
        for index in 0..norito::core::Header::SIZE {
            let mut changed = bytes.clone();
            changed[index] ^= 0x80;
            assert_eq!(keeper_network(&changed), None);
            assert_parity(&changed);
        }
        for flags in 0..=u8::MAX {
            if flags == norito::core::default_encode_flags() {
                continue;
            }
            let mut changed = bytes.clone();
            changed[norito::core::Header::SIZE - 1] = flags;
            assert_eq!(keeper_network(&changed), None);
            assert_parity(&changed);
        }
        let mut padding = bytes.clone();
        padding.insert(norito::core::Header::SIZE, 0);
        assert_eq!(keeper_network(&padding), None);
        assert_parity(&padding);
        let mut payload = norito::canonical_frame_payload::<SccpLcAdvanceV1>(
            &bytes,
            norito::core::default_encode_flags(),
        )
        .unwrap()
        .to_vec();
        payload[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(keeper_network(&frame(&payload)), None);
        assert_parity(&frame(&payload));
    }
}
