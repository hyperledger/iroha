//! Parity/recovery scenarios for the Norito Streaming integration harness.
use crate::streaming::{self, baseline_test_vector_with_frames, bundled_test_vector_with_frames};
use norito::streaming::chunk::{chunk_commitments, chunk_leaf_hash};
use std::convert::TryFrom;
const GF_PRIMITIVE: u8 = 0x02;
const GF_REDUCTION: u8 = 0x1d; // 0x11d without the leading bit used for modular reduction
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= GF_REDUCTION;
        }
        b >>= 1;
    }
    result
}
fn gf_pow(mut base: u8, mut exp: u8) -> u8 {
    let mut result = 1u8;
    while exp != 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}
fn gf_inv(value: u8) -> u8 {
    assert!(value != 0, "inverse undefined for zero in GF(256)");
    gf_pow(value, 254)
}
fn gf_exp(value: usize) -> u8 {
    u8::try_from(value).expect("FEC exponent fits in GF(256)")
}
fn rs12_10_parity(chunks: &[Vec<u8>], shard_len: usize) -> (Vec<u8>, Vec<u8>) {
    let mut parity1 = vec![0u8; shard_len];
    let mut parity2 = vec![0u8; shard_len];
    for (idx, chunk) in chunks.iter().enumerate() {
        let weight1 = gf_pow(GF_PRIMITIVE, gf_exp(idx));
        let weight2 = gf_pow(GF_PRIMITIVE, gf_exp(2 * idx));
        for pos in 0..shard_len {
            let byte = if pos < chunk.len() { chunk[pos] } else { 0 };
            parity1[pos] ^= gf_mul(byte, weight1);
            parity2[pos] ^= gf_mul(byte, weight2);
        }
    }
    (parity1, parity2)
}
fn reconstruct_single_missing(
    chunks: &[Vec<u8>],
    parity1: &[u8],
    parity2: &[u8],
    missing_idx: usize,
    shard_len: usize,
) -> Vec<u8> {
    let mut recovered = vec![0u8; shard_len];
    let weight_missing = gf_pow(GF_PRIMITIVE, gf_exp(missing_idx));
    let weight_missing2 = gf_pow(GF_PRIMITIVE, gf_exp(2 * missing_idx));
    let inv_weight_missing = gf_inv(weight_missing);
    for pos in 0..shard_len {
        let mut accum1 = parity1[pos];
        let mut accum2 = parity2[pos];
        for (idx, chunk) in chunks.iter().enumerate() {
            if idx == missing_idx {
                continue;
            }
            let weight1 = gf_pow(GF_PRIMITIVE, gf_exp(idx));
            let weight2 = gf_pow(GF_PRIMITIVE, gf_exp(2 * idx));
            let byte = if pos < chunk.len() { chunk[pos] } else { 0 };
            accum1 ^= gf_mul(byte, weight1);
            accum2 ^= gf_mul(byte, weight2);
        }
        let value = gf_mul(accum1, inv_weight_missing);
        let expected = gf_mul(value, weight_missing2);
        assert_eq!(accum2, expected, "second parity mismatch at position {pos}");
        recovered[pos] = value;
    }
    recovered
}
fn fec_vectors(frame_count: usize) -> Vec<(&'static str, streaming::StreamingTestVector)> {
    vec![
        ("baseline", baseline_test_vector_with_frames(frame_count)),
        (
            "rans_bundled",
            bundled_test_vector_with_frames(frame_count, 4),
        ),
    ]
}
#[test]
fn rs12_10_parity_recovers_missing_chunk() {
    const DATA_SHARDS: usize = 10;
    for (label, vector) in fec_vectors(DATA_SHARDS) {
        assert_eq!(
            vector.chunk_payloads.len(),
            DATA_SHARDS,
            "{label} vector must emit exactly {DATA_SHARDS} chunks"
        );
        let max_chunk_len = vector.max_chunk_len();
        assert!(
            max_chunk_len > 0,
            "{label} chunk payloads must be non-empty"
        );
        let (parity1, parity2) = rs12_10_parity(&vector.chunk_payloads, max_chunk_len);
        let missing_idx = 3;
        let recovered = reconstruct_single_missing(
            &vector.chunk_payloads,
            &parity1,
            &parity2,
            missing_idx,
            max_chunk_len,
        );
        assert_eq!(
            &recovered[..vector.chunk_payloads[missing_idx].len()],
            vector.chunk_payloads[missing_idx].as_slice(),
            "{label} parity reconstruction must match original chunk"
        );
        assert!(
            recovered[vector.chunk_payloads[missing_idx].len()..]
                .iter()
                .all(|byte| *byte == 0),
            "{label} padding beyond original chunk length must remain zeroed"
        );
        let expected_leaf = vector.chunk_commitments[missing_idx];
        let recovered_leaf = chunk_leaf_hash(
            vector.manifest.segment_number,
            u16::try_from(missing_idx).expect("chunk index fits in u16"),
            &recovered[..vector.chunk_payloads[missing_idx].len()],
        );
        assert_eq!(
            recovered_leaf, expected_leaf,
            "{label} recovered chunk commitment must match fixture"
        );
        let mut chunk_refs: Vec<(u16, &[u8])> = vector
            .chunk_payloads
            .iter()
            .enumerate()
            .map(|(idx, chunk)| {
                (
                    u16::try_from(idx).expect("chunk index fits in u16"),
                    chunk.as_slice(),
                )
            })
            .collect();
        let parity_chunk_id = u16::try_from(chunk_refs.len()).expect("chunk count fits in u16");
        chunk_refs.push((parity_chunk_id, parity1.as_slice()));
        let commitments = chunk_commitments(vector.manifest.segment_number, &chunk_refs);
        let parity_leaf = chunk_leaf_hash(
            vector.manifest.segment_number,
            parity_chunk_id,
            parity1.as_slice(),
        );
        assert_eq!(
            parity_leaf,
            commitments
                .last()
                .copied()
                .expect("parity commitment present"),
            "{label} parity commitment must be reproducible"
        );
    }
}
#[test]
fn rs12_10_detects_dual_missing_chunks() {
    const DATA_SHARDS: usize = 10;
    for (label, vector) in fec_vectors(DATA_SHARDS) {
        let max_chunk_len = vector.max_chunk_len();
        let (parity1, parity2) = rs12_10_parity(&vector.chunk_payloads, max_chunk_len);
        let mut available = vector.chunk_payloads.clone();
        let missing_primary = 2;
        let missing_secondary = 7;
        available[missing_secondary] = vec![0u8; available[missing_secondary].len()];
        let result = std::panic::catch_unwind(|| {
            reconstruct_single_missing(
                &available,
                &parity1,
                &parity2,
                missing_primary,
                max_chunk_len,
            )
        });
        assert!(
            result.is_err(),
            "{label} single-shard recovery must fail when more than one shard is absent"
        );
    }
}
#[test]
fn rs12_10_detects_parity_corruption() {
    const DATA_SHARDS: usize = 10;
    let vector = baseline_test_vector_with_frames(DATA_SHARDS);
    let max_chunk_len = vector.max_chunk_len();
    let (mut parity1, parity2) = rs12_10_parity(&vector.chunk_payloads, max_chunk_len);
    parity1[0] ^= 0x5A;
    let half_index = parity1.len() / 2;
    parity1[half_index] ^= 0xA5;
    let result = std::panic::catch_unwind(|| {
        reconstruct_single_missing(&vector.chunk_payloads, &parity1, &parity2, 4, max_chunk_len)
    });
    assert!(
        result.is_err(),
        "tampered parity must be detected during reconstruction"
    );
}
