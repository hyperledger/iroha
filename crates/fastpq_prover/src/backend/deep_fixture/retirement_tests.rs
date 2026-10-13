//! Whole current-protocol construction controls replacing synthetic predecessor proofs.

use super::*;
use crate::{
    Error,
    backend::{
        compact_public_columns::PUBLIC_COLUMNS, compact_transfer_air::CompactTransferAir,
        deep_engine,
    },
    gadgets::{
        compact_smt_air::{PhysicalSmtWitness, PublicStatement, PublicUpdate},
        compact_trace_columns::{decode_smt_row, smt_row_cells},
    },
};

fn limbs(bytes: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
}

fn digest(seed: u8) -> [u32; 8] {
    limbs(iroha_crypto::Hash::new([seed; 33]).as_ref())
}

/// One complete satisfiable public fixture, shared with the frozen-transcript tests.
pub(super) fn fixture() -> (PublicStatement, PhysicalSmtWitness) {
    let siblings = core::array::from_fn(|level| digest(u8::try_from(level + 17).unwrap()));
    let path = 0xa59c_71e3;
    let first = digest(1);
    let second = digest(2);
    let mut root = first;
    for (level, sibling) in siblings.iter().enumerate() {
        let (left, right) = if (path >> level) & 1 == 0 {
            (root, *sibling)
        } else {
            (*sibling, root)
        };
        let mut message = b"fastpq:v1:smt:node|".to_vec();
        for limb in left.into_iter().chain(right) {
            message.extend_from_slice(&limb.to_le_bytes());
        }
        root = limbs(iroha_crypto::Hash::new(message).as_ref());
    }
    let statement = PublicStatement {
        updates: [
            PublicUpdate {
                old_leaf: first,
                new_leaf: second,
                path,
            },
            PublicUpdate {
                old_leaf: second,
                new_leaf: first,
                path,
            },
        ],
        old_root: root,
        new_root: root,
    };
    let witness = PhysicalSmtWitness::from_inputs(&statement, &[siblings, siblings]).unwrap();
    (statement, witness)
}

#[test]
#[ignore = "two full current q77 proofs with one and four Rayon workers"]
fn seeded_complete_proof_bytes_are_identical_across_worker_counts() {
    let mut reference = None;
    for threads in [1, 4] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        let bytes = pool.install(|| {
            let (statement, witness) = fixture();
            let relation = CompactTransferAir::new(&statement, Some(b"q77 worker parity")).unwrap();
            let source = OwnedTraceSource::from_rows(witness.rows()).unwrap();
            drop(witness);
            let bytes = prove(&relation, source, 0x077_004).unwrap();
            assert_eq!(
                deep_engine::verify_committed(&relation, &bytes, engine_verification_limits())
                    .unwrap()
                    .work()
                    .air_evaluations,
                1
            );
            bytes
        });
        if let Some(expected) = &reference {
            assert_eq!(&bytes, expected);
        } else {
            reference = Some(bytes);
        }
    }
}

#[test]
#[ignore = "fresh full q77 false-statement numerator rejects before a proof can be minted"]
fn newly_committed_false_public_claim_fails_exact_full_air_division() {
    let (mut statement, witness) = fixture();
    statement.new_root[7] ^= 1;
    let relation = CompactTransferAir::new(&statement, Some(b"q77 false statement")).unwrap();
    let source = OwnedTraceSource::from_rows(witness.rows()).unwrap();
    drop(witness);
    assert!(
        matches!(prove(&relation, source, 0x077_005), Err(Error::InvalidTraceShape { details })
        if details == "full AIR numerator has a nonzero vanishing-polynomial remainder")
    );
}

#[test]
#[ignore = "fresh q77 commitments to rotated and swapped nonconstant private rows"]
fn freshly_recommitted_rotated_and_swapped_private_rows_fail_full_air_division() {
    for swapped in [false, true] {
        let (statement, mut witness) = fixture();
        let rows = witness.rows_mut();
        if swapped {
            for pair in rows.chunks_exact_mut(2) {
                let first = smt_row_cells(&pair[0]);
                let second = smt_row_cells(&pair[1]);
                let mut a = second;
                let mut b = first;
                for column in PUBLIC_COLUMNS {
                    a[column] = first[column];
                    b[column] = second[column];
                }
                pair[0] = decode_smt_row(&a).unwrap();
                pair[1] = decode_smt_row(&b).unwrap();
            }
        } else {
            let first = smt_row_cells(&rows[0]);
            for i in 0..rows.len() {
                let current = smt_row_cells(&rows[i]);
                let mut next = if i + 1 == rows.len() {
                    first
                } else {
                    smt_row_cells(&rows[i + 1])
                };
                for column in PUBLIC_COLUMNS {
                    next[column] = current[column];
                }
                rows[i] = decode_smt_row(&next).unwrap();
            }
        }
        // Canonical cells, exact physical shape and every public schedule cell
        // remain intact; the actual private recurrence must cause the refusal.
        let source = OwnedTraceSource::from_rows(witness.rows()).unwrap();
        drop(witness);
        let relation =
            CompactTransferAir::new(&statement, Some(b"q77 false private recurrence")).unwrap();
        assert!(
            matches!(prove(&relation, source, 0x077_006), Err(Error::InvalidTraceShape { details })
            if details == "full AIR numerator has a nonzero vanishing-polynomial remainder")
        );
    }
}
