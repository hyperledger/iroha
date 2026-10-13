//! Packed/native planner parity across bit boundaries and compression choices.

use super::*;
use iroha_pasta::CancellationToken;

fn compare(rows: &[Vec<bool>], degrees: &[usize], maximum: usize) {
    let native: Vec<_> = rows
        .iter()
        .zip(degrees)
        .enumerate()
        .map(
            |(selector, (activations, max_degree))| SelectorDescription {
                selector: selector + 17,
                activations,
                max_degree: *max_degree,
            },
        )
        .collect();
    let bytes: Vec<Vec<u8>> = rows
        .iter()
        .map(|rows| {
            rows.chunks(8)
                .map(|chunk| {
                    chunk
                        .iter()
                        .enumerate()
                        .fold(0, |byte, (bit, active)| byte | (u8::from(*active) << bit))
                })
                .collect()
        })
        .collect();
    let packed: Vec<_> = bytes
        .iter()
        .zip(degrees)
        .enumerate()
        .map(
            |(selector, (activations, max_degree))| PackedSelectorDescription {
                selector: selector + 17,
                activations,
                max_degree: *max_degree,
            },
        )
        .collect();
    assert_eq!(
        plan_packed_cancellable(&packed, maximum, None),
        plan(&native, maximum),
        "rows={rows:?}, degrees={degrees:?}, maximum={maximum}"
    );
}

#[test]
fn packed_planner_matches_every_three_selector_three_row_pattern() {
    for pattern in 0..512 {
        let rows: Vec<Vec<bool>> = (0..3)
            .map(|selector| {
                (0..3)
                    .map(|row| pattern & (1 << (selector * 3 + row)) != 0)
                    .collect()
            })
            .collect();
        for degrees in [[0, 0, 0], [1, 1, 1], [2, 0, 2], [1, 4, 1], [5, 1, 3]] {
            for maximum in 0..=5 {
                compare(&rows, &degrees, maximum);
            }
        }
    }
}

#[test]
fn packed_planner_preserves_byte_boundaries_sparse_overlap_and_degree_ties() {
    compare(&[], &[], 0);
    for count in [0, 1, 2, 7, 8, 9, 63, 64, 65, 1023, 1024, 1025, 4097] {
        let rows: Vec<Vec<bool>> = (0..8)
            .map(|selector| {
                (0..count)
                    .map(|row| match selector {
                        0 => false,
                        1 => true,
                        2 => row == count - 1,
                        3 => row == 0,
                        4 => row % 2 == 0,
                        5 => row % 2 == 1,
                        6 => row == 7 || row == 1023,
                        _ => row == 8 || row == 1024,
                    })
                    .collect()
            })
            .collect();
        for degrees in [[1; 8], [2, 0, 2, 0, 4, 1, 1, 1], [1, 4, 1, 1, 0, 5, 2, 3]] {
            for maximum in 0..=6 {
                compare(&rows, &degrees, maximum);
            }
        }
    }
}

#[test]
fn packed_planner_refuses_extent_mismatch_and_preserves_cancellation() {
    let first = [0_u8; 256];
    let second = [0_u8; 255];
    let mut selectors = [
        PackedSelectorDescription {
            selector: 4,
            activations: &first,
            max_degree: 1,
        },
        PackedSelectorDescription {
            selector: 9,
            activations: &second,
            max_degree: 1,
        },
    ];
    assert_eq!(
        plan_packed_cancellable(&selectors, 4, None),
        Err(CompressionError::ActivationLength {
            selector: 9,
            expected: 2048,
            found: 2040,
        })
    );
    let token = CancellationToken::new();
    token.cancel();
    assert_eq!(
        plan_packed_cancellable(&selectors, 4, Some(&token)),
        Err(CompressionError::Cancelled)
    );
    assert_eq!(
        plan_packed_cancellable(&[], 4, Some(&token)),
        Err(CompressionError::Cancelled)
    );
    selectors[1].activations = &first;
    let fresh = CancellationToken::new();
    assert_eq!(
        plan_packed_cancellable(&selectors, 4, Some(&fresh)),
        Ok(vec![vec![0, 1]])
    );
    let during = CancellationToken::new();
    assert_eq!(
        plan_with_overlap(&[(4, 1), (9, 1)], 4, Some(&during), |_, _| {
            during.cancel();
            Ok(false)
        }),
        Err(CompressionError::Cancelled)
    );
}
