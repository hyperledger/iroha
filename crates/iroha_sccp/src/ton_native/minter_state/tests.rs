//! Regression controls for exact locked storage, canonical rows and proven dictionary absence.

use super::*;
use crate::v1::ton_cell::{Cell, TonMinterDataV1, TonMinterInitV1, minter_initial_data};
use std::collections::BTreeMap;

fn init() -> TonMinterInitV1 {
    let fixture: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/sccp/ton_stateinit_v1.json"
    )))
    .unwrap();
    let keys: Vec<[u8; 48]> = fixture["vectors"][0]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| {
            let text = key.as_str().unwrap().trim_start_matches("0x");
            let mut bytes = [0; 48];
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
            }
            bytes
        })
        .collect();
    TonMinterInitV1 {
        taira_network_id: [1; 32],
        consensus_instance: [2; 32],
        route_revision: 3,
        max_supply: 1000,
        pin: SccpCommitteePinV1 {
            generation: 1,
            committee_root: committee_root(&keys).unwrap(),
            start_height: 5,
            until_ms: 10_000,
        },
        keys,
        wallet_code: locked_code_refs()[1],
        bucket_code: locked_code_refs()[2],
    }
}

// Serialize opaque code references as native pruned branches. The account's hash-zero
// commitment must still equal the independent ordinary-cell builder's original root.
fn proof_boc(root: Cell) -> Vec<u8> {
    fn visit(
        reference: &CellRef,
        cells: &mut Vec<TonBocCell>,
        seen: &mut BTreeMap<H256, usize>,
    ) -> usize {
        if let Some(index) = seen.get(reference.hash()) {
            return *index;
        }
        let cell = reference.cell().map_or_else(
            || {
                let mut data = vec![1, 1];
                data.extend_from_slice(reference.hash());
                data.extend_from_slice(&reference.depth().to_be_bytes());
                TonBocCell {
                    descriptor: 0x28,
                    data_descriptor: 72,
                    data: data.into(),
                    refs: vec![].into(),
                    exotic: true,
                }
            },
            |cell| {
                let refs: Vec<_> = cell
                    .refs()
                    .iter()
                    .map(|child| visit(child, cells, seen))
                    .collect();
                let mut data = cell.data().to_vec();
                if cell.bit_len() % 8 != 0 {
                    *data.last_mut().unwrap() |= 0x80 >> (cell.bit_len() % 8);
                }
                TonBocCell {
                    descriptor: u8::try_from(refs.len()).unwrap()
                        | refs
                            .iter()
                            .fold(0, |mask, i| mask | (cells[*i].descriptor & 0xe0)),
                    data_descriptor: u8::try_from(cell.bit_len() / 8 + cell.bit_len().div_ceil(8))
                        .unwrap(),
                    data: data.into(),
                    refs: refs.into(),
                    exotic: false,
                }
            },
        );
        let index = cells.len();
        cells.push(cell);
        seen.insert(*reference.hash(), index);
        index
    }
    let mut cells = Vec::new();
    visit(&root.into(), &mut cells, &mut BTreeMap::new());
    let last = cells.len() - 1;
    let cells: Vec<_> = cells
        .into_iter()
        .rev()
        .map(|mut cell| {
            cell.refs = cell
                .refs
                .iter()
                .map(|i| last - i)
                .collect::<Vec<_>>()
                .into();
            cell
        })
        .collect();
    assert!(cells.len() < 256);
    let mut body = Vec::new();
    for cell in &cells {
        body.extend_from_slice(&[cell.descriptor, cell.data_descriptor]);
        body.extend_from_slice(&cell.data);
        body.extend(cell.refs.iter().map(|i| u8::try_from(*i).unwrap()));
    }
    let mut out = TON_BOC_MAGIC.to_vec();
    out.extend_from_slice(&[1, 2, u8::try_from(cells.len()).unwrap(), 1, 0]);
    out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    out.push(0);
    out.extend(body);
    ton_canonical_boc_v1(&out).expect("canonical account proof ordering")
}

fn account(data: Cell, code: SccpTonCodeRefV1) -> Cell {
    let mut out = CellBuilder::new();
    out.store_bit(true)
        .unwrap()
        .store_uint(2, 2)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_uint(0, 8)
        .unwrap()
        .store_bytes(&[9; 32])
        .unwrap()
        .store_uint(0, 3)
        .unwrap()
        .store_uint(0, 3)
        .unwrap()
        .store_uint(0, 3)
        .unwrap()
        .store_uint(0, 32)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_coins(0)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_bit(true)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_maybe_ref(Some(code))
        .unwrap()
        .store_maybe_ref(Some(data))
        .unwrap()
        .store_bit(false)
        .unwrap();
    out.build()
}

fn open(data: Cell, code: SccpTonCodeRefV1) -> Result<TonMinterStateV1, TonNativeSourceError> {
    let account = account(data, code);
    let root = *account.hash();
    let wire = proof_boc(account);
    assert_eq!(
        ton_boc_single_root_hash_v1(&wire),
        Some(root),
        "serialized account root"
    );
    let _cells = wallet_state::open_account_state(&wire, &root, &[9; 32], &Memory::detached())
        .expect("fixture Account opener");
    parse_minter_state(&wire, &root, &[9; 32], &Memory::detached())
}

fn root(
    data: &TonMinterDataV1,
    book: Cell,
    checkpoints: Cell,
    initialized: bool,
    total: u128,
) -> Cell {
    CellBuilder::new()
        .store_bit(initialized)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_coins(total)
        .unwrap()
        .store_coins(0)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_ref(data.config.clone())
        .unwrap()
        .store_ref(data.committee.clone())
        .unwrap()
        .store_ref(checkpoints)
        .unwrap()
        .store_ref(book)
        .unwrap()
        .build()
}

fn row(stage: u8, attempt: u64, nonce: u64) -> Cell {
    row_in_phase(stage, 2, attempt, nonce)
}

fn row_in_phase(stage: u8, phase: u8, attempt: u64, nonce: u64) -> Cell {
    let tail = CellBuilder::new()
        .store_bit(false)
        .unwrap()
        .store_uint(2, 2)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_uint(0, 8)
        .unwrap()
        .store_bytes(&[6; 32])
        .unwrap()
        .store_uint(2, 2)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_uint(0, 8)
        .unwrap()
        .store_bytes(&[7; 32])
        .unwrap()
        .store_bytes(&[8; 32])
        .unwrap()
        .build();
    CellBuilder::new()
        .store_uint(u128::from(stage), 3)
        .unwrap()
        .store_uint(u128::from(phase), 2)
        .unwrap()
        .store_uint(u128::from(attempt), 64)
        .unwrap()
        .store_uint(u128::from(nonce), 64)
        .unwrap()
        .store_uint(10, 96)
        .unwrap()
        .store_uint(1, 10)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_uint(11, 64)
        .unwrap()
        .store_uint(0, 2)
        .unwrap()
        .store_ref(tail)
        .unwrap()
        .build()
}

fn book(first: Cell, second: Cell, count: u16, next: u64) -> Cell {
    let leaf = |bit: bool, row: Cell| {
        CellBuilder::new()
            .store_uint(2, 2)
            .unwrap()
            .store_bit(true)
            .unwrap()
            .store_bit(bit)
            .unwrap()
            .store_ref(row)
            .unwrap()
            .build()
    };
    let dictionary = CellBuilder::new()
        .store_uint(2, 2)
        .unwrap()
        .store_uint(62, 7)
        .unwrap()
        .store_uint(0, 62)
        .unwrap()
        .store_ref(leaf(true, first))
        .unwrap()
        .store_ref(leaf(false, second))
        .unwrap()
        .build();
    CellBuilder::new()
        .store_uint(u128::from(next), 64)
        .unwrap()
        .store_uint(u128::from(count), 10)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_maybe_ref(Some(dictionary))
        .unwrap()
        .build()
}

#[test]
fn minter_storage_opens_exact_original_account_and_locked_code_references() {
    let init = init();
    let data = minter_initial_data(&init).unwrap();
    let state = open(data.root.clone(), locked_code_refs()[0]).unwrap();
    assert!(!state.initialized);
    assert_eq!(state.initial, init.pin);
    assert_eq!(state.max_supply, 1000);
    assert_eq!(state.network, [1; 32]);
    assert_eq!(state.instance, [2; 32]);
    assert_eq!(state.revision, 3);
    assert_eq!(state.committee.high, 4);
    assert!(state.checkpoints.is_empty());
    assert!(state.recovery.is_empty());
    for field in 0..2 {
        let mut code = locked_code_refs()[0];
        if field == 0 {
            code.hash[0] ^= 1;
        } else {
            code.depth += 1;
        }
        assert!(open(data.root.clone(), code).is_err());
    }
    for index in 0..2 {
        let mut init = init.clone();
        if index == 0 {
            init.wallet_code.hash[0] ^= 1;
        } else {
            init.bucket_code.depth += 1;
        }
        assert!(
            open(
                minter_initial_data(&init).unwrap().root,
                locked_code_refs()[0]
            )
            .is_err()
        );
    }
    let account = account(data.root.clone(), locked_code_refs()[0]);
    let hash = *account.hash();
    let wire = proof_boc(account);
    assert!(parse_minter_state(&wire, &[0; 32], &[9; 32], &Memory::detached()).is_err());
    assert!(parse_minter_state(&wire, &hash, &[8; 32], &Memory::detached()).is_err());
    assert!(
        open(
            root(
                &data,
                data.recovery.clone(),
                data.checkpoints.clone(),
                true,
                1001
            ),
            locked_code_refs()[0]
        )
        .is_err()
    );
}

#[test]
fn bounced_mint_admits_only_failed_unconsume_at_attempt_zero() {
    let data = minter_initial_data(&init()).unwrap();
    for stage in 1..=5 {
        for phase in 0..=3 {
            let state = open(
                root(
                    &data,
                    book(row_in_phase(stage, phase, 0, 7), row(3, 1, 8), 2, 3),
                    data.checkpoints.clone(),
                    true,
                    0,
                ),
                locked_code_refs()[0],
            );
            assert_eq!(state.is_ok(), (stage, phase) == (4, 2), "{stage}/{phase}");
            if let Ok(state) = state {
                assert_eq!(state.recovery[0].stage, 4);
                assert_eq!(state.recovery[0].phase, 2);
                assert_eq!(state.recovery[0].attempt, 0);
            }
        }
    }
}

#[test]
fn complete_recovery_dictionary_preserves_original_rows_and_rejects_false_absence() {
    let data = minter_initial_data(&init()).unwrap();
    let first = row(2, 1, 7);
    let second = row(3, 2, 8);
    let state = open(
        root(
            &data,
            book(first.clone(), second.clone(), 2, 3),
            data.checkpoints.clone(),
            true,
            0,
        ),
        locked_code_refs()[0],
    )
    .unwrap();
    assert_eq!(state.recovery.len(), 2);
    assert_eq!(state.next_operation_id, 3);
    assert_eq!(state.recovery[0].operation_id, 1);
    assert_eq!(state.recovery[1].operation_id, 2);
    assert_eq!(state.recovery[0].row_boc, first.to_boc().unwrap());
    assert_eq!(state.recovery[1].row_boc, second.to_boc().unwrap());
    for (first, count, next) in [
        (first.clone(), 1, 3),
        (first.clone(), 513, 3),
        (first.clone(), 2, 2),
        (row(0, 1, 7), 2, 3),
        (row(2, 0, 7), 2, 3),
    ] {
        assert!(
            open(
                root(
                    &data,
                    book(first, second.clone(), count, next),
                    data.checkpoints.clone(),
                    true,
                    0
                ),
                locked_code_refs()[0]
            )
            .is_err()
        );
    }
    let later = open(
        root(
            &data,
            book(row(3, 2, 7), second, 2, 3),
            data.checkpoints.clone(),
            true,
            0,
        ),
        locked_code_refs()[0],
    )
    .unwrap();
    assert_eq!(state.recovery[0].identity, later.recovery[0].identity);
    assert_ne!(state.recovery[0].attempt, later.recovery[0].attempt);
}

#[test]
fn checkpoints_require_exact_complete_ordered_slots() {
    let data = minter_initial_data(&init()).unwrap();
    let make = |heights: &[u64]| {
        let mut out = CellBuilder::new();
        out.store_uint(heights.len() as u128, 2).unwrap();
        for height in heights {
            out.store_uint(u128::from(*height), 64)
                .unwrap()
                .store_bytes(&[4; 32])
                .unwrap();
        }
        out.build()
    };
    let state = open(
        root(&data, data.recovery.clone(), make(&[5, 6, 7]), true, 0),
        locked_code_refs()[0],
    )
    .unwrap();
    assert_eq!(state.checkpoints.len(), 3);
    for heights in [&[0][..], &[5, 5], &[6, 5]] {
        assert!(
            open(
                root(&data, data.recovery.clone(), make(heights), true, 0),
                locked_code_refs()[0]
            )
            .is_err()
        );
    }
    let trailing = CellBuilder::new()
        .store_uint(0, 2)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .build();
    assert!(
        open(
            root(&data, data.recovery.clone(), trailing, true, 0),
            locked_code_refs()[0]
        )
        .is_err()
    );
}
