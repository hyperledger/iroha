//! Native account-layout and pristine-minter observation refusal controls.

use super::*;
use iroha_sccp::v1::ton_cell::CellBuilder;

fn value(word: [u8; 32]) -> TvmStackValueV1 {
    let mut bytes = [0; 33];
    bytes[1..].copy_from_slice(&word);
    TvmStackValueV1::Integer(TvmIntV1(bytes))
}
fn state(args: &ConstructorArgsV1) -> Vec<TvmStackValueV1> {
    let mut fields = vec![value([0; 32]); 24];
    fields[0] = TvmStackValueV1::Integer(TvmIntV1([0xff; 33]));
    for (index, bytes) in [
        (2, args.taira_network_id),
        (3, args.consensus_instance),
        (4, word_u64(u64::from(args.route_revision))),
        (5, word_u64(args.pin.generation)),
        (6, args.pin.committee_root),
        (7, word_u64(args.pin.start_height)),
        (8, word_u64(args.pin.until_ms)),
        (9, args.pin.committee_root),
        (10, word_u64(args.pin.until_ms)),
        (11, word_u64(args.pin.start_height)),
        (13, word_u64(args.pin.generation)),
        (22, word_u128(args.max_wrapped_supply)),
    ] {
        fields[index] = value(bytes);
    }
    fields
}

fn account(account: [u8; 32], code: Cell, storage_extra: u128, active: bool) -> Cell {
    let mut cell = CellBuilder::new();
    cell.store_bit(true)
        .unwrap()
        .store_uint(2, 2)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_uint(0, 8)
        .unwrap()
        .store_bytes(&account)
        .unwrap()
        .store_uint(0, 3)
        .unwrap()
        .store_uint(0, 3)
        .unwrap()
        .store_uint(storage_extra, 3)
        .unwrap();
    if storage_extra == 1 {
        cell.store_bytes(&[0x11; 32]).unwrap();
    }
    cell.store_uint(1, 32)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_uint(1, 64)
        .unwrap()
        .store_coins(100)
        .unwrap()
        .store_bit(false)
        .unwrap();
    if active {
        cell.store_bit(true)
            .unwrap()
            .store_bit(false)
            .unwrap()
            .store_bit(false)
            .unwrap()
            .store_bit(true)
            .unwrap()
            .store_ref(code)
            .unwrap()
            .store_bit(true)
            .unwrap()
            .store_ref(CellBuilder::new().build())
            .unwrap()
            .store_bit(false)
            .unwrap();
    } else {
        cell.store_uint(0, 2).unwrap();
    }
    cell.build()
}

#[test]
fn active_account_code_binds_address_and_exact_current_layout() {
    let address = [1; 32];
    let mut code = CellBuilder::new();
    code.store_uint(42, 8).unwrap();
    let code = code.build();
    for extra in [0, 1] {
        let root = account(address, code.clone(), extra, true);
        assert_eq!(
            account_code(&root.to_boc().unwrap(), &address).unwrap(),
            SccpTonCodeRefV1 {
                hash: *code.hash(),
                depth: code.depth()
            }
        );
        assert!(account_code(&root.to_boc().unwrap(), &[2; 32]).is_err());
        let mut trailing = CellBuilder::new();
        for bit in 0..root.bit_len() {
            trailing
                .store_bit(root.data()[bit / 8] & (0x80 >> (bit % 8)) != 0)
                .unwrap();
        }
        trailing.store_bit(false).unwrap();
        for child in root.refs() {
            trailing.store_ref(child.clone()).unwrap();
        }
        assert!(account_code(&trailing.build().to_boc().unwrap(), &address).is_err());
    }
    assert!(
        account_code(
            &account(address, code.clone(), 2, true).to_boc().unwrap(),
            &address
        )
        .is_err()
    );
    assert!(
        account_code(
            &account(address, code, 0, false).to_boc().unwrap(),
            &address
        )
        .is_err()
    );
    assert!(account_code(&[], &address).is_err());
    let mut absent = CellBuilder::new();
    absent.store_bit(false).unwrap();
    assert!(account_code(&absent.build().to_boc().unwrap(), &address).is_err());
}

#[test]
fn minter_pristine_checks_every_fixed_identity_and_zero_balance_field() {
    let args = super::super::tests::args();
    let pristine = state(&args);
    assert_eq!(
        pristine_state(&args, &pristine).unwrap().generation,
        args.pin.generation
    );
    for index in [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 16, 17, 18, 19, 20, 21, 22,
    ] {
        let mut changed = pristine.clone();
        changed[index] = value(word_u64(1));
        assert!(pristine_state(&args, &changed).is_err(), "field {index}");
    }
    assert!(pristine_state(&args, &pristine[..23]).is_err());
    let mut changed = pristine;
    changed[10] = TvmStackValueV1::Null;
    assert!(pristine_state(&args, &changed).is_err());
}

#[test]
fn checkpoint_slots_are_complete_ordered_and_zero_when_unused() {
    let empty = vec![value([0; 32]); 7];
    assert!(checkpoints(&empty).unwrap().is_empty());
    let mut one = empty.clone();
    one[0] = value(word_u64(1));
    one[1] = value(word_u64(2));
    one[2] = value([3; 32]);
    assert_eq!(checkpoints(&one).unwrap(), vec![(2, [3; 32])]);
    let mut trailing = one.clone();
    trailing[6] = value([4; 32]);
    assert!(checkpoints(&trailing).is_err());
    let mut repeated = one.clone();
    repeated[0] = value(word_u64(2));
    repeated[3] = value(word_u64(2));
    repeated[4] = value([4; 32]);
    assert!(checkpoints(&repeated).is_err());
    one[0] = value(word_u64(4));
    assert!(checkpoints(&one).is_err());
    assert!(checkpoints(&empty[..6]).is_err());
}
