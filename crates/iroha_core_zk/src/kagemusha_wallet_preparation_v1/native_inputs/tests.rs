//! Exact retained recovery-path conversion and hostile source substitutions.

use ff::Field;
use iroha_kagemusha_proof::tree::IndexedTree;

use super::*;

struct Recovery {
    effect: KagemushaWalletEffectV1,
    originals: Vec<Vec<u8>>,
    before: [u8; 32],
    after: [u8; 32],
    expected: IndexedInsert<Fp>,
    before_empty: Vec<u8>,
}

fn word(bytes: [u8; 32]) -> Fp {
    Option::<Fp>::from(Fp::from_repr(bytes)).unwrap()
}

fn recovery() -> Recovery {
    let mut wire = KagemushaWalletIndexedTreeV1::new();
    let mut native = IndexedTree::<Fp>::new();
    for ordinal in [2, 11, 13] {
        let leaf = KagemushaWalletRedeemLeafV1 {
            ordinal,
            nullifier: Fp::from(17).to_repr(),
            amount: 19,
            online_charge: 3,
        };
        let key = leaf.key();
        let value = leaf.leaf_value().unwrap();
        wire.insert(key, value).unwrap();
        native.insert(word(key), word(value)).unwrap();
    }
    let leaf = KagemushaWalletRedeemLeafV1 {
        ordinal: 7,
        nullifier: Fp::from(23).to_repr(),
        amount: 29,
        online_charge: 5,
    };
    let before = wire.root();
    assert_eq!(before, native.root().to_repr());
    let before_empty = wire
        .opening(u32::try_from(wire.next_free_slot()).unwrap())
        .empty_transcript();
    let insertion = wire.insert(leaf.key(), leaf.leaf_value().unwrap()).unwrap();
    let expected = native
        .insert(word(leaf.key()), word(leaf.leaf_value().unwrap()))
        .unwrap();
    assert_eq!(wire.root(), native.root().to_repr());
    Recovery {
        effect: KagemushaWalletEffectV1::Unload {
            nullifier: leaf.nullifier,
            redeem_ordinal: leaf.ordinal,
            amount: leaf.amount,
            online_charge: leaf.online_charge,
            charge_quote: Fp::from(31).to_repr(),
        },
        originals: vec![
            insertion.low_opening.leaf_transcript(&insertion.low),
            insertion.slot_opening.empty_transcript(),
        ],
        before,
        after: wire.root(),
        expected,
        before_empty,
    }
}

fn convert(source: &Recovery) -> Result<Option<IndexedInsert<Fp>>, Error> {
    consuming_recovery(
        &source.effect,
        &source.originals,
        &source.before,
        &source.after,
    )
}

#[test]
fn unload_originals_match_independent_native_tree_and_every_path_word() {
    let source = recovery();
    assert_eq!(convert(&source).unwrap(), Some(source.expected));
    assert_ne!(source.expected.leaf.key, Fp::ZERO);
    assert_ne!(source.expected.leaf.next_key, Fp::ZERO);
    assert_ne!(source.before, source.after);
    assert_ne!(source.originals[1], source.before_empty);
}

#[test]
fn load_originals_bind_receipt_ordinal_amount_and_both_recovery_roots() {
    let mut wire = KagemushaWalletIndexedTreeV1::new();
    let mut native = IndexedTree::<Fp>::new();
    let leaf = KagemushaWalletLoadLeafV1 {
        ordinal: 7,
        receipt_digest: Fp::from(29).to_repr(),
        amount: 31,
    };
    let before = wire.root();
    let inserted = wire.insert(leaf.key(), leaf.leaf_value().unwrap()).unwrap();
    let expected = native
        .insert(word(leaf.key()), word(leaf.leaf_value().unwrap()))
        .unwrap();
    let after = wire.root();
    let originals = vec![
        inserted.low_opening.leaf_transcript(&inserted.low),
        inserted.slot_opening.empty_transcript(),
    ];
    let effect = KagemushaWalletEffectV1::Load {
        receipt_digest: leaf.receipt_digest,
        load_ordinal: leaf.ordinal,
        amount: leaf.amount,
        online_charge: 3,
    };
    assert_eq!(
        load_recovery(&effect, &originals, &before, &after).unwrap(),
        expected
    );
    assert_eq!(after, native.root().to_repr());
    for malformed in [
        vec![],
        originals[..1].to_vec(),
        vec![originals[1].clone(), originals[0].clone()],
        vec![originals[0].clone(); 2],
    ] {
        assert!(load_recovery(&effect, &malformed, &before, &after).is_err());
    }
    assert!(
        load_recovery(
            &KagemushaWalletEffectV1::Retiring,
            &originals,
            &before,
            &after
        )
        .is_err()
    );
    for changed in [
        KagemushaWalletEffectV1::Load {
            receipt_digest: Fp::from(37).to_repr(),
            load_ordinal: 7,
            amount: 31,
            online_charge: 3,
        },
        KagemushaWalletEffectV1::Load {
            receipt_digest: leaf.receipt_digest,
            load_ordinal: 8,
            amount: 31,
            online_charge: 3,
        },
        KagemushaWalletEffectV1::Load {
            receipt_digest: leaf.receipt_digest,
            load_ordinal: 7,
            amount: 32,
            online_charge: 3,
        },
    ] {
        assert!(load_recovery(&changed, &originals, &before, &after).is_err());
    }
    assert!(load_recovery(&effect, &originals, &after, &after).is_err());
    assert!(load_recovery(&effect, &originals, &before, &before).is_err());
    for index in 0..32 {
        let mut changed = inserted;
        changed.slot_opening.siblings[index] =
            Fp::from(u64::try_from(index + 2).unwrap()).to_repr();
        let originals = vec![
            changed.low_opening.leaf_transcript(&changed.low),
            changed.slot_opening.empty_transcript(),
        ];
        assert!(load_recovery(&effect, &originals, &before, &after).is_err());
    }
}

#[test]
fn unload_requires_exact_path_count_order_roles_and_canonical_frames() {
    let source = recovery();
    let wrong = vec![
        vec![],
        vec![source.originals[0].clone()],
        vec![source.originals[1].clone(), source.originals[0].clone()],
        vec![source.originals[0].clone(); 2],
        vec![source.originals[1].clone(); 2],
        [source.originals.clone(), vec![source.originals[0].clone()]].concat(),
    ];
    for originals in wrong {
        assert_eq!(
            consuming_recovery(&source.effect, &originals, &source.before, &source.after),
            Err(Error::Authority)
        );
    }
    for role in 0..2 {
        for change in 0..3 {
            let mut originals = source.originals.clone();
            match change {
                0 => originals[role].push(0),
                1 => {
                    originals[role].pop();
                }
                _ => {
                    let first_sibling = if role == 0 { 100 } else { 4 };
                    originals[role][first_sibling..first_sibling + 32].fill(0xff);
                }
            }
            assert_eq!(
                consuming_recovery(&source.effect, &originals, &source.before, &source.after),
                Err(Error::Authority)
            );
        }
    }
}

#[test]
fn unload_authenticates_both_paths_against_exact_old_and_new_roots() {
    let source = recovery();
    // Low key/value/next key, leaf slot and both ends of each sibling path.
    for (role, offsets) in [(0, vec![0, 32, 64, 96, 100, 1092]), (1, vec![0, 4, 996])] {
        for offset in offsets {
            let mut originals = source.originals.clone();
            originals[role][offset] ^= 1;
            assert_eq!(
                consuming_recovery(&source.effect, &originals, &source.before, &source.after),
                Err(Error::Authority),
                "changed role {role} byte {offset}"
            );
        }
    }
    for change_old in [true, false] {
        let mut before = source.before;
        let mut after = source.after;
        if change_old {
            before = Fp::from(37).to_repr();
        } else {
            after = Fp::from(41).to_repr();
        }
        assert_eq!(
            consuming_recovery(&source.effect, &source.originals, &before, &after),
            Err(Error::Authority)
        );
    }
    let mut originals = source.originals.clone();
    originals[1] = source.before_empty;
    assert_eq!(
        consuming_recovery(&source.effect, &originals, &source.before, &source.after),
        Err(Error::Authority),
        "the insertion slot must open after relinking the low leaf"
    );
    originals[1] = originals[0][96..].to_vec();
    assert_eq!(
        consuming_recovery(&source.effect, &originals, &source.before, &source.after),
        Err(Error::Authority),
        "an occupied low-leaf slot cannot be reused as the empty destination"
    );
}

#[test]
fn unload_recovery_value_binds_every_redeem_leaf_field() {
    let source = recovery();
    for changed in 0..5 {
        let mut effect = source.effect;
        let KagemushaWalletEffectV1::Unload {
            nullifier,
            redeem_ordinal,
            amount,
            online_charge,
            ..
        } = &mut effect
        else {
            unreachable!();
        };
        match changed {
            0 => *nullifier = Fp::from(43).to_repr(),
            1 => *redeem_ordinal += 1,
            2 => *amount += 1,
            3 => *online_charge += 1,
            _ => *nullifier = [0xff; 32],
        }
        assert_eq!(
            consuming_recovery(&effect, &source.originals, &source.before, &source.after),
            Err(Error::Authority)
        );
    }
}

#[test]
fn bootstrap_and_retiring_accept_no_map_paths_and_retiring_cannot_change_root() {
    let source = recovery();
    assert_eq!(no_map_openings(&[]), Ok(()));
    assert_eq!(no_map_openings(&[vec![]]), Err(Error::Authority));
    assert_eq!(no_map_openings(&source.originals), Err(Error::Authority));
    assert_eq!(
        consuming_recovery(
            &KagemushaWalletEffectV1::Retiring,
            &[],
            &source.before,
            &source.before
        ),
        Ok(None)
    );
    assert_eq!(
        consuming_recovery(
            &KagemushaWalletEffectV1::Retiring,
            &[],
            &source.before,
            &source.after
        ),
        Err(Error::Authority)
    );
    assert_eq!(
        consuming_recovery(
            &KagemushaWalletEffectV1::Retiring,
            &source.originals,
            &source.before,
            &source.before
        ),
        Err(Error::Authority)
    );
    assert_eq!(
        consuming_recovery(
            &KagemushaWalletEffectV1::ArchiveSent {
                credit_id: Fp::from(43).to_repr(),
                credited: Fp::from(47).to_repr()
            },
            &[],
            &source.before,
            &source.before
        ),
        Err(Error::Authority)
    );
}
