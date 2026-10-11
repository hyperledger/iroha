//! σ-field Poseidon, packed-byte and indexed-map witness tests.

use super::*;
use crate::kagemusha::kagemusha_wallet_v1::{
    KagemushaWalletValidationErrorV1,
    digest::{KAGEMUSHA_WALLET_FIELD_MODULUS_V1, kagemusha_wallet_field_from_u128_v1},
};

fn int(value: u128) -> [u8; 32] {
    kagemusha_wallet_field_from_u128_v1(value)
}

fn hex32(text: &str) -> [u8; 32] {
    let mut value = [0_u8; 32];
    value.copy_from_slice(&hex::decode(text).expect("hex"));
    value
}

#[track_caller]
fn assert_invalid<T: core::fmt::Debug>(result: WalletResult<T>, expected: &str) {
    match result {
        Err(KagemushaWalletValidationErrorV1::InvalidField { field }) if field == expected => {}
        other => panic!("expected invalid `{expected}`, got {other:?}"),
    }
}

/// A canonical stand-in key with `seed` in every byte below the most significant.
fn key(seed: u8) -> [u8; 32] {
    let mut value = [seed; 32];
    value[31] = seed & 0x3f;
    value
}

/// Leaf value of a stand-in leaf.
fn leaf(seed: u8) -> [u8; 32] {
    kagemusha_wallet_poseidon_v1(
        KAGEMUSHA_WALLET_CREDIT_DIGEST_VALUE_DOMAIN_V1,
        &[int(seed.into())],
    )
    .expect("leaf")
}

fn flip(value: &[u8; 32], height: usize) -> [u8; 32] {
    let mut flipped = *value;
    flipped[height / 8] ^= 1 << (height % 8);
    flipped
}

#[test]
fn kagemusha_wallet_v1_poseidon_domains_are_distinct_ascii_words() {
    let mut seen = std::collections::BTreeSet::new();
    for (name, domain) in KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1 {
        let ascii = domain.to_le_bytes();
        assert!(ascii.iter().all(u8::is_ascii_graphic), "{name}");
        assert_eq!(&ascii[..3], b"kgw", "{name}");
        assert!(seen.insert(domain), "{name}");
    }
    for (domain, ascii) in [
        (KAGEMUSHA_WALLET_CORE_DOMAIN_V1, b"kgwcore1"),
        (KAGEMUSHA_WALLET_REST_DOMAIN_V1, b"kgwrest1"),
        (KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1, b"kgwstmt1"),
        (KAGEMUSHA_WALLET_CREDIT_DOMAIN_V1, b"kgwcrdt1"),
        (KAGEMUSHA_WALLET_SEND_CHAIN_DOMAIN_V1, b"kgwschn1"),
        (KAGEMUSHA_WALLET_RECV_CHAIN_DOMAIN_V1, b"kgwrchn1"),
        (
            KAGEMUSHA_WALLET_CONSUMED_CREDIT_VALUE_DOMAIN_V1,
            b"kgwccrd1",
        ),
        (
            KAGEMUSHA_WALLET_PENDING_OUTGOING_VALUE_DOMAIN_V1,
            b"kgwpout1",
        ),
        (KAGEMUSHA_WALLET_LOAD_VALUE_DOMAIN_V1, b"kgwload1"),
        (KAGEMUSHA_WALLET_REDEEM_VALUE_DOMAIN_V1, b"kgwrdm_1"),
        (KAGEMUSHA_WALLET_FEE_CLAIM_VALUE_DOMAIN_V1, b"kgwfee_1"),
        (KAGEMUSHA_WALLET_QUOTA_USAGE_VALUE_DOMAIN_V1, b"kgwquse1"),
        (KAGEMUSHA_WALLET_CREDIT_DIGEST_VALUE_DOMAIN_V1, b"kgwcdig1"),
        (KAGEMUSHA_WALLET_INDEXED_LEAF_DOMAIN_V1, b"kgwimlf1"),
        (KAGEMUSHA_WALLET_INDEXED_NODE_DOMAIN_V1, b"kgwimnd1"),
        (KAGEMUSHA_WALLET_BLACKLIST_LEAF_DOMAIN_V1, b"kgwblkl1"),
        (KAGEMUSHA_WALLET_BLACKLIST_NODE_DOMAIN_V1, b"kgwblkn1"),
        (KAGEMUSHA_WALLET_QUOTA_WINDOW_DOMAIN_V1, b"kgwqwin1"),
        (KAGEMUSHA_WALLET_QUOTA_NODE_DOMAIN_V1, b"kgwqwnd1"),
        (KAGEMUSHA_WALLET_PROOF_DOMAIN_V1, b"kgwprf_1"),
        (KAGEMUSHA_WALLET_STEP_PROOF_DOMAIN_V1, b"kgwstep1"),
        (KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1, b"kgwpay_1"),
        (KAGEMUSHA_WALLET_LINEAGE_DOMAIN_V1, b"kgwlin_1"),
        (KAGEMUSHA_WALLET_CREDIT_OPENING_DOMAIN_V1, b"kgwcopn1"),
        (KAGEMUSHA_WALLET_CREDIT_STATUS_DOMAIN_V1, b"kgwcsts1"),
        (KAGEMUSHA_WALLET_CREDITED_DOMAIN_V1, b"kgwcrdd1"),
    ] {
        assert_eq!(domain.to_le_bytes(), *ascii);
        assert!(
            KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1
                .iter()
                .any(|(_, listed)| *listed == domain)
        );
    }
    assert_eq!(seen.len(), KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1.len());
}

/// `P` reproduces the KAGEMUSHA domain-hash vectors of the vendored sponge
/// (`fixtures/native_prover/kats_v1.json`, `kagemusha_v1_poseidon.fp`).
#[test]
fn kagemusha_wallet_v1_poseidon_reproduces_the_native_prover_kats() {
    use norito::json::Value;
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/native_prover/kats_v1.json");
    let text = std::fs::read_to_string(path).expect("kats_v1.json");
    let fixture = norito::json::parse_value(&text).expect("json");
    let fp = fixture
        .get("kagemusha_v1_poseidon")
        .and_then(|section| section.get("fp"))
        .expect("fp section");
    let Some(Value::Array(vectors)) = fp.get("vectors") else {
        panic!("vectors");
    };
    assert!(vectors.len() >= 5);
    for vector in vectors {
        let ascii = vector
            .get("domain")
            .and_then(Value::as_str)
            .expect("domain");
        let mut word = [0_u8; 8];
        word.copy_from_slice(ascii.as_bytes());
        let Some(Value::Array(inputs)) = vector.get("inputs") else {
            panic!("inputs");
        };
        let inputs: Vec<[u8; 32]> = inputs
            .iter()
            .map(|input| hex32(input.as_str().expect("input")))
            .collect();
        let output = hex32(
            vector
                .get("output")
                .and_then(Value::as_str)
                .expect("output"),
        );
        let domain = u64::from_le_bytes(word);
        assert_eq!(
            kagemusha_wallet_poseidon_v1(domain, &inputs).expect("canonical inputs"),
            output,
            "{ascii}"
        );
        assert_eq!(poseidon_items_v1(domain, &inputs), output, "{ascii}");
    }
    // This vendored generic-P known-answer fixture uses a separate 256-round domain pair.
    // It is not the wallet indexed-map construction, which has depth 32 and a sentinel.
    let empty = u64::from_le_bytes(*b"kgmemp_1");
    let node = u64::from_le_bytes(*b"kgmnode1");
    let mut root = kagemusha_wallet_poseidon_v1(empty, &[]).expect("empty");
    for _ in 0..256 {
        root = kagemusha_wallet_poseidon_v1(node, &[root, root]).expect("node");
    }
    let expected = fp
        .get("empty_replay_root")
        .and_then(Value::as_str)
        .expect("empty root");
    assert_eq!(root, hex32(expected));
}

#[test]
fn kagemusha_wallet_v1_poseidon_rejects_noncanonical_items() {
    assert_invalid(
        kagemusha_wallet_poseidon_v1(
            KAGEMUSHA_WALLET_CORE_DOMAIN_V1,
            &[KAGEMUSHA_WALLET_FIELD_MODULUS_V1],
        ),
        "poseidon.item",
    );
    assert_invalid(
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_CORE_DOMAIN_V1, &[int(1), [0xff; 32]]),
        "poseidon.item",
    );
    let mut below = KAGEMUSHA_WALLET_FIELD_MODULUS_V1;
    below[0] = 0;
    kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_CORE_DOMAIN_V1, &[below]).expect("p - 1");
    // The domain and the arity separate equal element lists.
    let one = kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_CORE_DOMAIN_V1, &[int(1)]).expect("a");
    assert_ne!(
        one,
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_REST_DOMAIN_V1, &[int(1)]).expect("b")
    );
    assert_ne!(
        one,
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_CORE_DOMAIN_V1, &[int(1), int(0)])
            .expect("c")
    );
}

/// The `P_bytes` packing rule: the length element, then 31-byte little-endian chunks, the
/// last zero-filled; empty input and the 31-byte chunk boundaries.
#[test]
fn kagemusha_wallet_v1_packed_bytes_rule() {
    assert_eq!(KAGEMUSHA_WALLET_PACKED_CHUNK_BYTES_V1, 31);
    let bytes: Vec<u8> = (1..=63_u8).collect();
    for (len, elements) in [(0, 1), (1, 2), (30, 2), (31, 2), (32, 3), (62, 3), (63, 4)] {
        let items = kagemusha_wallet_packed_bytes_v1(&bytes[..len]);
        assert_eq!(items.len(), elements, "len {len}");
        assert_eq!(
            items[0],
            int(u128::try_from(len).expect("len")),
            "len {len}"
        );
        for (index, item) in items.iter().enumerate().skip(1) {
            let start = (index - 1) * 31;
            let end = (start + 31).min(len);
            let mut expected = [0_u8; 32];
            expected[..end - start].copy_from_slice(&bytes[start..end]);
            assert_eq!(*item, expected, "len {len} chunk {index}");
            assert_eq!(item[31], 0);
        }
        assert_eq!(
            kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1, &bytes[..len]),
            kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1, &items)
                .expect("packed items are canonical"),
            "len {len}"
        );
    }
    // A full chunk of 0xff is still canonical (below 2^248).
    let full = kagemusha_wallet_packed_bytes_v1(&[0xff; 31]);
    assert_eq!(full[1][..31], [0xff; 31]);
    // The length element separates inputs that pack to equal chunks.
    assert_ne!(
        kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1, &[0]),
        kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1, &[0, 0])
    );
    assert_ne!(
        kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_PROOF_DOMAIN_V1, &[]),
        kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_STEP_PROOF_DOMAIN_V1, &[])
    );
}

#[test]
fn kagemusha_wallet_v1_indexed_tree_defaults_and_empty_root() {
    let empty_leaf = kagemusha_wallet_indexed_empty_subtree_v1(0).expect("empty slot");
    assert_eq!(empty_leaf, [0; 32]);
    let mut node = empty_leaf;
    for height in 1..=KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1 {
        node = kagemusha_wallet_indexed_node_v1(&node, &node).expect("node");
        assert_eq!(
            kagemusha_wallet_indexed_empty_subtree_v1(height).ok(),
            Some(node)
        );
    }
    let tree = KagemushaWalletIndexedTreeV1::new();
    let sentinel = KagemushaWalletIndexedLeafV1::SENTINEL;
    assert_eq!(tree.leaf_at(0), Some(sentinel));
    assert_eq!(tree.opening(0).leaf_root(&sentinel).ok(), Some(tree.root()));
    assert_eq!(kagemusha_wallet_empty_map_root_v1(), tree.root());
    assert_ne!(tree.root(), node, "an empty map authenticates its sentinel");
    assert_invalid(
        kagemusha_wallet_indexed_empty_subtree_v1(33),
        "indexed_tree.height",
    );
    assert_invalid(
        kagemusha_wallet_indexed_node_v1(&[0xff; 32], &node),
        "poseidon.item",
    );
}

#[test]
fn kagemusha_wallet_v1_pair_keys_are_canonical_and_injective() {
    let key = kagemusha_wallet_pair_key_v1(2, 0x0102);
    let mut expected = [0_u8; 32];
    expected[..16].copy_from_slice(&0x0102_u128.to_le_bytes());
    expected[16] = 2;
    assert_eq!(key, expected);
    assert!(
        super::super::digest::kagemusha_wallet_is_canonical_field_v1(
            &kagemusha_wallet_pair_key_v1(u8::MAX, u128::MAX)
        )
    );
    assert_ne!(
        kagemusha_wallet_pair_key_v1(1, 5),
        kagemusha_wallet_pair_key_v1(2, 5)
    );
    assert_ne!(
        kagemusha_wallet_pair_key_v1(1, 5),
        kagemusha_wallet_pair_key_v1(1, 6)
    );
}

#[test]
fn kagemusha_wallet_v1_indexed_tree_root_by_hand() {
    let a = key(0x10);
    let b = flip(&a, 0);
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    let before_a = tree.root();
    let insert_a = tree.insert(a, leaf(1)).expect("insert a");
    assert_eq!(
        insert_a.verify(&before_a, &a, &leaf(1)).ok(),
        Some(tree.root())
    );
    let before_b = tree.root();
    let insert_b = tree.insert(b, leaf(2)).expect("insert b");
    assert_eq!(
        insert_b.verify(&before_b, &b, &leaf(2)).ok(),
        Some(tree.root())
    );
    assert_eq!(tree.len(), 2);
    assert!(!tree.is_empty());
    assert_eq!(tree.next_free_slot(), 3);
    let sentinel = KagemushaWalletIndexedLeafV1 {
        next_key: a,
        ..KagemushaWalletIndexedLeafV1::SENTINEL
    };
    let a_leaf = KagemushaWalletIndexedLeafV1 {
        key: a,
        value: leaf(1),
        next_key: b,
    };
    let b_leaf = KagemushaWalletIndexedLeafV1 {
        key: b,
        value: leaf(2),
        next_key: [0; 32],
    };
    assert_eq!(tree.leaf_at(0), Some(sentinel));
    assert_eq!(tree.leaf_at(1), Some(a_leaf));
    assert_eq!(tree.leaf_at(2), Some(b_leaf));
    let left = kagemusha_wallet_indexed_node_v1(
        &sentinel.hash().expect("sentinel"),
        &a_leaf.hash().expect("a"),
    )
    .expect("left");
    let right =
        kagemusha_wallet_indexed_node_v1(&b_leaf.hash().expect("b"), &[0; 32]).expect("right");
    let mut node = kagemusha_wallet_indexed_node_v1(&left, &right).expect("subtree");
    for height in 2..KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1 {
        node = kagemusha_wallet_indexed_node_v1(
            &node,
            &kagemusha_wallet_indexed_empty_subtree_v1(height).expect("default"),
        )
        .expect("node");
    }
    assert_eq!(tree.root(), node);
    let update = tree.update(&a, leaf(3)).expect("update");
    assert_eq!(update.leaf.value, leaf(1));
    assert_eq!(update.verify(&node, &leaf(3)).ok(), Some(tree.root()));
    assert_ne!(tree.root(), node);
    assert_eq!(tree.get(&a), Some(leaf(3)));
    let before_remove = tree.root();
    let remove = tree.remove(&a).expect("remove a");
    assert_eq!(remove.leaf.value, leaf(3));
    assert_eq!(remove.verify(&before_remove, &a).ok(), Some(tree.root()));
    assert_eq!(tree.get(&a), None);
    let before_remove = tree.root();
    let remove = tree.remove(&b).expect("remove b");
    assert_eq!(remove.leaf.value, leaf(2));
    assert_eq!(remove.verify(&before_remove, &b).ok(), Some(tree.root()));
    assert_eq!(tree.root(), kagemusha_wallet_empty_map_root_v1());
    assert_eq!(tree.next_free_slot(), 3, "deleted slots remain consumed");
    let new = tree.insert(a, leaf(1)).expect("reinsert");
    assert_eq!(new.slot_opening.slot, 3, "removed slots are never reused");
    assert_eq!(tree.leaf_at(1), None);
    assert_eq!(tree.leaf_at(2), None);
    assert_invalid(tree.insert([0xff; 32], leaf(1)), "indexed_tree.key");
    assert_invalid(tree.insert([0; 32], leaf(1)), "indexed_tree.key");
    assert_invalid(tree.insert(b, [0xff; 32]), "indexed_tree.value");
    assert_invalid(tree.insert(b, [0; 32]), "indexed_tree.value");
    assert_invalid(tree.insert(a, leaf(3)), "indexed_tree.present");
}

#[test]
fn kagemusha_wallet_v1_indexed_tree_membership_and_absence_openings() {
    let base = key(0x5a);
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    tree.insert(base, leaf(1)).expect("base");
    for (seed, height) in [(2, 0_usize), (3, 7), (4, 200)] {
        tree.insert(flip(&base, height), leaf(seed))
            .expect("neighbour");
    }
    let root = tree.root();
    let (member, opening) = tree.membership(&base).expect("member");
    assert_eq!(opening.siblings.len(), 32);
    assert_eq!(
        opening.slot, 1,
        "path is allocated slot, independent of key bits"
    );
    assert_eq!((member.key, member.value), (base, leaf(1)));
    kagemusha_wallet_indexed_verify_membership_v1(&root, &member, &opening).expect("membership");
    assert_eq!(opening.leaf_root(&member).ok(), Some(root));
    assert_eq!(opening.leaf_transcript(&member).len(), 1_124);
    assert_eq!(opening.empty_transcript().len(), 1_028);
    for height in [0_usize, 7, 200] {
        let other = flip(&base, height);
        let (leaf, witness) = tree.membership(&other).expect("neighbour");
        assert_eq!(
            (leaf.key, leaf.value),
            (other, tree.get(&other).expect("value"))
        );
        assert!(witness.slot >= 2);
        kagemusha_wallet_indexed_verify_membership_v1(&root, &leaf, &witness)
            .expect("neighbour membership");
    }
    let absent = flip(&base, 3);
    let (low, absence) = tree.non_membership(&absent).expect("absence");
    assert!(low.brackets(&absent));
    kagemusha_wallet_indexed_verify_non_membership_v1(&root, &absent, &low, &absence)
        .expect("absence");
    assert_invalid(tree.membership(&absent), "indexed_tree.absent");
    assert_invalid(tree.non_membership(&base), "indexed_tree.present");
    assert_invalid(
        kagemusha_wallet_indexed_verify_non_membership_v1(&root, &base, &member, &opening),
        "indexed_tree.low_leaf",
    );
    let wrong_value = KagemushaWalletIndexedLeafV1 {
        value: leaf(9),
        ..member
    };
    assert_invalid(
        kagemusha_wallet_indexed_verify_membership_v1(&root, &wrong_value, &opening),
        "indexed_opening.root",
    );
    let wrong_key = KagemushaWalletIndexedLeafV1 {
        key: flip(&base, 100),
        next_key: [0; 32],
        ..member
    };
    assert_invalid(
        kagemusha_wallet_indexed_verify_membership_v1(&root, &wrong_key, &opening),
        "indexed_opening.root",
    );
    let mut sibling = opening;
    sibling.siblings[1] = leaf(7);
    assert_invalid(
        kagemusha_wallet_indexed_verify_membership_v1(&root, &member, &sibling),
        "indexed_opening.root",
    );
    let bytes = opening.sibling_bytes();
    assert_eq!(
        KagemushaWalletIndexedOpeningV1::from_sibling_bytes(opening.slot, &bytes).ok(),
        Some(opening)
    );
    assert_invalid(
        KagemushaWalletIndexedOpeningV1::from_sibling_bytes(opening.slot, &bytes[..992]),
        "indexed_opening.siblings",
    );
    assert_invalid(
        KagemushaWalletIndexedOpeningV1::from_sibling_bytes(
            opening.slot,
            &[bytes.clone(), vec![0; 32]].concat(),
        ),
        "indexed_opening.siblings",
    );
    let mut moved = opening;
    moved.slot = 2;
    assert_invalid(
        kagemusha_wallet_indexed_verify_membership_v1(&root, &member, &moved),
        "indexed_opening.root",
    );
    let mut reordered = opening;
    reordered.siblings.swap(0, 1);
    assert_invalid(
        kagemusha_wallet_indexed_verify_membership_v1(&root, &member, &reordered),
        "indexed_opening.root",
    );
    let mut noncanonical = opening;
    noncanonical.siblings[0] = [0xff; 32];
    assert_invalid(noncanonical.leaf_root(&member), "indexed_opening.sibling");
    assert_invalid(
        KagemushaWalletIndexedLeafV1 {
            key: [0xff; 32],
            ..member
        }
        .hash(),
        "indexed_leaf.field",
    );
    assert_invalid(
        KagemushaWalletIndexedLeafV1 {
            value: [0xff; 32],
            ..member
        }
        .hash(),
        "indexed_leaf.field",
    );
    assert_invalid(
        KagemushaWalletIndexedLeafV1 {
            next_key: member.key,
            ..member
        }
        .hash(),
        "indexed_leaf.next_key",
    );
    assert_invalid(tree.membership(&[0xff; 32]), "indexed_tree.key");
    let empty = KagemushaWalletIndexedTreeV1::new();
    let (sentinel, opening) = empty.non_membership(&base).expect("empty absence");
    assert_eq!(sentinel, KagemushaWalletIndexedLeafV1::SENTINEL);
    assert_eq!(opening.slot, 0);
    assert_eq!(opening.siblings.len(), 32);
    kagemusha_wallet_indexed_verify_non_membership_v1(&empty.root(), &base, &sentinel, &opening)
        .expect("empty absence");
}

#[test]
fn kagemusha_wallet_v1_indexed_tree_commits_insertion_order_and_replays_deterministically() {
    let keys: Vec<[u8; 32]> = (1..=6_u8).map(key).collect();
    let mut forward = KagemushaWalletIndexedTreeV1::new();
    let mut replay = KagemushaWalletIndexedTreeV1::new();
    let mut backward = KagemushaWalletIndexedTreeV1::new();
    for (index, key) in keys.iter().enumerate() {
        let value = leaf(u8::try_from(index).expect("seed"));
        let previous = forward.root();
        let witness = forward.insert(*key, value).expect("insert");
        replay.insert(*key, value).expect("same ordered insertion");
        assert_eq!(
            witness.verify(&previous, key, &value).ok(),
            Some(forward.root())
        );
        assert_eq!(forward.root(), replay.root());
    }
    for (index, key) in keys.iter().enumerate().rev() {
        backward
            .insert(*key, leaf(u8::try_from(index).expect("seed")))
            .expect("insert");
    }
    assert_ne!(
        forward.root(),
        backward.root(),
        "allocated slots commit to insertion order"
    );
    assert_eq!(forward.len(), backward.len());
    assert_eq!(forward.next_free_slot(), backward.next_free_slot());
    for (index, key) in keys.iter().enumerate() {
        let (left, left_opening) = forward.membership(key).expect("forward");
        let (right, right_opening) = backward.membership(key).expect("backward");
        assert_eq!(
            left, right,
            "both linked maps retain identical key/value/next-key state"
        );
        assert_eq!(left.value, leaf(u8::try_from(index).expect("seed")));
        assert_ne!(left_opening.slot, right_opening.slot);
        kagemusha_wallet_indexed_verify_membership_v1(&forward.root(), &left, &left_opening)
            .expect("forward membership");
        kagemusha_wallet_indexed_verify_membership_v1(&backward.root(), &right, &right_opening)
            .expect("backward membership");
    }
}

#[test]
fn kagemusha_wallet_v1_indexed_transition_witnesses_reject_wrong_roots_and_links() {
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    let a = int(5);
    let b = int(9);
    let previous = tree.root();
    let insert = tree.insert(a, leaf(1)).expect("insert");
    let inserted = tree.root();
    assert_eq!(insert.verify(&previous, &a, &leaf(1)).ok(), Some(inserted));
    assert_invalid(insert.verify(&previous, &a, &[0; 32]), "indexed_tree.value");
    let mut wrong_slot = insert;
    wrong_slot.slot_opening.slot = 0;
    assert_invalid(
        wrong_slot.verify(&previous, &a, &leaf(1)),
        "indexed_tree.slot",
    );
    let mut wrong_low = insert;
    wrong_low.low.next_key = a;
    assert_invalid(
        wrong_low.verify(&previous, &a, &leaf(1)),
        "indexed_tree.low_leaf",
    );
    tree.insert(b, leaf(2)).expect("insert b");
    let previous = tree.root();
    let update = tree.update(&a, leaf(3)).expect("update");
    assert_eq!(update.verify(&previous, &leaf(3)).ok(), Some(tree.root()));
    assert_invalid(update.verify(&inserted, &leaf(3)), "indexed_opening.root");
    assert_invalid(update.verify(&previous, &[0xff; 32]), "indexed_tree.value");
    let previous = tree.root();
    let remove = tree.remove(&a).expect("remove");
    assert_eq!(remove.verify(&previous, &a).ok(), Some(tree.root()));
    let mut wrong_link = remove;
    wrong_link.predecessor.next_key = b;
    assert_invalid(wrong_link.verify(&previous, &a), "indexed_tree.remove");
    let mut same_slot = remove;
    same_slot.leaf_opening.slot = same_slot.predecessor_opening.slot;
    assert_invalid(same_slot.verify(&previous, &a), "indexed_tree.remove");
    assert_invalid(remove.verify(&inserted, &a), "indexed_opening.root");
    assert_invalid(remove.verify(&previous, &b), "indexed_tree.remove");
}
