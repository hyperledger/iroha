//! σ-field Poseidon, packed-byte, integer-order and indexed-tree tests.

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

/// A stand-in map value.
fn value(seed: u8) -> [u8; 32] {
    kagemusha_wallet_poseidon_v1(
        KAGEMUSHA_WALLET_CREDIT_DIGEST_VALUE_DOMAIN_V1,
        &[int(seed.into())],
    )
    .expect("value")
}

/// Node over canonical children.
fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    kagemusha_wallet_indexed_node_v1(left, right).expect("node")
}

/// Leaf hash of `(key, value, next_key)`.
fn leaf_hash(key: &[u8; 32], value: &[u8; 32], next_key: &[u8; 32]) -> [u8; 32] {
    KagemushaWalletIndexedLeafV1 {
        key: *key,
        value: *value,
        next_key: *next_key,
    }
    .hash()
    .expect("leaf")
}

fn empty(height: usize) -> [u8; 32] {
    kagemusha_wallet_indexed_empty_subtree_v1(height).expect("empty subtree")
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
        (KAGEMUSHA_WALLET_LOAD_RECEIPT_DOMAIN_V1, b"kgwolod1"),
        (KAGEMUSHA_WALLET_REDEEM_VALUE_DOMAIN_V1, b"kgwrdm_1"),
        (KAGEMUSHA_WALLET_FEE_CLAIM_VALUE_DOMAIN_V1, b"kgwfee_1"),
        (KAGEMUSHA_WALLET_QUOTA_USAGE_LEAF_DOMAIN_V1, b"kgwquse1"),
        (KAGEMUSHA_WALLET_QUOTA_USAGE_NODE_DOMAIN_V1, b"kgwqusn1"),
        (
            KAGEMUSHA_WALLET_BLACKLIST_HISTORY_VALUE_DOMAIN_V1,
            b"kgwbhst1",
        ),
        (KAGEMUSHA_WALLET_CERTIFICATE_SET_DOMAIN_V1, b"kgwcset1"),
        (KAGEMUSHA_WALLET_PACKAGE_DOMAIN_V1, b"kgwpkg_1"),
        (KAGEMUSHA_WALLET_NULLIFIER_DOMAIN_V1, b"kgwnull1"),
        (KAGEMUSHA_WALLET_OPERATION_ID_DOMAIN_V1, b"kgwopid1"),
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
    assert_eq!(seen.len(), 33);
    // The superseded sparse-tree domains are gone.
    for retired in [*b"kgwsmte1", *b"kgwsmtn1"] {
        assert!(!seen.contains(&u64::from_le_bytes(retired)));
    }
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
    // The empty depth-256 replay root of the same construction (another domain pair).
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

/// Integer order of 32-byte little-endian values, at the limb boundary and against the
/// unsigned byte order (owner answer A4).
#[test]
fn kagemusha_wallet_v1_integer_order_is_the_limb_order() {
    use core::cmp::Ordering::{Equal, Greater, Less};
    let mut low_limb_one = [0_u8; 32];
    low_limb_one[0] = 1;
    let mut high_limb_one = [0_u8; 32];
    high_limb_one[16] = 1;
    // Byte 0 decides the unsigned byte order; the high limb decides the integer order.
    assert_eq!(low_limb_one.cmp(&high_limb_one), Greater);
    assert_eq!(
        kagemusha_wallet_integer_cmp_v1(&low_limb_one, &high_limb_one),
        Less
    );
    // `lo = 2^128 − 1, hi = 0` is just below `lo = 0, hi = 1`.
    let mut max_low = [0_u8; 32];
    max_low[..16].copy_from_slice(&[0xff; 16]);
    assert_eq!(
        kagemusha_wallet_integer_cmp_v1(&max_low, &high_limb_one),
        Less
    );
    // Equal high limbs compare by the low limb, most significant byte first.
    let mut a = [0x11_u8; 32];
    let mut b = a;
    a[15] = 0x10;
    b[0] = 0x00;
    assert_eq!(kagemusha_wallet_integer_cmp_v1(&a, &b), Less);
    assert_eq!(a.cmp(&b), Greater);
    assert_eq!(kagemusha_wallet_integer_cmp_v1(&a, &a), Equal);
    // The sentinels are the extremes.
    for value in [low_limb_one, high_limb_one, max_low, a, b] {
        assert_eq!(kagemusha_wallet_integer_cmp_v1(&[0; 32], &value), Less);
        assert_eq!(kagemusha_wallet_integer_cmp_v1(&value, &[0xff; 32]), Less);
    }
    // Pair keys order by kind, then ordinal.
    assert_eq!(
        kagemusha_wallet_integer_cmp_v1(
            &kagemusha_wallet_pair_key_v1(1, u128::MAX),
            &kagemusha_wallet_pair_key_v1(2, 0)
        ),
        Less
    );
}

/// The empty subtrees, the sentinel leaf and the empty-tree root, and their pinned values.
#[test]
fn kagemusha_wallet_v1_indexed_tree_empty_root() {
    assert_eq!(empty(0), [0; 32]);
    for height in 0..KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1 {
        assert_eq!(empty(height + 1), node(&empty(height), &empty(height)));
    }
    assert_invalid(
        kagemusha_wallet_indexed_empty_subtree_v1(KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1 + 1),
        "indexed_tree.height",
    );
    let sentinel = KagemushaWalletIndexedLeafV1::SENTINEL
        .hash()
        .expect("sentinel");
    assert_eq!(
        sentinel,
        kagemusha_wallet_poseidon_v1(
            KAGEMUSHA_WALLET_INDEXED_LEAF_DOMAIN_V1,
            &[[0; 32], [0; 32], [0; 32]]
        )
        .expect("sentinel")
    );
    let mut root = sentinel;
    for height in 0..KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1 {
        root = node(&root, &empty(height));
    }
    let tree = KagemushaWalletIndexedTreeV1::new();
    assert_eq!(tree.root(), root);
    assert_eq!(kagemusha_wallet_empty_map_root_v1(), root);
    assert_eq!(tree.len(), 0);
    assert!(tree.is_empty());
    assert_eq!(tree.next_free_slot(), 1);
    assert_eq!(
        tree.leaf_at(0),
        Some(KagemushaWalletIndexedLeafV1::SENTINEL)
    );
    assert_eq!(hex::encode(sentinel), SENTINEL_LEAF_HEX);
    assert_eq!(hex::encode(root), EMPTY_ROOT_HEX);
    assert_invalid(
        kagemusha_wallet_indexed_node_v1(&[0xff; 32], &root),
        "poseidon.item",
    );
}

/// Pinned sentinel leaf `P(kgwimlf1, [0, 0, 0])`.
const SENTINEL_LEAF_HEX: &str = "d3f1ff2c55cd0da336138793d486261211bfdbc7a4b6e9be336b8b09bc0e3a1c";
/// Pinned empty-tree root.
const EMPTY_ROOT_HEX: &str = "e1844c5683af83c12383e719e37a29a9b1867d1c171e77e1d060bafc401d5118";

/// A two-insertion tree recomputed by hand: slots 0, 1, 2 and the sorted links.
#[test]
fn kagemusha_wallet_v1_indexed_tree_root_by_hand() {
    let (low, high) = (key(0x05), key(0x09));
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    // Insert the larger key first: slot 1 holds it, slot 2 the smaller one.
    tree.insert(high, value(1)).expect("high");
    tree.insert(low, value(2)).expect("low");
    assert_eq!(tree.len(), 2);
    assert_eq!(tree.next_free_slot(), 3);
    let slot0 = leaf_hash(&[0; 32], &[0; 32], &low);
    let slot1 = leaf_hash(&high, &value(1), &[0; 32]);
    let slot2 = leaf_hash(&low, &value(2), &high);
    let mut root = node(&node(&slot0, &slot1), &node(&slot2, &empty(0)));
    for height in 2..KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1 {
        root = node(&root, &empty(height));
    }
    assert_eq!(tree.root(), root);
    assert_eq!(tree.get(&high), Some(value(1)));
    assert_eq!(tree.get(&low), Some(value(2)));
    assert_eq!(tree.get(&key(0x07)), None);
    assert_eq!(tree.get(&[0; 32]), None);
    // The root depends on insertion order (slots), not only on the key set.
    let mut other = KagemushaWalletIndexedTreeV1::new();
    other.insert(low, value(2)).expect("low");
    other.insert(high, value(1)).expect("high");
    assert_ne!(other.root(), tree.root());
}

/// Successive insertions at slots 1, 2, 3, … keep one list sorted by key.
#[test]
fn kagemusha_wallet_v1_indexed_tree_insertions_link_sorted_leaves() {
    let keys = [key(0x20), key(0x08), key(0x30), key(0x10), key(0x01)];
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    for (index, key) in keys.iter().enumerate() {
        let before = tree.root();
        let slot = tree.next_free_slot();
        let seed = u8::try_from(index).expect("seed");
        let witness = tree.insert(*key, value(seed)).expect("insert");
        assert_eq!(
            witness.slot_opening.slot,
            u32::try_from(slot).expect("slot")
        );
        assert_eq!(
            witness.verify(&before, key, &value(seed)).ok(),
            Some(tree.root())
        );
        assert_eq!(
            tree.leaf_at(witness.slot_opening.slot).map(|leaf| leaf.key),
            Some(*key)
        );
    }
    // Walk the list from the sentinel.
    let mut sorted = keys;
    sorted.sort_by(kagemusha_wallet_integer_cmp_v1);
    let mut current = tree.leaf_at(0).expect("sentinel");
    for expected in sorted {
        assert_eq!(current.next_key, expected);
        let (leaf, _) = tree.membership(&expected).expect("member");
        current = leaf;
    }
    assert_eq!(current.next_key, [0; 32]);
    // Inserting a present key, a zero or noncanonical key, or a zero value is rejected.
    let root = tree.root();
    assert_invalid(tree.insert(keys[0], value(9)), "indexed_tree.present");
    assert_invalid(tree.insert([0; 32], value(9)), "indexed_tree.key");
    assert_invalid(tree.insert([0xff; 32], value(9)), "indexed_tree.key");
    assert_invalid(tree.insert(key(0x02), [0; 32]), "indexed_tree.value");
    assert_invalid(tree.insert(key(0x02), [0xff; 32]), "indexed_tree.value");
    assert_eq!(tree.root(), root);
}

/// Membership and non-membership openings, through the sentinel, an interior low leaf and the
/// largest key.
#[test]
fn kagemusha_wallet_v1_indexed_tree_membership_and_non_membership() {
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    for (seed, key) in [(1, key(0x10)), (2, key(0x20)), (3, key(0x30))] {
        tree.insert(key, value(seed)).expect("insert");
    }
    let root = tree.root();
    for member in [key(0x10), key(0x20), key(0x30)] {
        let (leaf, opening) = tree.membership(&member).expect("membership");
        assert_eq!(leaf.key, member);
        kagemusha_wallet_indexed_verify_membership_v1(&root, &leaf, &opening).expect("member");
        assert_eq!(
            opening.leaf_transcript(&leaf).len(),
            KAGEMUSHA_WALLET_INDEXED_LEAF_OPENING_TRANSCRIPT_BYTES_V1
        );
    }
    for (absent, low_key) in [
        (key(0x01), [0; 32]),
        (key(0x18), key(0x10)),
        (key(0x3e), key(0x30)),
    ] {
        let (low, opening) = tree.non_membership(&absent).expect("non-membership");
        assert_eq!(low.key, low_key);
        assert!(low.brackets(&absent));
        kagemusha_wallet_indexed_verify_non_membership_v1(&root, &absent, &low, &opening)
            .expect("absent");
        // The same low leaf proves nothing about a key it does not bracket.
        assert_invalid(
            kagemusha_wallet_indexed_verify_non_membership_v1(&root, &key(0x20), &low, &opening),
            "indexed_tree.low_leaf",
        );
    }
    assert_eq!(tree.non_membership(&key(0x01)).expect("low").1.slot, 0);
    assert_invalid(tree.membership(&key(0x18)), "indexed_tree.absent");
    assert_invalid(tree.non_membership(&key(0x20)), "indexed_tree.present");
    assert_invalid(tree.membership(&[0; 32]), "indexed_tree.key");
    assert_invalid(tree.non_membership(&[0xff; 32]), "indexed_tree.key");
    // An empty slot never opens as a leaf.
    let empty_slot = tree.opening(9);
    assert_eq!(empty_slot.empty_root().ok(), Some(root));
    assert_eq!(
        empty_slot.empty_transcript().len(),
        KAGEMUSHA_WALLET_INDEXED_EMPTY_OPENING_TRANSCRIPT_BYTES_V1
    );
    assert_invalid(
        kagemusha_wallet_indexed_verify_membership_v1(
            &root,
            &KagemushaWalletIndexedLeafV1 {
                key: key(0x40),
                value: value(4),
                next_key: [0; 32],
            },
            &empty_slot,
        ),
        "indexed_opening.root",
    );
}

/// Tampered openings, forged low leaves and noncanonical siblings are rejected.
#[test]
fn kagemusha_wallet_v1_indexed_tree_rejects_tampered_openings() {
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    for (seed, key) in [(1, key(0x10)), (2, key(0x20)), (3, key(0x30))] {
        tree.insert(key, value(seed)).expect("insert");
    }
    let root = tree.root();
    let (leaf, opening) = tree.membership(&key(0x20)).expect("membership");
    for height in [0_usize, 1, 5, 31] {
        let mut tampered = opening;
        tampered.siblings[height][0] ^= 1;
        assert_invalid(
            kagemusha_wallet_indexed_verify_membership_v1(&root, &leaf, &tampered),
            "indexed_opening.root",
        );
        let mut moved = opening;
        moved.slot ^= 1 << height;
        assert_invalid(
            kagemusha_wallet_indexed_verify_membership_v1(&root, &leaf, &moved),
            "indexed_opening.root",
        );
    }
    for forged in [
        KagemushaWalletIndexedLeafV1 {
            value: value(9),
            ..leaf
        },
        KagemushaWalletIndexedLeafV1 {
            next_key: key(0x28),
            ..leaf
        },
    ] {
        assert_invalid(
            kagemusha_wallet_indexed_verify_membership_v1(&root, &forged, &opening),
            "indexed_opening.root",
        );
    }
    // A forged low leaf that brackets the key but is not in the tree.
    let forged_low = KagemushaWalletIndexedLeafV1 {
        key: key(0x10),
        value: value(1),
        next_key: key(0x30),
    };
    let (_, low_opening) = tree.non_membership(&key(0x18)).expect("low");
    assert_invalid(
        kagemusha_wallet_indexed_verify_non_membership_v1(
            &root,
            &key(0x20),
            &forged_low,
            &low_opening,
        ),
        "indexed_opening.root",
    );
    // A next key not above the key, and a noncanonical sibling.
    assert_invalid(
        KagemushaWalletIndexedLeafV1 {
            next_key: key(0x01),
            ..leaf
        }
        .hash(),
        "indexed_leaf.next_key",
    );
    let mut noncanonical = opening;
    noncanonical.siblings[3] = [0xff; 32];
    assert_invalid(noncanonical.leaf_root(&leaf), "indexed_opening.sibling");
    assert_invalid(
        KagemushaWalletIndexedOpeningV1::from_sibling_bytes(1, &[0; 1023]),
        "indexed_opening.siblings",
    );
    assert_invalid(
        KagemushaWalletIndexedOpeningV1::from_sibling_bytes(1, &[0xff; 1024]),
        "indexed_opening.sibling",
    );
    let round_trip =
        KagemushaWalletIndexedOpeningV1::from_sibling_bytes(opening.slot, &opening.sibling_bytes())
            .expect("round trip");
    assert_eq!(round_trip, opening);
}

/// Opening transcripts (§3.2, owner answer A2) parse back to their leaf and opening: a leaf
/// opening is exactly 1,124 bytes, an empty-slot opening exactly 1,028, each with 32 canonical
/// siblings; every other length, an invalid leaf and a noncanonical value are rejected.
#[test]
fn kagemusha_wallet_v1_indexed_opening_transcripts_round_trip() {
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    for (seed, key) in [(1, key(0x10)), (2, key(0x20))] {
        tree.insert(key, value(seed)).expect("insert");
    }
    let root = tree.root();
    let (leaf, opening) = tree.membership(&key(0x20)).expect("membership");
    let leaf_bytes = opening.leaf_transcript(&leaf);
    assert_eq!(
        leaf_bytes.len(),
        KAGEMUSHA_WALLET_INDEXED_LEAF_OPENING_TRANSCRIPT_BYTES_V1
    );
    let (parsed_leaf, parsed) =
        KagemushaWalletIndexedOpeningV1::from_transcript(&leaf_bytes).expect("leaf opening");
    assert_eq!((parsed_leaf, parsed), (Some(leaf), opening));
    kagemusha_wallet_indexed_verify_membership_v1(&root, &leaf, &parsed).expect("verifies");
    // The sentinel, linked to the smallest key, is a valid low leaf.
    let (low, low_opening) = tree.non_membership(&key(0x08)).expect("low");
    assert_eq!(
        low,
        KagemushaWalletIndexedLeafV1 {
            next_key: key(0x10),
            ..KagemushaWalletIndexedLeafV1::SENTINEL
        }
    );
    assert_eq!(
        KagemushaWalletIndexedOpeningV1::from_transcript(&low_opening.leaf_transcript(&low))
            .expect("sentinel opening"),
        (Some(low), low_opening)
    );
    let empty_slot = tree.opening(u32::try_from(tree.next_free_slot()).expect("slot"));
    let empty_bytes = empty_slot.empty_transcript();
    assert_eq!(
        empty_bytes.len(),
        KAGEMUSHA_WALLET_INDEXED_EMPTY_OPENING_TRANSCRIPT_BYTES_V1
    );
    let (no_leaf, parsed_empty) =
        KagemushaWalletIndexedOpeningV1::from_transcript(&empty_bytes).expect("empty opening");
    assert_eq!((no_leaf, parsed_empty), (None, empty_slot));
    assert_eq!(parsed_empty.empty_root().expect("empty root"), root);
    // Other lengths, a noncanonical field or sibling and a next key not above the key.
    for length in [0, 4, 32, 1_027, 1_029, 1_123, 1_125, 1_156] {
        assert_invalid(
            KagemushaWalletIndexedOpeningV1::from_transcript(&vec![0; length]),
            "indexed_opening.transcript",
        );
    }
    let mut sibling = leaf_bytes.clone();
    sibling[1_124 - 32..].fill(0xff);
    assert_invalid(
        KagemushaWalletIndexedOpeningV1::from_transcript(&sibling),
        "indexed_opening.sibling",
    );
    let mut empty_sibling = empty_bytes.clone();
    empty_sibling[4..36].fill(0xff);
    assert_invalid(
        KagemushaWalletIndexedOpeningV1::from_transcript(&empty_sibling),
        "indexed_opening.sibling",
    );
    let mut field = leaf_bytes.clone();
    field[32..64].fill(0xff);
    assert_invalid(
        KagemushaWalletIndexedOpeningV1::from_transcript(&field),
        "indexed_leaf.field",
    );
    let mut next = leaf_bytes;
    next.copy_within(0..32, 64);
    assert_invalid(
        KagemushaWalletIndexedOpeningV1::from_transcript(&next),
        "indexed_leaf.next_key",
    );
}

/// Insertion witnesses: an occupied target slot and a forged low leaf are rejected.
#[test]
fn kagemusha_wallet_v1_indexed_tree_insert_witness_rejects_forgeries() {
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    tree.insert(key(0x10), value(1)).expect("first");
    let before = tree.root();
    let mut after = tree.clone();
    let witness = after.insert(key(0x20), value(2)).expect("second");
    assert_eq!(
        witness.verify(&before, &key(0x20), &value(2)).ok(),
        Some(after.root())
    );
    // Another value or key yields another root or fails.
    assert_ne!(
        witness.verify(&before, &key(0x20), &value(3)).ok(),
        Some(after.root())
    );
    assert_invalid(
        witness.verify(&before, &key(0x05), &value(2)),
        "indexed_tree.low_leaf",
    );
    assert_invalid(
        witness.verify(&before, &key(0x20), &[0; 32]),
        "indexed_tree.value",
    );
    // The written slot must be empty in the intermediate root: slot 1 is occupied.
    let mut occupied = witness;
    occupied.slot_opening = tree.opening(1);
    assert_invalid(
        occupied.verify(&before, &key(0x20), &value(2)),
        "indexed_tree.slot",
    );
    // A slot opening taken before the low leaf's update is not against the intermediate root.
    let mut stale = witness;
    stale.slot_opening = tree.opening(2);
    assert_invalid(
        stale.verify(&before, &key(0x20), &value(2)),
        "indexed_tree.slot",
    );
}

/// The `ArchiveSent` removal relinks the predecessor and clears the slot, which is never reused
/// (technical decision Q2); no indexed map updates a value in place; the tree is full at `2^32`
/// slots and slot `2^32 − 1` is valid (technical decision Q1).
#[test]
fn kagemusha_wallet_v1_indexed_tree_remove_and_capacity() {
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    for (seed, key) in [(1, key(0x10)), (2, key(0x20)), (3, key(0x30))] {
        tree.insert(key, value(seed)).expect("insert");
    }
    // A present key cannot be re-inserted with another value: there is no in-place update.
    assert_invalid(tree.insert(key(0x20), value(7)), "indexed_tree.present");
    assert_eq!(tree.get(&key(0x20)), Some(value(2)));

    let before = tree.root();
    let remove = tree.remove(&key(0x20)).expect("remove");
    assert_eq!(remove.predecessor.key, key(0x10));
    assert_eq!(remove.predecessor.next_key, key(0x20));
    assert_eq!(remove.leaf.next_key, key(0x30));
    assert_eq!(remove.verify(&before, &key(0x20)).ok(), Some(tree.root()));
    assert_eq!(tree.get(&key(0x20)), None);
    assert_eq!(tree.len(), 2);
    assert_eq!(tree.leaf_at(remove.leaf_opening.slot), None);
    assert_eq!(
        tree.membership(&key(0x10)).expect("relinked").0.next_key,
        key(0x30)
    );
    assert_invalid(tree.remove(&key(0x20)), "indexed_tree.absent");
    // A forged removal: the predecessor must link the removed key.
    let mut forged = remove;
    forged.predecessor.next_key = key(0x30);
    assert_invalid(forged.verify(&before, &key(0x20)), "indexed_tree.remove");
    let mut same_slot = remove;
    same_slot.leaf_opening = remove.predecessor_opening;
    assert_invalid(same_slot.verify(&before, &key(0x20)), "indexed_tree.remove");
    // Unlinking without clearing would leave an orphan whose membership still opens: the
    // removal's result clears the slot, so the removed leaf no longer opens.
    assert_invalid(
        kagemusha_wallet_indexed_verify_membership_v1(
            &tree.root(),
            &remove.leaf,
            &remove.leaf_opening,
        ),
        "indexed_opening.root",
    );
    // A removal frees no slot: the next insertion takes slot 4.
    assert_eq!(tree.next_free_slot(), 4);
    let witness = tree.insert(key(0x20), value(8)).expect("reinsert");
    assert_eq!(witness.slot_opening.slot, 4);

    // The last slot is 2^32 − 1; an insertion at 2^32 is rejected.
    let mut full = KagemushaWalletIndexedTreeV1::new();
    full.next_free = KAGEMUSHA_WALLET_INDEXED_TREE_SLOTS_V1 - 1;
    let before = full.root();
    let last = full.insert(key(0x01), value(1)).expect("last slot");
    assert_eq!(last.slot_opening.slot, u32::MAX);
    assert_eq!(
        last.verify(&before, &key(0x01), &value(1)).ok(),
        Some(full.root())
    );
    let root = full.root();
    assert_invalid(full.insert(key(0x02), value(2)), "indexed_tree.full");
    assert_eq!(full.root(), root);
}
