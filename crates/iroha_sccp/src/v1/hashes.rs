//! SCCP v1 payload hash, message id and leaves (spec §3.3, §3.4, §3.5).
//!
//! `payload_hash`, `message_id`, `transfer_leaf`, the internal `node` hash and
//! `history_leaf`, plus the static ABI `word(x)` helpers of §0. Every hash is Ethereum Keccak-256
//! over an explicit big-endian preimage.

use tiny_keccak::{Hasher as _, Keccak};

use super::constants::{HISTORY_TAG, LEAF_TAG, MESSAGE_TAG, NODE_TAG, PAYLOAD_TAG};

/// Ethereum Keccak-256 over the concatenation of `parts`.
#[must_use]
pub fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0_u8; 32];
    hasher.finalize(&mut out);
    out
}

/// `word(x)` of an unsigned integer: left-zero-padded big-endian 32 bytes.
#[must_use]
pub fn word_u128(value: u128) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

/// `word(x)` of a `u64`.
#[must_use]
pub fn word_u64(value: u64) -> [u8; 32] {
    word_u128(u128::from(value))
}

/// `word(x)` of an `address`: twelve zero bytes then the 20 address bytes.
#[must_use]
pub fn word_address(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(address);
    word
}

/// `word(x)` of a `bool`: `uint256` 0 or 1.
#[must_use]
pub fn word_bool(value: bool) -> [u8; 32] {
    word_u64(u64::from(value))
}

/// `payload_hash = keccak256("SCCP/PAYLOAD/V1" ‖ payload)` (§3.3).
#[must_use]
pub fn payload_hash(payload: &[u8]) -> [u8; 32] {
    keccak256(&[PAYLOAD_TAG, payload])
}

/// `message_id = keccak256("SCCP/MESSAGE/V1" ‖ lane_bytes ‖ payload_hash)` (§3.3).
#[must_use]
pub fn message_id(lane: &[u8; 66], payload_hash: &[u8; 32]) -> [u8; 32] {
    keccak256(&[MESSAGE_TAG, lane, payload_hash])
}

/// `transfer_leaf = keccak256("SCCP/LEAF/V1" ‖ message_id ‖ destination_word)` (§3.4).
#[must_use]
pub fn transfer_leaf(message_id: &[u8; 32], destination_word: &[u8; 32]) -> [u8; 32] {
    keccak256(&[LEAF_TAG, message_id, destination_word])
}

/// Lowercase hex of `bytes` without a prefix (key file names, logs and diagnostics).
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// `node(l, r) = keccak256("SCCP/NODE/V1" ‖ l ‖ r)` (§3.4).
#[must_use]
pub fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    keccak256(&[NODE_TAG, left, right])
}

/// `history_leaf = keccak256("SCCP/HISTORY/V1" ‖ u64 height ‖ sccp_root ‖ u32 message_count)`.
#[must_use]
pub fn history_leaf(height: u64, sccp_root: &[u8; 32], message_count: u32) -> [u8; 32] {
    keccak256(&[
        HISTORY_TAG,
        &height.to_be_bytes(),
        sccp_root,
        &message_count.to_be_bytes(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        to_hex(bytes)
    }

    #[test]
    fn to_hex_is_lowercase_and_unprefixed() {
        assert_eq!(to_hex(&[]), "");
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }

    #[test]
    fn keccak256_known_vectors() {
        assert_eq!(
            hex(&keccak256(&[])),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        // Concatenation is part-boundary independent.
        assert_eq!(keccak256(&[b"ab", b"c"]), keccak256(&[b"abc"]));
    }

    #[test]
    fn word_helpers_pad_big_endian() {
        assert_eq!(word_u64(1)[31], 1);
        assert_eq!(word_u64(1)[..31], [0; 31]);
        assert_eq!(word_u128(u128::MAX)[..16], [0; 16]);
        assert_eq!(word_u128(u128::MAX)[16..], [0xff; 16]);
        assert_eq!(word_bool(true), word_u64(1));
        assert_eq!(word_bool(false), [0; 32]);
        let word = word_address(&[0x22; 20]);
        assert_eq!(word[..12], [0; 12]);
        assert_eq!(word[12..], [0x22; 20]);
    }

    #[test]
    fn leaf_kinds_are_domain_separated() {
        let a = [0xaa; 32];
        let b = [0xbb; 32];
        // Transfer leaves and internal nodes share a 76-byte length but differ in prefix.
        assert_ne!(transfer_leaf(&a, &b), node(&a, &b));
        assert_eq!(transfer_leaf(&a, &b), keccak256(&[b"SCCP/LEAF/V1", &a, &b]));
        assert_eq!(node(&a, &b), keccak256(&[b"SCCP/NODE/V1", &a, &b]));
        assert_ne!(node(&a, &b), node(&b, &a));
    }

    #[test]
    fn payload_hash_and_message_id_follow_the_formula() {
        let payload = [1_u8, 2, 3];
        let hash = payload_hash(&payload);
        assert_eq!(hash, keccak256(&[b"SCCP/PAYLOAD/V1", &payload]));
        let lane = [0x5a; 66];
        assert_eq!(
            message_id(&lane, &hash),
            keccak256(&[b"SCCP/MESSAGE/V1", &lane, &hash])
        );
    }

    #[test]
    fn history_leaf_layout() {
        let root = [0x77; 32];
        let expected = keccak256(&[
            b"SCCP/HISTORY/V1",
            &[0, 0, 0, 0, 0, 0, 0x01, 0x02],
            &root,
            &[0, 0, 0, 3],
        ]);
        assert_eq!(history_leaf(0x0102, &root, 3), expected);
        assert_ne!(history_leaf(0x0102, &root, 4), expected);
    }
}
