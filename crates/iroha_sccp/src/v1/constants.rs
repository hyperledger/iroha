//! SCCP v1 compiled constants (spec §3.9).
//!
//! Domain tags, contract bounds, codec and
//! domain ids, profile tags and route ids shared by Taira and every destination. Current
//! EVM selectors and event topics are owned by `destination_abi`. Every hash in
//! this module is written out as a literal and recomputed from its canonical preimage by the golden
//! tests below, so a typo in either the string or the value fails the build's test suite.

use iroha_data_model::sccp::params::SCCP_MESSAGES_MAX_PER_BLOCK_V1;

/// Decode a 64-digit lowercase or uppercase hex literal at compile time.
const fn hex32(literal: &str) -> [u8; 32] {
    let bytes = literal.as_bytes();
    assert!(bytes.len() == 64, "hex32 literal must have 64 digits");
    let mut out = [0_u8; 32];
    let mut index = 0;
    while index < 32 {
        out[index] = (hex_nibble(bytes[2 * index]) << 4) | hex_nibble(bytes[2 * index + 1]);
        index += 1;
    }
    out
}

/// Decode one hex digit at compile time.
const fn hex_nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        b'A'..=b'F' => digit - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}

// ---------------------------------------------------------------------------------------------
// Domain tags (§3.3, §3.4, §3.5, §3.7)
// ---------------------------------------------------------------------------------------------

/// Payload hash tag (15 bytes, §3.3).
pub const PAYLOAD_TAG: &[u8] = b"SCCP/PAYLOAD/V1";
/// Message id tag (15 bytes, §3.3).
pub const MESSAGE_TAG: &[u8] = b"SCCP/MESSAGE/V1";
/// Transfer leaf tag (12 bytes, §3.4).
pub const LEAF_TAG: &[u8] = b"SCCP/LEAF/V1";
/// Control leaf tag (15 bytes, §3.4).
pub const CONTROL_TAG: &[u8] = b"SCCP/CONTROL/V1";
/// Internal tree node tag (12 bytes, §3.4).
pub const NODE_TAG: &[u8] = b"SCCP/NODE/V1";
/// History leaf tag (15 bytes, §3.5).
pub const HISTORY_TAG: &[u8] = b"SCCP/HISTORY/V1";
/// Maximum SCCP leaves (transfers and controls) per block.
pub const MAX_BLOCK_LEAVES: u32 = SCCP_MESSAGES_MAX_PER_BLOCK_V1;
/// Maximum siblings of a block commitment path (`ceil(log2(512))`).
pub const MAX_BLOCK_PATH: usize = 9;
/// Maximum siblings of a history path.
pub const MAX_HISTORY_PATH: usize = 32;
/// Maximum history size (`2^32` SCCP-bearing blocks).
pub const MAX_HISTORY_SIZE: u64 = 1 << 32;
/// Maximum `voidFrozen` range on EVM.
pub const MAX_VOID_FROZEN_RANGE_EVM: u64 = 256;
/// Maximum `sccp_void_frozen` range on TON (one bucket).
pub const MAX_VOID_FROZEN_RANGE_TON: u64 = 512;

// ---------------------------------------------------------------------------------------------
// Payload layout (§3.1, §3.2)
// ---------------------------------------------------------------------------------------------

/// Payload kind byte of a transfer.
pub const PAYLOAD_KIND_TRANSFER: u8 = 0x02;
/// Payload version byte.
pub const PAYLOAD_VERSION: u8 = 0x01;
/// Maximum encoded payload length.
pub const MAX_PAYLOAD_BYTES: usize = 4096;
/// Codec 1: printable ASCII text (`asset_id`, `route_id`).
pub const CODEC_CANONICAL_TEXT: u8 = 1;
/// Codec 2: 20-byte nonzero EVM address.
pub const CODEC_EVM_ADDRESS20: u8 = 2;
/// Codec 3: Taira `AccountAddress` payload bytes.
pub const CODEC_TAIRA_ACCOUNT: u8 = 3;
/// Codec 7: 36-byte TON account (`i32` workchain 0 ‖ account id).
pub const CODEC_TON_ACCOUNT36: u8 = 7;
/// Maximum canonical-text length.
pub const MAX_CANONICAL_TEXT_BYTES: usize = 256;
/// Maximum Taira account payload length.
pub const MAX_TAIRA_ACCOUNT_BYTES: usize = 1024;
/// Exclusive upper bound of amounts when either endpoint is TON (`2^96`).
pub const TON_AMOUNT_BOUND: u128 = 1 << 96;
/// Scale of Taira XOR and decimals of every destination token.
pub const XOR_DECIMALS: u32 = 9;
/// `asset_id` text of Taira XOR.
pub const ASSET_ID_XOR: &str = "xor";

// ---------------------------------------------------------------------------------------------
// Profiles: tags, domains, identities and routes (§2)
// ---------------------------------------------------------------------------------------------

/// `sora-taira` profile tag.
pub const TAG_SORA_TAIRA: u8 = 0x40;
/// `ethereum-mainnet` profile tag.
pub const TAG_ETHEREUM: u8 = 0x41;
/// `bsc-mainnet` profile tag.
pub const TAG_BSC: u8 = 0x42;
/// `ton-mainnet` profile tag.
pub const TAG_TON: u8 = 0x44;
/// SCCP domain of Taira.
pub const DOMAIN_SORA_TAIRA: u32 = 0;
/// SCCP domain of Ethereum.
pub const DOMAIN_ETHEREUM: u32 = 1;
/// SCCP domain of BSC.
pub const DOMAIN_BSC: u32 = 2;
/// SCCP domain of TON.
pub const DOMAIN_TON: u32 = 4;
/// Ethereum mainnet chain id.
pub const ETHEREUM_CHAIN_ID: u64 = 1;
/// BSC mainnet chain id.
pub const BSC_CHAIN_ID: u64 = 56;
/// TON mainnet global id.
pub const TON_GLOBAL_ID: i32 = -239;
/// Route id of the Ethereum route.
pub const ROUTE_ID_ETHEREUM: &str = "taira_eth_xor";
/// Route id of the BSC route.
pub const ROUTE_ID_BSC: &str = "taira_bsc_xor";
/// Route id of the TON route.
pub const ROUTE_ID_TON: &str = "taira_ton_xor";

// ---------------------------------------------------------------------------------------------
// secp256k1 (§0, §3.8)
// ---------------------------------------------------------------------------------------------

/// secp256k1 group order `N`.
pub const SECP256K1_N: [u8; 32] =
    hex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
/// `HALF_N = floor(N / 2)`, the largest admitted `s`.
pub const SECP256K1_HALF_N: [u8; 32] =
    hex32("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0");

/// Exact keyless CREATE2 proxy runtime required on both Ethereum and BSC (§5.2.1).
pub const SCCP_EVM_DEPLOYER_RUNTIME: [u8; 69] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xe0, 0x36, 0x01, 0x60, 0x00, 0x81, 0x60, 0x20, 0x82, 0x37, 0x80, 0x35, 0x82, 0x82, 0x34, 0xf5,
    0x80, 0x15, 0x15, 0x60, 0x39, 0x57, 0x81, 0x82, 0xfd, 0x5b, 0x80, 0x82, 0x52, 0x50, 0x50, 0x50,
    0x60, 0x14, 0x60, 0x0c, 0xf3,
];
/// Keccak-256 of [`SCCP_EVM_DEPLOYER_RUNTIME`], independently pinned by the EVM model.
pub const SCCP_EVM_DEPLOYER_RUNTIME_HASH: [u8; 32] =
    hex32("2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989");

// ---------------------------------------------------------------------------------------------
// TON cell layout (§5.3.1, §5.3.2)
// ---------------------------------------------------------------------------------------------

/// Bytes per non-final snake chunk.
pub const TON_SNAKE_CHUNK_BYTES: usize = 127;
/// Compressed BLS12-381 keys per full `KeyChunk`.
pub const TON_KEY_CHUNK_KEYS: usize = 2;
/// Hashes per full `HashChunk`.
pub const TON_HASH_CHUNK_HASHES: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_proxy_runtime_matches_the_independent_evm_hash() {
        use crate::v1::hashes::keccak256;
        assert_eq!(SCCP_EVM_DEPLOYER_RUNTIME.len(), 69);
        assert_eq!(
            keccak256(&[&SCCP_EVM_DEPLOYER_RUNTIME]),
            SCCP_EVM_DEPLOYER_RUNTIME_HASH
        );
        let model = include_str!("../../../../contracts/evm/sccp/test/sccp_v1_fixtures.test.js");
        assert!(model.contains("2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989"));
    }

    #[test]
    fn domain_tags_have_the_spec_lengths() {
        assert_eq!(PAYLOAD_TAG.len(), 15);
        assert_eq!(MESSAGE_TAG.len(), 15);
        assert_eq!(LEAF_TAG.len(), 12);
        assert_eq!(CONTROL_TAG.len(), 15);
        assert_eq!(NODE_TAG.len(), 12);
        assert_eq!(HISTORY_TAG.len(), 15);
    }

    #[test]
    fn contract_bounds_have_the_spec_values() {
        assert_eq!(MAX_BLOCK_LEAVES, 512);
        assert_eq!(1_u32 << MAX_BLOCK_PATH, MAX_BLOCK_LEAVES);
        assert_eq!(1_u64 << MAX_HISTORY_PATH, MAX_HISTORY_SIZE);
        assert_eq!(TON_AMOUNT_BOUND, 79_228_162_514_264_337_593_543_950_336);
    }

    #[test]
    fn secp256k1_half_order_is_floor_of_half() {
        // HALF_N * 2 + 1 == N
        let mut doubled = [0_u8; 32];
        let mut carry = 1_u16;
        for index in (0..32).rev() {
            let value = u16::from(SECP256K1_HALF_N[index]) * 2 + carry;
            doubled[index] = u8::try_from(value & 0xff).expect("one byte");
            carry = value >> 8;
        }
        assert_eq!(carry, 0);
        assert_eq!(doubled, SECP256K1_N);
    }

    #[test]
    fn hex32_decodes_mixed_case() {
        let value = hex32("00FFaa0000000000000000000000000000000000000000000000000000000001");
        assert_eq!(value[0], 0);
        assert_eq!(value[1], 0xff);
        assert_eq!(value[2], 0xaa);
        assert_eq!(value[31], 1);
        assert_eq!(hex_nibble(b'F'), 15);
    }
}
