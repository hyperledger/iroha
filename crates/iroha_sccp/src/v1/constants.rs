//! Current SCCP payload, domain, tree and destination bounds.
//! Native ABI selectors and topics are owned by [`super::destination_abi`].

use iroha_data_model::sccp::params::SCCP_MESSAGES_MAX_PER_BLOCK_V1;

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
// TON cell layout (§5.3.1, §5.3.2)
// ---------------------------------------------------------------------------------------------

/// Bytes per non-final snake chunk.
pub const TON_SNAKE_CHUNK_BYTES: usize = 127;
/// Compressed BLS keys per full `KeyChunk`.
pub const TON_KEY_CHUNK_KEYS: usize = 2;
/// Hashes per full `HashChunk`.
pub const TON_HASH_CHUNK_HASHES: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;

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
}
