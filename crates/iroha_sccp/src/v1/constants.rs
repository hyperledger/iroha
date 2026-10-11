//! SCCP v1 compiled constants (spec §3.9).
//!
//! Domain tags, EIP-712 type hashes, event topics, EVM selectors, contract bounds, codec and
//! domain ids, profile tags and route ids shared by Taira and every destination. Every hash in
//! this module is written out as a literal and recomputed from its canonical string by the golden
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
/// Roster preimage tag (14 bytes, §3.7).
pub const ROSTER_TAG: &[u8] = b"SCCP/ROSTER/V1";

// ---------------------------------------------------------------------------------------------
// EIP-712 (§3.6)
// ---------------------------------------------------------------------------------------------

/// Canonical EIP-712 domain type string.
pub const EIP712_DOMAIN_TYPE: &str = "EIP712Domain(string name,string version,bytes32 salt)";
/// `keccak256(EIP712_DOMAIN_TYPE)`.
pub const DOMAIN_TYPEHASH: [u8; 32] =
    hex32("599a80fcaa47b95e2323ab4d34d34e0cc9feda4b843edafcc30c7bdf60ea15bf");
/// EIP-712 domain name.
pub const EIP712_NAME: &str = "SCCP";
/// `keccak256("SCCP")`.
pub const NAME_HASH: [u8; 32] =
    hex32("d7bacbdfe367013f66397ff7242325c31126ab14c95620817c994f22f1d123ba");
/// EIP-712 domain version.
pub const EIP712_VERSION: &str = "1";
/// `keccak256("1")`.
pub const VERSION_HASH: [u8; 32] =
    hex32("c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6");
/// Canonical `SccpAttestation` type string (§3.6).
pub const ATTESTATION_TYPE: &str = "SccpAttestation(uint64 height,uint64 epoch,uint64 timestampMs,bytes32 blockHash,bytes32 sccpRoot,uint32 messageCount,bytes32 historyRoot,uint64 historySize,bytes32 rosterDigest,bytes32 nextRosterDigest)";
/// `keccak256(ATTESTATION_TYPE)`.
pub const ATTESTATION_TYPEHASH: [u8; 32] =
    hex32("6ea54d1f320a2e5892d6a362adc4b569967facc991d3a327cbc84b746f520c66");
/// Canonical `SccpBridgeKey` proof-of-possession type string (§3.6).
pub const BRIDGE_KEY_TYPE: &str =
    "SccpBridgeKey(bytes32 peerKeyHash,address bridgeAddress,uint64 activationEpoch)";
/// `keccak256(BRIDGE_KEY_TYPE)`.
pub const BRIDGE_KEY_TYPEHASH: [u8; 32] =
    hex32("87f74eabbf9693141811f707b2d51c6a18546376727b384e155d2539ed0a1a3a");

// ---------------------------------------------------------------------------------------------
// Event topics (§3.9, §5.2.2)
// ---------------------------------------------------------------------------------------------

/// Canonical signature of the inbound source event.
pub const EVENT_TRANSFER_TO_TAIRA: &str = "SccpTransferToTaira(bytes32,address,uint64,bytes)";
/// `topic0` of [`EVENT_TRANSFER_TO_TAIRA`].
pub const TOPIC_TRANSFER_TO_TAIRA: [u8; 32] =
    hex32("79ac1cc63262b80bfbf96e55b2d49d96bd82f018ce0192f7002168724c7d264b");
/// Canonical signature of the finalization event.
pub const EVENT_FINALIZED: &str = "SccpFinalized(bytes32,uint64,address,uint256)";
/// `topic0` of [`EVENT_FINALIZED`].
pub const TOPIC_FINALIZED: [u8; 32] =
    hex32("8ab0eb669cb9abcdf0e37e9ce8443162d317d10c2b059296e40aebbd3fa23748");
/// Canonical signature of the void event.
pub const EVENT_VOIDED: &str = "SccpVoided(bytes32,uint64)";
/// `topic0` of [`EVENT_VOIDED`].
pub const TOPIC_VOIDED: [u8; 32] =
    hex32("fc0fe8523e61c1e6bcbb957a8b692dd0b08e1774c4c4bd897fbc68c047c82fcf");
/// Canonical signature of the roster rotation event.
pub const EVENT_ROSTER_ROTATED: &str = "SccpRosterRotated(uint64,bytes32,uint64)";
/// `topic0` of [`EVENT_ROSTER_ROTATED`].
pub const TOPIC_ROSTER_ROTATED: [u8; 32] =
    hex32("8619e96c15d0af080499408d3d5fb9af0101014daa9acaad772a5aa03ebf315e");
/// Canonical signature of the applied-control event.
pub const EVENT_CONTROL_APPLIED: &str = "SccpControlApplied(uint64,bool)";
/// `topic0` of [`EVENT_CONTROL_APPLIED`].
pub const TOPIC_CONTROL_APPLIED: [u8; 32] =
    hex32("38b98e72aaf30cffd4309ad36378e1587525135a709fe14074156ebb44254d65");

/// Every event of §3.9 as `(canonical signature, topic0)`.
pub const EVENT_TOPICS: [(&str, [u8; 32]); 5] = [
    (EVENT_TRANSFER_TO_TAIRA, TOPIC_TRANSFER_TO_TAIRA),
    (EVENT_FINALIZED, TOPIC_FINALIZED),
    (EVENT_VOIDED, TOPIC_VOIDED),
    (EVENT_ROSTER_ROTATED, TOPIC_ROSTER_ROTATED),
    (EVENT_CONTROL_APPLIED, TOPIC_CONTROL_APPLIED),
];

// ---------------------------------------------------------------------------------------------
// EVM selectors (§5.2.2): canonical signatures with tuples expanded
// ---------------------------------------------------------------------------------------------

/// Expanded `AttestationV1` tuple type.
pub const ABI_ATTESTATION: &str =
    "(uint64,uint64,uint64,bytes32,bytes32,uint32,bytes32,uint64,bytes32,bytes32)";
/// Expanded `RosterV1` tuple type.
pub const ABI_ROSTER: &str = "(uint64,uint64,uint64,uint8,bytes)";
/// Expanded `SignaturesV1` tuple type.
pub const ABI_SIGNATURES: &str = "(uint32,bytes)";
/// Expanded `MessageProofV1` tuple type.
pub const ABI_MESSAGE_PROOF: &str = "(bytes,uint32,bytes32[])";
/// Expanded `HistoryProofV1` tuple type.
pub const ABI_HISTORY_PROOF: &str = "(uint64,bytes32,uint32,uint64,bytes32[])";
/// Expanded `ControlProofV1` tuple type.
pub const ABI_CONTROL_PROOF: &str = "(uint64,bool,uint32,bytes32[])";

/// `finalizeFromTaira(AttestationV1,RosterV1,SignaturesV1,MessageProofV1)`.
pub const SIG_FINALIZE_FROM_TAIRA: &str = "finalizeFromTaira((uint64,uint64,uint64,bytes32,bytes32,uint32,bytes32,uint64,bytes32,bytes32),(uint64,uint64,uint64,uint8,bytes),(uint32,bytes),(bytes,uint32,bytes32[]))";
/// Selector of [`SIG_FINALIZE_FROM_TAIRA`].
pub const SELECTOR_FINALIZE_FROM_TAIRA: [u8; 4] = [0x80, 0x56, 0xd1, 0x61];
/// `finalizeFromTairaHistorical(AttestationV1,RosterV1,SignaturesV1,HistoryProofV1,MessageProofV1)`.
pub const SIG_FINALIZE_FROM_TAIRA_HISTORICAL: &str = "finalizeFromTairaHistorical((uint64,uint64,uint64,bytes32,bytes32,uint32,bytes32,uint64,bytes32,bytes32),(uint64,uint64,uint64,uint8,bytes),(uint32,bytes),(uint64,bytes32,uint32,uint64,bytes32[]),(bytes,uint32,bytes32[]))";
/// Selector of [`SIG_FINALIZE_FROM_TAIRA_HISTORICAL`].
pub const SELECTOR_FINALIZE_FROM_TAIRA_HISTORICAL: [u8; 4] = [0x96, 0x92, 0x57, 0x36];
/// `rotateRosters(RotationV1[])`.
pub const SIG_ROTATE_ROSTERS: &str = "rotateRosters(((uint64,uint64,uint64,bytes32,bytes32,uint32,bytes32,uint64,bytes32,bytes32),(uint64,uint64,uint64,uint8,bytes),(uint32,bytes),(uint64,uint64,uint64,uint8,bytes))[])";
/// Selector of [`SIG_ROTATE_ROSTERS`].
pub const SELECTOR_ROTATE_ROSTERS: [u8; 4] = [0x90, 0x9e, 0xa4, 0x56];
/// `applyControl(AttestationV1,RosterV1,SignaturesV1,ControlProofV1)`.
pub const SIG_APPLY_CONTROL: &str = "applyControl((uint64,uint64,uint64,bytes32,bytes32,uint32,bytes32,uint64,bytes32,bytes32),(uint64,uint64,uint64,uint8,bytes),(uint32,bytes),(uint64,bool,uint32,bytes32[]))";
/// Selector of [`SIG_APPLY_CONTROL`].
pub const SELECTOR_APPLY_CONTROL: [u8; 4] = [0x0c, 0xe9, 0x70, 0xd6];
/// `applyControlHistorical(AttestationV1,RosterV1,SignaturesV1,HistoryProofV1,ControlProofV1)`.
pub const SIG_APPLY_CONTROL_HISTORICAL: &str = "applyControlHistorical((uint64,uint64,uint64,bytes32,bytes32,uint32,bytes32,uint64,bytes32,bytes32),(uint64,uint64,uint64,uint8,bytes),(uint32,bytes),(uint64,bytes32,uint32,uint64,bytes32[]),(uint64,bool,uint32,bytes32[]))";
/// Selector of [`SIG_APPLY_CONTROL_HISTORICAL`].
pub const SELECTOR_APPLY_CONTROL_HISTORICAL: [u8; 4] = [0x93, 0x5a, 0x91, 0x3b];
/// `transferToTaira(bytes,uint256,uint64)`.
pub const SIG_TRANSFER_TO_TAIRA: &str = "transferToTaira(bytes,uint256,uint64)";
/// Selector of [`SIG_TRANSFER_TO_TAIRA`].
pub const SELECTOR_TRANSFER_TO_TAIRA: [u8; 4] = [0xeb, 0xfc, 0x6c, 0xa8];
/// `voidExpired(uint64,AttestationV1,RosterV1,SignaturesV1,MessageProofV1)`.
pub const SIG_VOID_EXPIRED: &str = "voidExpired(uint64,(uint64,uint64,uint64,bytes32,bytes32,uint32,bytes32,uint64,bytes32,bytes32),(uint64,uint64,uint64,uint8,bytes),(uint32,bytes),(bytes,uint32,bytes32[]))";
/// Selector of [`SIG_VOID_EXPIRED`].
pub const SELECTOR_VOID_EXPIRED: [u8; 4] = [0xc3, 0xde, 0x98, 0xad];
/// `voidExpiredHistorical(uint64,AttestationV1,RosterV1,SignaturesV1,HistoryProofV1,MessageProofV1)`.
pub const SIG_VOID_EXPIRED_HISTORICAL: &str = "voidExpiredHistorical(uint64,(uint64,uint64,uint64,bytes32,bytes32,uint32,bytes32,uint64,bytes32,bytes32),(uint64,uint64,uint64,uint8,bytes),(uint32,bytes),(uint64,bytes32,uint32,uint64,bytes32[]),(bytes,uint32,bytes32[]))";
/// Selector of [`SIG_VOID_EXPIRED_HISTORICAL`].
pub const SELECTOR_VOID_EXPIRED_HISTORICAL: [u8; 4] = [0xbe, 0x33, 0x5b, 0x84];
/// `voidFrozen(uint64,uint64)`.
pub const SIG_VOID_FROZEN: &str = "voidFrozen(uint64,uint64)";
/// Selector of [`SIG_VOID_FROZEN`].
pub const SELECTOR_VOID_FROZEN: [u8; 4] = [0x5b, 0x09, 0x4c, 0x00];
/// `rosterState()`.
pub const SIG_ROSTER_STATE: &str = "rosterState()";
/// Selector of [`SIG_ROSTER_STATE`].
pub const SELECTOR_ROSTER_STATE: [u8; 4] = [0x85, 0xa0, 0x0f, 0x5c];
/// `isConsumed(uint64)`.
pub const SIG_IS_CONSUMED: &str = "isConsumed(uint64)";
/// Selector of [`SIG_IS_CONSUMED`].
pub const SELECTOR_IS_CONSUMED: [u8; 4] = [0x95, 0xb6, 0x70, 0x34];
/// `transferNonces(address)`.
pub const SIG_TRANSFER_NONCES: &str = "transferNonces(address)";
/// Selector of [`SIG_TRANSFER_NONCES`].
pub const SELECTOR_TRANSFER_NONCES: [u8; 4] = [0xf6, 0xf0, 0xe8, 0xa6];
/// `tairaNetworkId()`.
pub const SIG_TAIRA_NETWORK_ID: &str = "tairaNetworkId()";
/// Selector of [`SIG_TAIRA_NETWORK_ID`].
pub const SELECTOR_TAIRA_NETWORK_ID: [u8; 4] = [0x6b, 0x91, 0xd7, 0x31];
/// `routeRevision()`.
pub const SIG_ROUTE_REVISION: &str = "routeRevision()";
/// Selector of [`SIG_ROUTE_REVISION`].
pub const SELECTOR_ROUTE_REVISION: [u8; 4] = [0x18, 0x18, 0x89, 0x1a];
/// `maxWrappedSupply()`.
pub const SIG_MAX_WRAPPED_SUPPLY: &str = "maxWrappedSupply()";
/// Selector of [`SIG_MAX_WRAPPED_SUPPLY`].
pub const SELECTOR_MAX_WRAPPED_SUPPLY: [u8; 4] = [0xd8, 0xbc, 0x4d, 0xcd];
/// `mintingPaused()`.
pub const SIG_MINTING_PAUSED: &str = "mintingPaused()";
/// Selector of [`SIG_MINTING_PAUSED`].
pub const SELECTOR_MINTING_PAUSED: [u8; 4] = [0xe1, 0xa2, 0x83, 0xd6];
/// `controlNonce()`.
pub const SIG_CONTROL_NONCE: &str = "controlNonce()";
/// Selector of [`SIG_CONTROL_NONCE`].
pub const SELECTOR_CONTROL_NONCE: [u8; 4] = [0x4f, 0xaa, 0xc8, 0xca];
/// `domainSeparator()`.
pub const SIG_DOMAIN_SEPARATOR: &str = "domainSeparator()";
/// Selector of [`SIG_DOMAIN_SEPARATOR`].
pub const SELECTOR_DOMAIN_SEPARATOR: [u8; 4] = [0xf6, 0x98, 0xda, 0x25];
/// `initialRosterDigest()`.
pub const SIG_INITIAL_ROSTER_DIGEST: &str = "initialRosterDigest()";
/// Selector of [`SIG_INITIAL_ROSTER_DIGEST`].
pub const SELECTOR_INITIAL_ROSTER_DIGEST: [u8; 4] = [0x97, 0x52, 0x5b, 0xf3];
/// `initialRosterGeneration()`.
pub const SIG_INITIAL_ROSTER_GENERATION: &str = "initialRosterGeneration()";
/// Selector of [`SIG_INITIAL_ROSTER_GENERATION`].
pub const SELECTOR_INITIAL_ROSTER_GENERATION: [u8; 4] = [0x3d, 0xda, 0xa7, 0xc6];
/// `opCount()`.
pub const SIG_OP_COUNT: &str = "opCount()";
/// Selector of [`SIG_OP_COUNT`].
pub const SELECTOR_OP_COUNT: [u8; 4] = [0xcb, 0x58, 0x06, 0x5f];
/// `maxRosterValidityMs()`.
pub const SIG_MAX_ROSTER_VALIDITY_MS: &str = "maxRosterValidityMs()";
/// Selector of [`SIG_MAX_ROSTER_VALIDITY_MS`].
pub const SELECTOR_MAX_ROSTER_VALIDITY_MS: [u8; 4] = [0xde, 0xdd, 0xb5, 0x07];

/// Every selector of §5.2.2 as `(function name, canonical signature, selector)`.
pub const SELECTORS: [(&str, &str, [u8; 4]); 22] = [
    (
        "finalizeFromTaira",
        SIG_FINALIZE_FROM_TAIRA,
        SELECTOR_FINALIZE_FROM_TAIRA,
    ),
    (
        "finalizeFromTairaHistorical",
        SIG_FINALIZE_FROM_TAIRA_HISTORICAL,
        SELECTOR_FINALIZE_FROM_TAIRA_HISTORICAL,
    ),
    ("rotateRosters", SIG_ROTATE_ROSTERS, SELECTOR_ROTATE_ROSTERS),
    ("applyControl", SIG_APPLY_CONTROL, SELECTOR_APPLY_CONTROL),
    (
        "applyControlHistorical",
        SIG_APPLY_CONTROL_HISTORICAL,
        SELECTOR_APPLY_CONTROL_HISTORICAL,
    ),
    (
        "transferToTaira",
        SIG_TRANSFER_TO_TAIRA,
        SELECTOR_TRANSFER_TO_TAIRA,
    ),
    ("voidExpired", SIG_VOID_EXPIRED, SELECTOR_VOID_EXPIRED),
    (
        "voidExpiredHistorical",
        SIG_VOID_EXPIRED_HISTORICAL,
        SELECTOR_VOID_EXPIRED_HISTORICAL,
    ),
    ("voidFrozen", SIG_VOID_FROZEN, SELECTOR_VOID_FROZEN),
    ("rosterState", SIG_ROSTER_STATE, SELECTOR_ROSTER_STATE),
    ("isConsumed", SIG_IS_CONSUMED, SELECTOR_IS_CONSUMED),
    (
        "transferNonces",
        SIG_TRANSFER_NONCES,
        SELECTOR_TRANSFER_NONCES,
    ),
    (
        "tairaNetworkId",
        SIG_TAIRA_NETWORK_ID,
        SELECTOR_TAIRA_NETWORK_ID,
    ),
    ("routeRevision", SIG_ROUTE_REVISION, SELECTOR_ROUTE_REVISION),
    (
        "maxWrappedSupply",
        SIG_MAX_WRAPPED_SUPPLY,
        SELECTOR_MAX_WRAPPED_SUPPLY,
    ),
    ("mintingPaused", SIG_MINTING_PAUSED, SELECTOR_MINTING_PAUSED),
    ("controlNonce", SIG_CONTROL_NONCE, SELECTOR_CONTROL_NONCE),
    (
        "domainSeparator",
        SIG_DOMAIN_SEPARATOR,
        SELECTOR_DOMAIN_SEPARATOR,
    ),
    (
        "initialRosterDigest",
        SIG_INITIAL_ROSTER_DIGEST,
        SELECTOR_INITIAL_ROSTER_DIGEST,
    ),
    (
        "initialRosterGeneration",
        SIG_INITIAL_ROSTER_GENERATION,
        SELECTOR_INITIAL_ROSTER_GENERATION,
    ),
    ("opCount", SIG_OP_COUNT, SELECTOR_OP_COUNT),
    (
        "maxRosterValidityMs",
        SIG_MAX_ROSTER_VALIDITY_MS,
        SELECTOR_MAX_ROSTER_VALIDITY_MS,
    ),
];

// ---------------------------------------------------------------------------------------------
// Contract constants and bounds (§3.9, §5)
// ---------------------------------------------------------------------------------------------

/// `PREVIOUS_ROSTER_GRACE_MS` (24 h).
pub const PREVIOUS_ROSTER_GRACE_MS: u64 = 86_400_000;
/// `MAX_ROSTER_VALIDITY_MS` (30 d).
pub const MAX_ROSTER_VALIDITY_MS: u64 = 2_592_000_000;
/// `MAX_CLOCK_SKEW_MS` (1 h).
pub const MAX_CLOCK_SKEW_MS: u64 = 3_600_000;
/// Maximum SCCP leaves (transfers and controls) per block.
pub const MAX_BLOCK_LEAVES: u32 = SCCP_MESSAGES_MAX_PER_BLOCK_V1;
/// Maximum siblings of a block commitment path (`ceil(log2(512))`).
pub const MAX_BLOCK_PATH: usize = 9;
/// Maximum siblings of a history path.
pub const MAX_HISTORY_PATH: usize = 32;
/// Maximum history size (`2^32` SCCP-bearing blocks).
pub const MAX_HISTORY_SIZE: u64 = 1 << 32;
/// Minimum roster size `n`.
pub const MIN_ROSTER_MEMBERS: usize = 4;
/// Maximum roster size `n`.
pub const MAX_ROSTER_MEMBERS: usize = 31;
/// Maximum rotations in one `rotateRosters` call.
pub const MAX_ROTATIONS_PER_CALL: usize = 16;
/// Maximum `voidFrozen` range on EVM.
pub const MAX_VOID_FROZEN_RANGE_EVM: u64 = 256;
/// Maximum `sccp_void_frozen` range on TON (one bucket).
pub const MAX_VOID_FROZEN_RANGE_TON: u64 = 512;
/// Length of one encoded signature `r ‖ s ‖ v`.
pub const SIGNATURE_BYTES: usize = 65;

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

// ---------------------------------------------------------------------------------------------
// TON cell layout (§5.3.1, §5.3.2)
// ---------------------------------------------------------------------------------------------

/// Bytes per non-final snake chunk.
pub const TON_SNAKE_CHUNK_BYTES: usize = 127;
/// Addresses per full `MemberChunk`.
pub const TON_MEMBER_CHUNK_ADDRESSES: usize = 6;
/// Hashes per full `HashChunk`.
pub const TON_HASH_CHUNK_HASHES: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::hashes::keccak256;

    fn selector_of(signature: &str) -> [u8; 4] {
        let hash = keccak256(&[signature.as_bytes()]);
        [hash[0], hash[1], hash[2], hash[3]]
    }

    #[test]
    fn domain_tags_have_the_spec_lengths() {
        assert_eq!(PAYLOAD_TAG.len(), 15);
        assert_eq!(MESSAGE_TAG.len(), 15);
        assert_eq!(LEAF_TAG.len(), 12);
        assert_eq!(CONTROL_TAG.len(), 15);
        assert_eq!(NODE_TAG.len(), 12);
        assert_eq!(HISTORY_TAG.len(), 15);
        assert_eq!(ROSTER_TAG.len(), 14);
    }

    #[test]
    fn eip712_hashes_match_their_strings() {
        assert_eq!(keccak256(&[EIP712_DOMAIN_TYPE.as_bytes()]), DOMAIN_TYPEHASH);
        assert_eq!(keccak256(&[EIP712_NAME.as_bytes()]), NAME_HASH);
        assert_eq!(keccak256(&[EIP712_VERSION.as_bytes()]), VERSION_HASH);
        assert_eq!(
            keccak256(&[ATTESTATION_TYPE.as_bytes()]),
            ATTESTATION_TYPEHASH
        );
        assert_eq!(
            keccak256(&[BRIDGE_KEY_TYPE.as_bytes()]),
            BRIDGE_KEY_TYPEHASH
        );
    }

    #[test]
    fn event_topics_match_their_signatures() {
        for (signature, topic) in EVENT_TOPICS {
            assert_eq!(keccak256(&[signature.as_bytes()]), topic, "{signature}");
        }
    }

    #[test]
    fn selectors_match_their_signatures() {
        for (name, signature, selector) in SELECTORS {
            assert!(signature.starts_with(name), "{name}");
            assert_eq!(selector_of(signature), selector, "{signature}");
        }
    }

    #[test]
    fn selectors_expand_the_named_tuples() {
        let attestation_roster_signatures =
            format!("{ABI_ATTESTATION},{ABI_ROSTER},{ABI_SIGNATURES}");
        assert_eq!(
            SIG_FINALIZE_FROM_TAIRA,
            format!("finalizeFromTaira({attestation_roster_signatures},{ABI_MESSAGE_PROOF})")
        );
        assert_eq!(
            SIG_FINALIZE_FROM_TAIRA_HISTORICAL,
            format!(
                "finalizeFromTairaHistorical({attestation_roster_signatures},{ABI_HISTORY_PROOF},{ABI_MESSAGE_PROOF})"
            )
        );
        assert_eq!(
            SIG_ROTATE_ROSTERS,
            format!("rotateRosters(({attestation_roster_signatures},{ABI_ROSTER})[])")
        );
        assert_eq!(
            SIG_APPLY_CONTROL,
            format!("applyControl({attestation_roster_signatures},{ABI_CONTROL_PROOF})")
        );
        assert_eq!(
            SIG_APPLY_CONTROL_HISTORICAL,
            format!(
                "applyControlHistorical({attestation_roster_signatures},{ABI_HISTORY_PROOF},{ABI_CONTROL_PROOF})"
            )
        );
        assert_eq!(
            SIG_VOID_EXPIRED,
            format!("voidExpired(uint64,{attestation_roster_signatures},{ABI_MESSAGE_PROOF})")
        );
        assert_eq!(
            SIG_VOID_EXPIRED_HISTORICAL,
            format!(
                "voidExpiredHistorical(uint64,{attestation_roster_signatures},{ABI_HISTORY_PROOF},{ABI_MESSAGE_PROOF})"
            )
        );
    }

    #[test]
    fn selectors_are_unique_and_disjoint_from_erc20() {
        let mut seen = std::collections::BTreeSet::new();
        for (_, _, selector) in SELECTORS {
            assert!(seen.insert(selector), "duplicate selector {selector:?}");
        }
        // No collision with the ERC-20 surface.
        for erc20 in [
            "name()",
            "symbol()",
            "decimals()",
            "totalSupply()",
            "balanceOf(address)",
            "transfer(address,uint256)",
            "transferFrom(address,address,uint256)",
            "approve(address,uint256)",
            "allowance(address,address)",
        ] {
            assert!(!seen.contains(&selector_of(erc20)), "{erc20}");
        }
    }

    #[test]
    fn contract_bounds_have_the_spec_values() {
        assert_eq!(PREVIOUS_ROSTER_GRACE_MS, 86_400_000);
        assert_eq!(MAX_ROSTER_VALIDITY_MS, 2_592_000_000);
        assert_eq!(MAX_CLOCK_SKEW_MS, 3_600_000);
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
