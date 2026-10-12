// SCCP v1 TON constants (specs/sccp.md revision 5, §3 and §5.3).
//
// The Acton suite pins these values against the shared fixtures and the
// specification: `tests/unit/sccp-vectors.test.tolk` compares the constants
// themselves, and the fixture replays of the other suites pin what they
// encode (payloads, control leaves, certificates, opcodes and exit codes).

/// All SCCP TON contracts live in the basechain.
const SCCP_WORKCHAIN = BASECHAIN

/// `GLOBALID` of TON mainnet (§5.1.5 step 1).
const SCCP_TON_GLOBAL_ID = -239

/// SCCP domains (§3.2).
const SCCP_DOMAIN_TAIRA = 0
const SCCP_DOMAIN_TON = 4

/// Network profile tags (§2.1).
const SCCP_TAG_TAIRA = 0x40
const SCCP_TAG_TON = 0x44

/// `identity_word(ton-mainnet)`: two's-complement `int256(-239)` (§2.1).
const SCCP_TON_IDENTITY_WORD = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff11

/// Transfer payload constants (§3.2).
const SCCP_PAYLOAD_KIND_TRANSFER = 0x02
const SCCP_PAYLOAD_VERSION = 0x01
const SCCP_CODEC_CANONICAL_TEXT = 1
const SCCP_CODEC_TAIRA_ACCOUNT = 3
const SCCP_CODEC_TON_ACCOUNT36 = 7
/// `asset_id = "xor"` as a 24-bit big-endian integer.
const SCCP_ASSET_ID_XOR = 0x786f72
const SCCP_ASSET_ID_XOR_LEN = 3
/// `route_id = "taira_ton_xor"` as a 104-bit big-endian integer.
const SCCP_ROUTE_ID_TON = 0x74616972615f746f6e5f786f72
const SCCP_ROUTE_ID_TON_LEN = 13
const SCCP_TON_ACCOUNT36_LEN = 36
const SCCP_MAX_TAIRA_ACCOUNT_BYTES = 1024
const SCCP_MAX_PAYLOAD_BYTES = 4096
/// Amounts crossing a TON endpoint are below 2^96 (§3.2).
const SCCP_TON_AMOUNT_LIMIT = 0x1000000000000000000000000

/// Standard snake cells: 127 data bytes per non-final chunk (§5.3.2).
const SCCP_SNAKE_CHUNK_BYTES = 127
const SCCP_SNAKE_CHUNK_BITS = 1016

/// Commitment trees and history (§3.4, §3.5).
const SCCP_MAX_BLOCK_LEAVES = 512
const SCCP_MAX_BLOCK_PATH = 9
const SCCP_MAX_HISTORY_PATH = 32
const SCCP_MAX_HISTORY_SIZE = 0x100000000
const SCCP_HASHES_PER_CHUNK = 3

/// Committees (§0, §3.7): `n = 3f + 1` with `4 ≤ n ≤ 31`, `q = n − f`.
const SCCP_MIN_COMMITTEE_SIZE = 4
const SCCP_MAX_COMMITTEE_SIZE = 31
/// Compressed BLS12-381 G1 keys per `KeyChunk` (§5.3.1); 2 × 384 + 1 bits.
const SCCP_KEYS_PER_CHUNK = 2
const SCCP_KEY_BITS = 384
/// `KeyChunk`s of the largest committee: 15 chunks of two keys and one of one.
const SCCP_MAX_KEY_CHUNKS = 16
/// Compressed BLS12-381 G2 signature (§3.7).
const SCCP_SIGNATURE_BITS = 768
/// First 32 bytes of the compressed identity signature, `0xc0` followed by
/// 95 zero bytes (§5.1.3 step 6); its other 64 bytes are zero.
const SCCP_IDENTITY_SIGNATURE_HEAD = 0xc000000000000000000000000000000000000000000000000000000000000000

/// The largest `u64`. `op_count` and the two time sums saturate at it, and a
/// stored `outbound_nonce` of this value is exhausted (§5.1.1, §5.1.2, §5.1.7).
const SCCP_MAX_U64 = 0xffffffffffffffff

/// Contract constants of §3.9.
const SCCP_MAX_VALIDITY_MS = 2592000000
const SCCP_MAX_FAST_PAUSE_MS = 2592000000
const SCCP_MAX_INIT_SLACK_MS = 3600000
/// TON keeps three checkpoint slots (§5.1.3).
const SCCP_CHECKPOINT_SLOTS = 3
/// `MAX_VOID_FROZEN_RANGE_TON`: one bucket.
const SCCP_MAX_VOID_FROZEN_RANGE = 512

/// Finality header `X` (§3.6): 221 bytes split at offset 109 into
/// `XHead` (872 bits) and `XTail` (896 bits).
const SCCP_X_HEAD_BITS = 872
const SCCP_X_TAIL_BITS = 896
/// `ASCII("SCCP/FINALITY/V1")` as a 128-bit big-endian integer.
const SCCP_X_MAGIC = 0x534343502f46494e414c4954592f5631
const SCCP_X_FLAG_ACTIVE = 1
const SCCP_X_FLAG_ROTATION = 2
/// Flag bits 2–7, which X1 requires to be zero.
const SCCP_X_FLAGS_RESERVED = 0xfc
/// Bit offset of `height` in `XHead` (byte 48 of `X`).
const SCCP_X_HEIGHT_OFFSET_BITS = 384
/// X6: a `ROTATION` header has `height` and `generation` of at most 2^64 − 2,
/// so the successor's start and generation are `u64` values.
const SCCP_MAX_ROTATION_FIELD = 0xfffffffffffffffe

/// `QC_FIXED` without its trailing `signers` word (§3.7, §5.3.2): 112 bytes.
const SCCP_QC_FIXED_CELL_BITS = 896
/// `TairaCert` root: `signature:bits768 signers:uint32` (§5.3.2).
const SCCP_TAIRA_CERT_BITS = 800
/// Data bits of the proof cells of §5.3.2; the Maybe bit of each path is its
/// last bit.
const SCCP_BLOCK_REF_BITS = 425
const SCCP_MESSAGE_PROOF_BITS = 41
const SCCP_CONTROL_PROOF_BITS = 690

/// `RESULT_TAG = ASCII("iroha/sumeragi/result/v1")` (§3.6), 24 bytes.
const SCCP_RESULT_TAG = 0x69726f68612f73756d65726167692f726573756c742f7631
const SCCP_RESULT_TAG_BITS = 192
/// `ASCII("sumeragi/sig")` (§3.7), 12 bytes.
const SCCP_SIG_TAG = 0x73756d65726167692f736967
const SCCP_SIG_TAG_BITS = 96
/// Commit vote kind; a PrepareQC (`0x02`) is never accepted (§3.8 step 5).
const SCCP_KIND_COMMIT = 0x03

/// Latch reasons of `sccp_latched` (§5.1.2).
const SCCP_LATCH_V1 = 1
const SCCP_LATCH_V2 = 2
const SCCP_LATCH_V3 = 3

/// Control tracks (§3.4).
const SCCP_TRACK_PARLIAMENT = 1
const SCCP_TRACK_FAST_PAUSE = 2

/// Domain tags as big-endian integers (§3.3, §3.4, §3.5, §3.7).
const SCCP_TAG_COMMITTEE_V1 = 0x534343502f434f4d4d49545445452f5631
const SCCP_TAG_COMMITTEE_V1_BITS = 136
const SCCP_TAG_LEAF_V1 = 0x534343502f4c4541462f5631
const SCCP_TAG_LEAF_V1_BITS = 96
const SCCP_TAG_CONTROL_V1 = 0x534343502f434f4e54524f4c2f5631
const SCCP_TAG_CONTROL_V1_BITS = 120
const SCCP_TAG_NODE_V1 = 0x534343502f4e4f44452f5631
const SCCP_TAG_NODE_V1_BITS = 96
const SCCP_TAG_HISTORY_V1 = 0x534343502f484953544f52592f5631
const SCCP_TAG_HISTORY_V1_BITS = 120
const SCCP_TAG_PAYLOAD_V1 = 0x534343502f5041594c4f41442f5631
const SCCP_TAG_PAYLOAD_V1_BITS = 120
const SCCP_TAG_MESSAGE_V1 = 0x534343502f4d4553534147452f5631
const SCCP_TAG_MESSAGE_V1_BITS = 120

/// Consumption buckets hold 512 nonce flags each (§5.3.3).
const SCCP_BUCKET_BITS = 512
const SCCP_BUCKET_SHIFT = 9
const SCCP_BUCKET_MASK = 511
/// Finalize and void deploy at most this many buckets ahead of `deployed_buckets` (§5.3.4).
const SCCP_MAX_DEPLOY_AHEAD = 4
/// Upper bound of one `sccp_deploy_buckets` request.
const SCCP_MAX_DEPLOY_BUCKETS_PER_CALL = 16

/// Consume kinds carried by `ConsumeTail.kind` (§5.3.3).
const SCCP_CONSUME_KIND_MINT = 0
const SCCP_CONSUME_KIND_VOID = 1

/// Kinds of the minter's `retries` entries (§5.3.4): an `sccp_unconsume` of
/// the key nonce, or the activation of the bucket whose first nonce is the key.
const SCCP_RETRY_UNCONSUME = 1
const SCCP_RETRY_ACTIVATE = 2

/// Jetton metadata (§5.3.1): 9 decimals everywhere.
const SCCP_JETTON_DECIMALS = 9

/// Opcodes that appear in bounced bodies (first 32 bits after `0xFFFFFFFF`).
const SCCP_OP_CONSUME = 0x53434331
const SCCP_OP_CONSUMED = 0x53434332
const SCCP_OP_CONSUME_RANGE = 0x53434333
const SCCP_OP_RANGE_CONSUMED = 0x53434334
const SCCP_OP_UNCONSUME = 0x53434335
const SCCP_OP_ALREADY_CONSUMED = 0x53434336
const SCCP_OP_ACTIVATE_BUCKET = 0x53434338
const SCCP_OP_CONSUME_REVERTED = 0x53434339
const SCCP_OP_INTERNAL_TRANSFER = 0x178d4519
const SCCP_OP_BURN_NOTIFICATION = 0x7bdd97de
