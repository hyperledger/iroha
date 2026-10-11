//! TON mainnet liteserver answers recorded in `fixtures/sccp/rpc/ton/transport` (captured on
//! 2026-09-28; `specs/sccp.md` §4.13.3, §11), decoded into the light client's frames so tests run
//! real chain data through the production verifier.
//!
//! The recording names masterchain block `B` (`masterchain_block_seqno`), its previous key block
//! `K` and `K`'s previous key block `P`. It holds the forward link `K → B` and the key-block hop
//! `P → K` (Simplex signature sets with their `dest_proof` and the `from` block's config proof),
//! `K`'s configs 34, 28 and 15 (`liteServer.configInfo`), the full block `B`
//! (`liteServer.blockData`, an indexed `BoC` with cache bits), a basechain transaction of the
//! USDT jetton master with its block proof, and that block's `liteServer.shardBlockProof`. Every
//! `BoC` is returned in the canonical proof form the light client accepts.
//!
//! The TL decoding here is a minimal reader for exactly these answers; the production decoders
//! live in `iroha_sccp_rpc::ton::schema`.

use std::{fs, path::PathBuf};

use crate::{
    light_client::ton::TonLcBootstrapV1,
    ton_native::{
        TonBlockIdExtV1, TonBlockSignaturesV1, TonOrdinaryBlockSignaturesV1,
        TonSimplexBlockSignaturesV1, TonValidatorSignatureV1, ton_canonical_boc_v1,
    },
};

/// Seqno of the recorded masterchain block `B`.
pub const CAPTURED_BLOCK_SEQNO: u32 = 95_426_772;
/// Seqno of `B`'s previous key block `K`.
pub const CAPTURED_KEY_BLOCK_SEQNO: u32 = 95_424_597;
/// Seqno of `K`'s previous key block `P`.
pub const CAPTURED_PREVIOUS_KEY_BLOCK_SEQNO: u32 = 95_284_948;
/// Account id of the recorded basechain account (the USDT jetton master).
pub const CAPTURED_ACCOUNT: [u8; 32] = [
    0xb1, 0x13, 0xa9, 0x94, 0xb5, 0x02, 0x4a, 0x16, 0x71, 0x9f, 0x69, 0x13, 0x93, 0x28, 0xeb, 0x75,
    0x95, 0x96, 0xc3, 0x8a, 0x25, 0xf5, 0x90, 0x28, 0xb1, 0x46, 0xfe, 0xcd, 0xc3, 0x62, 0x1d, 0xfe,
];
/// Logical time of the recorded transaction.
pub const CAPTURED_TRANSACTION_LT: u64 = 106_248_525_000_009;

const PARTIAL_BLOCK_PROOF: u32 = 0x8ed0_d2c1;
const BLOCK_LINK_FORWARD: u32 = 0x520f_ce1c;
const SIGNATURE_SET_ORDINARY: u32 = 0xf644_a6e6;
const SIGNATURE_SET_SIMPLEX: u32 = 0xac24_9800;
const CONFIG_INFO: u32 = 0xae7b_272f;
const TRANSACTION_INFO: u32 = 0x0ede_ed47;
const BLOCK_DATA: u32 = 0xa574_ed6c;
const SHARD_BLOCK_PROOF: u32 = 0x1d62_a07a;
const BOOL_TRUE: u32 = 0x9972_75b5;
const BOOL_FALSE: u32 = 0xbc79_9737;

fn transport_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sccp/rpc/ton/transport")
}

fn answer(name: &str) -> Vec<u8> {
    let path = transport_dir().join("answers").join(format!("{name}.tl"));
    fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// Fail unless `recorded.json` names the identifiers this module pins.
fn check_recording() {
    let path = transport_dir().join("recorded.json");
    let index =
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let account = crate::v1::hashes::to_hex(&CAPTURED_ACCOUNT);
    for expected in [
        format!("\"masterchain_block_seqno\": {CAPTURED_BLOCK_SEQNO}"),
        format!("\"key_block_seqno\": {CAPTURED_KEY_BLOCK_SEQNO}"),
        format!("\"prev_key_block_seqno\": {CAPTURED_PREVIOUS_KEY_BLOCK_SEQNO}"),
        format!("\"transaction_lt\": {CAPTURED_TRANSACTION_LT}"),
        format!("\"account\": \"0:{account}\""),
    ] {
        assert!(index.contains(&expected), "recorded.json lacks {expected}");
    }
}

/// A minimal TL reader over one recorded answer.
struct TlReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TlReader<'a> {
    fn new(bytes: &'a [u8], constructor: u32) -> Self {
        let mut reader = Self { bytes, offset: 0 };
        assert_eq!(reader.u32(), constructor, "answer constructor");
        reader
    }

    fn take(&mut self, len: usize) -> &'a [u8] {
        let end = self.offset + len;
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        out
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().expect("4 bytes"))
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().expect("8 bytes"))
    }

    fn h256(&mut self) -> [u8; 32] {
        self.take(32).try_into().expect("32 bytes")
    }

    fn bool(&mut self) -> bool {
        match self.u32() {
            BOOL_TRUE => true,
            BOOL_FALSE => false,
            other => panic!("not a TL Bool: {other:#x}"),
        }
    }

    fn bytes(&mut self) -> Vec<u8> {
        let first = usize::from(self.take(1)[0]);
        let (len, prefix) = if first < 254 {
            (first, 1)
        } else {
            let len = self.take(3);
            (
                usize::from(len[0]) | usize::from(len[1]) << 8 | usize::from(len[2]) << 16,
                4,
            )
        };
        let out = self.take(len).to_vec();
        self.take((4 - (prefix + len) % 4) % 4);
        out
    }

    fn block(&mut self) -> TonBlockIdExtV1 {
        TonBlockIdExtV1 {
            workchain: i32::from_le_bytes(self.take(4).try_into().expect("4 bytes")),
            shard: self.u64(),
            seqno: self.u32(),
            root_hash: self.h256(),
            file_hash: self.h256(),
        }
    }

    fn signatures(&mut self) -> Vec<TonValidatorSignatureV1> {
        let count = self.u32();
        let mut signatures: Vec<TonValidatorSignatureV1> = (0..count)
            .map(|_| TonValidatorSignatureV1 {
                node_id_short: self.h256(),
                signature: self.bytes(),
            })
            .collect();
        signatures.sort_by_key(|signature| signature.node_id_short);
        signatures
    }

    fn finish(&self) {
        assert_eq!(self.offset, self.bytes.len(), "trailing answer bytes");
    }
}

fn canonical(bytes: &[u8]) -> Vec<u8> {
    ton_canonical_boc_v1(bytes).expect("recorded BoCs re-encode canonically")
}

/// One recorded `liteServer.blockLinkForward`.
#[derive(Clone, Debug)]
pub struct CapturedForwardLinkV1 {
    /// Whether `to` is a key block.
    pub to_key_block: bool,
    /// The known block.
    pub from: TonBlockIdExtV1,
    /// The signed block.
    pub to: TonBlockIdExtV1,
    /// Canonical header proof of `to` (its `state_update` is pruned).
    pub dest_proof: Vec<u8>,
    /// Canonical proof of `from`'s block, opening its `McBlockExtra` config.
    pub config_proof: Vec<u8>,
    /// Signatures of `to`, in node-id order.
    pub signatures: TonBlockSignaturesV1,
}

/// The single forward link of the recorded `getBlockProof` answer `name`
/// (`get_block_proof_forward`: `K → B`; `get_block_proof_key_hop`: `P → K`).
#[must_use]
pub fn forward_link(name: &str) -> CapturedForwardLinkV1 {
    check_recording();
    let raw = answer(name);
    let mut reader = TlReader::new(&raw, PARTIAL_BLOCK_PROOF);
    assert!(reader.bool(), "complete proof");
    reader.block();
    reader.block();
    assert_eq!(reader.u32(), 1, "one link");
    assert_eq!(reader.u32(), BLOCK_LINK_FORWARD);
    let to_key_block = reader.bool();
    let from = reader.block();
    let to = reader.block();
    let dest_proof = canonical(&reader.bytes());
    let config_proof = canonical(&reader.bytes());
    let signatures = match reader.u32() {
        SIGNATURE_SET_SIMPLEX => {
            let catchain_seqno = reader.u32();
            let validator_list_hash_short = reader.u32();
            let signatures = reader.signatures();
            TonBlockSignaturesV1::Simplex(TonSimplexBlockSignaturesV1 {
                catchain_seqno,
                validator_list_hash_short,
                signatures,
                session_id: reader.h256(),
                slot: reader.u32(),
                candidate_data: reader.bytes(),
            })
        }
        SIGNATURE_SET_ORDINARY => {
            let validator_list_hash_short = reader.u32();
            let catchain_seqno = reader.u32();
            TonBlockSignaturesV1::Ordinary(TonOrdinaryBlockSignaturesV1 {
                catchain_seqno,
                validator_list_hash_short,
                signatures: reader.signatures(),
            })
        }
        other => panic!("unknown signature set {other:#x}"),
    };
    reader.finish();
    CapturedForwardLinkV1 {
        to_key_block,
        from,
        to,
        dest_proof,
        config_proof,
        signatures,
    }
}

/// Recorded `liteServer.configInfo` of `K` (configs 34, 28 and 15).
#[derive(Clone, Debug)]
pub struct CapturedConfigV1 {
    /// The key block.
    pub block: TonBlockIdExtV1,
    /// Canonical proof of the key block's header and `state_update` (a full header proof).
    pub state_proof: Vec<u8>,
    /// Canonical proof of its state opening configs 34, 28 and 15.
    pub config_proof: Vec<u8>,
}

/// `K`'s recorded configs.
#[must_use]
pub fn key_block_config() -> CapturedConfigV1 {
    check_recording();
    let raw = answer("get_config_params");
    let mut reader = TlReader::new(&raw, CONFIG_INFO);
    reader.u32();
    let block = reader.block();
    let state_proof = canonical(&reader.bytes());
    let config_proof = canonical(&reader.bytes());
    reader.finish();
    CapturedConfigV1 {
        block,
        state_proof,
        config_proof,
    }
}

/// The weak-subjectivity bootstrap of `K` built from its recorded configs.
#[must_use]
pub fn key_block_bootstrap() -> TonLcBootstrapV1 {
    let config = key_block_config();
    TonLcBootstrapV1 {
        block_id: config.block,
        header_proof: config.state_proof,
        config_proof: config.config_proof,
    }
}

/// Recorded `liteServer.transactionInfo` of the jetton master.
#[derive(Clone, Debug)]
pub struct CapturedTransactionV1 {
    /// The basechain block carrying the transaction.
    pub block: TonBlockIdExtV1,
    /// Canonical proof of that block reaching the transaction (header included,
    /// `state_update` pruned).
    pub proof: Vec<u8>,
    /// Canonical transaction `BoC`.
    pub transaction: Vec<u8>,
}

/// The recorded transaction.
#[must_use]
pub fn transaction() -> CapturedTransactionV1 {
    check_recording();
    let raw = answer("get_one_transaction");
    let mut reader = TlReader::new(&raw, TRANSACTION_INFO);
    let block = reader.block();
    let proof = canonical(&reader.bytes());
    let transaction = canonical(&reader.bytes());
    reader.finish();
    CapturedTransactionV1 {
        block,
        proof,
        transaction,
    }
}

/// Recorded `liteServer.shardBlockProof` of the transaction's block.
#[derive(Clone, Debug)]
pub struct CapturedShardProofV1 {
    /// The masterchain block registering the first link.
    pub masterchain: TonBlockIdExtV1,
    /// `(block, proof)` links; link 0's proof is rooted at `masterchain` (its `ShardHashes`
    /// path), link `i + 1`'s at link `i` (its `prev_ref`).
    pub links: Vec<(TonBlockIdExtV1, Vec<u8>)>,
}

/// The recorded shard-block proof.
#[must_use]
pub fn shard_block_proof() -> CapturedShardProofV1 {
    check_recording();
    let raw = answer("get_shard_block_proof");
    let mut reader = TlReader::new(&raw, SHARD_BLOCK_PROOF);
    let masterchain = reader.block();
    let count = reader.u32();
    let links = (0..count)
        .map(|_| (reader.block(), canonical(&reader.bytes())))
        .collect();
    reader.finish();
    CapturedShardProofV1 { masterchain, links }
}

/// The recorded full block `B` (`getBlock`) exactly as served: an indexed `BoC` with CRC and
/// cache bits.
#[must_use]
pub fn full_block_raw() -> Vec<u8> {
    let raw = answer("get_block");
    let mut reader = TlReader::new(&raw, BLOCK_DATA);
    reader.block();
    let data = reader.bytes();
    reader.finish();
    data
}

/// The recorded full block `B` (`getBlock`), re-encoded canonically: a header proof of `B` with
/// every cell, `state_update` and `ShardHashes` included.
#[must_use]
pub fn full_block() -> (TonBlockIdExtV1, Vec<u8>) {
    check_recording();
    let raw = answer("get_block");
    let mut reader = TlReader::new(&raw, BLOCK_DATA);
    let block = reader.block();
    let data = canonical(&reader.bytes());
    reader.finish();
    (block, data)
}
