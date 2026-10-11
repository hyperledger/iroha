//! Signing and hash preimages (spec §2.1, §3.1–§3.3, §1.8): fixed byte layouts built by hand,
//! independent of any codec. Every layout starts with a domain tag; instance, scheduling epoch/context, height and view are
//! in every consensus signing preimage; block hash and result are bound in every vote.
//! The probe echo (kind `0x05`, §7.4 R2) independently binds restart anchoring.

use crate::{
    crypto::Crypto,
    message::{BlockHeader, Qc, TimeoutCert, VoteKind},
    types::{Committee, EpochConfig, EpochId, Hash32, PublicKey},
};

/// Domain tag of every signing preimage.
pub const TAG_SIG: &[u8] = b"sumeragi/sig";
/// Domain tag of `block_hash`.
pub const TAG_BLOCK: &[u8] = b"sumeragi/block";
/// Domain tag of `payload_hash`.
pub const TAG_PAY: &[u8] = b"sumeragi/payload";
/// Domain tag of `att_digest`.
pub const TAG_ATT: &[u8] = b"sumeragi/attach";
/// Domain tag of `qc_digest`.
pub const TAG_QC: &[u8] = b"sumeragi/qc";
/// Domain tag of `tc_digest`.
pub const TAG_TC: &[u8] = b"sumeragi/tc";
/// Domain tag of `committee_digest`.
pub const TAG_COMMITTEE: &[u8] = b"sumeragi/committee";
/// Domain tag of the topology seed.
pub const TAG_TOPOLOGY: &[u8] = b"sumeragi/topology";
/// Domain tag of the (application-side) instance-id derivation (§1.8).
pub const TAG_INSTANCE: &[u8] = b"sumeragi/instance";
/// Kind byte of a proposal signature.
pub const KIND_PROPOSAL: u8 = 0x01;
/// Kind byte of a Prepare vote.
pub const KIND_PREPARE: u8 = 0x02;
/// Kind byte of a Commit vote.
pub const KIND_COMMIT: u8 = 0x03;
/// Kind byte of a timeout vote.
pub const KIND_TIMEOUT: u8 = 0x04;
/// Kind byte of a probe echo (§3.3, §7.4 R2).
pub const KIND_ECHO: u8 = 0x05;

/// Append the canonical length-prefixed public key.
pub(crate) fn put_kb(out: &mut Vec<u8>, pk: &PublicKey) {
    let raw = pk.as_bytes();
    // Keys longer than `MAX_PUBLIC_KEY_LEN` (≪ 65 535) are rejected at every intake.
    let len = u16::try_from(raw.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(raw);
}

/// Append the canonical counted list of public keys.
fn put_keys(out: &mut Vec<u8>, list: &[PublicKey]) {
    put_len32(out, list.len());
    for pk in list {
        put_kb(out, pk);
    }
}

fn put_len32(out: &mut Vec<u8>, len: usize) {
    // Every list reaching a preimage is bounded far below 2^32 by the intake limits.
    out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes());
}

/// `enc(None) = 0x00 ; enc(Some(w)) = 0x01 ‖ be64(w)` (optional view).
pub fn enc_view(out: &mut Vec<u8>, view: Option<u64>) {
    match view {
        None => out.push(0x00),
        Some(w) => {
            out.push(0x01);
            out.extend_from_slice(&w.to_be_bytes());
        }
    }
}

/// `opt(None) = 0x00 ; opt(Some(x)) = 0x01 ‖ x` (optional digest).
pub fn opt_digest(out: &mut Vec<u8>, digest: Option<&Hash32>) {
    match digest {
        None => out.push(0x00),
        Some(d) => {
            out.push(0x01);
            out.extend_from_slice(d.as_bytes());
        }
    }
}

fn put_epoch(out: &mut Vec<u8>, epoch: &EpochId) {
    // MS43: signatures cease binding the scheduling epoch and its complete context.
    if !cfg!(sumeragi_mutation = "MS43") {
        out.extend_from_slice(&epoch.epoch.to_be_bytes());
        out.extend_from_slice(epoch.context.as_bytes());
    }
}

fn put_round(out: &mut Vec<u8>, instance: &Hash32, epoch: &EpochId, height: u64, view: u64) {
    out.extend_from_slice(instance.as_bytes());
    put_epoch(out, epoch);
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(&view.to_be_bytes());
}

/// Common signing envelope; the three round messages share the replay-domain mutation.
fn signing_prefix(kind: u8, instance: &Hash32, epoch: &EpochId) -> Vec<u8> {
    let mut out = Vec::with_capacity(200);
    out.extend_from_slice(TAG_SIG);
    out.push(kind);
    let instance = if cfg!(sumeragi_mutation = "MS16") && kind <= KIND_TIMEOUT {
        &Hash32::ZERO
    } else {
        instance
    };
    out.extend_from_slice(instance.as_bytes());
    put_epoch(&mut out, epoch);
    out
}

/// Preimage of `block_hash` (§3.2):
/// `TAG_BLOCK ‖ I ‖ E ‖ be64(h) ‖ be64(origin_view) ‖ parent_hash ‖ parent_result ‖ payload_hash ‖
/// availability_digest ‖ be32(payload_len) ‖ be32(proposer) ‖ keys(skipped_leaders) ‖ be32(control_len) ‖ control`.
pub fn block_hash_preimage(header: &BlockHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(200);
    out.extend_from_slice(TAG_BLOCK);
    put_round(
        &mut out,
        &header.instance,
        &header.epoch,
        header.height,
        header.origin_view,
    );
    out.extend_from_slice(header.parent_hash.as_bytes());
    out.extend_from_slice(header.parent_result.as_bytes());
    out.extend_from_slice(header.payload_hash.as_bytes());
    out.extend_from_slice(header.availability_digest.as_bytes());
    out.extend_from_slice(&header.payload_len.to_be_bytes());
    out.extend_from_slice(&header.proposer.to_be_bytes());
    put_keys(&mut out, &header.skipped_leaders);
    // MS46: control bytes disappear from every signature rooted in this header hash.
    if !cfg!(sumeragi_mutation = "MS46") {
        put_len32(&mut out, header.control_witness.len());
        out.extend_from_slice(header.control_witness.as_slice());
    }
    out
}

/// `block_hash(header)` (§3.2).
pub fn block_hash(crypto: &dyn Crypto, header: &BlockHeader) -> Hash32 {
    crypto.hash(&block_hash_preimage(header))
}

/// `payload_hash = H(TAG_PAY ‖ payload)` (§3.2).
pub fn payload_hash(crypto: &dyn Crypto, payload: &[u8]) -> Hash32 {
    crypto.hash_chunks(&[TAG_PAY, payload])
}

/// `prop_preimage(h, v, bh, ad) = TAG_SIG ‖ 0x01 ‖ I ‖ E ‖ be64(h) ‖ be64(v) ‖ bh ‖ ad` (§3.3).
pub fn prop_preimage(
    instance: &Hash32,
    epoch: &EpochId,
    height: u64,
    view: u64,
    bh: &Hash32,
    ad: &Hash32,
) -> Vec<u8> {
    let mut out = signing_prefix(KIND_PROPOSAL, instance, epoch);
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(&view.to_be_bytes());
    out.extend_from_slice(bh.as_bytes());
    out.extend_from_slice(ad.as_bytes());
    out
}

/// `vote_preimage(kind, h, v, bh, R) = TAG_SIG ‖ kind ‖ I ‖ E ‖ be64(h) ‖ be64(v) ‖ bh ‖ R` (§3.3).
#[allow(clippy::too_many_arguments, reason = "one per §3.3 layout field")]
pub fn vote_preimage(
    kind: VoteKind,
    instance: &Hash32,
    epoch: &EpochId,
    height: u64,
    view: u64,
    bh: &Hash32,
    result: &Hash32,
) -> Vec<u8> {
    let mut out = signing_prefix(kind.byte(), instance, epoch);
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(&view.to_be_bytes());
    out.extend_from_slice(bh.as_bytes());
    #[cfg(not(sumeragi_mutation = "MS17"))]
    out.extend_from_slice(result.as_bytes());
    out
}

/// `tmo_preimage(h, v, hq) = TAG_SIG ‖ 0x04 ‖ I ‖ E ‖ be64(h) ‖ be64(v) ‖ enc(hq)` (§3.3).
pub fn tmo_preimage(
    instance: &Hash32,
    epoch: &EpochId,
    height: u64,
    view: u64,
    hq: Option<u64>,
) -> Vec<u8> {
    let mut out = signing_prefix(KIND_TIMEOUT, instance, epoch);
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(&view.to_be_bytes());
    enc_view(&mut out, hq);
    out
}

/// `echo_preimage(nonce, height) = TAG_SIG ‖ 0x05 ‖ I ‖ E ‖ be64(nonce) ‖ be64(height)` (§3.3): the
/// signed answer to a probe (§7.4 R2). It binds the prober's nonce and the replier's reported
/// height; its kind byte keeps it from verifying as a proposal, vote or timeout.
pub fn echo_preimage(instance: &Hash32, epoch: &EpochId, nonce: u64, height: u64) -> Vec<u8> {
    let mut out = signing_prefix(KIND_ECHO, instance, epoch);
    out.extend_from_slice(&nonce.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out
}

/// Preimage of `qc_digest(c)` (§3.3): `TAG_QC ‖ c.kind ‖ I ‖ E ‖ be64(c.height) ‖ be64(c.view) ‖
/// c.block_hash ‖ c.result ‖ be32(len(c.signers)) ‖ c.signers ‖ c.agg_sig`.
// SPEC: `I` in qc_digest / tc_digest is taken from the certificate's own `instance` field (every
// verified certificate has `instance == I`) (Appendix E, E13).
pub fn qc_digest_preimage(qc: &Qc) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAG_QC.len() + 1 + 32 + 16 + 64 + 4 + 8 + 96);
    out.extend_from_slice(TAG_QC);
    out.push(qc.kind.byte());
    put_round(&mut out, &qc.instance, &qc.epoch, qc.height, qc.view);
    out.extend_from_slice(qc.block_hash.as_bytes());
    out.extend_from_slice(qc.result.as_bytes());
    put_len32(&mut out, qc.signers.as_bytes().len());
    out.extend_from_slice(qc.signers.as_bytes());
    out.extend_from_slice(&qc.agg_sig.0);
    out
}

/// `qc_digest(c)` (§3.3).
pub fn qc_digest(crypto: &dyn Crypto, qc: &Qc) -> Hash32 {
    crypto.hash(&qc_digest_preimage(qc))
}

/// Preimage of `tc_digest(t)` (§3.3): `TAG_TC ‖ I ‖ E ‖ be64(t.height) ‖ be64(t.view) ‖
/// be32(len(t.entries)) ‖ [be32(idx) ‖ enc(hq)]… ‖ t.agg_sig ‖ opt(t.high_pqc.map(qc_digest))`.
pub fn tc_digest_preimage(crypto: &dyn Crypto, tc: &TimeoutCert) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAG_TC.len() + 32 + 16 + 4 + tc.entries.len() * 13 + 96 + 33);
    out.extend_from_slice(TAG_TC);
    put_round(&mut out, &tc.instance, &tc.epoch, tc.height, tc.view);
    put_len32(&mut out, tc.entries.len());
    for entry in &tc.entries {
        out.extend_from_slice(&entry.signer.to_be_bytes());
        enc_view(&mut out, entry.hq);
    }
    out.extend_from_slice(&tc.agg_sig.0);
    let high = tc.high_pqc.as_ref().map(|qc| qc_digest(crypto, qc));
    opt_digest(&mut out, high.as_ref());
    out
}

/// `tc_digest(t)` (§3.3).
pub fn tc_digest(crypto: &dyn Crypto, tc: &TimeoutCert) -> Hash32 {
    crypto.hash(&tc_digest_preimage(crypto, tc))
}

/// Preimage of `att_digest(justify, parent_qc)`:
/// `TAG_ATT ‖ opt(justify.map(tc_digest)) ‖ opt(parent_qc.map(qc_digest))` (§3.3).
pub fn att_digest_preimage(
    crypto: &dyn Crypto,
    justify: Option<&TimeoutCert>,
    parent_qc: Option<&Qc>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAG_ATT.len() + 66);
    out.extend_from_slice(TAG_ATT);
    let tc = justify.map(|tc| tc_digest(crypto, tc));
    opt_digest(&mut out, tc.as_ref());
    let qc = parent_qc.map(|qc| qc_digest(crypto, qc));
    opt_digest(&mut out, qc.as_ref());
    out
}

/// `ad = att_digest(justify, parent_qc)` (§3.3).
pub fn att_digest(
    crypto: &dyn Crypto,
    justify: Option<&TimeoutCert>,
    parent_qc: Option<&Qc>,
) -> Hash32 {
    crypto.hash(&att_digest_preimage(crypto, justify, parent_qc))
}

/// Preimage of `committee_digest(C) = H(TAG_COMMITTEE ‖ be32(n) ‖ kb(C[0]) ‖ … ‖ kb(C[n−1]))`.
pub fn committee_digest_preimage(committee: &Committee) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAG_COMMITTEE.len() + 4 + committee.n() * 50);
    out.extend_from_slice(TAG_COMMITTEE);
    put_keys(&mut out, committee.members());
    out
}

/// `committee_digest(C)` (§2.1, exported for light clients, §11).
pub fn committee_digest(crypto: &dyn Crypto, committee: &Committee) -> Hash32 {
    crypto.hash(&committee_digest_preimage(committee))
}

/// `seed_C = H(TAG_TOPOLOGY ‖ I ‖ E ‖ leader_seed ‖ committee_digest(C))` (§2.1).
pub fn topology_seed(
    crypto: &dyn Crypto,
    instance: &Hash32,
    epoch: &EpochConfig,
    committee: &Committee,
) -> Hash32 {
    let mut out = Vec::with_capacity(TAG_TOPOLOGY.len() + 64);
    out.extend_from_slice(TAG_TOPOLOGY);
    out.extend_from_slice(instance.as_bytes());
    put_epoch(&mut out, &epoch.id);
    out.extend_from_slice(epoch.leader_seed.as_bytes());
    out.extend_from_slice(committee_digest(crypto, committee).as_bytes());
    crypto.hash(&out)
}

/// Kind of a consensus instance (§1.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceKind {
    /// The global (Nexus) chain.
    Global,
    /// A dataspace chain.
    Dataspace,
    /// A lane chain.
    Lane,
}

impl InstanceKind {
    /// Kind byte: 0 = global, 1 = dataspace, 2 = lane.
    pub const fn byte(self) -> u8 {
        match self {
            Self::Global => 0,
            Self::Dataspace => 1,
            Self::Lane => 2,
        }
    }
}

/// Application-side instance-id derivation (§1.8):
/// `I = H("sumeragi/instance" ‖ genesis_hash ‖ chain_id_bytes ‖ kind:u8 ‖ be32(index))`.
/// The core itself only ever sees the resulting 32 opaque bytes.
pub fn instance_id(
    crypto: &dyn Crypto,
    genesis_hash: &Hash32,
    chain_id: &[u8],
    kind: InstanceKind,
    index: u32,
) -> Hash32 {
    let mut out = Vec::with_capacity(TAG_INSTANCE.len() + 32 + chain_id.len() + 5);
    out.extend_from_slice(TAG_INSTANCE);
    out.extend_from_slice(genesis_hash.as_bytes());
    out.extend_from_slice(chain_id);
    out.push(kind.byte());
    out.extend_from_slice(&index.to_be_bytes());
    crypto.hash(&out)
}

#[cfg(test)]
mod tests {
    //! Golden vectors. Expected bytes and digests were produced by an independent Python
    //! implementation of the §3 layouts (SHA-256 as `H`, which is also the fake scheme's hash).
    use super::*;
    use crate::{
        message::TcEntry,
        testing::FakeCrypto,
        types::{AggregateSignature, Bitmap, SIGNATURE_LEN},
    };

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    fn h(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn key(byte: u8, len: usize) -> PublicKey {
        PublicKey::new(vec![byte; len]).unwrap()
    }

    fn golden_qc() -> Qc {
        Qc {
            epoch: crate::testing::TEST_EPOCH.id,
            kind: VoteKind::Prepare,
            instance: h(0x11),
            height: 7,
            view: 1,
            block_hash: h(0x22),
            result: h(0x33),
            signers: Bitmap::from_indices(4, [0, 1, 3]).unwrap(),
            agg_sig: AggregateSignature([0x55; SIGNATURE_LEN]),
        }
    }

    fn golden_tc() -> TimeoutCert {
        TimeoutCert {
            epoch: crate::testing::TEST_EPOCH.id,
            instance: h(0x11),
            height: 7,
            view: 2,
            entries: vec![
                TcEntry {
                    signer: 0,
                    hq: None,
                },
                TcEntry {
                    signer: 1,
                    hq: Some(1),
                },
                TcEntry {
                    signer: 3,
                    hq: Some(1),
                },
            ],
            agg_sig: AggregateSignature([0x66; SIGNATURE_LEN]),
            high_pqc: Some(golden_qc()),
        }
    }

    fn golden_header() -> BlockHeader {
        BlockHeader {
            control_witness: crate::types::ControlWitness::empty(),
            epoch: crate::testing::TEST_EPOCH.id,
            instance: h(0x11),
            height: 7,
            origin_view: 2,
            parent_hash: h(0x44),
            parent_result: h(0x45),
            payload_hash: h(0x46),
            availability_digest: h(0x47),
            payload_len: 3,
            proposer: 2,
            skipped_leaders: vec![key(0xa1, 32), key(0xa2, 48)],
        }
    }

    /// `hex(I ‖ E)` of the golden vectors: instance `h(0x11)` in the test epoch.
    fn instance_epoch_hex() -> String {
        format!("{}0000000000000000{}", "11".repeat(32), "e0".repeat(32))
    }

    #[test]
    fn tag_constants() {
        assert_eq!(TAG_SIG, b"sumeragi/sig");
        assert_eq!(TAG_BLOCK, b"sumeragi/block");
        assert_eq!(TAG_PAY, b"sumeragi/payload");
        assert_eq!(TAG_ATT, b"sumeragi/attach");
        assert_eq!(TAG_QC, b"sumeragi/qc");
        assert_eq!(TAG_TC, b"sumeragi/tc");
        assert_eq!(TAG_COMMITTEE, b"sumeragi/committee");
        assert_eq!(TAG_TOPOLOGY, b"sumeragi/topology");
        assert_eq!(
            [
                KIND_PROPOSAL,
                KIND_PREPARE,
                KIND_COMMIT,
                KIND_TIMEOUT,
                KIND_ECHO
            ],
            [1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn primitive_encodings() {
        let mut out = vec![];
        put_kb(&mut out, &key(0xab, 3));
        assert_eq!(hex(&out), "0003ababab");
        out.clear();
        put_keys(&mut out, &[key(1, 1), key(2, 2)]);
        assert_eq!(hex(&out), "0000000200010100020202");
        out.clear();
        put_keys(&mut out, &[]);
        assert_eq!(hex(&out), "00000000");
        let mut out = vec![];
        enc_view(&mut out, None);
        enc_view(&mut out, Some(0x0102));
        assert_eq!(hex(&out), "00010000000000000102");
        let mut out = vec![];
        opt_digest(&mut out, None);
        opt_digest(&mut out, Some(&h(0xee)));
        assert_eq!(out.len(), 1 + 1 + 32);
        assert_eq!(out[..2], [0, 1]);
        assert!(out[2..].iter().all(|b| *b == 0xee));
        assert_eq!((u8::from(false), u8::from(true)), (0, 1));
    }

    #[test]
    fn golden_signing_preimages() {
        let epoch = &crate::testing::TEST_EPOCH.id;
        let ie = instance_epoch_hex();
        let prop = prop_preimage(&h(0x11), epoch, 7, 2, &h(0x22), &h(0x44));
        assert_eq!(
            hex(&prop),
            format!(
                "{}01{ie}{:016x}{:016x}{}{}",
                hex(TAG_SIG),
                7,
                2,
                "22".repeat(32),
                "44".repeat(32)
            )
        );
        let vote = |kind| vote_preimage(kind, &h(0x11), epoch, 7, 2, &h(0x22), &h(0x33));
        let prepare = vote(VoteKind::Prepare);
        let commit = vote(VoteKind::Commit);
        let expected_tail = format!(
            "{ie}{:016x}{:016x}{}{}",
            7,
            2,
            "22".repeat(32),
            "33".repeat(32)
        );
        assert_eq!(hex(&prepare), format!("{}02{expected_tail}", hex(TAG_SIG)));
        assert_eq!(hex(&commit), format!("{}03{expected_tail}", hex(TAG_SIG)));
        let tmo = |hq| tmo_preimage(&h(0x11), epoch, 7, 2, hq);
        assert_eq!(
            hex(&tmo(None)),
            format!("{}04{ie}{:016x}{:016x}00", hex(TAG_SIG), 7, 2)
        );
        assert_eq!(
            hex(&tmo(Some(1))),
            format!("{}04{ie}{:016x}{:016x}01{:016x}", hex(TAG_SIG), 7, 2, 1)
        );
        // SHA-256 digests of the preimages (independent Python implementation).
        let crypto = FakeCrypto::new();
        assert_eq!(
            crypto.hash(&prop).to_string(),
            "74387e4970874078d8b5999dca1c03dd03e8c4f24a6fe37e7b5eca6a28da8713"
        );
        assert_eq!(
            crypto.hash(&prepare).to_string(),
            "dc2d9dc63e8fdbf90bc3611ec77e88ab60e16fc7d20c6269444c6ed93b2259b8"
        );
        assert_eq!(
            crypto.hash(&commit).to_string(),
            "e137a977b2eb4238a69de4550bee4710f19ba7a6ab29aad424c2fb09ce4adeae"
        );
        assert_eq!(
            crypto.hash(&tmo(Some(1))).to_string(),
            "62b8c5fa3f8a852a7de9f3df85e826ff5fa5fee776e0c87ae7e556f76dfb6937"
        );
    }

    #[test]
    fn golden_echo_preimage() {
        // `TAG_SIG ‖ 0x05 ‖ I ‖ E ‖ be64(nonce) ‖ be64(height)`; digest from an independent Python
        // implementation (SHA-256).
        let echo = echo_preimage(
            &h(0x11),
            &crate::testing::TEST_EPOCH.id,
            0x0102_0304_0506_0708,
            7,
        );
        assert_eq!(
            hex(&echo),
            "73756d65726167692f7369670511111111111111111111111111111111111111111111111111111111111111110000000000000000e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e001020304050607080000000000000007"
        );
        assert_eq!(
            FakeCrypto::new().hash(&echo).to_string(),
            "73d599df3c33ad5de89a43074a7eb5568dc591954bdaf1c3cf42f6587852789d"
        );
        // Never equal to a consensus preimage of the same numbers (kind byte).
        assert_ne!(
            echo[..13],
            tmo_preimage(&h(0x11), &crate::testing::TEST_EPOCH.id, 1, 7, None)[..13]
        );
        assert_ne!(
            echo_preimage(&h(0x11), &crate::testing::TEST_EPOCH.id, 1, 7),
            echo_preimage(&h(0x12), &crate::testing::TEST_EPOCH.id, 1, 7),
            "instance bound"
        );
        assert_ne!(
            echo_preimage(&h(0x11), &crate::testing::TEST_EPOCH.id, 1, 7),
            echo_preimage(&h(0x11), &crate::testing::TEST_EPOCH.id, 2, 7),
            "nonce bound"
        );
        assert_ne!(
            echo_preimage(&h(0x11), &crate::testing::TEST_EPOCH.id, 1, 7),
            echo_preimage(&h(0x11), &crate::testing::TEST_EPOCH.id, 1, 8),
            "height bound"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn golden_block_hash_and_body() {
        let crypto = FakeCrypto::new();
        let header = golden_header();
        let preimage = block_hash_preimage(&header);
        let expected = format!(
            "{}{}{:016x}{:016x}{}{}{}{}{:08x}{:08x}00000002{}{}{}{}00000000",
            hex(TAG_BLOCK),
            instance_epoch_hex(),
            7,
            2,
            "44".repeat(32),
            "45".repeat(32),
            "46".repeat(32),
            "47".repeat(32),
            3,
            2,
            "0020",
            "a1".repeat(32),
            "0030",
            "a2".repeat(48)
        );
        assert_eq!(hex(&preimage), expected);
        assert_eq!(
            block_hash(&crypto, &header).to_string(),
            "6f63676aa20ade34ff0f8f9c899e2009d5c8ba03f2a1d9aa4c905e9b26c1fffd"
        );
        assert_eq!(
            payload_hash(&crypto, &[1, 2, 3]).to_string(),
            "a0a0dfa08688a53aaa799ab662a06c9efe6a0c41050e6b023b1a6b6cb9ff320c"
        );
        // Actual body admission is exercised by availability worker controls. This owner
        // only defines exact payload/header preimages; changed or truncated bytes differ.
        assert_ne!(
            payload_hash(&crypto, &[1, 2, 3]),
            payload_hash(&crypto, &[1, 2, 4])
        );
        assert_ne!(
            payload_hash(&crypto, &[1, 2, 3]),
            payload_hash(&crypto, &[1, 2])
        );
        // Every header field is bound by the hash.
        let base = block_hash(&crypto, &golden_header());
        let variants = vec![
            BlockHeader {
                instance: h(0x12),
                ..golden_header()
            },
            BlockHeader {
                height: 8,
                ..golden_header()
            },
            BlockHeader {
                origin_view: 3,
                ..golden_header()
            },
            BlockHeader {
                parent_hash: h(0),
                ..golden_header()
            },
            BlockHeader {
                parent_result: h(0),
                ..golden_header()
            },
            BlockHeader {
                payload_hash: h(0),
                ..golden_header()
            },
            BlockHeader {
                availability_digest: h(0),
                ..golden_header()
            },
            BlockHeader {
                payload_len: 0,
                ..golden_header()
            },
            BlockHeader {
                proposer: 3,
                ..golden_header()
            },
            BlockHeader {
                skipped_leaders: vec![key(0xa1, 32)],
                ..golden_header()
            },
            BlockHeader {
                control_witness: crate::types::ControlWitness::try_from_slice(&[1]).unwrap(),
                ..golden_header()
            },
        ];
        for variant in variants {
            assert_ne!(block_hash(&crypto, &variant), base, "{variant:?}");
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn golden_certificate_digests() {
        let crypto = FakeCrypto::new();
        let qc = golden_qc();
        let qc_pre = qc_digest_preimage(&qc);
        assert_eq!(hex(&qc_pre), GOLDEN_QC_PREIMAGE);
        assert_eq!(
            qc_digest(&crypto, &qc).to_string(),
            "3829668bed13775ef7e2e7420bc08ad3cbe755ad39a2296086a081dc0ac39f38"
        );
        let tc = golden_tc();
        let tc_pre = tc_digest_preimage(&crypto, &tc);
        assert_eq!(hex(&tc_pre), GOLDEN_TC_PREIMAGE);
        assert_eq!(
            tc_digest(&crypto, &tc).to_string(),
            "8ec0784d9af32fb1f4d8da411972f008227c31fe01107e987452ff9313464df6"
        );
        let tc_none = TimeoutCert {
            high_pqc: None,
            ..golden_tc()
        };
        assert_eq!(*tc_digest_preimage(&crypto, &tc_none).last().unwrap(), 0);

        let att = att_digest_preimage(&crypto, Some(&tc), Some(&qc));
        assert_eq!(
            hex(&att),
            format!(
                "{}01{}01{}",
                hex(TAG_ATT),
                tc_digest(&crypto, &tc),
                qc_digest(&crypto, &qc)
            )
        );
        assert_eq!(
            hex(&att_digest_preimage(&crypto, None, None)),
            format!("{}0000", hex(TAG_ATT))
        );
        assert_eq!(
            att_digest(&crypto, Some(&tc), Some(&qc)).to_string(),
            "e4052eae246a84845a0effee595f8b4e30f6b139992463a8cc86afa049183260"
        );
        assert_eq!(
            att_digest(&crypto, None, None).to_string(),
            "21f1533cc89e45310d5124187eef8e5ff7dbeb6da41314863ecae13dd75a61a9"
        );
        // Every certificate field is bound.
        let base = qc_digest(&crypto, &qc);
        for variant in [
            Qc {
                kind: VoteKind::Commit,
                ..golden_qc()
            },
            Qc {
                instance: h(0),
                ..golden_qc()
            },
            Qc {
                height: 8,
                ..golden_qc()
            },
            Qc {
                view: 2,
                ..golden_qc()
            },
            Qc {
                block_hash: h(0),
                ..golden_qc()
            },
            Qc {
                result: h(0),
                ..golden_qc()
            },
            Qc {
                signers: Bitmap::from_indices(4, [0, 1, 2]).unwrap(),
                ..golden_qc()
            },
            Qc {
                agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
                ..golden_qc()
            },
        ] {
            assert_ne!(qc_digest(&crypto, &variant), base);
        }
        let base = tc_digest(&crypto, &tc);
        for variant in [
            TimeoutCert {
                view: 3,
                ..golden_tc()
            },
            TimeoutCert {
                entries: golden_tc().entries[..2].to_vec(),
                ..golden_tc()
            },
            TimeoutCert {
                high_pqc: None,
                ..golden_tc()
            },
            TimeoutCert {
                agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
                ..golden_tc()
            },
        ] {
            assert_ne!(tc_digest(&crypto, &variant), base);
        }
    }

    #[test]
    fn golden_committee_digest_seed_and_instance() {
        let crypto = FakeCrypto::new();
        let committee =
            Committee::new(vec![key(3, 32), key(1, 32), key(2, 32), key(4, 32)]).unwrap();
        let pre = committee_digest_preimage(&committee);
        assert_eq!(
            hex(&pre),
            format!(
                "{}00000004{}",
                hex(TAG_COMMITTEE),
                (1..=4u8).fold(String::new(), |mut out, b| {
                    out.push_str("0020");
                    out.push_str(&format!("{b:02x}").repeat(32));
                    out
                })
            )
        );
        assert_eq!(
            committee_digest(&crypto, &committee).to_string(),
            "3677e41d43338fa446798e0bf05dc89cff145f2d9e95ded090523820f756e42d"
        );
        assert_eq!(
            topology_seed(&crypto, &h(0x11), &crate::testing::TEST_EPOCH, &committee).to_string(),
            "de56c6059900ec08726ebd96a8db6f60a7a7c047286414d483186797706fed11"
        );
        assert_eq!(
            instance_id(&crypto, &h(0x77), b"taira", InstanceKind::Dataspace, 5).to_string(),
            "a64b7c6d3c7ab3f01588d915f24332a748953cafc6b7450e8cb00c92c9b98d54"
        );
        assert_ne!(
            instance_id(&crypto, &h(0x77), b"taira", InstanceKind::Global, 5),
            instance_id(&crypto, &h(0x77), b"taira", InstanceKind::Lane, 5)
        );
        assert_eq!(
            [
                InstanceKind::Global.byte(),
                InstanceKind::Dataspace.byte(),
                InstanceKind::Lane.byte()
            ],
            [0, 1, 2]
        );
    }

    #[test]
    fn instance_height_view_separate_domains() {
        // SR16/SR17: instance, height, view, kind and result change every signing preimage.
        let epoch = &crate::testing::TEST_EPOCH.id;
        // A Prepare/Commit preimage of block `h(2)`; the other fields vary per case.
        let vote = |kind, instance: u8, height, view, result: u8| {
            vote_preimage(kind, &h(instance), epoch, height, view, &h(2), &h(result))
        };
        let base = vote(VoteKind::Prepare, 1, 1, 1, 3);
        assert_ne!(base, vote(VoteKind::Prepare, 9, 1, 1, 3));
        assert_ne!(base, vote(VoteKind::Prepare, 1, 2, 1, 3));
        assert_ne!(base, vote(VoteKind::Prepare, 1, 1, 2, 3));
        assert_ne!(base, vote(VoteKind::Commit, 1, 1, 1, 3));
        assert_ne!(base, vote(VoteKind::Prepare, 1, 1, 1, 4));
        assert_ne!(
            tmo_preimage(&h(1), epoch, 1, 1, None),
            tmo_preimage(&h(9), epoch, 1, 1, None)
        );
        assert_ne!(
            prop_preimage(&h(1), epoch, 1, 1, &h(2), &h(3)),
            prop_preimage(&h(9), epoch, 1, 1, &h(2), &h(3))
        );
        // Kind bytes keep proposals, votes and timeouts apart.
        assert_ne!(
            prop_preimage(&h(1), epoch, 1, 1, &h(2), &h(3))[..13],
            vote(VoteKind::Prepare, 1, 1, 1, 3)[..13]
        );
    }

    const GOLDEN_QC_PREIMAGE: &str = "73756d65726167692f71630211111111111111111111111111111111111111111111111111111111111111110000000000000000e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e00000000000000007000000000000000122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333000000010b555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555";
    const GOLDEN_TC_PREIMAGE: &str = "73756d65726167692f746311111111111111111111111111111111111111111111111111111111111111110000000000000000e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0000000000000000700000000000000020000000300000000000000000101000000000000000100000003010000000000000001666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666013829668bed13775ef7e2e7420bc08ad3cbe755ad39a2296086a081dc0ac39f38";
}
