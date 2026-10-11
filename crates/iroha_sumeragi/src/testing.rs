//! Deterministic fake cryptography and harness keys for tests and the simulator (spec §13.1).
//!
//! - [`FakeCrypto`]: SHA-256 as `H`; signatures are `SIGNATURE_LEN` bytes derived from the key
//!   and message; aggregates are limb-wise sums modulo `2^256`, so they are order-independent
//!   like BLS and verifiable from the keys and messages alone.
//! - [`FakeSigner`] records the provenance `(key, preimage, signature)` of every signature it
//!   produces in an optional shared [`SignLog`]; [`FakeCrypto`] records the parts of every
//!   aggregate it forms. Oracles (O-SIGN, O-CERT) check certificates against this log, so a
//!   signature that verifies but was never produced by its key's signer is detected.
//! - [`FakeValidators`]: a committee of harness-held keys with helpers that sign votes,
//!   timeouts, proposals and build certificates (including deliberately malformed ones).

/// Explicit stationary scheduling context for protocol-unit fixtures.
/// Rotation harnesses replace bounds and identity from their declared schedule.
pub const TEST_EPOCH: crate::types::EpochConfig = crate::types::EpochConfig {
    da_layout: crate::availability::recommended_data_availability_layout(),
    id: crate::types::EpochId {
        epoch: 0,
        context: crate::types::Hash32([0xE0; 32]),
    },
    authority_generation: crate::types::Hash32([0xE1; 32]),
    first_height: 0,
    last_height: u64::MAX,
    leader_seed: crate::types::Hash32([0xE2; 32]),
};

/// Explicit successor identity for test schedules; no production caller derives authority here.
pub fn scheduled_epoch(
    epoch: u64,
    first_height: u64,
    last_height: u64,
) -> crate::types::EpochConfig {
    let mut context = TEST_EPOCH;
    context.id.epoch = epoch;
    context.first_height = first_height;
    context.last_height = last_height;
    if epoch != 0 || first_height != 0 || last_height != u64::MAX {
        let mut bytes = b"sumeragi/test-epoch".to_vec();
        bytes.extend_from_slice(&epoch.to_be_bytes());
        bytes.extend_from_slice(&first_height.to_be_bytes());
        bytes.extend_from_slice(&last_height.to_be_bytes());
        context.id.context = crate::types::Hash32(sha256(&bytes));
        context.authority_generation = context.id.context;
        bytes.push(1);
        context.leader_seed = crate::types::Hash32(sha256(&bytes));
    }
    context
}

/// Window slot after an applied cut, with no guessed next-epoch roster.
pub fn window_slot(
    active: &crate::types::HeightConfig,
    height: u64,
    config: crate::types::HeightConfig,
) -> crate::types::ConfigSlot {
    if active.epoch.contains(height) {
        crate::types::ConfigSlot::Ready(config)
    } else {
        crate::types::ConfigSlot::PendingBoundary {
            boundary_height: active.epoch.last_height,
            predecessor: active.epoch.id,
        }
    }
}

/// The atomic application result supplied by a simulated original execution.
pub fn applied_config(
    height: u64,
    current: &crate::types::HeightConfig,
    next: crate::types::HeightConfig,
    after_next: crate::types::HeightConfig,
) -> crate::types::AppliedConfig {
    if height == current.epoch.last_height {
        crate::types::AppliedConfig::Boundary { next, after_next }
    } else {
        crate::types::AppliedConfig::Continuation {
            after_next: window_slot(current, height + 2, after_next),
        }
    }
}

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use sha2::{Digest, Sha256};

use crate::{
    crypto::{Crypto, Signer},
    message::{BlockHeader, Proposal, Qc, TcEntry, TimeoutCert, TimeoutVote, Vote, VoteKind},
    preimage,
    types::{
        AggregateSignature, Bitmap, Committee, Hash32, PublicKey, SIGNATURE_LEN, Signature,
        ValidatorIndex, usize_of,
    },
};

/// SHA-256 (FIPS 180-4), the fake scheme's `H`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha256_chunks(&[data])
}

/// Hash the same canonical stream using the shared SHA-256 backend without concatenation.
fn sha256_chunks(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(*chunk);
    }
    hasher.finalize().into()
}

const TAG_FAKE_SIG: &[u8] = b"sumeragi/fake-sig";
const TAG_FAKE_PK: &[u8] = b"sumeragi/fake-pk";
const LIMBS: usize = SIGNATURE_LEN / 32;

/// The fake signature of `key` over `msg`: limb `i` is
/// `SHA-256("sumeragi/fake-sig" ‖ i ‖ kb(key) ‖ msg)`.
pub fn fake_sig(key: &PublicKey, msg: &[u8]) -> Signature {
    let mut out = [0u8; SIGNATURE_LEN];
    let mut kb = Vec::new();
    preimage::put_kb(&mut kb, key);
    for (limb, chunk) in out.chunks_exact_mut(32).enumerate() {
        let limb = [u8::try_from(limb).unwrap_or(u8::MAX)];
        // Keep the canonical key encoding and hash the same stream without a limb buffer.
        chunk.copy_from_slice(&sha256_chunks(&[TAG_FAKE_SIG, &limb, &kb, msg]));
    }
    Signature(out)
}

/// Limb-wise sum modulo `2^256` of `SIGNATURE_LEN`-byte big-endian values.
fn add_into(acc: &mut [u8; SIGNATURE_LEN], value: &[u8; SIGNATURE_LEN]) {
    for limb in 0..LIMBS {
        let mut carry = 0u16;
        for i in (limb * 32..(limb + 1) * 32).rev() {
            let sum = u16::from(acc[i]) + u16::from(value[i]) + carry;
            acc[i] = sum.to_be_bytes()[1];
            carry = sum >> 8;
        }
    }
}

/// Deterministic fake [`Crypto`] with optional aggregate provenance recording.
#[derive(Clone, Debug, Default)]
pub struct FakeCrypto {
    log: Option<SignLog>,
}

impl FakeCrypto {
    /// A fake scheme that records nothing.
    pub fn new() -> Self {
        Self { log: None }
    }

    /// A fake scheme that records the parts of every aggregate in `log`.
    pub fn with_log(log: SignLog) -> Self {
        Self { log: Some(log) }
    }

    /// The provenance log, if any.
    pub fn log(&self) -> Option<&SignLog> {
        self.log.as_ref()
    }

    fn sum(sigs: &[Signature]) -> AggregateSignature {
        let mut acc = [0u8; SIGNATURE_LEN];
        for sig in sigs {
            add_into(&mut acc, &sig.0);
        }
        AggregateSignature(acc)
    }
}

impl Crypto for FakeCrypto {
    fn hash_chunks(&self, chunks: &[&[u8]]) -> Hash32 {
        Hash32(sha256_chunks(chunks))
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
        fake_sig(pk, msg) == *sig
    }

    fn aggregate(&self, sigs: &[Signature]) -> AggregateSignature {
        let agg = Self::sum(sigs);
        if let Some(log) = &self.log {
            log.record_aggregate(agg, sigs.to_vec());
        }
        agg
    }

    fn verify_aggregate(&self, pks: &[&PublicKey], msg: &[u8], agg: &AggregateSignature) -> bool {
        if pks.is_empty() {
            return false;
        }
        let expected: Vec<Signature> = pks.iter().map(|pk| fake_sig(pk, msg)).collect();
        Self::sum(&expected) == *agg
    }

    fn verify_aggregate_multi(
        &self,
        groups: &[(Vec<&PublicKey>, Vec<u8>)],
        agg: &AggregateSignature,
    ) -> bool {
        if groups.is_empty() || groups.iter().any(|(pks, _)| pks.is_empty()) {
            return false;
        }
        let expected: Vec<Signature> = groups
            .iter()
            .flat_map(|(pks, msg)| pks.iter().map(move |pk| fake_sig(pk, msg)))
            .collect();
        Self::sum(&expected) == *agg
    }
}

/// One signature produced by a [`FakeSigner`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRecord {
    /// Signing key.
    pub key: PublicKey,
    /// Signed preimage.
    pub preimage: Vec<u8>,
    /// Produced signature.
    pub sig: Signature,
}

#[derive(Debug, Default)]
struct LogInner {
    signatures: Vec<SignRecord>,
    signed: BTreeSet<(PublicKey, Vec<u8>)>,
    aggregates: BTreeMap<AggregateSignature, Vec<Signature>>,
}

/// Shared provenance log of every genuine signature and every aggregate formed.
#[derive(Clone, Debug, Default)]
pub struct SignLog {
    inner: Arc<Mutex<LogInner>>,
}

impl SignLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, LogInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Record a genuine signature.
    pub fn record_signature(&self, key: &PublicKey, preimage: &[u8], sig: Signature) {
        let mut inner = self.lock();
        inner.signed.insert((key.clone(), preimage.to_vec()));
        inner.signatures.push(SignRecord {
            key: key.clone(),
            preimage: preimage.to_vec(),
            sig,
        });
    }

    /// Record the parts of an aggregate.
    pub fn record_aggregate(&self, agg: AggregateSignature, parts: Vec<Signature>) {
        self.lock().aggregates.insert(agg, parts);
    }

    /// Every recorded signature in production order.
    pub fn signatures(&self) -> Vec<SignRecord> {
        self.lock().signatures.clone()
    }

    /// Every recorded signature of `key` in production order.
    pub fn signatures_by(&self, key: &PublicKey) -> Vec<SignRecord> {
        self.lock()
            .signatures
            .iter()
            .filter(|record| &record.key == key)
            .cloned()
            .collect()
    }

    /// Number of recorded signatures.
    pub fn len(&self) -> usize {
        self.lock().signatures.len()
    }

    /// Whether no signature was recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether `key`'s signer genuinely signed `preimage`.
    pub fn was_signed(&self, key: &PublicKey, preimage: &[u8]) -> bool {
        self.lock()
            .signed
            .contains(&(key.clone(), preimage.to_vec()))
    }

    /// The parts of an aggregate formed by a logging [`FakeCrypto`].
    pub fn aggregate_parts(&self, agg: &AggregateSignature) -> Option<Vec<Signature>> {
        self.lock().aggregates.get(agg).cloned()
    }

    /// O-CERT for a QC: every signer of `committee = C_{qc.height}` in the bitmap genuinely
    /// signed the vote preimage.
    pub fn qc_provenance_ok(&self, committee: &Committee, qc: &Qc) -> bool {
        let preimage = qc.preimage();
        committee
            .keys_of(&qc.signers)
            .is_some_and(|keys| keys.iter().all(|key| self.was_signed(key, &preimage)))
    }

    /// O-CERT for a TC: every entry's signer genuinely signed its timeout preimage, and the
    /// attached `PrepareQC` (if any) passes [`SignLog::qc_provenance_ok`].
    pub fn tc_provenance_ok(&self, committee: &Committee, tc: &TimeoutCert) -> bool {
        let entries_ok = tc.entries.iter().all(|entry| {
            committee.get(entry.signer).is_some_and(|key| {
                self.was_signed(
                    key,
                    &preimage::tmo_preimage(&tc.instance, &tc.epoch, tc.height, tc.view, entry.hq),
                )
            })
        });
        entries_ok
            && tc
                .high_pqc
                .as_ref()
                .is_none_or(|qc| self.qc_provenance_ok(committee, qc))
    }
}

/// A deterministic fake signing key that records its signatures.
#[derive(Clone, Debug)]
pub struct FakeSigner {
    key: PublicKey,
    log: Option<SignLog>,
}

impl FakeSigner {
    /// The signer whose 32-byte key is `SHA-256("sumeragi/fake-pk" ‖ seed)`.
    pub fn from_seed(seed: &[u8], log: Option<SignLog>) -> Self {
        let mut input = TAG_FAKE_PK.to_vec();
        input.extend_from_slice(seed);
        let key = PublicKey::new(sha256(&input).to_vec()).expect("a 32-byte key is well formed");
        Self { key, log }
    }

    /// A signer for an explicit key.
    pub fn with_key(key: PublicKey, log: Option<SignLog>) -> Self {
        Self { key, log }
    }
}

impl Signer for FakeSigner {
    fn public_key(&self) -> &PublicKey {
        &self.key
    }

    fn sign(&self, preimage: &[u8]) -> Signature {
        let sig = fake_sig(&self.key, preimage);
        if let Some(log) = &self.log {
            log.record_signature(&self.key, preimage, sig);
        }
        sig
    }
}

/// A committee of harness-held fake keys (canonical order) with signing helpers.
#[derive(Clone, Debug)]
pub struct FakeValidators {
    /// Fake crypto (logging into the same log as the signers, if any).
    pub crypto: FakeCrypto,
    /// The committee.
    pub committee: Committee,
    signers: Vec<FakeSigner>,
}

// Harness helpers mirror the protocol's tuples `(kind, I, h, v, bh, R)`.
#[allow(clippy::too_many_arguments)]
impl FakeValidators {
    /// `n` keys derived from `(seed, i)`; `log` records every signature and aggregate.
    pub fn new(n: usize, seed: u64, log: Option<SignLog>) -> Self {
        let mut signers: Vec<FakeSigner> = (0..n)
            .map(|i| {
                let mut s = seed.to_be_bytes().to_vec();
                s.extend_from_slice(&u64::try_from(i).unwrap_or(u64::MAX).to_be_bytes());
                FakeSigner::from_seed(&s, log.clone())
            })
            .collect();
        signers.sort_by(|a, b| a.key.cmp(&b.key));
        let committee = Committee::new(signers.iter().map(|s| s.key.clone()).collect())
            .unwrap_or_else(|e| panic!("fake committee: {e}"));
        let crypto = log.map_or_else(FakeCrypto::new, FakeCrypto::with_log);
        Self {
            crypto,
            committee,
            signers,
        }
    }

    /// The signer of canonical index `index`.
    pub fn signer(&self, index: ValidatorIndex) -> &FakeSigner {
        &self.signers[usize_of(index)]
    }

    /// All signers in canonical order.
    pub fn signers(&self) -> &[FakeSigner] {
        &self.signers
    }

    /// The key of canonical index `index`.
    pub fn key(&self, index: ValidatorIndex) -> PublicKey {
        self.signer(index).key.clone()
    }

    /// A signed vote under the fixture committee.
    pub fn vote(
        &self,
        kind: VoteKind,
        signer: ValidatorIndex,
        instance: &Hash32,
        height: u64,
        view: u64,
        block_hash: &Hash32,
        result: &Hash32,
    ) -> Vote {
        let msg = preimage::vote_preimage(
            kind,
            instance,
            &crate::testing::TEST_EPOCH.id,
            height,
            view,
            block_hash,
            result,
        );
        Vote {
            epoch: crate::testing::TEST_EPOCH.id,
            kind,
            instance: *instance,
            height,
            view,
            block_hash: *block_hash,
            result: *result,
            signer,
            sig: self.signer(signer).sign(&msg),
        }
    }

    /// A certificate signed by exactly the fixture signers, including invalid quorum counts.
    pub fn qc(
        &self,
        kind: VoteKind,
        instance: &Hash32,
        height: u64,
        view: u64,
        block_hash: &Hash32,
        result: &Hash32,
        signers: &[ValidatorIndex],
    ) -> Qc {
        let msg = preimage::vote_preimage(
            kind,
            instance,
            &crate::testing::TEST_EPOCH.id,
            height,
            view,
            block_hash,
            result,
        );
        let mut sorted = signers.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let sigs: Vec<Signature> = sorted
            .iter()
            .map(|index| self.signer(*index).sign(&msg))
            .collect();
        Qc {
            epoch: crate::testing::TEST_EPOCH.id,
            kind,
            instance: *instance,
            height,
            view,
            block_hash: *block_hash,
            result: *result,
            signers: Bitmap::from_indices(self.committee.n(), sorted.iter().copied())
                .unwrap_or_else(|| Bitmap::new(self.committee.n())),
            agg_sig: self.crypto.aggregate(&sigs),
        }
    }

    /// A signed timeout vote carrying `high_pqc`.
    pub fn timeout(
        &self,
        signer: ValidatorIndex,
        instance: &Hash32,
        height: u64,
        view: u64,
        high_pqc: Option<Qc>,
    ) -> TimeoutVote {
        let hq = high_pqc.as_ref().map(|qc| qc.view);
        let msg =
            preimage::tmo_preimage(instance, &crate::testing::TEST_EPOCH.id, height, view, hq);
        TimeoutVote {
            epoch: crate::testing::TEST_EPOCH.id,
            instance: *instance,
            height,
            view,
            high_pqc,
            signer,
            sig: self.signer(signer).sign(&msg),
        }
    }

    /// A TC from exactly `entries` (signer, carried `PrepareQC`), any number: entries sorted by
    /// index, `high_pqc` = the `PrepareQC` of the maximal `hq` (lowest index among equals).
    pub fn tc(
        &self,
        instance: &Hash32,
        height: u64,
        view: u64,
        entries: &[(ValidatorIndex, Option<Qc>)],
    ) -> TimeoutCert {
        let mut timeouts: Vec<TimeoutVote> = entries
            .iter()
            .map(|(signer, qc)| self.timeout(*signer, instance, height, view, qc.clone()))
            .collect();
        timeouts.sort_by_key(|t| t.signer);
        let high_pqc = timeouts
            .iter()
            .filter(|t| t.high_pqc.is_some())
            .max_by(|a, b| a.hq().cmp(&b.hq()).then(b.signer.cmp(&a.signer)))
            .and_then(|t| t.high_pqc.clone());
        let sigs: Vec<Signature> = timeouts.iter().map(|t| t.sig).collect();
        TimeoutCert {
            epoch: crate::testing::TEST_EPOCH.id,
            instance: *instance,
            height,
            view,
            entries: timeouts
                .iter()
                .map(|t| TcEntry {
                    signer: t.signer,
                    hq: t.hq(),
                })
                .collect(),
            agg_sig: self.crypto.aggregate(&sigs),
            high_pqc,
        }
    }

    /// A proposal signed by `leader` over `prop_preimage(height, view, bh, ad)`.
    pub fn proposal(
        &self,
        leader: ValidatorIndex,
        instance: &Hash32,
        height: u64,
        view: u64,
        header: BlockHeader,
        justify: Option<TimeoutCert>,
        parent_qc: Option<Qc>,
    ) -> Proposal {
        let bh = preimage::block_hash(&self.crypto, &header);
        let ad = preimage::att_digest(&self.crypto, justify.as_ref(), parent_qc.as_ref());
        let msg = preimage::prop_preimage(
            instance,
            &crate::testing::TEST_EPOCH.id,
            height,
            view,
            &bh,
            &ad,
        );
        Proposal {
            instance: *instance,
            height,
            view,
            header,
            justify,
            parent_qc,
            sig: self.signer(leader).sign(&msg),
        }
    }
}

/// Construct fixture custody through the real signed RS16 author worker.
/// Invalid carrier tests must mutate the untrusted wire record, never this opaque output.
pub fn author_body(
    header: crate::message::BlockHeader,
    payload: &[u8],
    config: &crate::types::HeightConfig,
    budget: &iroha_allocation::AllocationBudget,
    crypto: &dyn crate::crypto::Crypto,
    signer: &dyn crate::crypto::Signer,
) -> crate::availability::AvailableBody {
    let mut bytes = crate::availability::PayloadBytes::from_untrusted(payload.to_vec()).unwrap();
    bytes.admit(budget).unwrap();
    let instance = header.instance;
    crate::availability::PayloadAuthoring::new(header, bytes)
        .complete(instance, config, budget, crypto, signer)
        .unwrap_or_else(|(_, error)| panic!("fixture authoring failed: {error:?}"))
        .body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let million = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha256(&million)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        // Block-boundary lengths.
        for len in [55usize, 56, 63, 64, 65, 119, 120] {
            assert_eq!(sha256(&vec![0x61; len]).len(), 32);
        }
    }

    #[test]
    fn chunked_hash_preserves_every_split_and_empty_chunk() {
        let crypto = FakeCrypto::new();
        for len in [0, 1, 15, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 257] {
            let bytes: Vec<_> = (0..len)
                .map(|i| u8::try_from((i * 37) % 256).unwrap())
                .collect();
            let expected = crypto.hash(&bytes);
            for split in 0..=len {
                assert_eq!(
                    crypto.hash_chunks(&[&[], &bytes[..split], &[], &bytes[split..], &[]]),
                    expected
                );
            }
            let singles: Vec<_> = bytes.chunks(1).collect();
            assert_eq!(crypto.hash_chunks(&singles), expected);
        }
    }

    #[test]
    fn fake_signature_chunks_match_canonical_bytes_at_padding_boundaries() {
        for key_len in [0, 1, 32, 128, 129] {
            // Include malformed keys: fake cryptography must retain its original byte relation.
            let key = PublicKey::unchecked(vec![0xA5; key_len]);
            let mut kb = Vec::new();
            preimage::put_kb(&mut kb, &key);
            let prefix_len = b"sumeragi/fake-sig".len() + 1 + kb.len();
            let mut message_lengths = vec![0];
            for remainder in [0, 1, 55, 56, 63] {
                let len = (remainder + 64 - prefix_len % 64) % 64;
                message_lengths.extend([len, len + 64]);
            }
            for message_len in message_lengths {
                let message: Vec<_> = (0..message_len)
                    .map(|i| u8::try_from((i * 37) % 256).unwrap())
                    .collect();
                let mut expected = [0_u8; SIGNATURE_LEN];
                for (limb, chunk) in expected.chunks_exact_mut(32).enumerate() {
                    // The original concatenated stream is the byte oracle, not a second verifier.
                    let mut input = b"sumeragi/fake-sig".to_vec();
                    input.push(u8::try_from(limb).unwrap());
                    input.extend_from_slice(&kb);
                    input.extend_from_slice(&message);
                    chunk.copy_from_slice(&sha256(&input));
                }
                assert_eq!(
                    fake_sig(&key, &message),
                    Signature(expected),
                    "canonical fake-signature bytes changed for key length {key_len}, message length {message_len}"
                );
            }
        }
    }

    #[test]
    fn sha256_known_answers_preserve_segmented_padding_boundaries() {
        // Independent fixed SHA-256 answers for the deterministic byte pattern below.
        // The digest table is not produced by the backend under test.
        for (len, expected) in [
            (
                0,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                1,
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            ),
            (
                15,
                "289e69682ffe652c2ebd30cd40a24fbafd95559c44c3fa33ff5118ca28e72c3b",
            ),
            (
                55,
                "3b453d648ef01a1ddbc30ef4cee00724bb53fe40b38a08c04cfd6009235c09bf",
            ),
            (
                56,
                "a5f1426b20451b15d1c92aef1b27b36b038d13a77874409d73889c02fa1ca778",
            ),
            (
                63,
                "b728e1a944ecf6d47629afefa1656cbe11fd7bf23145fcba144af99ea5ec14f5",
            ),
            (
                64,
                "17ff3615c8f2285b470ee569e15b37503eae49e36882b63ccc1aceb055d7f082",
            ),
            (
                65,
                "f747a3be9b4a85941804d77e333783b22f194e6252b37570fd51bc2bc7886a57",
            ),
            (
                119,
                "82de88568c056a67ab49f9f8408249a8ff036b4294485b27d1f5d5de43d90759",
            ),
            (
                120,
                "e207dc7fa98501df87f645ccd4d9864be6d3f8f96417ff84e54eb1fa40452b98",
            ),
            (
                127,
                "1b6e94ae18eff1dbc2ee77615845eaf55a88b19cb3a867179a0cfe90789943cf",
            ),
            (
                128,
                "44d942056dd7041cfe6a1bbcb1a1f3afc385bb951b5efd787e71f514f29e1ddc",
            ),
            (
                129,
                "a14a45b30d8e4eca06366744bea6597da4da3404e76a29019874cfec816bc586",
            ),
            (
                257,
                "73ea4e762e2440c42864b5db632d756001f14f43641692c8b142d912b6e6dc95",
            ),
        ] {
            let bytes: Vec<_> = (0..len)
                .map(|i| u8::try_from((i * 37) % 256).unwrap())
                .collect();
            assert_eq!(hex(&sha256(&bytes)), expected, "length {len}");
            for split in 0..=len {
                assert_eq!(
                    hex(&sha256_chunks(&[
                        &[],
                        &bytes[..split],
                        &[],
                        &bytes[split..],
                        &[]
                    ])),
                    expected,
                    "length {len}, split {split}"
                );
            }
            let singles: Vec<_> = bytes.chunks(1).collect();
            assert_eq!(hex(&sha256_chunks(&singles)), expected);
        }
    }

    #[test]
    fn fake_signatures_preserve_fixed_key_and_message_known_answers() {
        // Independent answers bind the original tag, limb, be16 key length and raw key.
        // Total preimage residues cover 55, 56, 63, 0 and 1 modulo the SHA block size.
        for (key_len, message_len, expected) in [
            (
                0,
                35,
                "cb8b9f5afe9ba52f3fb602edd6d5beb3f6956a121e061fc14b0dfd9289cf6157308a5239fc64715477fff9b92128935b8af878e2e832e5519ab8c07d6bd8967ccfd8005d812c4bc6f0e820c1213b11041490e667df1e057be8d00d0c813b311f",
            ),
            (
                1,
                35,
                "28f3aa8d3af40bb64a23c5d5b455a8152c5171fb44b16664079196e6e008c5456d86395ea6c4edcdcd749c53e27f4b389834954278ff09b53e94bcc13a8f739151fbe9075f106610abf2f6c3d7d31c61e891c1bb94ea0ed85caf9350362a1358",
            ),
            (
                32,
                11,
                "18202a85e8347ada731eda51e11fbe2dc61898469f33cb32ad897740a3bcd9a4db04907842fe5c3146f549a2b0e92f3677247544e1187f484f525bf5a8a7f0042a2ac544f0705127760e1fbb652f9b7b2dd0a939658100c6cc6117189bcf21f3",
            ),
            (
                128,
                44,
                "a251d9cd10f259767a3b99d9d87e0adcc2f7e25c3240fc635ecc2db38384e306b95c52e886ba94b371799cbf5caef47a6163679119bfd0f38605cd6c3d8688491dc110f52d3dc0f44f7ee1cf40f2830c15d35b8a574d76d502cf95e147859849",
            ),
            (
                129,
                44,
                "94bb1dce339f5cb50825bd34e4b3c145e07b32c23051eb8e92895f57dd82c2b2a3b9f778d24204bdf534f6ad666fbe6ffb625bd39534f3b00a9e47301a645ef5ac0d74be8cfd08481ac9dfe62ccf799a41c96c477d80f312118fd4a1f9683067",
            ),
        ] {
            // Malformed fixture keys still have the same canonical fake-signature bytes.
            let key = PublicKey::unchecked(vec![0xA5; key_len]);
            let message: Vec<_> = (0..message_len)
                .map(|i| u8::try_from((i * 37) % 256).unwrap())
                .collect();
            assert_eq!(
                hex(&fake_sig(&key, &message).0),
                expected,
                "key length {key_len}, message length {message_len}"
            );
        }
    }

    #[test]
    fn fake_signatures_and_aggregates() {
        let crypto = FakeCrypto::new();
        let a = FakeSigner::from_seed(b"a", None);
        let b = FakeSigner::from_seed(b"b", None);
        assert_eq!(a.public_key().as_bytes().len(), 32);
        let sig_a = a.sign(b"m");
        let sig_b = b.sign(b"m");
        assert!(crypto.verify(a.public_key(), b"m", &sig_a));
        assert!(!crypto.verify(b.public_key(), b"m", &sig_a));
        assert!(!crypto.verify(a.public_key(), b"n", &sig_a));
        let agg = crypto.aggregate(&[sig_a, sig_b]);
        assert_eq!(agg, crypto.aggregate(&[sig_b, sig_a]), "order independent");
        assert!(crypto.verify_aggregate(&[a.public_key(), b.public_key()], b"m", &agg));
        assert!(!crypto.verify_aggregate(&[a.public_key()], b"m", &agg));
        assert!(!crypto.verify_aggregate(&[], b"m", &crypto.aggregate(&[])));
        let sig_c = b.sign(b"other");
        let multi = crypto.aggregate(&[sig_a, sig_c]);
        assert!(crypto.verify_aggregate_multi(
            &[
                (vec![a.public_key()], b"m".to_vec()),
                (vec![b.public_key()], b"other".to_vec())
            ],
            &multi
        ));
        assert!(!crypto.verify_aggregate_multi(
            &[
                (vec![a.public_key()], b"m".to_vec()),
                (vec![b.public_key()], b"m".to_vec())
            ],
            &multi
        ));
        assert!(!crypto.verify_aggregate_multi(&[], &multi));
        assert!(!crypto.verify_aggregate_multi(&[(vec![], b"m".to_vec())], &multi));
        // Carries propagate within a limb.
        let mut acc = [0xffu8; SIGNATURE_LEN];
        let mut one = [0u8; SIGNATURE_LEN];
        one[31] = 1;
        add_into(&mut acc, &one);
        assert!(acc[..32].iter().all(|b| *b == 0));
        assert!(acc[32..].iter().all(|b| *b == 0xff));
    }

    #[test]
    fn provenance_log() {
        let log = SignLog::new();
        assert!(log.is_empty());
        let signer = FakeSigner::from_seed(b"x", Some(log.clone()));
        let crypto = FakeCrypto::with_log(log.clone());
        assert!(crypto.log().is_some());
        let sig = signer.sign(b"hello");
        assert_eq!(log.len(), 1);
        assert!(log.was_signed(signer.public_key(), b"hello"));
        assert!(!log.was_signed(signer.public_key(), b"bye"));
        // A forged-but-verifying signature (computed without the signer) is not in the log.
        let forged = fake_sig(signer.public_key(), b"bye");
        assert!(crypto.verify(signer.public_key(), b"bye", &forged));
        assert!(!log.was_signed(signer.public_key(), b"bye"));
        let agg = crypto.aggregate(&[sig]);
        assert_eq!(log.aggregate_parts(&agg), Some(vec![sig]));
        assert_eq!(log.signatures_by(signer.public_key()).len(), 1);
        assert_eq!(log.signatures()[0].preimage, b"hello".to_vec());
        let other = FakeSigner::with_key(PublicKey::new(vec![1; 32]).unwrap(), None);
        other.sign(b"unlogged");
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn harness_certificates_and_provenance() {
        let log = SignLog::new();
        let v = FakeValidators::new(4, 7, Some(log.clone()));
        let i = Hash32([1; 32]);
        for index in 0..4 {
            assert_eq!(v.committee.index_of(&v.key(index)), Some(index));
        }
        assert_eq!(v.signers().len(), 4);
        let qc = v.qc(
            VoteKind::Prepare,
            &i,
            3,
            1,
            &Hash32([2; 32]),
            &Hash32([3; 32]),
            &[2, 0, 2],
        );
        assert_eq!(qc.signers.ones().collect::<Vec<_>>(), vec![0, 2]);
        assert!(log.qc_provenance_ok(&v.committee, &qc));
        // A certificate whose aggregate was computed without the signers fails provenance.
        let unlogged = FakeValidators::new(4, 7, None);
        let forged = unlogged.qc(
            VoteKind::Commit,
            &i,
            3,
            1,
            &Hash32([2; 32]),
            &Hash32([3; 32]),
            &[1, 3],
        );
        assert!(!log.qc_provenance_ok(&v.committee, &forged));
        let tc = v.tc(&i, 3, 2, &[(3, Some(qc.clone())), (1, None)]);
        assert_eq!(tc.entries[0].signer, 1);
        assert_eq!(tc.high_pqc, Some(qc));
        assert!(log.tc_provenance_ok(&v.committee, &tc));
        let forged_tc = unlogged.tc(&i, 3, 2, &[(0, None)]);
        assert!(!log.tc_provenance_ok(&v.committee, &forged_tc));
        let bad_index = TimeoutCert {
            entries: vec![TcEntry {
                signer: 9,
                hq: None,
            }],
            ..forged_tc
        };
        assert!(!log.tc_provenance_ok(&v.committee, &bad_index));
    }
}
