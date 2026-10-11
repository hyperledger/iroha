//! Same-tape status and delivery-evidence transcripts for Archive.
//!
//! These bindings do not authorize a lineage or a receipt signature. The owning
//! A relation must join its total incoming Omega decoder/verifier verdict and
//! Q receipt-signature verdict, and retain both accumulator obligations.

use ff::{Field, PrimeField};
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{
    Bit, UintChip, Word, WordHasher,
    bytes::{
        PBytes, chunk_segments,
        tape::{ByteRun, SegmentSpec},
    },
};

use super::{
    ObjectKind, SignedObjectCells,
    credential::CredentialCells,
    credit_opening::CreditOpeningCells,
    decode_atom,
    predicates::{all, equal, is_constant, nonzero},
    receipt::{self, ReceiptContext},
    request::RequestCells,
    schema::Atom,
};
use crate::{
    a_relation::LineagePublicCells,
    operation_relation::incoming_statement::{
        DynamicStatementCells, IncomingStatementCells, StatementView,
    },
};
use iroha_plonk_recursion::obligation::ledger::Variant;

/// Original sources of the Receive-package form of Credited.
pub struct ReceiveEvidenceInputs<'a> {
    /// Total Receive statement linked to its incoming sigma Q slot.
    pub statement: &'a IncomingStatementCells,
    /// Receipt authenticated under the Request's quoted receiver key.
    pub receipt: &'a SignedObjectCells,
    /// Payer's held Request, already bound to its retained Payment.
    pub request: &'a RequestCells,
    /// Original receiver credential quoted in the Request.
    pub receiver: &'a CredentialCells,
    /// Pinned scheme relation identity of the payer's current lineage.
    pub relation: &'a [Word<Fp>; 2],
    /// Pinned Advance provider identity.
    pub provider: &'a [Word<Fp>; 2],
    /// Digest of the exact retained Payment.
    pub payment_digest: &'a Word<Fp>,
    /// Same-tape `P_bytes(kgwstep1, LE32 sigma.len || sigma)` bound to the
    /// incoming Q slot. Its key selection uses the Request's recorded blacklist.
    pub proof_digest: &'a Word<Fp>,
}

/// Receive-package digest with its total retained-Request/Payment binding.
#[derive(Clone, Debug)]
pub struct ReceiveEvidenceCells {
    digest: Word<Fp>,
    valid: Bit<Fp>,
}
impl ReceiveEvidenceCells {
    /// Bind the evidence without requiring the receiver's current credential
    /// digest to equal its original Request credential. The receipt signature,
    /// sigma proof, and their mandatory total decoder bits remain Q obligations.
    ///
    /// # Errors
    /// Non-Receive statement, wrong receipt class or layout failure.
    pub fn bind(
        uint: &mut UintChip<'_, Fp>,
        hash: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        inputs: &ReceiveEvidenceInputs<'_>,
    ) -> Result<Self, Error> {
        if !matches!(
            inputs.statement.variant(),
            Variant::Receive | Variant::ReceiveRenewed
        ) || inputs.receipt.kind() != ObjectKind::Receipt
        {
            return Err(Error::Synthesis);
        }
        let statement = inputs.statement.fields();
        let mut checks = vec![
            inputs.statement.valid().clone(),
            quoted_receiver(uint, region, inputs.request, inputs.receiver)?,
        ];
        for (left, right) in [
            (&statement[1..3], inputs.relation.as_slice()),
            (
                &statement[3..5],
                inputs.request.object().identifier(1)?.as_slice(),
            ),
            (
                &statement[5..7],
                inputs.request.object().identifier(2)?.as_slice(),
            ),
            (
                &statement[18..20],
                inputs.request.object().identifier(3)?.as_slice(),
            ),
        ] {
            checks.push(equal(uint.glue(), region, left, right)?);
        }
        for (actual, expected) in [
            (&statement[17], inputs.request.credit_id()),
            (&statement[20], inputs.request.object().word(9)?),
        ] {
            checks.push(uint.glue().is_equal(region, actual, expected)?);
        }
        checks.push(receipt::bind(
            uint,
            hash,
            region,
            inputs.receipt,
            &ReceiptContext {
                wallet: inputs.request.object().identifier(5)?,
                provider: inputs.provider,
                statement: inputs.statement,
                proof_digest: inputs.proof_digest,
                payment_digest: inputs.payment_digest,
            },
        )?);
        let digest = hash.hash_words(
            region,
            u64::from_le_bytes(*b"kgwpkg_1"),
            &[
                inputs.statement.digest().clone(),
                inputs.proof_digest.clone(),
                inputs.receipt.digest().clone(),
            ],
        )?;
        let valid = all(uint.glue(), region, &checks)?;
        Ok(Self { digest, valid })
    }
    /// Recomputed package digest for the Credited transcript's evidence field.
    pub const fn digest(&self) -> &Word<Fp> {
        &self.digest
    }
    /// Semantic verdict that must join the sigma/receipt Q verdicts.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }
}

fn quoted_receiver(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    request: &RequestCells,
    receiver: &CredentialCells,
) -> Result<Bit<Fp>, Error> {
    let mut checks = vec![request.valid().clone(), receiver.valid().clone()];
    for (request_index, credential_index) in [(1, 1), (2, 2), (5, 3), (6, 4)] {
        checks.push(equal(
            uint.glue(),
            region,
            request.object().identifier(request_index)?,
            receiver.object().identifier(credential_index)?,
        )?);
    }
    checks.push(uint.glue().is_equal(
        region,
        request.object().word(8)?,
        receiver.object().digest(),
    )?);
    all(uint.glue(), region, &checks)
}

/// Exact sources of a `CreditStatus` transcript and its retained-payment binding.
pub struct StatusInputs<'a> {
    /// Arbitrary-operation statement of the receiver's folded head.
    pub statement: &'a DynamicStatementCells,
    /// Receipt for that head; its signature must be checked under the lineage key.
    pub receipt: &'a SignedObjectCells,
    /// Same public fields consumed by the incoming Omega verifier. A total byte
    /// decoder may export its fixed valid dummy only with a mandatory false bit.
    pub lineage: &'a LineagePublicCells,
    /// `P_bytes(kgwlin_1, public transcript || transported Omega)` from the exact
    /// incoming proof tape, including the public bytes. This is not `D_A`.
    pub lineage_digest: &'a Word<Fp>,
    /// The head's carried proof digest, authenticated by its receipt.
    pub proof_digest: &'a Word<Fp>,
    /// Membership evidence in the same lineage's credit-digest root.
    pub opening: &'a CreditOpeningCells,
    /// Pinned Advance provider identity.
    pub provider: &'a [Word<Fp>; 2],
    /// Pinned scheme relation identity of the payer's current lineage.
    pub relation: &'a [Word<Fp>; 2],
    /// Payer's retained Request, already bound to its retained Payment.
    pub request: &'a RequestCells,
    /// Original receiver credential quoted by that Request. Renewal does not
    /// require its digest to equal the receiver head's current credential.
    pub receiver: &'a CredentialCells,
    /// Digest of the payer's exact retained Payment.
    pub payment_digest: &'a Word<Fp>,
}

/// Exact status digest and the total body/head/retained-payment predicate.
#[derive(Clone, Debug)]
pub struct StatusCells {
    digest: Word<Fp>,
    valid: Bit<Fp>,
}
impl StatusCells {
    /// `LE16 version` followed by five canonical field digests.
    pub const BYTES: usize = 162;
    /// Whole-transcript `P_bytes` chunks.
    pub fn primary_segments() -> Vec<usize> {
        chunk_segments(0, Self::BYTES)
    }
    /// Version and exact canonical field halves.
    pub fn secondary_segments() -> Vec<SegmentSpec> {
        segments(2, 5)
    }

    /// Decode the proof digest carried by the original Status transcript.
    ///
    /// This field has no proof preimage in `CreditStatus`. The receipt's copy is
    /// a separate semantic comparison: deriving this value from that receipt
    /// would incorrectly turn an original mismatch into a hard rejection.
    /// Noncanonical bytes select zero; [`Self::from_run`] on the same tape must
    /// still contribute its mandatory false structural verdict.
    /// # Errors
    /// Wrong transcript size/segments or layout failure.
    pub fn carried_proof_digest(
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        run: &ByteRun<Fp>,
    ) -> Result<Word<Fp>, Error> {
        if run.len() != Self::BYTES {
            return Err(Error::Synthesis);
        }
        let (words, _) = decode_atom(uint, region, run, 34, Atom::Field)?;
        words.into_iter().next().ok_or(Error::Synthesis)
    }

    /// Bind the original status transcript to all component tapes and identities.
    /// Malformed bytes and semantic mismatches return false while the digest
    /// still covers those original bytes. Each canonical component address is
    /// hard-bound to its supplied preimage: substituting a statement, receipt,
    /// proof carrier or opening cannot manufacture a no-op. Incoming proof and
    /// signature validity remain separate mandatory conjuncts.
    ///
    /// # Errors
    /// Wrong fixed transcript/receipt class, substituted canonical content
    /// address or layout failure. Noncanonical address bytes remain total false.
    pub fn from_run(
        uint: &mut UintChip<'_, Fp>,
        hash: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        run: &ByteRun<Fp>,
        inputs: &StatusInputs<'_>,
    ) -> Result<Self, Error> {
        if run.len() != Self::BYTES || inputs.receipt.kind() != ObjectKind::Receipt {
            return Err(Error::Synthesis);
        }
        let (digest, mut checks) = transcript(
            uint,
            hash,
            region,
            run,
            2,
            None,
            &[
                inputs.statement.digest(),
                inputs.proof_digest,
                inputs.receipt.digest(),
                inputs.lineage_digest,
                inputs.opening.digest(),
            ],
            0,
            u64::from_le_bytes(*b"kgwcsts1"),
        )?;
        checks.extend([
            inputs.statement.valid().clone(),
            quoted_receiver(uint, region, inputs.request, inputs.receiver)?,
        ]);
        let head = inputs.lineage.fields();
        let statement = inputs.statement.fields();
        for (left, right) in [
            (&head[1..3], &statement[3..5]),
            (&head[3..5], &statement[1..3]),
            (&head[3..5], inputs.relation.as_slice()),
            (
                &head[6..8],
                inputs.request.object().identifier(5)?.as_slice(),
            ),
            (&head[9..13], inputs.receiver.payment_key()?.as_slice()),
            (
                &statement[3..5],
                inputs.request.object().identifier(1)?.as_slice(),
            ),
            (
                &statement[5..7],
                inputs.request.object().identifier(2)?.as_slice(),
            ),
        ] {
            checks.push(equal(uint.glue(), region, left, right)?);
        }
        for (actual, expected) in [(&head[5], &statement[15]), (&head[8], &statement[7])] {
            checks.push(uint.glue().is_equal(region, actual, expected)?);
        }
        // The checked 104-bit packed value has a unique byte decomposition.
        // Extract its lifecycle without making witness-dependent circuit choices.
        let lifecycle =
            uint.assign::<8>(region, head[13].value().map(|f| u128::from(f.to_repr()[0])))?;
        let rest = uint.assign::<96>(
            region,
            head[13].value().map(|f| {
                let mut bytes = [0; 16];
                bytes[..12].copy_from_slice(&f.to_repr()[1..13]);
                u128::from_le_bytes(bytes)
            }),
        )?;
        let recomposed = uint.glue().linear(
            region,
            &[(Fp::ONE, lifecycle.word()), (Fp::from(256), rest.word())],
            Fp::ZERO,
        )?;
        iroha_plonk_gadgets::GlueChip::assert_equal(region, &recomposed, &head[13])?;
        checks.push(
            uint.glue()
                .is_equal(region, lifecycle.word(), &statement[8])?,
        );
        checks.push(inputs.opening.bind(
            uint.glue(),
            region,
            inputs.lineage.credit_root(),
            inputs.request.credit_id(),
            inputs.payment_digest,
        )?);
        checks.push(receipt::bind_dynamic(
            uint,
            hash,
            region,
            inputs.receipt,
            &ReceiptContext {
                wallet: head[6..8].try_into().map_err(|_| Error::Synthesis)?,
                provider: inputs.provider,
                statement: inputs.statement,
                proof_digest: inputs.proof_digest,
                payment_digest: inputs.receipt.word(11)?,
            },
        )?);
        let valid = all(uint.glue(), region, &checks)?;
        Ok(Self { digest, valid })
    }
    /// Hash of the original exact 162 bytes, including malformed input.
    pub const fn digest(&self) -> &Word<Fp> {
        &self.digest
    }
    /// Total semantic binding; incoming Omega and signature verdicts are additional.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }
}

/// Circuit-fixed Credited evidence kind, never selected by a witness byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    /// A Receive package digest with the corresponding sigma and receipt checks.
    Receive,
    /// A `CreditStatus` digest with the corresponding Omega and receipt checks.
    Status,
}
impl EvidenceKind {
    const fn tag(self) -> u64 {
        match self {
            Self::Receive => 1,
            Self::Status => 2,
        }
    }
}
/// Exact delivery transcript binding; evidence authentication remains mandatory.
#[derive(Clone, Debug)]
pub struct CreditedCells {
    digest: Word<Fp>,
    valid: Bit<Fp>,
}
impl CreditedCells {
    /// `LE16 version || evidence tag || credit || Payment || evidence digest`.
    pub const BYTES: usize = 99;
    /// Whole-transcript `P_bytes` chunks.
    pub fn primary_segments() -> Vec<usize> {
        chunk_segments(0, Self::BYTES)
    }
    /// Version, fixed-kind tag and exact canonical field halves.
    pub fn secondary_segments() -> Vec<SegmentSpec> {
        segments(3, 3)
    }
    /// Bind the circuit's fixed evidence kind, credit and exact component tapes.
    /// The Payment and evidence hashes are content addresses, so a canonical
    /// reference must equal its supplied preimage digest even on the no-op
    /// branch. Credit mismatch, wrong version/tag and noncanonical fields yield
    /// false. The complete evidence checks must also join Archive's verdict.
    ///
    /// # Errors
    /// Wrong fixed transcript/segments, substituted canonical component address
    /// or layout failure. Malformed field encodings remain total false.
    pub fn from_run(
        uint: &mut UintChip<'_, Fp>,
        hash: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        run: &ByteRun<Fp>,
        kind: EvidenceKind,
        expected: &[Word<Fp>; 3],
    ) -> Result<Self, Error> {
        if run.len() != Self::BYTES {
            return Err(Error::Synthesis);
        }
        let (digest, mut checks) = transcript(
            uint,
            hash,
            region,
            run,
            3,
            Some(kind.tag()),
            &expected.each_ref(),
            1,
            u64::from_le_bytes(*b"kgwcrdd1"),
        )?;
        for word in &expected[..2] {
            checks.push(nonzero(uint.glue(), region, core::slice::from_ref(word))?);
        }
        let valid = all(uint.glue(), region, &checks)?;
        Ok(Self { digest, valid })
    }
    /// Digest of all original transcript bytes.
    pub const fn digest(&self) -> &Word<Fp> {
        &self.digest
    }
    /// Transcript binding only, to be joined with the selected evidence verdict.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }
}

fn segments(prefix: usize, count: usize) -> Vec<SegmentSpec> {
    let mut out = vec![SegmentSpec::little(0, 2)];
    if prefix == 3 {
        out.push(SegmentSpec::little(2, 1));
    }
    for i in 0..count {
        for half in [0, 16] {
            out.push(SegmentSpec::little(prefix + 32 * i + half, 16));
        }
    }
    out
}
#[allow(clippy::too_many_arguments)]
fn transcript(
    uint: &mut UintChip<'_, Fp>,
    hash: &mut impl WordHasher<Fp>,
    region: &mut Region<'_, Fp>,
    run: &ByteRun<Fp>,
    prefix: usize,
    tag: Option<u64>,
    expected: &[&Word<Fp>],
    address_start: usize,
    domain: u64,
) -> Result<(Word<Fp>, Vec<Bit<Fp>>), Error> {
    let version = run.secondary_segment(SegmentSpec::little(0, 2))?.word();
    let mut checks = vec![is_constant(uint.glue(), region, version, 1)?];
    if let Some(tag) = tag {
        checks.push(is_constant(
            uint.glue(),
            region,
            run.secondary_segment(SegmentSpec::little(2, 1))?.word(),
            tag,
        )?);
    }
    for (i, expected) in expected.iter().enumerate() {
        let (word, valid) = decode_atom(uint, region, run, prefix + i * 32, Atom::Field)?;
        if i >= address_start {
            // Content addresses select the exact original components before
            // their semantic verdicts are joined. Only a noncanonical original
            // reference may use the total decoder's dummy; that original bit
            // itself forces false and cannot be chosen by the prover.
            let delta = uint.glue().sub(region, &word[0], expected)?;
            let bound = uint.glue().mul(region, valid.word(), &delta)?;
            iroha_plonk_gadgets::GlueChip::assert_constant(region, &bound, Fp::ZERO)?;
        }
        checks.push(valid);
        checks.push(uint.glue().is_equal(region, &word[0], expected)?);
    }
    let mut tape = PBytes::new();
    for segment in run.primary() {
        tape.push_bounded(segment.bounded().ok_or(Error::Synthesis)?)?;
    }
    if tape.len() != run.len() {
        return Err(Error::Synthesis);
    }
    Ok((tape.digest(uint.glue(), hash, region, domain)?, checks))
}
