//! Transitive Payment hashing from the same constrained component tapes.
//!
//! This layer binds the compact Payment transcript to its Request, credential,
//! Send statement, receipt and proof digest. It returns a total predicate;
//! recursive proof decisions and signature authorizations are separate,
//! mandatory inputs to the owning Receive or Archive operation.

use ff::{Field, PrimeField};
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{
    Bit, GlueChip, UintChip, Word, WordHasher,
    bytes::{
        PBytes, chunk_segments,
        tape::{ByteRun, SegmentSpec},
    },
};

use super::{
    ObjectKind, SignedObjectCells,
    credential::CredentialCells,
    decode_atom,
    predicates::{all, equal, is_constant, le64},
    receipt::{self, ReceiptContext},
    request::RequestCells,
    schema::Atom,
};
use crate::{
    a_relation::{IncomingLineageCells, LineagePublicCells, schedule::constrain_sigma_selector},
    operation_relation::incoming_statement::{IncomingStatementCells, StatementView},
};

const SCHEMA: [Atom; 5] = [
    Atom::Integer(2),
    Atom::Field,
    Atom::Key,
    Atom::Field,
    Atom::Field,
];

/// Same-tape components of a Payment's Send package.
///
/// The proof digest must be recomputed from exact `LE32 Ω.len || Ω ||
/// LE32 σ.len || σ` bytes under `kgwprf_1`, tied to the corresponding Q
/// slots. The owning relation separately authenticates the payer credential,
/// receipt signature and incoming predecessor, and closes every proof obligation.
pub struct PaymentInputs<'a, S: StatementView> {
    /// Exact signed Request carried by this Payment.
    pub request: &'a RequestCells,
    /// Payer credential from the retained Offer.
    pub payer: &'a CredentialCells,
    /// Send statement verified by the incoming sigma slot.
    pub statement: &'a S,
    /// Payer's Send receipt, verified under its payment key.
    pub receipt: &'a SignedObjectCells,
    /// Pinned Advance provider contract identity.
    pub provider: &'a [Word<Fp>; 2],
    /// Digest of the two exact proof encodings, including their lengths.
    pub proof_digest: &'a Word<Fp>,
}

/// Exact compact Payment transcript, recomputed package digest and total validity.
/// This is a constrained binding, not a proof or signature authorization.
#[derive(Clone, Debug)]
pub struct PaymentCells {
    digest: Word<Fp>,
    package: Word<Fp>,
    valid: Bit<Fp>,
}

/// Total Send consumer binding against the incoming predecessor and receiver.
///
/// This retains the original Payment/package digests and includes the decoded
/// predecessor's original structural verdict. It does not authenticate proofs,
/// signatures, the receiver's quoted credential, or recorded blacklist history;
/// those remain mandatory predicates of the owning Receive relation.
#[must_use = "include the total consumer verdict and bind its deterministic sigma selector"]
#[derive(Clone, Debug)]
pub struct IncomingPaymentCells {
    payment: PaymentCells,
    selector: Word<Fp>,
}

impl IncomingPaymentCells {
    /// Bind the exact Payment inputs to the Send predecessor and current receiver.
    ///
    /// The same `inputs` feed transcript/package hashing and every consumer
    /// comparison, so another statement or credential cannot be spliced after
    /// hashing. `predecessor` must come from the incoming proof's retained byte
    /// tape, and `receiver` from the owning operation's authenticated state.
    /// Invalid lifecycle, controls, widths, policy/time or identity yield false;
    /// bounded arithmetic uses only the checked dummy view after a decode error.
    ///
    /// # Errors
    /// Fixed tape/schema mismatch or synthesis failure. Invalid witnesses return
    /// false without changing the original byte digest.
    #[allow(
        clippy::too_many_arguments,
        reason = "one factory binds the same tape and all consumer inputs"
    )]
    pub fn from_run(
        uint: &mut UintChip<'_, Fp>,
        hash: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        run: &ByteRun<Fp>,
        inputs: &PaymentInputs<'_, IncomingStatementCells>,
        predecessor: &IncomingLineageCells,
        receiver: &LineagePublicCells,
    ) -> Result<Self, Error> {
        // A fabricated field-only encoding verdict cannot supply byte provenance.
        predecessor.carrier()?;
        let mut payment = PaymentCells::from_run(uint, hash, region, run, inputs)?;
        let pred = predecessor.checked().fields();
        let recv = receiver.fields();
        let statement = inputs.statement.fields();
        let mut checks = vec![payment.valid.clone(), predecessor.valid().clone()];
        for (a, b) in [
            (&statement[1..3], &pred[3..5]),
            (&statement[3..5], &pred[1..3]),
            (&pred[3..5], &recv[3..5]),
            (&pred[1..3], &recv[1..3]),
            (inputs.request.object().identifier(3)?, &pred[6..8]),
            (inputs.request.object().identifier(5)?, &recv[6..8]),
            (inputs.payer.payment_key()?.as_slice(), &pred[9..13]),
        ] {
            checks.push(equal(uint.glue(), region, a, b)?);
        }
        for (a, b) in [
            (&statement[14], &pred[5]),
            (&statement[7], &pred[8]),
            (inputs.payer.object().digest(), &pred[8]),
            (&statement[12], &pred[14]),
            (&statement[13], &pred[15]),
        ] {
            checks.push(uint.glue().is_equal(region, a, b)?);
        }
        let same_key = equal(uint.glue(), region, &pred[9..13], &recv[9..13])?;
        checks.push(uint.glue().not(region, &same_key)?);

        // This native decomposition is injective: the checked packed field is
        // below 2^104, and the three ranges bound the recomposition below 2^104.
        let packed = pred[13].value().map(|v| v.to_repr());
        let lifecycle = uint.assign::<8>(region, packed.map(|b| u128::from(b[0])))?;
        let epoch = uint.assign::<64>(
            region,
            packed.map(|b| {
                let mut bytes = [0; 8];
                bytes.copy_from_slice(&b[1..9]);
                u128::from(u64::from_le_bytes(bytes))
            }),
        )?;
        let controls = uint.assign::<32>(
            region,
            packed.map(|b| {
                let mut bytes = [0; 4];
                bytes.copy_from_slice(&b[9..13]);
                u128::from(u32::from_le_bytes(bytes))
            }),
        )?;
        let joined = uint.glue().linear(
            region,
            &[
                (Fp::ONE, lifecycle.word()),
                (Fp::from(2).pow_vartime([8]), epoch.word()),
                (Fp::from(2).pow_vartime([72]), controls.word()),
            ],
            Fp::ZERO,
        )?;
        GlueChip::assert_equal(region, &joined, &pred[13])?;
        let active = is_constant(uint.glue(), region, lifecycle.word(), 1)?;
        let retiring = is_constant(uint.glue(), region, lifecycle.word(), 2)?;
        let live = uint.glue().add(region, active.word(), retiring.word())?;
        checks.push(uint.glue().assert_bool(region, &live)?);
        for (actual, expected) in [
            (&statement[8], lifecycle.word()),
            (&statement[11], controls.word()),
        ] {
            checks.push(uint.glue().is_equal(region, actual, expected)?);
        }
        // An unknown controls bit gives false; it must not make the total
        // decoder's selector range check unsatisfiable before choosing burn.
        let mask = uint.assign::<3>(region, controls.value().map(|v| v & 7))?;
        let high = uint.assign::<29>(region, controls.value().map(|v| v >> 3))?;
        let joined = uint.glue().linear(
            region,
            &[(Fp::ONE, mask.word()), (Fp::from(8), high.word())],
            Fp::ZERO,
        )?;
        GlueChip::assert_equal(region, &joined, controls.word())?;
        let mask_valid = uint.glue().is_zero(region, high.word())?;
        let zero = uint.constant::<3>(region, 0)?;
        let safe_mask = uint
            .glue()
            .select(region, &mask_valid, mask.word(), zero.word())?;
        checks.push(mask_valid);
        let selector = constrain_sigma_selector(uint, region, 3, &safe_mask)?;
        let lower = inputs.statement.integer::<64>(uint, region, 24)?;
        checks.push(le64(
            uint,
            region,
            inputs.request.object().word(14)?,
            lower.word(),
        )?);
        checks.push(le64(
            uint,
            region,
            inputs.request.object().word(12)?,
            epoch.word(),
        )?);
        payment.valid = all(uint.glue(), region, &checks)?;
        Ok(Self { payment, selector })
    }

    /// Exact original Payment/package digests with the full consumer verdict.
    pub const fn payment(&self) -> &PaymentCells {
        &self.payment
    }

    /// Canonical Send sigma selector; undefined control bits select fixed Send0.
    /// The owning relation hard-binds Q's exported selector to this value, even
    /// when the original metadata/proof gives a false validity predicate.
    pub const fn sigma_index(&self) -> &Word<Fp> {
        &self.selector
    }
}
impl PaymentCells {
    /// Fixed `LE16 version || request || SEC1 key || credential || package` size.
    pub const BYTES: usize = 163;

    /// `P_bytes` chunks spanning the entire exact transcript.
    pub fn primary_segments() -> Vec<usize> {
        chunk_segments(0, Self::BYTES)
    }

    /// Integer, canonical field and big-endian key limb views of those bytes.
    pub fn secondary_segments() -> Vec<SegmentSpec> {
        let mut out = vec![
            SegmentSpec::little(0, 2),
            SegmentSpec::little(2, 16),
            SegmentSpec::little(18, 16),
            SegmentSpec::little(34, 1),
        ];
        for i in 0..4 {
            out.push(SegmentSpec::big(35 + i * 16, 16));
        }
        for offset in [99, 131] {
            out.push(SegmentSpec::little(offset, 16));
            out.push(SegmentSpec::little(offset + 16, 16));
        }
        out
    }

    /// Decode and bind an incoming Payment without replacing malformed bytes.
    ///
    /// The digest always hashes the original transcript. A noncanonical field,
    /// wrong SEC1 prefix, wrong version or invalid source body gives a false
    /// predicate. The Request, payer credential and package content addresses
    /// are hard-linked to the supplied component tapes: substituting a preimage
    /// is not an incoming verification failure that can authorize a burn.
    ///
    /// # Errors
    /// Wrong fixed length/segments, a non-Send statement, wrong receipt class or
    /// layout failure. Content-address mismatches are unsatisfiable; semantic
    /// mismatches return a constrained false verdict. The compact transcript is
    /// the canonical transitive projection of the Payment frame, not an
    /// independent source of unchecked Request/package references.
    pub fn from_run<S: StatementView>(
        uint: &mut UintChip<'_, Fp>,
        hash: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        run: &ByteRun<Fp>,
        inputs: &PaymentInputs<'_, S>,
    ) -> Result<Self, Error> {
        if run.len() != Self::BYTES || inputs.receipt.kind() != ObjectKind::Receipt {
            return Err(Error::Synthesis);
        }
        let mut offset = 0;
        let mut fields = Vec::new();
        let mut checks = Vec::new();
        for atom in SCHEMA {
            let (field, valid) = decode_atom(uint, region, run, offset, atom)?;
            fields.push(field);
            checks.push(valid);
            offset += atom.len();
        }
        checks.push(is_constant(uint.glue(), region, &fields[0][0], 1)?);
        let package = hash.hash_words(
            region,
            u64::from_le_bytes(*b"kgwpkg_1"),
            &[
                inputs.statement.digest().clone(),
                inputs.proof_digest.clone(),
                inputs.receipt.digest().clone(),
            ],
        )?;
        for (actual, expected) in [
            (&fields[1][0], inputs.request.object().digest()),
            (&fields[3][0], inputs.payer.object().digest()),
            (&fields[4][0], &package),
        ] {
            GlueChip::assert_equal(region, actual, expected)?;
        }
        checks.push(equal(
            uint.glue(),
            region,
            &fields[2],
            inputs.payer.payment_key()?,
        )?);
        checks.push(
            inputs
                .request
                .bind_send(uint, region, inputs.statement, inputs.payer)?,
        );
        let zero = uint.glue().constant(region, Fp::ZERO)?;
        checks.push(receipt::bind(
            uint,
            hash,
            region,
            inputs.receipt,
            &ReceiptContext {
                wallet: inputs.payer.object().identifier(3)?,
                provider: inputs.provider,
                statement: inputs.statement,
                proof_digest: inputs.proof_digest,
                payment_digest: &zero,
            },
        )?);
        let mut tape = PBytes::new();
        for segment in run.primary() {
            tape.push_bounded(segment.bounded().ok_or(Error::Synthesis)?)?;
        }
        if tape.len() != Self::BYTES {
            return Err(Error::Synthesis);
        }
        let digest = tape.digest(uint.glue(), hash, region, u64::from_le_bytes(*b"kgwpay_1"))?;
        let valid = all(uint.glue(), region, &checks)?;
        Ok(Self {
            digest,
            package,
            valid,
        })
    }
    /// Payment digest of the original exact 163-byte transcript.
    pub const fn digest(&self) -> &Word<Fp> {
        &self.digest
    }
    /// Recomputed package digest, never the unchecked carried value.
    pub const fn package_digest(&self) -> &Word<Fp> {
        &self.package
    }
    /// Binding/body verdict that must join every incoming verification predicate.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }
}
