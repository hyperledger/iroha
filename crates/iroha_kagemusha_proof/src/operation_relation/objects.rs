//! Canonical signed-object byte transcripts bound to signature-leaf inputs.
//!
//! Parsing proves exact widths, canonical Fp words, SEC1 framing and version;
//! it does not authenticate the signer or assert object-specific policy rules.
//! A binds the resulting message/key/signature to a hard-verified Q slot and
//! then constrains certificate purpose, identity, freshness and state effects.

use ff::{Field, PrimeField};
use iroha_pasta::{Fp, poseidon::hash_with_domain};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{
    Bit, GlueChip, UintChip, Word, WordHasher,
    bytes::{
        PBytes,
        element::{le_max, modulus_max},
        p_bytes_native,
        tape::{ByteRun, SegmentSpec},
    },
};

#[path = "objects/schema.rs"]
mod schema;
use schema::Atom;
pub use schema::ObjectKind;

pub mod credential;
pub mod credit_opening;
pub mod fee;
pub mod issuer;
pub mod payment;
pub mod policy;
pub(crate) mod predicates;
pub mod receipt;
pub mod request;
pub mod status;

/// The exact body fields, message and raw signature of one signed object.
/// Object authenticity is established only by composition with its Q slot.
#[derive(Clone, Debug)]
pub struct SignedObjectCells {
    kind: ObjectKind,
    fields: Vec<Vec<Word<Fp>>>,
    message: Word<Fp>,
    signature: [Word<Fp>; 4],
    digest: Word<Fp>,
    structural_valid: Bit<Fp>,
    field_canonicality: Vec<Bit<Fp>>,
}

impl SignedObjectCells {
    /// Parse one fixed body followed by raw big-endian `r || s` on the same tape.
    /// The run must use [`ObjectKind::primary_segments`] and
    /// [`ObjectKind::secondary_segments`], or an equivalent exact segment layout.
    ///
    /// # Errors
    /// Wrong fixed length/segments or layout failure. Noncanonical field bytes,
    /// wrong version and a SEC1 prefix other than 04 have no satisfying witness.
    pub fn from_run(
        uint: &mut UintChip<'_, Fp>,
        hash: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        kind: ObjectKind,
        run: &ByteRun<Fp>,
    ) -> Result<Self, Error> {
        let (object, valid) = Self::decode_soft(uint, hash, region, kind, run)?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        Ok(object)
    }

    /// Totally decode fixed-length bytes and return their structural verdict.
    ///
    /// The aggregate bit covers version, SEC1 prefix and canonical Fp atoms.
    /// A must include it in every incoming verdict. Noncanonical field atoms
    /// export zero with a false bit, never a reduced alias. The signing message
    /// and signature limbs remain bound to the original bytes in every case.
    /// The Request is the one exception: its message is `P(kgwrqst2, terms)`
    /// over the exported credit-id words without the payer fields, so every
    /// payer completion keeps the receiver's message, signature and digest; a
    /// noncanonical terms atom enters as its exported zero under a false bit.
    /// Payment auxiliary preimages separately require canonical Request field
    /// atoms so that this total view cannot alias a valid committed Request.
    /// Object-specific semantic validity and signature validity are separate.
    ///
    /// # Errors
    /// Wrong fixed schema length/segments or layout failure, not malformed bytes.
    pub fn decode_soft(
        uint: &mut UintChip<'_, Fp>,
        hash: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        kind: ObjectKind,
        run: &ByteRun<Fp>,
    ) -> Result<(Self, Bit<Fp>), Error> {
        if run.len() != kind.body_len() + 64 {
            return Err(Error::Synthesis);
        }
        let mut offset = 0;
        let mut fields = Vec::with_capacity(kind.schema().len());
        let mut field_canonicality = Vec::new();
        let one = uint.glue().constant(region, Fp::ONE)?;
        let mut valid = uint.glue().assert_bool(region, &one)?;
        for atom in kind.schema() {
            let (field, canonical) = decode_atom(uint, region, run, offset, *atom)?;
            valid = uint.glue().and(region, &valid, &canonical)?;
            if matches!(atom, Atom::Field) {
                field_canonicality.push(canonical);
            }
            fields.push(field);
            offset += atom.len();
        }
        let version = uint.glue().is_equal(region, &fields[0][0], &one)?;
        valid = uint.glue().and(region, &valid, &version)?;
        let signature = raw_pair(run, offset)?;
        let message = if kind == ObjectKind::Request {
            let terms = request_terms(fields.iter().flatten().cloned());
            hash.hash_words(region, kind.signing_domain(), &terms)?
        } else {
            let mut body = PBytes::new();
            for segment in run.primary() {
                if segment.spec().end() > offset {
                    break;
                }
                body.push_bounded(segment.bounded().ok_or(Error::Synthesis)?)?;
            }
            if body.len() != offset {
                return Err(Error::Synthesis);
            }
            body.digest(uint.glue(), hash, region, kind.signing_domain())?
        };
        let inputs = [
            message.clone(),
            signature[0].clone(),
            signature[1].clone(),
            signature[2].clone(),
            signature[3].clone(),
        ];
        let digest = hash.hash_words(region, kind.object_domain(), &inputs)?;
        Ok((
            Self {
                kind,
                fields,
                message,
                signature,
                digest,
                structural_valid: valid.clone(),
                field_canonicality,
            },
            valid,
        ))
    }
    /// Structural verdict of the original byte tape. Every semantic verifier
    /// includes this bit, so a canonicalized dummy field cannot hide bad bytes.
    pub const fn structural_valid(&self) -> &Bit<Fp> {
        &self.structural_valid
    }

    // Request content addresses hash decoded terms instead of the original byte
    // tape. A Payment auxiliary preimage must therefore use canonical field
    // atoms: their soft zero export cannot be used to falsify the verdict of the
    // same otherwise-valid Payment. Keep this separate from the version bit,
    // whose exact integer is already committed by the Request message.
    fn assert_canonical_fields(&self, region: &mut Region<'_, Fp>) -> Result<(), Error> {
        for canonical in &self.field_canonicality {
            GlueChip::assert_constant(region, canonical.word(), Fp::ONE)?;
        }
        Ok(())
    }

    /// Exact 32-byte identifier as two little-endian u128 cells.
    ///
    /// # Errors
    /// The fixed schema position is not an identifier.
    pub fn identifier(&self, index: usize) -> Result<&[Word<Fp>; 2], Error> {
        if !matches!(self.kind.schema().get(index), Some(Atom::Identifier)) {
            return Err(Error::Synthesis);
        }
        self.fields[index]
            .as_slice()
            .try_into()
            .map_err(|_| Error::Synthesis)
    }

    /// Exact SEC1 coordinate limbs, excluding the constrained prefix byte.
    ///
    /// # Errors
    /// The fixed schema position is not a P-256 key.
    pub fn key(&self, index: usize) -> Result<&[Word<Fp>; 4], Error> {
        if !matches!(self.kind.schema().get(index), Some(Atom::Key)) {
            return Err(Error::Synthesis);
        }
        self.fields[index]
            .as_slice()
            .try_into()
            .map_err(|_| Error::Synthesis)
    }

    /// Fixed authenticated-object class to be authorized by A.
    pub const fn kind(&self) -> ObjectKind {
        self.kind
    }
    /// Fields in the body's native transcript order. Integers/canonical fields
    /// have one cell; byte identifiers have two LE128 halves; keys have four
    /// cells `[x_lo, x_hi, y_lo, y_hi]` as exact unsigned integers.
    pub fn fields(&self) -> &[Vec<Word<Fp>>] {
        &self.fields
    }
    /// Canonical message whose 32-byte little-endian encoding Q hashes with SHA-256.
    pub const fn message(&self) -> &Word<Fp> {
        &self.message
    }
    /// Raw unsigned signature halves `[r_lo, r_hi, s_lo, s_hi]`.
    pub const fn signature(&self) -> &[Word<Fp>; 4] {
        &self.signature
    }
    /// `P(object domain, [message, r_lo, r_hi, s_lo, s_hi])`.
    pub const fn digest(&self) -> &Word<Fp> {
        &self.digest
    }
    /// Bind this exact body/signature and authorized key to a proved Q slot.
    ///
    /// The returned signature verdict must join the incoming predicate for a
    /// soft slot; hard slots are already constrained true by their fixed plan.
    /// This method does not replace the structural bit from `decode_soft` or
    /// authorize a caller-supplied key without the certificate/credential rules.
    ///
    /// # Errors
    /// Layout failure; substituting any linked input is unsatisfiable.
    pub fn bind_signature(
        &self,
        region: &mut Region<'_, Fp>,
        proof: &crate::a_relation::SignatureProofCells,
        authorized_key: &[Word<Fp>; 4],
    ) -> Result<Bit<Fp>, Error> {
        GlueChip::assert_equal(region, &self.message, proof.message())?;
        for (own, proved) in self.signature.iter().zip(proof.signature()) {
            GlueChip::assert_equal(region, own, proved)?;
        }
        for (own, proved) in authorized_key.iter().zip(proof.key()) {
            GlueChip::assert_equal(region, own, proved)?;
        }
        Ok(proof.valid().clone())
    }

    /// One integer or canonical-field cell at a fixed schema position.
    ///
    /// # Errors
    /// Wrong fixed field index or atom type.
    pub fn word(&self, index: usize) -> Result<&Word<Fp>, Error> {
        let field = self.fields.get(index).ok_or(Error::Synthesis)?;
        if field.len() != 1 {
            return Err(Error::Synthesis);
        }
        Ok(&field[0])
    }
}

/// Flattened Request field words outside the receiver signature: payer wallet
/// (5, 6), payer account (7, 8) and send ordinal (13). The payer completes
/// them after the receiver signed, so they enter `credit_id` but not `m`.
const REQUEST_PAYER_WORDS: [usize; 5] = [5, 6, 7, 8, 13];

/// The 19 Request terms: the flattened credit-id words without
/// [`REQUEST_PAYER_WORDS`], in transcript order.
fn request_terms<T>(words: impl IntoIterator<Item = T>) -> Vec<T> {
    words
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !REQUEST_PAYER_WORDS.contains(index))
        .map(|(_, word)| word)
        .collect()
}

/// Native signing message of one exact signed body (signature excluded), as
/// [`SignedObjectCells::decode_soft`] computes it: `P(kgwrqst2, terms)` over
/// the Request's exported terms words and `P_bytes(domain, body)` for every
/// other kind. A Request body of another length has no terms words.
#[must_use]
pub fn signed_message_native(kind: ObjectKind, body: &[u8]) -> Fp {
    if kind != ObjectKind::Request {
        return p_bytes_native(kind.signing_domain(), body);
    }
    let words = field_words_native(kind, body).unwrap_or_default();
    hash_with_domain(kind.signing_domain(), &request_terms(words))
}

/// Native mirror of the flattened [`SignedObjectCells::fields`]: an integer is
/// one word, an identifier its two LE128 halves, a field atom its canonical
/// value or zero when noncanonical, and a key its raw coordinate halves
/// `[x_lo, x_hi, y_lo, y_hi]`. `None` for a body of another length.
fn field_words_native(kind: ObjectKind, body: &[u8]) -> Option<Vec<Fp>> {
    if body.len() != kind.body_len() {
        return None;
    }
    let le = |bytes: &[u8]| {
        let mut value = [0; 16];
        value[..bytes.len()].copy_from_slice(bytes);
        Fp::from_u128(u128::from_le_bytes(value))
    };
    let limb = |bytes: &[u8]| {
        let mut value = [0; 16];
        value.copy_from_slice(bytes);
        Fp::from_u128(u128::from_be_bytes(value))
    };
    let mut words = Vec::new();
    let mut offset = 0;
    for atom in kind.schema() {
        let bytes = &body[offset..offset + atom.len()];
        match atom {
            Atom::Integer(_) => words.push(le(bytes)),
            Atom::Identifier => words.extend([le(&bytes[..16]), le(&bytes[16..])]),
            Atom::Field => {
                let mut repr = [0; 32];
                repr.copy_from_slice(bytes);
                words.push(Option::<Fp>::from(Fp::from_repr(repr)).unwrap_or(Fp::ZERO));
            }
            Atom::Key => {
                words.extend(
                    [&bytes[17..33], &bytes[1..17], &bytes[49..], &bytes[33..49]].map(limb),
                );
            }
        }
        offset += atom.len();
    }
    Some(words)
}

fn raw_pair(run: &ByteRun<Fp>, offset: usize) -> Result<[Word<Fp>; 4], Error> {
    let part = |at| {
        run.secondary_segment(SegmentSpec::big(at, 16))
            .map(|segment| segment.word().clone())
    };
    Ok([
        part(offset + 16)?,
        part(offset)?,
        part(offset + 48)?,
        part(offset + 32)?,
    ])
}

fn decode_atom(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    run: &ByteRun<Fp>,
    offset: usize,
    atom: Atom,
) -> Result<(Vec<Word<Fp>>, Bit<Fp>), Error> {
    let part = |at, len| {
        run.secondary_segment(SegmentSpec::little(at, len))
            .map(|segment| segment.word().clone())
    };
    let one = uint.glue().constant(region, Fp::ONE)?;
    let valid = uint.glue().assert_bool(region, &one)?;
    match atom {
        Atom::Integer(bytes) => Ok((vec![part(offset, bytes)?], valid)),
        Atom::Identifier => Ok((vec![part(offset, 16)?, part(offset + 16, 16)?], valid)),
        Atom::Field => {
            let lo = uint.range_check::<128>(region, &part(offset, 16)?)?;
            let hi = uint.range_check::<128>(region, &part(offset + 16, 16)?)?;
            let canonical = le_max(uint, region, &lo, &hi, modulus_max::<Fp>())?;
            let reduced = uint.glue().linear(
                region,
                &[
                    (Fp::ONE, lo.word()),
                    (Fp::from_u128(1 << 127).double(), hi.word()),
                ],
                Fp::ZERO,
            )?;
            let zero = uint.glue().constant(region, Fp::ZERO)?;
            let selected = uint.glue().select(region, &canonical, &reduced, &zero)?;
            Ok((vec![selected], canonical))
        }
        Atom::Key => {
            let expected = uint.glue().constant(region, Fp::from(4))?;
            let canonical = uint.glue().is_equal(region, &part(offset, 1)?, &expected)?;
            Ok((raw_pair(run, offset + 1)?.to_vec(), canonical))
        }
    }
}
