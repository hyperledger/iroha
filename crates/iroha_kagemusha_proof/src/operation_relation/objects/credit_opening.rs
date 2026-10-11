//! Total incoming credit-membership evidence from one exact byte transcript.

use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{
    Bit, GlueChip, RunningSumChip, UintChip, Word, WordHasher,
    bytes::{
        PBytes, chunk_segments,
        tape::{ByteRun, SegmentSpec},
    },
    imt::{DEPTH, ImtChip, LeafCells, PathCells},
};

use super::{
    decode_atom,
    predicates::{all, is_constant, nonzero},
    schema::Atom,
};

/// Immutable credit record and recomputed root from a canonical 32-level opening.
/// Its total verdict is for incoming status evidence; it cannot replace the hard
/// retained-wallet membership/search paths used by monetary map transitions.
#[derive(Clone, Debug)]
pub struct CreditOpeningCells {
    credit: Word<Fp>,
    payment: Word<Fp>,
    burned: Bit<Fp>,
    root: Word<Fp>,
    digest: Word<Fp>,
    valid: Bit<Fp>,
}
impl CreditOpeningCells {
    /// Exact `credit || Payment || u8 burned || next_key || LE32 slot || siblings` size.
    pub const BYTES: usize = 1125;
    /// Canonical 31-byte chunks for the entire opening transcript.
    pub fn primary_segments() -> Vec<usize> {
        chunk_segments(0, Self::BYTES)
    }
    /// Exact canonical field halves, boolean byte and unsigned slot views.
    pub fn secondary_segments() -> Vec<SegmentSpec> {
        let mut out = vec![SegmentSpec::little(64, 1), SegmentSpec::little(97, 4)];
        for offset in [0, 32, 65]
            .into_iter()
            .chain((0..DEPTH).map(|i| 101 + i * 32))
        {
            out.push(SegmentSpec::little(offset, 16));
            out.push(SegmentSpec::little(offset + 16, 16));
        }
        out.sort_by_key(|s| s.start);
        out
    }
    /// Bind all opening fields to original bytes and compute its Merkle root.
    ///
    /// Noncanonical fields, a non-boolean burn byte, zero identities/sentinel
    /// slot and an invalid next-key ordering return false. The digest retains
    /// the original bytes even when a canonical field or burn bit uses a dummy.
    /// No caller supplies an unconstrained membership/finality boolean.
    ///
    /// # Errors
    /// Wrong fixed size/segments or layout failure, not malformed evidence.
    pub fn from_run(
        glue: &mut GlueChip<Fp>,
        range: &mut RunningSumChip<Fp>,
        hash: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        run: &ByteRun<Fp>,
    ) -> Result<Self, Error> {
        if run.len() != Self::BYTES {
            return Err(Error::Synthesis);
        }
        let (credit, payment, burned, next, path, digest, mut checks) = {
            let mut uint = UintChip::new(glue, range);
            let mut checks = Vec::new();
            let mut field = |offset| {
                let (word, valid) = decode_atom(&mut uint, region, run, offset, Atom::Field)?;
                checks.push(valid);
                Ok::<_, Error>(word[0].clone())
            };
            let credit = field(0)?;
            let payment = field(32)?;
            let next = field(65)?;
            let siblings = (0..DEPTH)
                .map(|i| field(101 + i * 32))
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| Error::Synthesis)?;
            let raw_burned = run.secondary_segment(SegmentSpec::little(64, 1))?.word();
            let burned = is_constant(uint.glue(), region, raw_burned, 1)?;
            let unburned = is_constant(uint.glue(), region, raw_burned, 0)?;
            let either = uint.glue().add(region, burned.word(), unburned.word())?;
            checks.push(is_constant(uint.glue(), region, &either, 1)?);
            let slot = run.secondary_segment(SegmentSpec::little(97, 4))?.word();
            for word in [&credit, &payment, slot] {
                checks.push(nonzero(uint.glue(), region, core::slice::from_ref(word))?);
            }
            let path = PathCells::<Fp, DEPTH>::from_words(&mut uint, region, slot, siblings)?;
            let mut tape = PBytes::new();
            for segment in run.primary() {
                tape.push_bounded(segment.bounded().ok_or(Error::Synthesis)?)?;
            }
            if tape.len() != Self::BYTES {
                return Err(Error::Synthesis);
            }
            let digest =
                tape.digest(uint.glue(), hash, region, u64::from_le_bytes(*b"kgwcopn1"))?;
            (credit, payment, burned, next, path, digest, checks)
        };
        let value = hash.hash_words(
            region,
            u64::from_le_bytes(*b"kgwcdig1"),
            &[credit.clone(), payment.clone(), burned.word().clone()],
        )?;
        let mut imt = ImtChip::new(glue, range, hash);
        let increasing = imt.less(region, &credit, &next)?;
        let leaf = imt.leaf_hash(
            region,
            &LeafCells::from_words([credit.clone(), value, next.clone()]),
        )?;
        let root = imt.path_root(region, &leaf, &path)?;
        let terminal = glue.is_zero(region, &next)?;
        // Zero cannot be strictly greater than a canonical nonnegative key.
        let either = glue.add(region, terminal.word(), increasing.word())?;
        let ordered = is_constant(glue, region, &either, 1)?;
        checks.push(ordered);
        let valid = all(glue, region, &checks)?;
        Ok(Self {
            credit,
            payment,
            burned,
            root,
            digest,
            valid,
        })
    }
    /// Include body validity and the exact expected receiver root/credit/Payment.
    /// The caller separately authenticates the receiver lineage and its opening.
    ///
    /// # Errors
    /// Layout failure. Wrong or non-membership evidence returns false.
    pub fn bind(
        &self,
        glue: &mut GlueChip<Fp>,
        region: &mut Region<'_, Fp>,
        root: &Word<Fp>,
        credit: &Word<Fp>,
        payment: &Word<Fp>,
    ) -> Result<Bit<Fp>, Error> {
        let mut checks = vec![self.valid.clone()];
        for (actual, expected) in [
            (&self.root, root),
            (&self.credit, credit),
            (&self.payment, payment),
        ] {
            checks.push(glue.is_equal(region, actual, expected)?);
        }
        all(glue, region, &checks)
    }
    /// Original transcript digest, regardless of its validity.
    pub const fn digest(&self) -> &Word<Fp> {
        &self.digest
    }
    /// Root recomputed from the parsed leaf and all 32 siblings.
    pub const fn root(&self) -> &Word<Fp> {
        &self.root
    }
    /// Credit identity in this opening.
    pub const fn credit_id(&self) -> &Word<Fp> {
        &self.credit
    }
    /// First retained Payment digest for the credit.
    pub const fn payment_digest(&self) -> &Word<Fp> {
        &self.payment
    }
    /// Burn flag, meaningful only together with the body/membership verdict.
    pub const fn burned(&self) -> &Bit<Fp> {
        &self.burned
    }
    /// Body validity, before comparison with the authenticated lineage root.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }
}
