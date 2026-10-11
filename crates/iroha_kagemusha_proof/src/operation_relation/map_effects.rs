//! Exact Send/Receive map effects and lineage-adjusted burn accounting.
//!
//! Authentication is composed by A: the fee-schedule digest comes from its
//! authenticated Request and the Payment digest from its constrained wire
//! transcript. Receive's verdict is the output of the complete incoming-mode
//! relation, including [`MapEffectsChip::receive_nonmembership`]. A caller
//! cannot substitute a native boolean for that relation. These helpers do
//! not authorize a step or implement its other state changes.

use ff::{Field, PrimeField};
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{
    Bit, GlueChip, RunningSumChip, SpongeChip, UintChip, Word, WordHasher,
    imt::{DEPTH, ImtChip, OpeningCells, PathCells},
};
use iroha_plonk_recursion::obligation::ledger::Variant;

use super::{
    state::{StateCells, rest_index as rest},
    statement::StatementCells,
};
use crate::{a_relation::LineagePublicCells, witness::core_index as core};

/// Domain of the seven-field pending Send descriptor.
pub const PENDING_DOMAIN: u64 = u64::from_le_bytes(*b"kgwpout1");
/// Domain of the three-field earned fee claim.
pub const FEE_DOMAIN: u64 = u64::from_le_bytes(*b"kgwfee_1");
/// Domain of the three-field consumed Receive descriptor.
pub const CONSUMED_DOMAIN: u64 = u64::from_le_bytes(*b"kgwccrd1");
/// Domain of the permanent `(credit, Payment digest, burned)` record.
pub const CREDIT_DOMAIN: u64 = u64::from_le_bytes(*b"kgwcdig1");
/// Domain of `(ordinal, ordinary receipt digest, amount)` load recovery entries.
pub const LOAD_DOMAIN: u64 = u64::from_le_bytes(*b"kgwload1");
/// Domain of `(ordinal, nullifier, amount, charge)` redeem recovery entries.
pub const REDEEM_DOMAIN: u64 = u64::from_le_bytes(*b"kgwrdm_1");

/// Opened state and its authenticated lineage prefix.
#[derive(Clone, Copy, Debug)]
pub struct MapState<'a> {
    /// Canonical private core/rest opening.
    pub state: &'a StateCells,
    /// Prefix authenticated by the predecessor proof, or current A output.
    pub lineage: &'a LineagePublicCells,
}

/// Bound statement and the two state/lineage pairs of one non-bootstrap step.
#[derive(Clone, Copy, Debug)]
pub struct MapTransition<'a> {
    /// The validated fixed-variant statement verified by Q.
    pub statement: &'a StatementCells,
    /// Hard predecessor proof's state and prefix.
    pub predecessor: MapState<'a>,
    /// Current A output's state and prefix.
    pub successor: MapState<'a>,
}

/// Authenticated paths used by an insert or its fixed-layout no-op.
#[derive(Clone, Debug)]
pub struct InsertCells<const D: usize = DEPTH> {
    /// Old key's leaf for a no-op, or the bracketing low leaf for insertion.
    pub low: OpeningCells<Fp, D>,
    /// Empty destination after relinking, or the same old leaf for a no-op.
    pub slot: PathCells<Fp, D>,
}

/// Private paths and authenticated Request digest used by Send's maps.
#[derive(Clone, Debug)]
pub struct SendMapWitness<const D: usize = DEPTH> {
    /// Pending descriptor insertion from the lineage-adjusted root.
    pub pending: InsertCells<D>,
    /// Fee insertion iff the statement's fee is nonzero, otherwise no-op.
    pub fee: InsertCells<D>,
    /// Fee-schedule digest bound by the authenticated Request in A.
    pub fee_schedule: Word<Fp>,
}

/// Receive's committed OQ-3 consumed-map transition and permanent record paths.
#[derive(Clone, Debug)]
pub struct ReceiveMapWitness<const D: usize = DEPTH> {
    /// Transition selected by the committed successor core.
    pub consumed: InsertCells<D>,
    /// Structurally inserted key. On accept it is this Receive's credit.
    pub inserted_key: Word<Fp>,
    /// Structurally inserted value. On accept it is this Receive's descriptor.
    pub inserted_value: Word<Fp>,
    /// Constrained bit: insertion or unchanged-root branch under OQ-3.
    pub insert: Bit<Fp>,
    /// Existing credit's leaf or its bracketing low leaf, and its write path.
    pub credit: InsertCells<D>,
    /// Exact Payment digest bound by the consuming relation's wire transcript.
    pub payment_digest: Word<Fp>,
}

/// Two authenticated paths of a relink-then-clear removal.
#[derive(Clone, Debug)]
pub struct RemoveCells<const D: usize = DEPTH> {
    /// Predecessor leaf against the old root; its next key is the removed key.
    pub predecessor: OpeningCells<Fp, D>,
    /// Removed leaf against the root after relinking the predecessor.
    pub removed: OpeningCells<Fp, D>,
}

/// `ArchiveSent`'s retained descriptor and separate core/lineage removal paths.
#[derive(Clone, Debug)]
pub struct ArchiveMapWitness<const D: usize = DEPTH> {
    /// Exact seven-field descriptor of the retained outgoing Payment.
    /// A binds it to that Payment before checking its Credited evidence.
    pub descriptor: [Word<Fp>; 7],
    /// Removal committed by the step from the private core's pending map.
    pub core: RemoveCells<D>,
    /// The same descriptor in the potentially different adjusted pending map.
    pub lineage: RemoveCells<D>,
}

/// Domain of the permanent blacklist-version/root history value.
pub const BLACKLIST_HISTORY_DOMAIN: u64 = u64::from_le_bytes(*b"kgwbhst1");

/// Map relation sharing the caller's arithmetic, range and sponge lanes.
#[derive(Debug)]
pub struct MapEffectsChip<'a, H: WordHasher<Fp> = SpongeChip<Fp>> {
    glue: &'a mut GlueChip<Fp>,
    range: &'a mut RunningSumChip<Fp>,
    sponge: &'a mut H,
}

impl<'a, H: WordHasher<Fp>> MapEffectsChip<'a, H> {
    /// Insert the new blacklist's exact version/root in permanent history.
    ///
    /// Compose with `refresh::constrain` and authenticated signed-list fields;
    /// this helper checks the hard map obligation, not issuer authorization.
    ///
    /// # Errors
    /// Wrong fixed variant or layout failure. Duplicate versions, occupied
    /// insertion slots and incorrect successor roots are unsatisfiable.
    pub fn refresh_blacklist<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        insertion: &InsertCells<D>,
    ) -> Result<(), Error> {
        if transition.statement.variant() != Variant::RefreshBlacklist {
            return Err(Error::Synthesis);
        }
        self.bind(region, transition)?;
        let state = transition.successor.state;
        let version = &state.core()[core::BLACKLIST_VERSION];
        let root = &state.core()[core::BLACKLIST_ROOT];
        let value = self.sponge.hash_words(
            region,
            BLACKLIST_HISTORY_DOMAIN,
            &[version.clone(), root.clone()],
        )?;
        let new_root = ImtChip::new(self.glue, self.range, self.sponge).insert(
            region,
            &transition.predecessor.state.rest()[rest::BLACKLIST_HISTORY],
            version,
            &value,
            &insertion.low,
            &insertion.slot,
        )?;
        GlueChip::assert_equal(region, &new_root, &state.rest()[rest::BLACKLIST_HISTORY])
    }

    /// Hard-authenticate the search route for a Request's recorded list pair.
    ///
    /// For a nonzero recorded version, the resulting soft bit is true iff
    /// history contains that exact version/root. A must combine it with the
    /// Request's other verdicts. The zero-pair Receive variant omits this
    /// lookup and separately pins both Request words to zero. Current policy
    /// or list fields are deliberately not substituted for the Request pair.
    ///
    /// # Errors
    /// Layout failure. Zero/out-of-range versions, zero roots, false search
    /// routes and forged paths are unsatisfiable even on a burn branch.
    pub fn recorded_blacklist<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        state: &StateCells,
        version: &Word<Fp>,
        entries_root: &Word<Fp>,
        opening: &OpeningCells<Fp, D>,
    ) -> Result<Bit<Fp>, Error> {
        UintChip::new(self.glue, self.range).range_check::<64>(region, version)?;
        self.glue.assert_nonzero(region, entries_root)?;
        let absent = ImtChip::new(self.glue, self.range, self.sponge).absent(
            region,
            &state.rest()[rest::BLACKLIST_HISTORY],
            version,
            opening,
        )?;
        let value = self.sponge.hash_words(
            region,
            BLACKLIST_HISTORY_DOMAIN,
            &[version.clone(), entries_root.clone()],
        )?;
        let matches = self.glue.is_equal(region, opening.leaf.value(), &value)?;
        let present = self.glue.not(region, &absent)?;
        self.glue.and(region, &present, &matches)
    }

    /// Borrow existing chips without resetting their row cursors.
    pub const fn new(
        glue: &'a mut GlueChip<Fp>,
        range: &'a mut RunningSumChip<Fp>,
        sponge: &'a mut H,
    ) -> Self {
        Self {
            glue,
            range,
            sponge,
        }
    }

    fn bind(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
    ) -> Result<(), Error> {
        transition.statement.bind_states(
            &mut UintChip::new(self.glue, self.range),
            region,
            Some((transition.predecessor.state, transition.predecessor.lineage)),
            transition.successor.state,
            transition.successor.lineage,
        )
    }

    /// Constrain Load/Unload arithmetic and the exact insert-only recovery
    /// entry, with distinct `kind * 2^128 + ordinal` keys in one shared map.
    ///
    /// The owning A authenticates the receipt-bound native-authorized Advance
    /// or the Unload quote. Native verifies Load finality before that Advance.
    /// Duplicate ordinals, kind substitution and nullifier or charge changes
    /// cannot replace a prior entry or alter the committed successor root.
    ///
    /// # Errors
    /// Wrong variant or layout failure; incorrect arithmetic, paths and
    /// recovery descriptors have no satisfying witness.
    pub fn recovery<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        witness: &InsertCells<D>,
    ) -> Result<(), Error> {
        let (kind, domain) = match transition.statement.variant() {
            Variant::Load => (1_u64, LOAD_DOMAIN),
            Variant::Unload => (2_u64, REDEEM_DOMAIN),
            _ => return Err(Error::Synthesis),
        };
        super::administrative::monetary(
            &mut UintChip::new(self.glue, self.range),
            self.sponge,
            region,
            transition,
        )?;
        let effect = &transition.statement.fields()[17..];
        let two_to_128 = Fp::from_u128(1_u128 << 127).double();
        let key = self
            .glue
            .add_constant(region, &effect[1], Fp::from(kind) * two_to_128)?;
        let mut preimage = vec![effect[1].clone(), effect[0].clone(), effect[2].clone()];
        if kind == 2 {
            preimage.push(effect[3].clone());
        }
        let value = self.sponge.hash_words(region, domain, &preimage)?;
        let root = ImtChip::new(self.glue, self.range, self.sponge).insert(
            region,
            &transition.predecessor.state.core()[core::LOAD_REDEEM_ROOT],
            &key,
            &value,
            &witness.low,
            &witness.slot,
        )?;
        GlueChip::assert_equal(
            region,
            &root,
            &transition.successor.state.core()[core::LOAD_REDEEM_ROOT],
        )
    }

    /// Insert the exact Send descriptor and nonzero-fee claim, and carry
    /// unaffected maps and adjusted burn/credit values.
    ///
    /// Pending insertion starts from the predecessor *lineage* root: an
    /// earlier invalid Archive may have removed its private core leaf while
    /// the lineage kept it. A Send resynchronizes its successor core to that
    /// authenticated lineage root. Fee leaves use the Request's historical
    /// schedule, which need not be the sender's current held schedule.
    ///
    /// # Errors
    /// Non-Send variant or layout failure; wrong descriptors, roots or
    /// overflows have no satisfying witness.
    pub fn send<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        witness: &SendMapWitness<D>,
    ) -> Result<(), Error> {
        self.send_pending(region, transition, &witness.pending)?;
        self.send_fee_and_unchanged(region, transition, &witness.fee, &witness.fee_schedule)
    }

    /// Bind Send's exact pending descriptor insertion from its predecessor lineage.
    ///
    /// This is one part of [`Self::send`]. A fixed multi-stage program must also
    /// constrain [`Self::send_fee_and_unchanged`] against the identical statement,
    /// state openings and lineage prefixes retained by its context. This method
    /// alone does not authorize a complete Send.
    ///
    /// # Errors
    /// Wrong variant, layout failure, or unsatisfied statement/path/root binding.
    pub fn send_pending<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        pending_path: &InsertCells<D>,
    ) -> Result<(), Error> {
        if transition.statement.variant() != Variant::Send {
            return Err(Error::Synthesis);
        }
        self.bind(region, transition)?;
        let fields = transition.statement.fields();
        let credit = &fields[17];
        let descriptor = self
            .sponge
            .hash_words(region, PENDING_DOMAIN, &fields[17..24])?;
        let pending = ImtChip::new(self.glue, self.range, self.sponge).insert(
            region,
            transition.predecessor.lineage.pending_root(),
            credit,
            &descriptor,
            &pending_path.low,
            &pending_path.slot,
        )?;
        GlueChip::assert_equal(
            region,
            &pending,
            &transition.successor.state.core()[core::PENDING_OUTGOING_ROOT],
        )?;
        GlueChip::assert_equal(
            region,
            &pending,
            transition.successor.lineage.pending_root(),
        )
    }

    /// Bind Send's conditional fee insertion and every map/burn field it preserves.
    ///
    /// `fee_schedule` must come from the same authenticated Request. A fixed
    /// multi-stage program must also constrain [`Self::send_pending`] against
    /// the identical context-bound transition; no witness flag replaces it.
    ///
    /// # Errors
    /// Wrong variant, layout failure, or unsatisfied statement/path/unchanged binding.
    pub fn send_fee_and_unchanged<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        fee_path: &InsertCells<D>,
        fee_schedule: &Word<Fp>,
    ) -> Result<(), Error> {
        if transition.statement.variant() != Variant::Send {
            return Err(Error::Synthesis);
        }
        self.bind(region, transition)?;
        let fields = transition.statement.fields();
        let credit = &fields[17];
        let fee = &fields[22];
        let zero_fee = self.glue.is_zero(region, fee)?;
        let has_fee = self.glue.not(region, &zero_fee)?;
        let checked_schedule =
            self.glue
                .select_constant(region, &has_fee, fee_schedule, Fp::ONE)?;
        self.glue.assert_nonzero(region, &checked_schedule)?;
        let fee_value = self.sponge.hash_words(
            region,
            FEE_DOMAIN,
            &[credit.clone(), fee.clone(), fee_schedule.clone()],
        )?;
        let fee_root = ImtChip::new(self.glue, self.range, self.sponge).insert_if(
            region,
            &transition.predecessor.state.core()[core::FEE_CLAIM_ROOT],
            [credit, &fee_value],
            &fee_path.low,
            &fee_path.slot,
            &has_fee,
        )?;
        let successor = transition.successor.state.core();
        GlueChip::assert_equal(region, &fee_root, &successor[core::FEE_CLAIM_ROOT])?;
        for index in [core::CONSUMED_CREDIT_ROOT, core::LOAD_REDEEM_ROOT] {
            GlueChip::assert_equal(
                region,
                &transition.predecessor.state.core()[index],
                &successor[index],
            )?;
        }
        GlueChip::assert_equal(
            region,
            transition.predecessor.lineage.credit_root(),
            transition.successor.lineage.credit_root(),
        )?;
        GlueChip::assert_equal(
            region,
            transition.predecessor.lineage.burned_total(),
            transition.successor.lineage.burned_total(),
        )?;
        GlueChip::assert_equal(
            region,
            transition.predecessor.lineage.burned_total(),
            &successor[core::BURNED_TOTAL],
        )
    }

    /// Hard-authenticate the unique search route for this Receive's credit,
    /// returning the non-membership soft bit included in the global verdict.
    ///
    /// A malformed path or unrelated authenticated leaf is unsatisfiable;
    /// only actual membership returns false and can justify a duplicate burn.
    ///
    /// # Errors
    /// Wrong fixed variant or layout failure; false routes are unsatisfiable.
    pub fn receive_nonmembership<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        opening: &OpeningCells<Fp, D>,
    ) -> Result<Bit<Fp>, Error> {
        require_receive(transition.statement)?;
        ImtChip::new(self.glue, self.range, self.sponge).absent(
            region,
            &transition.predecessor.state.core()[core::CONSUMED_CREDIT_ROOT],
            &transition.statement.fields()[17],
            opening,
        )
    }

    /// Constrain the selected OQ-3 map effect, preserve the first credit
    /// record, and add the exact amount to adjusted burn iff `valid` is false.
    ///
    /// `valid` must be the complete incoming-mode relation's bit. Its soft
    /// checks include [`Self::receive_nonmembership`] for the same transition.
    /// On accept, insertion of the exact Receive key/value is mandatory.
    /// Burn allows only a structurally authenticated fresh-key insertion or
    /// no-op, and never overwrites the first credit digest or burn flag.
    /// The committed core burn stays unchanged; adjusted burn lives in Ω
    /// until a consuming Send, Unload or Retiring resynchronizes the core.
    ///
    /// # Errors
    /// Wrong variant or layout failure; invalid effects and u128 overflow
    /// have no satisfying witness.
    pub fn receive<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        witness: &ReceiveMapWitness<D>,
        valid: &Bit<Fp>,
    ) -> Result<(), Error> {
        self.receive_consumed(region, transition, witness, valid)?;
        self.receive_credit(region, transition, witness, valid)?;
        self.receive_burn_and_preserve(region, transition, valid)
    }

    /// Authenticate only the exact OQ-3 consumed-root update. A complete Receive
    /// must also constrain the credit record and burn/preserved-state effects
    /// under the identical transition and complete incoming verdict.
    /// # Errors
    /// Wrong variant, invalid insertion route, missing accepting insert or wrong root.
    pub fn receive_consumed<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        witness: &ReceiveMapWitness<D>,
        valid: &Bit<Fp>,
    ) -> Result<(), Error> {
        require_receive(transition.statement)?;
        self.bind(region, transition)?;
        let fields = transition.statement.fields();
        let credit = &fields[17];
        let amount = &fields[20];
        let consumed = self.sponge.hash_words(
            region,
            CONSUMED_DOMAIN,
            &[credit.clone(), amount.clone(), fields[9].clone()],
        )?;
        gated_equal(self.glue, region, valid, &witness.inserted_key, credit)?;
        gated_equal(self.glue, region, valid, &witness.inserted_value, &consumed)?;
        let accepting_insert = self.glue.and(region, valid, &witness.insert)?;
        GlueChip::assert_equal(region, accepting_insert.word(), valid.word())?;
        let consumed_root = ImtChip::new(self.glue, self.range, self.sponge).insert_if(
            region,
            &transition.predecessor.state.core()[core::CONSUMED_CREDIT_ROOT],
            [&witness.inserted_key, &witness.inserted_value],
            &witness.consumed.low,
            &witness.consumed.slot,
            &witness.insert,
        )?;
        GlueChip::assert_equal(
            region,
            &consumed_root,
            &transition.successor.state.core()[core::CONSUMED_CREDIT_ROOT],
        )
    }

    /// Authenticate the first exact Payment/burn credit record, preserving an
    /// already present record. Compose with both other Receive effect owners.
    /// # Errors
    /// Wrong variant, zero Payment digest, forged route or wrong successor root.
    pub fn receive_credit<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        witness: &ReceiveMapWitness<D>,
        valid: &Bit<Fp>,
    ) -> Result<(), Error> {
        require_receive(transition.statement)?;
        self.bind(region, transition)?;
        self.glue.assert_nonzero(region, &witness.payment_digest)?;
        let fields = transition.statement.fields();
        let credit = &fields[17];
        let burned = self.glue.not(region, valid)?;
        let credit_value = self.sponge.hash_words(
            region,
            CREDIT_DOMAIN,
            &[
                credit.clone(),
                witness.payment_digest.clone(),
                burned.word().clone(),
            ],
        )?;
        let record = ImtChip::new(self.glue, self.range, self.sponge).record(
            region,
            transition.predecessor.lineage.credit_root(),
            credit,
            &credit_value,
            &witness.credit.low,
            &witness.credit.slot,
        )?;
        GlueChip::assert_equal(
            region,
            record.root(),
            transition.successor.lineage.credit_root(),
        )
    }

    /// Apply the exact adjusted-burn iff rule and preserve unrelated roots.
    /// The consumed-root and credit-root owners are separate mandatory inputs
    /// to a complete Receive; this method alone does not authenticate them.
    /// # Errors
    /// Wrong variant, u128 overflow, discretionary burn or changed preserved state.
    pub fn receive_burn_and_preserve(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        valid: &Bit<Fp>,
    ) -> Result<(), Error> {
        require_receive(transition.statement)?;
        self.bind(region, transition)?;
        let burned = self.glue.not(region, valid)?;
        let amount = &transition.statement.fields()[20];
        let delta = self.glue.mul(region, burned.word(), amount)?;
        let mut uint = UintChip::new(self.glue, self.range);
        let previous_burn =
            uint.range_check::<128>(region, transition.predecessor.lineage.burned_total())?;
        let delta = uint.range_check::<128>(region, &delta)?;
        let new_burn = uint.checked_add(region, &previous_burn, &delta)?;
        GlueChip::assert_equal(
            region,
            new_burn.word(),
            transition.successor.lineage.burned_total(),
        )?;
        GlueChip::assert_equal(
            region,
            transition.predecessor.lineage.pending_root(),
            transition.successor.lineage.pending_root(),
        )?;
        let previous = transition.predecessor.state.core();
        let successor = transition.successor.state.core();
        for index in [
            core::BURNED_TOTAL,
            core::PENDING_OUTGOING_ROOT,
            core::FEE_CLAIM_ROOT,
            core::LOAD_REDEEM_ROOT,
        ] {
            GlueChip::assert_equal(region, &previous[index], &successor[index])?;
        }
        Ok(())
    }

    /// Authenticate and remove Archive's retained descriptor from the committed core.
    ///
    /// This hard owner binds the original statement/state pair and checks the
    /// exact successor core root. The separate adjusted-lineage owner remains
    /// mandatory; this method alone does not establish the complete transition.
    ///
    /// # Errors
    /// Wrong Archive variant or layout failure; descriptor, path, credit or
    /// committed successor-root substitution is unsatisfiable.
    pub fn archive_core_pending<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        descriptor: &[Word<Fp>; 7],
        removal: &RemoveCells<D>,
    ) -> Result<(), Error> {
        self.archive_descriptor(region, transition, descriptor, removal)?;
        self.bind(region, transition)?;
        let root = ImtChip::new(self.glue, self.range, self.sponge).remove(
            region,
            &transition.predecessor.state.core()[core::PENDING_OUTGOING_ROOT],
            &removal.predecessor,
            &removal.removed,
        )?;
        GlueChip::assert_equal(
            region,
            &root,
            &transition.successor.state.core()[core::PENDING_OUTGOING_ROOT],
        )
    }

    /// Authenticate Archive's adjusted pending removal and exact no-op branch.
    ///
    /// The path executes even when evidence is invalid. All unrelated state and
    /// held policy remain unchanged. The separate unconditional committed-core
    /// owner is mandatory; no intermediate root is proposed by either owner.
    ///
    /// # Errors
    /// Wrong Archive variant or layout failure; substituted descriptors, paths,
    /// adjusted roots or unrelated state changes are unsatisfiable.
    pub fn archive_lineage_pending<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        descriptor: &[Word<Fp>; 7],
        removal: &RemoveCells<D>,
        valid_evidence: &Bit<Fp>,
    ) -> Result<(), Error> {
        super::administrative::archive(
            &mut UintChip::new(self.glue, self.range),
            region,
            transition,
        )?;
        self.archive_descriptor(region, transition, descriptor, removal)?;
        let root = ImtChip::new(self.glue, self.range, self.sponge).remove(
            region,
            transition.predecessor.lineage.pending_root(),
            &removal.predecessor,
            &removal.removed,
        )?;
        let selected = self.glue.select(
            region,
            valid_evidence,
            &root,
            transition.predecessor.lineage.pending_root(),
        )?;
        GlueChip::assert_equal(
            region,
            &selected,
            transition.successor.lineage.pending_root(),
        )
    }

    fn archive_descriptor<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        descriptor: &[Word<Fp>; 7],
        removal: &RemoveCells<D>,
    ) -> Result<(), Error> {
        if !matches!(
            transition.statement.variant(),
            Variant::ArchiveReceive | Variant::ArchiveStatus
        ) {
            return Err(Error::Synthesis);
        }
        let credit = &transition.statement.fields()[17];
        GlueChip::assert_equal(region, &descriptor[0], credit)?;
        let value = self.sponge.hash_words(region, PENDING_DOMAIN, descriptor)?;
        GlueChip::assert_equal(region, removal.removed.leaf.key(), credit)?;
        GlueChip::assert_equal(region, removal.removed.leaf.value(), &value)
    }

    /// Compose both mandatory Archive pending-root owners.
    ///
    /// Both paths and the descriptor are hard-authenticated even on no-op.
    /// Invalid evidence preserves the adjusted pending leaf and unrelated state;
    /// the core removal is unconditional. This composition never authorizes
    /// deletion of the retained Payment before durable folding.
    ///
    /// # Errors
    /// Any failure of either exact map owner or the preserved-state relation.
    pub fn archive<const D: usize>(
        &mut self,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
        witness: &ArchiveMapWitness<D>,
        valid_evidence: &Bit<Fp>,
    ) -> Result<(), Error> {
        self.archive_core_pending(region, transition, &witness.descriptor, &witness.core)?;
        self.archive_lineage_pending(
            region,
            transition,
            &witness.descriptor,
            &witness.lineage,
            valid_evidence,
        )
    }
}

fn require_receive(statement: &StatementCells) -> Result<(), Error> {
    if matches!(
        statement.variant(),
        Variant::Receive | Variant::ReceiveRenewed
    ) {
        Ok(())
    } else {
        Err(Error::Synthesis)
    }
}

fn gated_equal(
    glue: &mut GlueChip<Fp>,
    region: &mut Region<'_, Fp>,
    enabled: &Bit<Fp>,
    left: &Word<Fp>,
    right: &Word<Fp>,
) -> Result<(), Error> {
    let delta = glue.sub(region, left, right)?;
    let selected = glue.mul(region, enabled.word(), &delta)?;
    GlueChip::assert_constant(region, &selected, Fp::ZERO)
}
