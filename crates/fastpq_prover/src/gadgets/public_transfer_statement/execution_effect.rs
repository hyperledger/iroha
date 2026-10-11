//! Strict complete-entry quantity effects over the shared two-update SMT relation.
//!
//! Transfer consumes balance/balance ports; mint and burn consume balance/supply
//! ports; retirement consumes zero-supply/lifecycle-presence ports. Arithmetic,
//! exact quantities, typed keys and original chronology are
//! checked here before generic SMT leaf bindings are constructed. Source facts
//! and final public inputs require independent authenticated expectations. Local
//! materialization establishes no finality, authorization or admission result.
//! TODO: replace the ordinary transfer-only source capture and artifact format
//! coherently before enabling this relation in any production proof dispatcher.

use iroha_allocation::{AllocationBudget, AllocationReservation, ChargedBuffer};

mod funded_paths;
mod funded_preparation;
use iroha_crypto::Hash;
use iroha_data_model::fastpq::{
    FastpqExecutionAssetV1, FastpqExecutionEffectKindV1, FastpqExecutionEffectStatementV1,
    FastpqExecutionEffectsV1, FastpqOperationKind, FastpqOrdinarySourceStatementLeafV1,
    FastpqPublicInputs, FastpqQuantityUnits, FastpqSourceRouteV1, FastpqStateTransition,
};
use iroha_primitives::numeric::Quantity;

use super::{
    PublicKeyAllocation, PublicPreparationWork, PublicTransferLimits, check_limit, checked_u32,
    digest_limbs, invariant,
    materialize::{
        CheckedUpdatePair, CheckedUpdateRow, CheckedUpdateTable, DerivedTransferSmtWitnesses,
        TransferSmtBuildLimits, derive_two_update_smt,
    },
    require_marked,
};
use crate::gadgets::compact_smt_air::{PublicStatement, PublicUpdate};
use crate::{PublicInputs, Result};

const KEY_DOMAIN: &[u8] = b"fastpq:execution-effects:v1:key|";
const ORDERING_DOMAIN: &[u8] = b"fastpq:execution-effects:v1:ordering|";
const STATEMENT_DOMAIN: &[u8] = b"fastpq:execution-effects:v1:statement|";

/// Explicit complete-entry public preparation limits; no private path work is included.
#[allow(
    clippy::struct_field_names,
    reason = "every field is an inclusive maximum, named like the crate's other `*Limits` policies"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionEffectLimits {
    /// Maximum original typed effects in one logical execution entry.
    pub max_effects: usize,
    /// Maximum participant rows, exactly twice the effect count.
    pub max_rows: usize,
    /// Maximum complete canonical statement frame bytes.
    pub max_public_bytes: usize,
    /// Maximum distinct complete tagged quantity keys.
    pub max_unique_keys: usize,
    /// Maximum occupied-interval lookups for deterministic path allocation.
    pub max_allocation_steps: usize,
}
impl Default for ExecutionEffectLimits {
    fn default() -> Self {
        let limits = PublicTransferLimits::default();
        Self {
            max_effects: limits.max_deltas,
            max_rows: limits.max_rows,
            max_public_bytes: limits.max_public_bytes,
            max_unique_keys: limits.max_unique_keys,
            max_allocation_steps: limits.max_allocation_steps,
        }
    }
}

/// Independent expectations obtained from authenticated execution/source state.
/// Copying these fields from the offered statement does not authenticate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionEffectExpectations {
    /// Exact complete original effect tape commitment.
    pub effects_digest: Hash,
    /// Exact complete canonical statement commitment, including all context.
    pub statement_digest: Hash,
    /// Exact expected public inputs, including externally authorized roots.
    pub public_inputs: FastpqPublicInputs,
}

/// One checked participant row; roles retain typed effect semantics instead of aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionEffectRow {
    /// Original contiguous effect ordinal, independent of key sorting.
    pub effect_ordinal: u32,
    /// Port zero then one: source/destination, balance/supply or zero-supply/lifecycle.
    pub leg: usize,
    /// Complete typed-key allocation index.
    pub key_index: usize,
    /// Exact common asset/incarnation scale; lifecycle presence always uses scale zero.
    pub scale: u32,
    /// Complete normalized pre-value.
    pub before: FastpqQuantityUnits,
    /// Complete normalized post-value.
    pub after: FastpqQuantityUnits,
    /// Original normalized operation amount, retained even for zero effects.
    pub amount: FastpqQuantityUnits,
    /// Exact leaf hashes and collision-resolved path consumed by the common AIR.
    pub update: PublicUpdate,
}

/// Private-field public table after complete statement/expectation and semantic checks.
pub struct PreparedExecutionEffects {
    public_inputs: PublicInputs,
    keys: funded_preparation::KeyAllocations,
    rows: ChargedBuffer<ExecutionEffectRow>,
    pairs: ChargedBuffer<[usize; 2]>,
    ordering_hash: Hash,
    work: PublicPreparationWork,
}
impl std::fmt::Debug for PreparedExecutionEffects {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedExecutionEffects")
            .field("public_inputs", &self.public_inputs)
            .field("keys", &self.keys)
            .field("rows", &self.rows.as_slice())
            .field("pairs", &self.pairs.as_slice())
            .field("ordering_hash", &self.ordering_hash)
            .field("work", &self.work)
            .finish()
    }
}
impl PreparedExecutionEffects {
    /// Participant bindings in the canonical key/operation row order.
    #[must_use]
    pub fn rows(&self) -> &[ExecutionEffectRow] {
        self.rows.as_slice()
    }
    /// Complete sorted typed quantity keys and paths.
    #[must_use]
    pub fn keys(&self) -> &[PublicKeyAllocation] {
        self.keys.as_slice()
    }
    /// Exact public preparation work; no SMT node hashes are included.
    #[must_use]
    pub const fn work(&self) -> PublicPreparationWork {
        self.work
    }
    /// Bind each chronological effect to independently committed intermediate roots.
    /// # Errors
    /// Rejects an incorrect root count or noncanonical hash marker.
    pub fn compact_statements(
        &self,
        intermediate: &[[u8; 32]],
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<ChargedBuffer<PublicStatement>> {
        if !reservation.belongs_to(budget) {
            return Err(crate::Error::AllocationForeignPool);
        }
        if intermediate.len() != self.pairs.as_slice().len().saturating_sub(1) {
            return Err(invariant(
                "execution effect intermediate-root count mismatch",
            ));
        }
        for root in intermediate {
            require_marked(root)?;
        }
        let mut statements =
            ChargedBuffer::from_reservation(self.pairs.as_slice().len(), reservation)?;
        let mut current = self.public_inputs.old_root;
        for (index, ports) in self.pairs.as_slice().iter().enumerate() {
            let next = intermediate
                .get(index)
                .copied()
                .unwrap_or(self.public_inputs.new_root);
            statements.push_reserved(PublicStatement {
                updates: [
                    self.rows.as_slice()[ports[0]].update,
                    self.rows.as_slice()[ports[1]].update,
                ],
                old_root: digest_limbs(current),
                new_root: digest_limbs(next),
            });
            current = next;
        }
        Ok(statements)
    }
    /// Materialize private paths and require exact independently expected old/new roots.
    /// # Errors
    /// Rejects limits, malformed internal ports or roots inconsistent with the public table.
    pub fn build_smt_witnesses(
        &self,
        limits: TransferSmtBuildLimits,
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<DerivedTransferSmtWitnesses> {
        let built = derive_two_update_smt(self, limits, budget, reservation)?;
        if built.roots() != (self.public_inputs.old_root, self.public_inputs.new_root) {
            return Err(invariant(
                "execution effect derived roots differ from public inputs",
            ));
        }
        Ok(built)
    }
}
impl CheckedUpdateTable for PreparedExecutionEffects {
    fn public_inputs(&self) -> PublicInputs {
        self.public_inputs
    }
    fn keys(&self) -> &[PublicKeyAllocation] {
        self.keys.as_slice()
    }
    fn row_count(&self) -> usize {
        self.rows.as_slice().len()
    }
    fn pair_count(&self) -> usize {
        self.pairs.as_slice().len()
    }
    fn row(&self, index: usize) -> Option<CheckedUpdateRow> {
        self.rows.as_slice().get(index).map(|row| CheckedUpdateRow {
            key_index: row.key_index,
            occurrence: [0, row.effect_ordinal, row.effect_ordinal],
            leg: row.leg,
            update: row.update,
        })
    }
    fn pair(&self, index: usize) -> Option<CheckedUpdatePair> {
        let ordinal = u32::try_from(index).ok()?;
        let ports = *self.pairs.as_slice().get(index)?;
        Some(CheckedUpdatePair {
            occurrence: [0, ordinal, ordinal],
            row_indices: ports,
            updates: [
                self.rows.as_slice().get(ports[0])?.update,
                self.rows.as_slice().get(ports[1])?.update,
            ],
        })
    }
}

/// Producer-owned local statement and paths; these do not certify execution or finality.
#[cfg(test)]
#[derive(Debug)]
pub struct ExecutionEffectMaterialization {
    /// Complete canonical statement retaining every original fact and occurrence.
    pub statement: FastpqExecutionEffectStatementV1,
    /// Exact private paths from the existing two-update SMT constructor.
    pub witnesses: DerivedTransferSmtWitnesses,
}

/// Borrowing source view of the one canonical complete-effect statement frame.
/// This projection never clones the original source tape or transition backing.
#[derive(Debug, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover.execution_effect.SourceExecutionEffectStatement",
    frame = "iroha_data_model::fastpq::FastpqExecutionEffectStatementV1"
)]
pub struct SourceExecutionEffectStatement<'a> {
    public_inputs: FastpqPublicInputs,
    ordering_hash: [u8; 32],
    transitions: &'a [FastpqStateTransition],
    effects: &'a FastpqExecutionEffectsV1,
}

impl<'a> SourceExecutionEffectStatement<'a> {
    /// Borrow the canonical fields of an offered owned statement without granting authority.
    #[must_use]
    pub fn from_owned(statement: &'a FastpqExecutionEffectStatementV1) -> Self {
        Self {
            public_inputs: statement.public_inputs,
            ordering_hash: statement.ordering_hash,
            transitions: &statement.transitions,
            effects: &statement.effects,
        }
    }

    /// Exact public fields, still requiring independently authenticated expectations.
    #[must_use]
    pub const fn public_inputs(&self) -> FastpqPublicInputs {
        self.public_inputs
    }

    /// Canonical complete operation-tagged row ordering commitment.
    #[must_use]
    pub const fn ordering_hash(&self) -> [u8; 32] {
        self.ordering_hash
    }

    /// Complete original effect tape retained by the statement owner.
    #[must_use]
    pub const fn effects(&self) -> &FastpqExecutionEffectsV1 {
        self.effects
    }

    /// Canonical statement commitment under the fixed complete-effect domain.
    /// # Errors
    /// Rejects canonical frame lengths beyond the explicit limit or encoding failures.
    pub fn digest(&self, max_bytes: usize) -> Result<Hash> {
        bounded_canonical_digest(STATEMENT_DOMAIN, self, max_bytes).map(|(digest, _)| digest)
    }
}

// Use the existing canonical sequence kernel; Norito deliberately does not
// implement SerializePayload for arbitrary references or typed slices.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover.execution_effect.TransitionSequence",
    frame = "alloc::vec::Vec<iroha_data_model::fastpq::FastpqStateTransition>"
)]
struct TransitionSequence<'a>(&'a [FastpqStateTransition]);
impl norito::SerializePayload for TransitionSequence<'_> {
    fn serialize(
        &self,
        writer: &mut norito::core::Encoder<'_>,
    ) -> std::result::Result<(), norito::Error> {
        norito::core::write_element_sequence::<FastpqStateTransition, _>(writer, self.0.iter())
    }
}
impl norito::SerializePayload for SourceExecutionEffectStatement<'_> {
    fn serialize(
        &self,
        writer: &mut norito::core::Encoder<'_>,
    ) -> std::result::Result<(), norito::Error> {
        norito::core::write_len_prefixed(writer, &self.public_inputs)?;
        // Derive treats this fixed byte array as a raw-byte field, not a Vec.
        norito::core::write_len(writer, 32)?;
        writer.write_all(&self.ordering_hash)?;
        norito::core::write_len_prefixed(writer, &TransitionSequence(self.transitions))?;
        norito::core::write_len_prefixed(writer, self.effects)
    }
}

/// Local materialization retaining a borrow of the original source-owned tape.
/// The caller must keep its original source owner alive for this result's lifetime.
/// Generated rows and their nested bytes retain original-pool charges.
#[derive(Debug)]
pub struct SourceExecutionEffectMaterialization<'a> {
    public_inputs: FastpqPublicInputs,
    ordering_hash: [u8; 32],
    transitions: funded_preparation::Transitions,
    effects: &'a FastpqExecutionEffectsV1,
    witnesses: DerivedTransferSmtWitnesses,
}
impl SourceExecutionEffectMaterialization<'_> {
    /// Borrow the exact original effects without materialization or a new owner.
    #[must_use]
    pub const fn effects(&self) -> &FastpqExecutionEffectsV1 {
        self.effects
    }

    /// Borrow private paths; no extraction can separate future original credit custody.
    #[must_use]
    pub const fn witnesses(&self) -> &DerivedTransferSmtWitnesses {
        &self.witnesses
    }

    /// Borrow one canonical statement serialization view of retained output and source.
    #[must_use]
    pub fn statement(&self) -> SourceExecutionEffectStatement<'_> {
        SourceExecutionEffectStatement {
            public_inputs: self.public_inputs,
            ordering_hash: self.ordering_hash,
            transitions: self.transitions.as_slice(),
            effects: self.effects,
        }
    }
}

/// Materialize an exact nonempty source leaf whose finality the caller already owns.
///
/// The original tape is checked against every representable source field before
/// materialization. Slot, permission context and transaction commitment are taken
/// from the independent leaf; old/new touched roots are derived locally. The leaf's
/// manifest position must be authenticated by its caller, since tape context does
/// not itself carry an inventory index. This helper creates no finality authority.
/// TODO: finish original source-tape dispatch and finalized source authentication
/// before exposing this private candidate module through a production dispatcher.
/// # Errors
/// Refuses empty/mismatched source tapes and all existing semantic/resource failures.
pub fn materialize_source_execution_effect_statement<'a>(
    effects: &'a FastpqExecutionEffectsV1,
    source: &FastpqOrdinarySourceStatementLeafV1,
    limits: ExecutionEffectLimits,
    tree_limits: TransferSmtBuildLimits,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<SourceExecutionEffectMaterialization<'a>> {
    let root = Hash::new(b"execution effect local root placeholder").into();
    let mut dsid = [0; 16];
    dsid[..8].copy_from_slice(&source.dataspace_id.as_u64().to_le_bytes());
    let inputs = FastpqPublicInputs {
        dsid,
        slot: source.slot,
        old_root: root,
        new_root: root,
        perm_root: source.perm_root,
        tx_set_hash: source.tx_set_hash,
    };
    check_source_leaf(effects, &inputs, source)?;
    let MaterializedEffectComponents {
        public_inputs,
        ordering_hash,
        transitions,
        witnesses,
    } = materialize_effect_components(
        effects,
        Hash::from_marked_bytes(source.effects_digest)
            .ok_or_else(|| invariant("execution effect source digest is noncanonical"))?,
        inputs,
        limits,
        tree_limits,
        budget,
        reservation,
    )?;
    let built = SourceExecutionEffectMaterialization {
        public_inputs,
        ordering_hash,
        transitions,
        effects,
        witnesses,
    };
    bounded_canonical_digest(
        STATEMENT_DOMAIN,
        &built.statement(),
        limits.max_public_bytes,
    )?;
    Ok(built)
}

/// Check the exact source leaf in addition to independent statement/root expectations.
///
/// Authenticating the supplied leaf and its ordered manifest position remains the
/// caller's responsibility. Existing complete statement, public-input, arithmetic,
/// row-order and root checks are retained without deriving authority from the offer.
/// # Errors
/// Refuses source/public-context substitution before any preparation allocation.
pub fn prepare_source_execution_effect_statement(
    statement: &FastpqExecutionEffectStatementV1,
    source: &FastpqOrdinarySourceStatementLeafV1,
    expected: ExecutionEffectExpectations,
    limits: ExecutionEffectLimits,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<PreparedExecutionEffects> {
    prepare_source_execution_effect_view(
        &SourceExecutionEffectStatement::from_owned(statement),
        source,
        expected,
        limits,
        budget,
        reservation,
    )
}

/// Prepare the original borrowed source statement without cloning its tape or rows.
/// # Errors
/// Rejects foreign credit, source/expectation substitution and all semantic limits.
pub fn prepare_source_execution_effect_view(
    statement: &SourceExecutionEffectStatement<'_>,
    source: &FastpqOrdinarySourceStatementLeafV1,
    expected: ExecutionEffectExpectations,
    limits: ExecutionEffectLimits,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<PreparedExecutionEffects> {
    if !reservation.belongs_to(budget) {
        return Err(crate::Error::AllocationForeignPool);
    }
    check_source_leaf(statement.effects, &statement.public_inputs, source)?;
    if expected.effects_digest.as_ref() != &source.effects_digest {
        return Err(invariant(
            "execution effect source digest expectation mismatch",
        ));
    }
    prepare_execution_effect_view(statement, expected, limits, budget, reservation)
}

/// Compare fixed source fields before normalization/tree allocation. Complete
/// effect hashing follows under the shared path's public size limits; diagnostic
/// errors retain the existing error representation.
fn check_source_leaf(
    effects: &FastpqExecutionEffectsV1,
    inputs: &FastpqPublicInputs,
    source: &FastpqOrdinarySourceStatementLeafV1,
) -> Result<()> {
    let mut dsid = [0; 16];
    dsid[..8].copy_from_slice(&source.dataspace_id.as_u64().to_le_bytes());
    require_marked(&source.effects_digest)?;
    if source.source.height == 0
        || source.effect_count == 0
        || usize::try_from(source.effect_count).ok() != Some(effects.effects.len())
        || source.statement_index > source.entry_index
        || effects.context.source != source.source
        || effects.context.entry.entry_hash != source.entry_hash
        || effects.context.entry.execution_kind != source.execution_kind
        || effects.context.entry.route != source.route
        || effects.context.entry.dataspace_id != source.dataspace_id
        || inputs.dsid != dsid
        || inputs.slot != source.slot
        || inputs.perm_root != source.perm_root
        || inputs.tx_set_hash != source.tx_set_hash
    {
        return Err(invariant(
            "execution effect independent source leaf mismatch",
        ));
    }
    Ok(())
}

/// Prepare the complete offered statement against independent expectations without SMT work.
/// # Errors
/// Rejects all count/byte/allocation bounds, commitment/input disagreement, malformed
/// lifecycle/context, arithmetic, missing/reordered effects, gaps and row mismatches.
pub fn prepare_execution_effect_statement(
    statement: &FastpqExecutionEffectStatementV1,
    expected: ExecutionEffectExpectations,
    limits: ExecutionEffectLimits,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<PreparedExecutionEffects> {
    prepare_execution_effect_view(
        &SourceExecutionEffectStatement::from_owned(statement),
        expected,
        limits,
        budget,
        reservation,
    )
}

fn prepare_execution_effect_view(
    statement: &SourceExecutionEffectStatement<'_>,
    expected: ExecutionEffectExpectations,
    limits: ExecutionEffectLimits,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<PreparedExecutionEffects> {
    if !reservation.belongs_to(budget) {
        return Err(crate::Error::AllocationForeignPool);
    }
    preflight(statement.effects, Some(statement.transitions), limits)?;
    let (statement_digest, frame_bytes) =
        bounded_canonical_digest(STATEMENT_DOMAIN, statement, limits.max_public_bytes)?;
    if statement_digest != expected.statement_digest
        || statement.public_inputs != expected.public_inputs
    {
        return Err(invariant(
            "execution effect independent statement expectation mismatch",
        ));
    }
    check_effects_digest(statement.effects, expected.effects_digest, limits)?;
    let (canonical, mut prepared) = funded_preparation::prepare(
        statement.effects,
        statement.public_inputs,
        limits,
        budget,
        reservation,
    )?;
    if canonical.as_slice() != statement.transitions
        || prepared.ordering_hash.as_ref() != &statement.ordering_hash
    {
        return Err(invariant(
            "execution effect canonical row/ordering mismatch",
        ));
    }
    prepared.work.public_bytes = frame_bytes;
    Ok(prepared)
}

/// Derive local touched-quantity roots from an independently expected complete effect tape.
///
/// All non-root public inputs remain exactly as supplied. No gap is filled and no
/// authorization or lifecycle token is generated. Returned roots concern only the
/// complete typed keys touched by this entry, not the global world state.
/// # Errors
/// Rejects count/byte/tree limits, facts commitment mismatch or any strict semantic failure.
#[cfg(test)]
fn materialize_execution_effect_statement(
    effects: &FastpqExecutionEffectsV1,
    expected_effects_digest: Hash,
    public_inputs: FastpqPublicInputs,
    limits: ExecutionEffectLimits,
    tree_limits: TransferSmtBuildLimits,
) -> Result<ExecutionEffectMaterialization> {
    // The owned fixture is a diagnostic oracle only. The source consumer below
    // borrows original tapes and never uses this test-only clone path.
    let bytes = materialization_allocation_bytes(effects, limits, tree_limits)?;
    let budget = AllocationBudget::new(bytes);
    let mut reservation = budget.try_reserve_bytes(bytes)?;
    let MaterializedEffectComponents {
        public_inputs,
        ordering_hash,
        transitions,
        witnesses,
    } = materialize_effect_components(
        effects,
        expected_effects_digest,
        public_inputs,
        limits,
        tree_limits,
        &budget,
        &mut reservation,
    )?;
    let statement = FastpqExecutionEffectStatementV1 {
        public_inputs,
        ordering_hash,
        transitions: transitions.fixture_copy(),
        effects: effects.clone(),
    };
    bounded_canonical_digest(STATEMENT_DOMAIN, &statement, limits.max_public_bytes)?;
    Ok(ExecutionEffectMaterialization {
        statement,
        witnesses,
    })
}

/// Conservative complete preparation/tree demand from the original input sizes.
/// No pool is created or acquired by this preflight; the caller funds it once.
/// # Errors
/// Rejects malformed sizes, public/tree limits and checked arithmetic overflow.
pub fn materialization_allocation_bytes(
    effects: &FastpqExecutionEffectsV1,
    limits: ExecutionEffectLimits,
    tree_limits: TransferSmtBuildLimits,
) -> Result<usize> {
    let public = funded_preparation::allocation_bytes(effects, limits)?;
    let rows = effects
        .effects
        .len()
        .checked_mul(2)
        .ok_or(iroha_allocation::AllocationRefusal::DemandOverflow)?;
    let keys = rows
        .min(limits.max_unique_keys)
        .min(tree_limits.max_unique_keys);
    let tree = tree_limits.allocation_bytes(rows, keys)?;
    public
        .checked_add(tree)
        .ok_or_else(|| iroha_allocation::AllocationRefusal::DemandOverflow.into())
}

/// Exact conservative backing demand for complete public preparation only.
/// # Errors
/// Rejects malformed input sizes, configured ceilings and checked arithmetic overflow.
pub fn preparation_allocation_bytes(
    effects: &FastpqExecutionEffectsV1,
    limits: ExecutionEffectLimits,
) -> Result<usize> {
    funded_preparation::allocation_bytes(effects, limits)
}

/// Owned generated fields; the original source tape is never part of this scratch.
struct MaterializedEffectComponents {
    public_inputs: FastpqPublicInputs,
    ordering_hash: [u8; 32],
    transitions: funded_preparation::Transitions,
    witnesses: DerivedTransferSmtWitnesses,
}

/// The single semantic/tree constructor shared by the source view and test oracle.
fn materialize_effect_components(
    effects: &FastpqExecutionEffectsV1,
    expected_effects_digest: Hash,
    mut public_inputs: FastpqPublicInputs,
    limits: ExecutionEffectLimits,
    tree_limits: TransferSmtBuildLimits,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<MaterializedEffectComponents> {
    if !reservation.belongs_to(budget) {
        return Err(crate::Error::AllocationForeignPool);
    }
    let demand = materialization_allocation_bytes(effects, limits, tree_limits)?;
    let mut reservation = reservation.try_partition_bytes(demand)?;
    preflight(effects, None, limits)?;
    check_limit(
        "max_execution_effect_tree_updates",
        effects
            .effects
            .len()
            .checked_mul(2)
            .ok_or_else(|| invariant("execution effect row count overflows"))?,
        tree_limits.max_updates,
    )?;
    check_effects_digest(effects, expected_effects_digest, limits)?;
    let mut scratch = public_inputs;
    if !effects.effects.is_empty() {
        let placeholder: [u8; 32] = Hash::new(b"execution effect local root placeholder").into();
        scratch.old_root = placeholder;
        scratch.new_root = placeholder;
    }
    let (transitions, prepared) =
        funded_preparation::prepare(effects, scratch, limits, budget, &mut reservation)?;
    let witnesses = derive_two_update_smt(&prepared, tree_limits, budget, &mut reservation)?;
    (public_inputs.old_root, public_inputs.new_root) = witnesses.roots();
    Ok(MaterializedEffectComponents {
        public_inputs,
        ordering_hash: prepared.ordering_hash.into(),
        transitions,
        witnesses,
    })
}

/// Hash one complete canonical frame without an output-sized allocation.
/// The measured public bound precedes streaming; the writer also enforces that
/// exact byte count, and no partial hash survives any encoder or writer refusal.
/// Nested serializer scratch remains a separate allocation obligation.
fn bounded_canonical_digest<T: norito::NoritoSerialize>(
    domain: &[u8],
    value: &T,
    max: usize,
) -> Result<(Hash, usize)> {
    use std::io::Write;

    struct ExactFrameWriter<'a> {
        inner: &'a mut dyn Write,
        expected: usize,
        written: usize,
    }
    impl Write for ExactFrameWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let next = self.written.checked_add(bytes.len()).ok_or_else(|| {
                std::io::Error::other("execution effect canonical frame length overflow")
            })?;
            if next > self.expected {
                return Err(std::io::Error::other(
                    "execution effect canonical frame exceeded measured bound",
                ));
            }
            self.inner.write_all(bytes)?;
            self.written = next;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    let length = norito::canonical_frame_len(value)?;
    check_limit("max_execution_effect_bytes", length, max)?;
    let mut encoding_error = None;
    let digest = Hash::new_from_writer(|writer| {
        writer.write_all(domain)?;
        let mut bounded = ExactFrameWriter {
            inner: writer,
            expected: length,
            written: 0,
        };
        norito::core::write_canonical_to_writer(value, &mut bounded).map_err(|error| {
            encoding_error = Some(error);
            std::io::Error::other("execution effect canonical encoding failed")
        })?;
        if bounded.written != length {
            return Err(std::io::Error::other(
                "execution effect canonical frame differs from measured bound",
            ));
        }
        Ok(())
    });
    if let Some(error) = encoding_error {
        return Err(error.into());
    }
    digest
        .map(|hash| (hash, length))
        .map_err(|_| invariant("execution effect bounded canonical streaming failed"))
}
fn check_effects_digest(
    effects: &FastpqExecutionEffectsV1,
    expected: Hash,
    limits: ExecutionEffectLimits,
) -> Result<()> {
    let length = norito::canonical_frame_len(effects)?;
    check_limit(
        "max_execution_effect_bytes",
        length,
        limits.max_public_bytes,
    )?;
    let digest = iroha_data_model::fastpq::execution_effects_digest_v1(effects)?;
    if digest != expected {
        return Err(invariant(
            "execution effect independent facts expectation mismatch",
        ));
    }
    Ok(())
}
fn preflight(
    effects: &FastpqExecutionEffectsV1,
    transitions: Option<&[FastpqStateTransition]>,
    limits: ExecutionEffectLimits,
) -> Result<()> {
    check_limit(
        "max_execution_effects",
        effects.effects.len(),
        limits.max_effects,
    )?;
    let count = effects
        .effects
        .len()
        .checked_mul(2)
        .ok_or_else(|| invariant("execution effect row count overflows"))?;
    checked_u32(count)?;
    check_limit("max_execution_effect_rows", count, limits.max_rows)?;
    if let Some(rows) = transitions {
        if rows.len() != count {
            return Err(invariant("execution effect row count mismatch"));
        }
        let mut bytes = 0usize;
        for row in rows {
            for value in [&row.key, &row.pre_value, &row.post_value] {
                bytes = bytes
                    .checked_add(value.len())
                    .ok_or_else(|| invariant("execution effect bytes overflow"))?;
                check_limit("max_execution_effect_bytes", bytes, limits.max_public_bytes)?;
            }
        }
    }
    // Stream exact field lengths before any complete tape/frame copy or normalized tables.
    let mut bytes = norito::canonical_frame_len(&effects.context)?;
    for effect in &effects.effects {
        bytes = bytes
            .checked_add(norito::canonical_frame_len(effect)?)
            .ok_or_else(|| invariant("execution effect bytes overflow"))?;
        check_limit("max_execution_effect_bytes", bytes, limits.max_public_bytes)?;
    }
    Ok(())
}

fn quantities(
    kind: &FastpqExecutionEffectKindV1,
) -> (&FastpqExecutionAssetV1, Option<[&Quantity; 5]>) {
    match kind {
        FastpqExecutionEffectKindV1::Transfer(t) => (
            &t.source.asset,
            Some([
                &t.amount,
                &t.source_before,
                &t.source_after,
                &t.destination_before,
                &t.destination_after,
            ]),
        ),
        FastpqExecutionEffectKindV1::Mint(t) | FastpqExecutionEffectKindV1::Burn(t) => (
            &t.balance.asset,
            Some([
                &t.amount,
                &t.balance_before,
                &t.balance_after,
                &t.supply_before,
                &t.supply_after,
            ]),
        ),
        FastpqExecutionEffectKindV1::Retire(asset) => (asset, None),
    }
}
fn operation_rank(operation: FastpqOperationKind) -> u8 {
    match operation {
        FastpqOperationKind::Transfer => 0,
        FastpqOperationKind::Mint => 1,
        FastpqOperationKind::Burn => 2,
        FastpqOperationKind::MetaSet => 3,
        _ => u8::MAX,
    }
}
fn inputs(value: FastpqPublicInputs) -> PublicInputs {
    PublicInputs {
        dsid: value.dsid,
        slot: value.slot,
        old_root: value.old_root,
        new_root: value.new_root,
        perm_root: value.perm_root,
        tx_set_hash: value.tx_set_hash,
    }
}

/// Check marked roots, source height, lane incarnation and empty-entry root equality.
fn check_context(
    effects: &FastpqExecutionEffectsV1,
    public_inputs: &FastpqPublicInputs,
) -> Result<()> {
    require_marked(&public_inputs.old_root)?;
    require_marked(&public_inputs.new_root)?;
    if effects.context.source.height == 0 {
        return Err(invariant("execution effect source height is zero"));
    }
    if let FastpqSourceRouteV1::Lane(lane) = effects.context.entry.route {
        require_marked(lane.lane_incarnation.as_ref())?;
    }
    if effects.effects.is_empty() && public_inputs.old_root != public_inputs.new_root {
        return Err(invariant(
            "empty execution effect statement changes its root",
        ));
    }
    Ok(())
}

/// Check one effect's typed arithmetic and return its two port keys and operation.
///
/// Transfers use source/destination balance ports; mint and burn use balance and
/// supply ports, where supply never falls below the balance.
fn check_effect_arithmetic(
    kind: &FastpqExecutionEffectKindV1,
    amount: FastpqQuantityUnits,
    port_values: &[FastpqQuantityUnits; 4],
) -> Result<FastpqOperationKind> {
    let [first_before, first_after, second_before, second_after] = *port_values;
    match kind {
        FastpqExecutionEffectKindV1::Retire(_) => {
            // The closed retirement operation uses fixed zero supply and exact
            // Boolean presence; validating these units needs no owned Quantity.
            if first_before.limbs().iter().any(|limb| *limb != 0)
                || first_after != first_before
                || second_before.limbs()[0] != 1
                || second_before.limbs()[1..].iter().any(|limb| *limb != 0)
                || second_after.limbs().iter().any(|limb| *limb != 0)
                || second_before.scale() != 0
                || second_after.scale() != 0
            {
                return Err(invariant(
                    "execution effect retirement presence/supply mismatch",
                ));
            }
            // The closed Retire variant determines exact supply/lifecycle ports.
            Ok(FastpqOperationKind::MetaSet)
        }
        FastpqExecutionEffectKindV1::Transfer(t) => {
            if t.source.asset != t.destination.asset {
                return Err(invariant(
                    "execution effect transfer crosses asset incarnations",
                ));
            }
            if first_before.checked_sub(&amount) != Some(first_after)
                || second_before.checked_add(&amount) != Some(second_after)
            {
                return Err(invariant("execution effect transfer arithmetic mismatch"));
            }
            Ok(FastpqOperationKind::Transfer)
        }
        FastpqExecutionEffectKindV1::Mint(t) | FastpqExecutionEffectKindV1::Burn(t) => {
            let mint = matches!(kind, FastpqExecutionEffectKindV1::Mint(_));
            if mint && t.amount.is_zero() {
                return Err(invariant("execution effect mint amount is zero"));
            }
            let arithmetic = if mint {
                first_before.checked_add(&amount) == Some(first_after)
                    && second_before.checked_add(&amount) == Some(second_after)
            } else {
                first_before.checked_sub(&amount) == Some(first_after)
                    && second_before.checked_sub(&amount) == Some(second_after)
            };
            if !arithmetic
                || second_before.checked_cmp(&first_before) == Some(std::cmp::Ordering::Less)
                || second_after.checked_cmp(&first_after) == Some(std::cmp::Ordering::Less)
            {
                return Err(invariant(
                    "execution effect balance/supply arithmetic mismatch",
                ));
            }
            Ok(if mint {
                FastpqOperationKind::Mint
            } else {
                FastpqOperationKind::Burn
            })
        }
    }
}

#[cfg(test)]
mod tests;
