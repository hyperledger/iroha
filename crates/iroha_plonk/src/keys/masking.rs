//! Exact public masking checks for source-qualified PIPA-R catalogs.
//!
//! Fixed rows are substituted into formal polynomials with physical-cell
//! aliases. Every gate/lookup that can read randomized tail advice is checked,
//! as are uncopied tail labels and the opening plan's independent pivots.
//! This is a source predicate, not a recursive soundness or wallet privacy proof.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    DescriptorBinding, Protocol,
    cs::{
        descriptor::{ExprNodeV1, ExprV1, QueryV1},
        descriptor_v2::ProtocolDescriptor,
    },
    keys::ProvingKey,
    pcs::multiopen::{OpeningPlan, Slot, SlotKind},
    protocol::check_zero_knowledge_budget,
};
use iroha_pasta::{CancellationToken, Fq, PastaCurve, PastaField};

type Check<T> = Result<T, String>;
const MAX_TERMS: usize = 100_000;
const MAX_CAPTURE_ROWS: usize = 262_144;
const MAX_CAPTURE_BYTES: usize = 64 << 20;

/// A public masking predicate or its bounded evaluation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Cooperative cancellation; no masking verdict was returned.
    Cancelled,
    /// Source, opening shape or bounded symbolic evaluation failed.
    Predicate(String),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("masking validation cancelled"),
            Self::Predicate(reason) => write!(f, "masking predicate: {reason}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::Predicate(value)
    }
}
impl From<iroha_pasta::Cancelled> for Error {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Cancelled
    }
}

/// Validate the actual fixed/copy tables and opening plan of an admitted key.
/// This grants no source or installation authority by itself.
/// # Errors
/// A masking predicate, resource bound or cancellation failed.
pub fn validate_proving_key<C: PastaCurve>(
    key: &ProvingKey<C>,
    cancellation: Option<&CancellationToken>,
) -> Result<(), Error> {
    validate_tables(
        key.binding(),
        key.fixed_values(),
        key.permutation_values(),
        cancellation,
    )
}

pub(super) fn validate_tables<F: PastaField>(
    binding: &DescriptorBinding,
    fixed: &[Vec<F>],
    sigma: &[Vec<F>],
    cancellation: Option<&CancellationToken>,
) -> Result<(), Error> {
    CancellationToken::checkpoint(cancellation)?;
    let d = binding.descriptor();
    if !binding.is_v2()
        || d.transcript != crate::cs::TranscriptV2::KagemushaPoseidonRp57Base
        || d.instance_mode != crate::cs::InstanceModeV1::Direct
        || d.proof_suffix != crate::cs::ProofSuffixV1::FoldedGenerator
    {
        return Err(Error::Predicate(
            "PIPA-R Direct folded-generator profile required".into(),
        ));
    }
    let (n, usable) = dimensions::<F>(d)?;
    if fixed.len() != d.num_fixed_columns as usize
        || sigma.len() != d.permutation.len()
        || fixed.iter().chain(sigma).any(|column| column.len() != n)
    {
        return Err(Error::Predicate("actual source table shape differs".into()));
    }
    let protocol = Protocol::new(d).map_err(|error| Error::Predicate(error.to_string()))?;
    check_zero_knowledge_budget(&protocol).map_err(|error| Error::Predicate(error.to_string()))?;
    opening_report(protocol.plan(), n, usize::from(d.blinding_factors))?;
    let selected = public_table_rows(d, n, usable)?;
    let cells = selected
        .len()
        .checked_mul(
            fixed
                .len()
                .checked_add(sigma.len())
                .ok_or_else(|| Error::Predicate("capture columns".into()))?,
        )
        .and_then(|value| value.checked_mul(32))
        .ok_or_else(|| Error::Predicate("capture extent".into()))?;
    if selected.len() > MAX_CAPTURE_ROWS || cells > MAX_CAPTURE_BYTES {
        return Err(Error::Predicate("bounded masking capture exceeded".into()));
    }
    let mut rows = BTreeMap::new();
    for row in selected {
        CancellationToken::checkpoint(cancellation)?;
        rows.insert(
            row,
            Row {
                fixed: fixed.iter().map(|col| col[row]).collect(),
                sigma: sigma.iter().map(|col| col[row]).collect(),
            },
        );
    }
    validate_public_rows(binding, &rows, cancellation)?;
    CancellationToken::checkpoint(cancellation)?;
    Ok(())
}

// Same variable for repeated/aliased queries into the same physical cell.
// Instance variables stay formal; only advice tail cells are randomized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Variable {
    instance: bool,
    column: u32,
    row: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Polynomial<F: PastaField = Fq>(BTreeMap<Vec<Variable>, F>);

impl<F: PastaField> Polynomial<F> {
    fn constant(value: F) -> Self {
        let terms = if value == F::ZERO {
            BTreeMap::new()
        } else {
            BTreeMap::from([(Vec::new(), value)])
        };
        Self(terms)
    }

    fn variable(variable: Variable) -> Self {
        Self(BTreeMap::from([(vec![variable], F::ONE)]))
    }

    fn add_term(&mut self, term: Vec<Variable>, value: F) -> Check<()> {
        let sum = self.0.get(&term).copied().unwrap_or(F::ZERO) + value;
        if sum == F::ZERO {
            self.0.remove(&term);
        } else {
            self.0.insert(term, sum);
        }
        if self.0.len() > MAX_TERMS {
            return Err("symbolic term cap".into());
        }
        Ok(())
    }

    fn add(mut self, other: Self) -> Check<Self> {
        for (term, value) in other.0 {
            self.add_term(term, value)?;
        }
        Ok(self)
    }

    fn scale(mut self, value: F) -> Self {
        if value == F::ZERO {
            self.0.clear();
        } else {
            for coefficient in self.0.values_mut() {
                *coefficient *= value;
            }
        }
        self
    }

    fn multiply(self, other: Self) -> Check<Self> {
        if self.0.len().saturating_mul(other.0.len()) > 10 * MAX_TERMS {
            return Err("symbolic product cap".into());
        }
        let mut output = Self::constant(F::ZERO);
        for (left, a) in self.0 {
            for (right, b) in &other.0 {
                let mut term = left.clone();
                term.extend_from_slice(right);
                term.sort_unstable();
                output.add_term(term, a * b)?;
            }
        }
        Ok(output)
    }

    fn touches_tail(&self, usable: usize) -> bool {
        self.0
            .keys()
            .flatten()
            .any(|variable| !variable.instance && variable.row >= usable)
    }
}

#[derive(Clone, Debug)]
/// Public evaluations captured from an independently source-qualified original.
/// This data structure grants no source or installation authority.
pub struct PublicRow<F: PastaField = Fq> {
    /// Actual expanded fixed-column values at this physical row.
    pub fixed: Vec<F>,
    /// Actual permutation-column values at this physical row.
    pub sigma: Vec<F>,
}
type Row<F = Fq> = PublicRow<F>;

/// The complete physical-row closure required by the masking predicate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiredRows {
    /// Every gate or lookup evaluation row that can read randomized advice.
    pub evaluation: BTreeSet<usize>,
    /// Evaluation rows plus every public fixed cell read at those rows.
    pub public: BTreeSet<usize>,
}

/// Compute the bounded public-row capture needed for an exact descriptor.
/// # Errors
/// Invalid geometry or the finite row-work/capture bound was exceeded.
pub fn required_rows(binding: &DescriptorBinding) -> Result<RequiredRows, Error> {
    let d = binding.descriptor();
    let n = binding.n();
    let usable = n
        .checked_sub(usize::from(d.blinding_factors) + 1)
        .filter(|value| *value > 1)
        .ok_or_else(|| Error::Predicate("usable rows".into()))?;
    Ok(RequiredRows {
        evaluation: boundary_rows(d, n, usable)?,
        public: public_table_rows(d, n, usable)?,
    })
}

/// Evaluate the opening-rank and private/R pivot predicates for this descriptor.
/// This is public DATA validation and grants no source authority.
/// # Errors
/// Profile, geometry, S7 budget or opening pivot failure.
pub fn report(binding: &DescriptorBinding) -> Result<Vec<String>, Error> {
    let d = binding.descriptor();
    if !binding.is_v2()
        || d.transcript != crate::cs::TranscriptV2::KagemushaPoseidonRp57Base
        || d.instance_mode != crate::cs::InstanceModeV1::Direct
        || d.proof_suffix != crate::cs::ProofSuffixV1::FoldedGenerator
    {
        return Err(Error::Predicate(
            "PIPA-R Direct folded-generator profile required".into(),
        ));
    }
    let protocol = Protocol::new(d).map_err(|error| Error::Predicate(error.to_string()))?;
    check_zero_knowledge_budget(&protocol).map_err(|error| Error::Predicate(error.to_string()))?;
    opening_report(
        protocol.plan(),
        protocol.shape().n,
        protocol.shape().blinding_factors,
    )
    .map_err(Error::from)
}

/// Check captured public rows with the same predicate as strict masked admission.
/// The caller must independently bind these rows to the exact admitted source;
/// arbitrary caller-supplied tables cannot create an admission capability.
/// # Errors
/// Profile, field, required row/column, support, rank, pivot or cancellation failure.
pub fn validate_public_rows<F: PastaField>(
    binding: &DescriptorBinding,
    rows: &BTreeMap<usize, PublicRow<F>>,
    cancellation: Option<&CancellationToken>,
) -> Result<(), Error> {
    CancellationToken::checkpoint(cancellation)?;
    report(binding)?;
    let required = required_rows(binding)?;
    let d = binding.descriptor();
    let bytes = required
        .public
        .len()
        .checked_mul(d.num_fixed_columns as usize + d.permutation.len())
        .and_then(|value| value.checked_mul(32))
        .ok_or_else(|| Error::Predicate("capture extent".into()))?;
    if bytes > MAX_CAPTURE_BYTES || rows.len() > MAX_CAPTURE_ROWS {
        return Err(Error::Predicate("bounded masking capture exceeded".into()));
    }
    for row in required.public {
        CancellationToken::checkpoint(cancellation)?;
        let values = rows
            .get(&row)
            .ok_or_else(|| Error::Predicate("missing required public row".into()))?;
        if values.fixed.len() != d.num_fixed_columns as usize
            || values.sigma.len() != d.permutation.len()
        {
            return Err(Error::Predicate("required public column count".into()));
        }
    }
    check_boundary_cancellable(d, rows, cancellation)?;
    CancellationToken::checkpoint(cancellation)?;
    Ok(())
}

fn canonical<F: PastaField>(bytes: [u8; 32]) -> Check<F> {
    Option::from(F::from_repr(bytes)).ok_or_else(|| "noncanonical scalar".to_owned())
}

fn dimensions<F: PastaField>(descriptor: &ProtocolDescriptor) -> Check<(usize, usize)> {
    let mut modulus = (-F::ONE).to_repr();
    for byte in &mut modulus {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    if descriptor.scalar_modulus != modulus || descriptor.curve.scalar_modulus() != modulus {
        return Err("mask scalar field differs from descriptor".into());
    }
    let n = 1_usize
        .checked_shl(u32::from(descriptor.k))
        .ok_or("domain size")?;
    let usable = n
        .checked_sub(usize::from(descriptor.blinding_factors) + 1)
        .filter(|usable| *usable > 1)
        .ok_or("usable rows")?;
    if u32::from(descriptor.k) > F::S {
        return Err("field domain size".into());
    }
    Ok((n, usable))
}

// Every gate/lookup row that can read randomized advice, plus every tail
// row. Outside this closure no advice variable can be a randomized tail cell.
// Retain the former end rows as redundant checks for the public-role profiles.
fn boundary_rows(
    descriptor: &ProtocolDescriptor,
    n: usize,
    usable: usize,
) -> Check<BTreeSet<usize>> {
    let work = descriptor
        .advice_queries
        .len()
        .checked_add(1)
        .and_then(|count| count.checked_mul(n.checked_sub(usable)?))
        .and_then(|count| count.checked_add(2))
        .ok_or("boundary work extent")?;
    if work > MAX_CAPTURE_ROWS {
        return Err("bounded boundary work exceeded".into());
    }
    let mut rows: BTreeSet<_> = [0, usable - 1].into_iter().chain(usable..n).collect();
    for query in &descriptor.advice_queries {
        for tail in usable..n {
            rows.insert(shifted(tail, -i64::from(query.rotation), n)?);
        }
    }
    Ok(rows)
}

// Fixed columns are public constants. Read their actual rotated cells, even
// when those cells are outside the mask-dependent evaluation-row closure.
fn public_table_rows(
    descriptor: &ProtocolDescriptor,
    n: usize,
    usable: usize,
) -> Check<BTreeSet<usize>> {
    let evaluation = boundary_rows(descriptor, n, usable)?;
    let work = evaluation
        .len()
        .checked_mul(
            descriptor
                .fixed_queries
                .len()
                .checked_add(1)
                .ok_or("fixed work extent")?,
        )
        .ok_or("fixed work extent")?;
    if work > MAX_CAPTURE_ROWS {
        return Err("bounded public-row work exceeded".into());
    }
    let mut rows = evaluation.clone();
    for row in evaluation {
        for query in &descriptor.fixed_queries {
            rows.insert(rotated(row, query.rotation, n)?);
        }
    }
    Ok(rows)
}

fn omega<F: PastaField>(k: u8) -> F {
    let mut root = F::ROOT_OF_UNITY;
    for _ in u32::from(k)..F::S {
        root = root.square();
    }
    root
}

fn shifted(row: usize, rotation: i64, n: usize) -> Check<usize> {
    let n = i64::try_from(n).map_err(|_| "domain extent")?;
    if n <= 1 {
        return Err("domain extent".into());
    }
    let row = i64::try_from(row).map_err(|_| "row extent")?;
    if !(0..n).contains(&row) {
        return Err("row extent".into());
    }
    let sum = row.checked_add(rotation).ok_or("rotation extent")?;
    usize::try_from(sum.rem_euclid(n)).map_err(|_| "rotated row extent".into())
}

fn rotated(row: usize, rotation: i32, n: usize) -> Check<usize> {
    shifted(row, i64::from(rotation), n)
}

fn symbolic<F: PastaField>(
    descriptor: &ProtocolDescriptor,
    rows: &BTreeMap<usize, Row<F>>,
    row: usize,
    n: usize,
    expression: &ExprV1,
) -> Check<Polynomial<F>> {
    let query = |queries: &[QueryV1], index: u32, instance: bool| -> Check<Polynomial<F>> {
        let query = queries.get(index as usize).ok_or("query index")?;
        Ok(Polynomial::variable(Variable {
            instance,
            column: query.column,
            row: rotated(row, query.rotation, n)?,
        }))
    };
    let mut stack: Vec<Polynomial<F>> = Vec::new();
    for node in expression {
        // Exhaustive typed dispatch: unknown wire tags fail descriptor decode;
        // adding a new node requires an explicit symbolic interpretation here.
        let value = match *node {
            ExprNodeV1::Constant(value) => Polynomial::constant(canonical(value)?),
            ExprNodeV1::Fixed(index) => {
                let query = descriptor
                    .fixed_queries
                    .get(index as usize)
                    .ok_or("fixed query index")?;
                let fixed_row = rotated(row, query.rotation, n)?;
                let value = rows
                    .get(&fixed_row)
                    .and_then(|values| values.fixed.get(query.column as usize))
                    .ok_or("fixed row/column")?;
                Polynomial::constant(*value)
            }
            ExprNodeV1::Advice(index) => query(&descriptor.advice_queries, index, false)?,
            ExprNodeV1::Instance(index) => query(&descriptor.instance_queries, index, true)?,
            ExprNodeV1::Negated | ExprNodeV1::Scaled(_) => {
                let value = stack.pop().ok_or("unary stack")?;
                value.scale(match *node {
                    ExprNodeV1::Scaled(bytes) => canonical(bytes)?,
                    _ => -F::ONE,
                })
            }
            ExprNodeV1::Sum | ExprNodeV1::Product => {
                let right = stack.pop().ok_or("binary stack")?;
                let left = stack.pop().ok_or("binary stack")?;
                if *node == ExprNodeV1::Sum {
                    left.add(right)?
                } else {
                    left.multiply(right)?
                }
            }
        };
        stack.push(value);
        if stack.len() > 1024 {
            return Err("expression stack cap".into());
        }
    }
    if stack.len() != 1 {
        return Err("final expression stack".into());
    }
    stack.pop().ok_or_else(|| "empty expression".into())
}

#[cfg(test)]
fn check_boundary<F: PastaField>(
    descriptor: &ProtocolDescriptor,
    rows: &BTreeMap<usize, Row<F>>,
) -> Check<()> {
    check_boundary_cancellable(descriptor, rows, None).map_err(|error| error.to_string())
}

fn check_boundary_cancellable<F: PastaField>(
    descriptor: &ProtocolDescriptor,
    rows: &BTreeMap<usize, Row<F>>,
    cancellation: Option<&CancellationToken>,
) -> Result<(), Error> {
    let (n, usable) = dimensions::<F>(descriptor)?;
    for query in &descriptor.fixed_queries {
        rotated(0, query.rotation, n)?;
        if query.column >= descriptor.num_fixed_columns {
            return Err(Error::Predicate("fixed query column".into()));
        }
    }
    for (queries, columns) in [
        (
            &descriptor.advice_queries,
            descriptor.num_advice_columns as usize,
        ),
        (
            &descriptor.instance_queries,
            descriptor.instance_lengths.len(),
        ),
    ] {
        for query in queries {
            rotated(0, query.rotation, n)?;
            if query.column as usize >= columns {
                return Err(Error::Predicate("query column".into()));
            }
        }
    }
    let root = omega::<F>(descriptor.k);
    for row in boundary_rows(descriptor, n, usable)? {
        CancellationToken::checkpoint(cancellation)?;
        let values = rows
            .get(&row)
            .ok_or_else(|| Error::Predicate("missing boundary row".into()))?;
        if values.fixed.len() != descriptor.num_fixed_columns as usize
            || values.sigma.len() != descriptor.permutation.len()
        {
            return Err(Error::Predicate("boundary column count".into()));
        }
        if row >= usable {
            if values.fixed.iter().any(|value| *value != F::ZERO) {
                return Err(Error::Predicate(format!("nonzero fixed tail row={row}")));
            }
            let mut expected = root.pow_vartime([
                u64::try_from(row).map_err(|_| Error::Predicate("row extent".into()))?
            ]);
            for value in &values.sigma {
                if *value != expected {
                    return Err(Error::Predicate(format!("tail copy not fixed row={row}")));
                }
                expected *= F::DELTA;
            }
        }
        for (gate, expressions) in descriptor.gates.iter().enumerate() {
            for (index, expression) in expressions.iter().enumerate() {
                let polynomial = symbolic(descriptor, rows, row, n, expression)?;
                if polynomial.touches_tail(usable) {
                    return Err(Error::Predicate(format!(
                        "gate tail dependence row={row} gate={gate} expr={index}"
                    )));
                }
                if row >= usable && !polynomial.0.is_empty() {
                    return Err(Error::Predicate(format!(
                        "tail gate not zero row={row} gate={gate} expr={index}"
                    )));
                }
            }
        }
        if row < usable {
            for (lookup, pair) in descriptor.lookups.iter().enumerate() {
                for (side, expressions) in [("input", &pair.inputs), ("table", &pair.tables)] {
                    for (index, expression) in expressions.iter().enumerate() {
                        if symbolic(descriptor, rows, row, n, expression)?.touches_tail(usable) {
                            return Err(Error::Predicate(format!(
                                "lookup tail dependence row={row} lookup={lookup} side={side} expr={index}"
                            )));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

// Counts independent *domain rows*, not commitment blinds. Blinds are an
// additional independent scalar per commitment and do not replace row rank.
fn fresh_rows(kind: SlotKind, n: usize, b: usize) -> Option<usize> {
    match kind {
        SlotKind::Advice | SlotKind::LookupPermutedInput | SlotKind::LookupPermutedTable => {
            Some(b + 1)
        }
        SlotKind::PermutationProduct | SlotKind::LookupProduct => Some(b),
        SlotKind::Random => Some(n),
        SlotKind::Instance | SlotKind::Fixed | SlotKind::PermutationSigma | SlotKind::Vanishing => {
            None
        }
    }
}

fn opening_report(plan: &OpeningPlan, n: usize, b: usize) -> Check<Vec<String>> {
    let slots = plan.slots();
    let h = Slot::new(SlotKind::Vanishing, 0);
    let r = Slot::new(SlotKind::Random, 0);
    if slots.last().map(|s| s.slot) != Some(r)
        || slots
            .iter()
            .filter(|s| s.slot.kind == SlotKind::Random)
            .count()
            != 1
        || slots
            .iter()
            .filter(|s| s.slot.kind == SlotKind::Vanishing)
            .count()
            != 1
    {
        return Err("h/R uniqueness or R not last".into());
    }
    let h_slot = slots.iter().find(|s| s.slot == h).ok_or("missing h")?;
    let r_slot = slots.last().ok_or("missing R")?;
    if h_slot.set != r_slot.set
        || h_slot.points.len() != 1
        || plan.rotations().get(h_slot.points[0]) != Some(&0)
        || h_slot.points != r_slot.points
    {
        return Err("h/R must share exactly rotation zero".into());
    }
    let n_i64 = i64::try_from(n).map_err(|_| "domain extent")?;
    if n_i64 <= 1 || b >= n || b < 2 {
        return Err("mask dimensions".into());
    }
    let mut reduced = std::collections::BTreeSet::new();
    for rotation in plan.rotations() {
        if !reduced.insert(i64::from(*rotation).rem_euclid(n_i64)) {
            return Err("rotation alias modulo n".into());
        }
    }
    let mut output = Vec::new();
    for slot in slots {
        let rotations: Vec<_> = slot.points.iter().map(|i| plan.rotations()[*i]).collect();
        if slot.slot.kind == SlotKind::Instance {
            return Err("mask predicate requires Direct instances".into());
        }
        if let Some(fresh) = fresh_rows(slot.slot.kind, n, b) {
            let revealed = slot
                .points
                .len()
                .checked_add(1)
                .ok_or("evaluation extent")?;
            let residual = fresh
                .checked_sub(revealed)
                .filter(|v| *v > 0)
                .ok_or("no residual mask rank")?;
            if slot.slot.kind != SlotKind::Random && revealed > b - 1 {
                return Err("S7 opening budget".into());
            }
            output.push(format!("slot={:?}:{} set={} rotations={rotations:?} fresh_rows={fresh} rank_with_x3={revealed} residual={residual}", slot.slot.kind,slot.slot.index,slot.set));
        } else {
            output.push(format!(
                "slot={:?}:{} set={} rotations={rotations:?} fresh_rows=0",
                slot.slot.kind, slot.slot.index, slot.set
            ));
        }
    }
    for (set, points) in plan.sets().iter().enumerate() {
        let members: Vec<_> = slots.iter().filter(|s| s.set == set).collect();
        if members.is_empty() {
            return Err("empty opening group".into());
        }
        let branch = if set == h_slot.set {
            // The production Horner fold walks *forward* slot order. Thus the
            // globally last R is last in this group and has coefficient ONE.
            if members.last().map(|s| s.slot) != Some(r) {
                return Err("R coefficient not one".into());
            }
            "quotient_R_coefficient_one"
        } else if members
            .iter()
            .any(|s| fresh_rows(s.slot.kind, n, b).is_some())
        {
            // Forward Horner order gives the final private slot coefficient one,
            // including raw x1 = zero. An earlier private slot is insufficient.
            if members.last().is_none_or(|last| {
                last.slot.kind == SlotKind::Random || fresh_rows(last.slot.kind, n, b).is_none()
            }) {
                return Err("private residual coefficient not one".into());
            }
            "residual_witness_coefficient_one"
        } else if members
            .iter()
            .all(|s| matches!(s.slot.kind, SlotKind::Fixed | SlotKind::PermutationSigma))
        {
            // These evaluations are deterministic public preprocessing. They
            // MUST NOT be sampled uniformly by the outer proof simulator.
            "exact_public_preprocessing"
        } else {
            return Err("uncovered opening group".into());
        };
        let rotations: Vec<_> = points.iter().map(|i| plan.rotations()[*i]).collect();
        output.push(format!("set={set} rotations={rotations:?} branch={branch}"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct BoundarySource {
        enabled_row: usize,
    }

    impl<F: PastaField> crate::frontend::Circuit<F> for BoundarySource {
        type Config = (crate::cs::Column<crate::cs::Advice>, crate::cs::Selector);
        type FloorPlanner = crate::frontend::SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            *self
        }

        fn configure(meta: &mut crate::cs::ConstraintSystem<F>) -> Self::Config {
            let advice = meta.advice_column();
            let selector = meta.selector();
            meta.create_gate("rotated masked source", |cells| {
                vec![
                    cells.query_selector(selector)
                        * (cells.query_advice(advice, crate::cs::Rotation::next())
                            - cells.query_advice(advice, crate::cs::Rotation::cur())),
                ]
            });
            (advice, selector)
        }

        fn synthesize(
            &self,
            (_advice, selector): Self::Config,
            mut layouter: impl crate::frontend::Layouter<F>,
        ) -> Result<(), crate::frontend::Error> {
            layouter.assign_region(
                || "actual source selector",
                |mut region| {
                    selector.enable(&mut region, self.enabled_row)?;
                    Ok(())
                },
            )
        }
    }

    fn strict_masking_admission<C: PastaCurve>() {
        use crate::keys::{
            CosetCachePolicy, KeygenConfigV2, SourceBoundVerifyingKeyV2, keygen_pk_v2, pk::artifact,
        };
        let params = crate::pcs::ipa::PinnedParams::<C>::derive(6).unwrap();
        for enabled_row in [0, 57] {
            let circuit = BoundarySource { enabled_row };
            let key = keygen_pk_v2(&params, &circuit, &KeygenConfigV2::pipa_r(vec![])).unwrap();
            assert_eq!(key.binding().descriptor().blinding_factors, 5);
            let bytes = key.artifact_bytes_v2().unwrap();
            let config = artifact::ReadConfig {
                maximum_bytes: bytes.len(),
                maximum_rows: 64,
                coset_cache: CosetCachePolicy::OnDemand,
                msm_budget: iroha_pasta::msm::MemoryBudget::DEFAULT,
            };
            // Generic admission alone checks the exact source and VK but does
            // not establish independence from randomized advice tail rows.
            SourceBoundVerifyingKeyV2::from_artifact_v2(
                &bytes,
                key.binding(),
                &params,
                &circuit,
                config,
            )
            .unwrap();
            let metadata = SourceBoundVerifyingKeyV2::from_masked_artifact_v2(
                &bytes,
                key.binding(),
                &params,
                &circuit,
                config,
            );
            let full = ProvingKey::from_masked_artifact_v2(
                &bytes,
                key.binding(),
                &params,
                &circuit,
                config,
            );
            if enabled_row == 0 {
                assert_eq!(
                    metadata.unwrap().verifying_key().to_bytes(),
                    key.vk().to_bytes()
                );
                assert_eq!(full.unwrap().artifact_bytes_v2().unwrap(), bytes);
                validate_proving_key(&key, None).unwrap();
                let mut changed = bytes.clone();
                *changed.last_mut().unwrap() ^= 1;
                assert!(
                    SourceBoundVerifyingKeyV2::from_masked_artifact_v2(
                        &changed,
                        key.binding(),
                        &params,
                        &circuit,
                        config
                    )
                    .is_err()
                );
                let different = BoundarySource { enabled_row: 1 };
                assert!(
                    SourceBoundVerifyingKeyV2::from_masked_artifact_v2(
                        &bytes,
                        key.binding(),
                        &params,
                        &different,
                        config
                    )
                    .is_err()
                );
            } else {
                assert!(matches!(
                    metadata,
                    Err(artifact::Error::Masking(Error::Predicate(_)))
                ));
                assert!(matches!(
                    full,
                    Err(artifact::Error::Masking(Error::Predicate(_)))
                ));
                assert!(
                    validate_proving_key(&key, None)
                        .unwrap_err()
                        .to_string()
                        .contains("gate tail dependence")
                );
            }
            let signal = CancellationToken::new();
            signal.cancel();
            assert!(matches!(
                validate_proving_key(&key, Some(&signal)),
                Err(Error::Cancelled)
            ));
            assert!(matches!(
                SourceBoundVerifyingKeyV2::from_masked_artifact_v2_cancellable(
                    &bytes,
                    key.binding(),
                    &params,
                    &circuit,
                    config,
                    Some(&signal)
                ),
                Err(artifact::Error::Cancelled)
            ));
            assert!(matches!(
                ProvingKey::from_masked_artifact_v2_cancellable(
                    &bytes,
                    key.binding(),
                    &params,
                    &circuit,
                    config,
                    Some(&signal)
                ),
                Err(artifact::Error::Cancelled)
            ));
        }
    }

    #[test]
    fn strict_admission_retains_source_checks_and_requires_masking_both_curves() {
        strict_masking_admission::<iroha_pasta::Ep>();
        strict_masking_admission::<iroha_pasta::Eq>();
    }
    use crate::cs::descriptor::{
        ColumnKindV1, LookupKindV1, LookupV1, PermutationColumnV1, SelectorsV1,
    };
    use crate::cs::{CurveV1, InstanceModeV1, ProofSuffixV1, TranscriptV2};
    use ff::{Field, PrimeField};
    use iroha_pasta::Fp;

    // Small DATA for the same exact predicate; no witness or key generation.
    fn fixture() -> (ProtocolDescriptor, BTreeMap<usize, Row>) {
        let descriptor = ProtocolDescriptor {
            protocol_version: 1,
            curve: CurveV1::Pallas,
            base_modulus: CurveV1::Pallas.base_modulus(),
            scalar_modulus: CurveV1::Pallas.scalar_modulus(),
            params_digest: [1; 32],
            k: 3,
            transcript: TranscriptV2::KagemushaPoseidonRp57Base,
            instance_mode: InstanceModeV1::Direct,
            proof_suffix: ProofSuffixV1::FoldedGenerator,
            degree: 3,
            blinding_factors: 1,
            permutation_chunk_len: 1,
            quotient_pieces: 2,
            lookup_kind: LookupKindV1::Halo2Permuted,
            num_fixed_columns: 1,
            num_advice_columns: 1,
            instance_lengths: vec![1],
            fixed_queries: vec![QueryV1 {
                column: 0,
                rotation: 0,
            }],
            advice_queries: vec![QueryV1 {
                column: 0,
                rotation: 0,
            }],
            instance_queries: vec![QueryV1 {
                column: 0,
                rotation: 0,
            }],
            selectors: SelectorsV1 {
                compress: true,
                first_column: 0,
                entries: vec![],
            },
            gates: vec![vec![vec![
                ExprNodeV1::Fixed(0),
                ExprNodeV1::Advice(0),
                ExprNodeV1::Product,
            ]]],
            permutation: vec![
                PermutationColumnV1 {
                    kind: ColumnKindV1::Advice,
                    index: 0,
                },
                PermutationColumnV1 {
                    kind: ColumnKindV1::Fixed,
                    index: 0,
                },
            ],
            lookups: vec![LookupV1 {
                inputs: vec![vec![ExprNodeV1::Advice(0)]],
                tables: vec![vec![ExprNodeV1::Fixed(0)]],
            }],
            instance_types: None,
        };
        let rows = (0..8)
            .map(|row| {
                (
                    row,
                    Row {
                        fixed: vec![if row < 6 { Fq::ONE } else { Fq::ZERO }],
                        sigma: vec![
                            omega::<Fq>(3).pow_vartime([u64::try_from(row).unwrap()]),
                            Fq::DELTA * omega::<Fq>(3).pow_vartime([u64::try_from(row).unwrap()]),
                        ],
                    },
                )
            })
            .collect();
        (descriptor, rows)
    }

    #[test]
    fn exact_cancellation_and_physical_query_aliases_pass() {
        let (mut d, rows) = fixture();
        check_boundary(&d, &rows).unwrap();
        d.advice_queries.push(d.advice_queries[0]);
        d.gates.push(vec![vec![
            ExprNodeV1::Advice(0),
            ExprNodeV1::Advice(1),
            ExprNodeV1::Negated,
            ExprNodeV1::Sum,
            ExprNodeV1::Instance(0),
            ExprNodeV1::Product,
            ExprNodeV1::Scaled(Fq::from(7).to_repr()),
        ]]);
        check_boundary(&d, &rows).unwrap();
        d.advice_queries.push(QueryV1 {
            column: 0,
            rotation: 1,
        });
        // Expand both products before cancellation, even where a_next is a pad.
        d.gates.push(vec![vec![
            ExprNodeV1::Advice(0),
            ExprNodeV1::Advice(2),
            ExprNodeV1::Product,
            ExprNodeV1::Advice(2),
            ExprNodeV1::Advice(0),
            ExprNodeV1::Product,
            ExprNodeV1::Negated,
            ExprNodeV1::Sum,
        ]]);
        check_boundary(&d, &rows).unwrap();
    }

    #[test]
    fn next_and_previous_usable_gates_cannot_touch_randomized_tail() {
        for (rotation, row) in [(1, 5), (-1, 0)] {
            let (mut d, rows) = fixture();
            d.advice_queries.push(QueryV1 {
                column: 0,
                rotation,
            });
            // q * (a_rot - a_cur): all tail fixed/copy checks still pass.
            d.gates[0][0] = vec![
                ExprNodeV1::Fixed(0),
                ExprNodeV1::Advice(1),
                ExprNodeV1::Advice(0),
                ExprNodeV1::Negated,
                ExprNodeV1::Sum,
                ExprNodeV1::Product,
            ];
            assert!(
                check_boundary(&d, &rows)
                    .unwrap_err()
                    .contains(&format!("gate tail dependence row={row}"))
            );
        }
    }

    #[test]
    fn tail_fixed_copy_and_nonzero_gate_mutations_refuse() {
        let (d, rows) = fixture();
        let mut changed = rows.clone();
        changed.get_mut(&6).unwrap().fixed[0] = Fq::ONE;
        assert!(
            check_boundary(&d, &changed)
                .unwrap_err()
                .contains("nonzero fixed tail")
        );
        let mut changed = rows.clone();
        changed.get_mut(&7).unwrap().sigma[1] += Fq::ONE;
        assert!(
            check_boundary(&d, &changed)
                .unwrap_err()
                .contains("tail copy not fixed")
        );
        let mut d = d;
        d.gates
            .push(vec![vec![ExprNodeV1::Constant(Fq::ONE.to_repr())]]);
        assert!(
            check_boundary(&d, &rows)
                .unwrap_err()
                .contains("tail gate not zero")
        );
    }

    #[test]
    fn either_lookup_side_refuses_next_and_previous_tail_dependence() {
        for rotation in [-1, 1] {
            for input in [false, true] {
                let (mut d, rows) = fixture();
                d.advice_queries.push(QueryV1 {
                    column: 0,
                    rotation,
                });
                let expressions = if input {
                    &mut d.lookups[0].inputs
                } else {
                    &mut d.lookups[0].tables
                };
                expressions[0] = vec![ExprNodeV1::Advice(1)];
                assert!(
                    check_boundary(&d, &rows)
                        .unwrap_err()
                        .contains("lookup tail dependence")
                );
            }
        }
    }

    #[test]
    fn malformed_queries_and_expressions_refuse() {
        let (d, rows) = fixture();
        let mut changed = d.clone();
        changed.fixed_queries[0].column = 1;
        assert!(
            check_boundary(&changed, &rows)
                .unwrap_err()
                .contains("fixed query column")
        );
        for instance in [false, true] {
            let mut changed = d.clone();
            if instance {
                changed.instance_queries[0].column = 1;
            } else {
                changed.advice_queries[0].column = 1;
            }
            assert!(
                check_boundary(&changed, &rows)
                    .unwrap_err()
                    .contains("query column")
            );
        }
        for expression in [
            vec![],
            vec![ExprNodeV1::Product],
            vec![ExprNodeV1::Advice(99)],
            vec![ExprNodeV1::Constant([255; 32])],
            vec![ExprNodeV1::Advice(0), ExprNodeV1::Advice(0)],
        ] {
            let mut changed = d.clone();
            changed.gates[0][0] = expression;
            assert!(check_boundary(&changed, &rows).is_err());
        }
    }

    #[test]
    fn arbitrary_rotations_close_previously_unchecked_boundary_rows() {
        for (rotation, row) in [(2, 4), (-2, 1), (6, 1)] {
            let (mut d, mut rows) = fixture();
            d.advice_queries[0].rotation = rotation;
            d.lookups.clear();
            // Isolate a nonzero selector at a row missed by the former
            // {0, usable-1, tail} scan. All tail fixed/copy checks still pass.
            for values in rows.values_mut() {
                values.fixed[0] = Fq::ZERO;
            }
            rows.get_mut(&row).unwrap().fixed[0] = Fq::ONE;
            assert!(![0, 5, 6, 7].contains(&row));
            assert!(boundary_rows(&d, 8, 6).unwrap().contains(&row));
            assert!(
                check_boundary(&d, &rows)
                    .unwrap_err()
                    .contains(&format!("gate tail dependence row={row}"))
            );
            rows.get_mut(&row).unwrap().fixed[0] = Fq::ZERO;
            check_boundary(&d, &rows).unwrap();
        }
        assert_eq!(rotated(0, i32::MIN, 8).unwrap(), 0);
        assert_eq!(rotated(1, i32::MAX, 8).unwrap(), 0);
    }

    #[test]
    fn rotated_fixed_lookup_selectors_use_the_actual_public_cell() {
        for input in [false, true] {
            let (mut d, mut rows) = fixture();
            d.advice_queries[0].rotation = 2;
            d.fixed_queries[0].rotation = -1;
            d.gates.clear();
            for values in rows.values_mut() {
                values.fixed[0] = Fq::ZERO;
            }
            // row4 reads advice6 (masked) and fixed3 (public, nonzero).
            // fixed4 is zero, so incorrectly ignoring the fixed rotation passes.
            rows.get_mut(&3).unwrap().fixed[0] = Fq::ONE;
            let expr = vec![
                ExprNodeV1::Fixed(0),
                ExprNodeV1::Advice(0),
                ExprNodeV1::Product,
            ];
            d.lookups[0].inputs = vec![vec![ExprNodeV1::Constant(Fq::ZERO.to_repr())]];
            d.lookups[0].tables = d.lookups[0].inputs.clone();
            if input {
                d.lookups[0].inputs[0] = expr;
            } else {
                d.lookups[0].tables[0] = expr;
            }
            assert!(!boundary_rows(&d, 8, 6).unwrap().contains(&3));
            assert!(public_table_rows(&d, 8, 6).unwrap().contains(&3));
            let error = check_boundary(&d, &rows).unwrap_err();
            assert!(error.contains("lookup tail dependence row=4"));
            assert!(error.contains(if input { "side=input" } else { "side=table" }));
            rows.get_mut(&3).unwrap().fixed[0] = Fq::ZERO;
            check_boundary(&d, &rows).unwrap();
            rows.remove(&3);
            assert!(
                check_boundary(&d, &rows)
                    .unwrap_err()
                    .contains("fixed row/column")
            );
        }
    }

    #[test]
    fn rotated_table_reader_keeps_closure_rows_and_refuses_missing_boundary() {
        let (mut d, mut rows) = fixture();
        d.advice_queries[0].rotation = 2;
        d.fixed_queries[0].rotation = -1;
        assert_eq!(
            boundary_rows(&d, 8, 6).unwrap(),
            BTreeSet::from([0, 4, 5, 6, 7])
        );
        assert_eq!(
            public_table_rows(&d, 8, 6).unwrap(),
            BTreeSet::from([0, 3, 4, 5, 6, 7])
        );
        for values in rows.values_mut() {
            values.fixed[0] = Fq::ZERO;
        }
        d.lookups.clear();
        check_boundary(&d, &rows).unwrap();
        rows.remove(&4);
        assert!(
            check_boundary(&d, &rows)
                .unwrap_err()
                .contains("missing boundary row")
        );
    }

    #[test]
    fn fp_sigma_boundary_and_noncanonical_scalar_are_checked_in_fp() {
        let (mut d, _) = fixture();
        d.curve = CurveV1::Vesta;
        d.base_modulus = CurveV1::Vesta.base_modulus();
        d.scalar_modulus = CurveV1::Vesta.scalar_modulus();
        let mut rows: BTreeMap<usize, Row<Fp>> = (0..8)
            .map(|row| {
                let power = omega::<Fp>(3).pow_vartime([u64::try_from(row).unwrap()]);
                (
                    row,
                    Row {
                        fixed: vec![if row < 6 { Fp::ONE } else { Fp::ZERO }],
                        sigma: vec![power, Fp::DELTA * power],
                    },
                )
            })
            .collect();
        check_boundary(&d, &rows).unwrap();
        assert_eq!(
            canonical::<Fp>([255; 32]).unwrap_err(),
            "noncanonical scalar"
        );
        rows.get_mut(&7).unwrap().sigma[0] += Fp::ONE;
        assert!(
            check_boundary(&d, &rows)
                .unwrap_err()
                .contains("tail copy not fixed")
        );
    }

    fn plan_queries() -> Vec<crate::pcs::multiopen::OpeningQuery> {
        use crate::pcs::multiopen::OpeningQuery;
        [
            (SlotKind::Advice, 0),
            (SlotKind::Advice, 1),
            (SlotKind::Advice, -1),
            (SlotKind::PermutationProduct, 0),
            (SlotKind::PermutationProduct, 1),
            (SlotKind::PermutationProduct, -6),
            (SlotKind::LookupPermutedInput, 0),
            (SlotKind::LookupPermutedInput, -1),
            // A synthetic public-only point set exercises the deterministic
            // branch; actual role profiles need not contain such a group.
            (SlotKind::Fixed, 2),
            (SlotKind::PermutationSigma, 2),
            (SlotKind::Vanishing, 0),
            (SlotKind::Random, 0),
        ]
        .into_iter()
        .map(|(kind, rotation)| OpeningQuery::new(Slot::new(kind, 0), rotation))
        .collect()
    }

    #[test]
    fn actual_plan_rank_keeps_public_only_groups_and_quotient_r_distinct() {
        let plan = OpeningPlan::new(&plan_queries()).unwrap();
        let report = opening_report(&plan, 64, 5).unwrap();
        assert!(
            report
                .iter()
                .any(|s| s.contains("fresh_rows=6 rank_with_x3=4 residual=2"))
        );
        assert!(
            report
                .iter()
                .any(|s| s.contains("fresh_rows=5 rank_with_x3=4 residual=1"))
        );
        assert!(
            report
                .iter()
                .any(|s| s.contains("exact_public_preprocessing"))
        );
        assert!(
            report
                .iter()
                .any(|s| s.contains("quotient_R_coefficient_one"))
        );
        assert!(
            report
                .iter()
                .any(|s| s.contains("residual_witness_coefficient_one"))
        );
        // Query repetition does not create another evaluation constraint.
        let mut queries = plan_queries();
        queries.insert(1, queries[0]);
        let repeated = OpeningPlan::new(&queries).unwrap();
        assert_eq!(opening_report(&repeated, 64, 5).unwrap(), report);
    }

    #[test]
    fn mixed_group_requires_final_private_coefficient_one() {
        use crate::pcs::multiopen::OpeningQuery;
        let mut queries = plan_queries();
        // Same point set as Advice, inserted after all private slots: the private
        // coefficient would vanish at raw x1 = zero in a forward Horner fold.
        let at = queries.len() - 2;
        for rotation in [0, 1, -1] {
            queries.insert(
                at,
                OpeningQuery::new(Slot::new(SlotKind::Fixed, 1), rotation),
            );
        }
        assert!(
            opening_report(&OpeningPlan::new(&queries).unwrap(), 64, 5)
                .unwrap_err()
                .contains("private residual coefficient not one")
        );
    }

    #[test]
    fn quotient_mask_order_points_and_rotation_alias_mutations_refuse() {
        let queries = plan_queries();
        let mut missing = queries.clone();
        missing.pop();
        assert!(opening_report(&OpeningPlan::new(&missing).unwrap(), 64, 5).is_err());
        let mut reversed = queries.clone();
        let end = reversed.len();
        reversed.swap(end - 1, end - 2);
        assert!(
            opening_report(&OpeningPlan::new(&reversed).unwrap(), 64, 5)
                .unwrap_err()
                .contains("R not last")
        );
        let mut wrong_point = queries.clone();
        wrong_point.last_mut().unwrap().rotation = 1;
        assert!(
            opening_report(&OpeningPlan::new(&wrong_point).unwrap(), 64, 5)
                .unwrap_err()
                .contains("rotation zero")
        );
        let mut alias = queries;
        alias.insert(
            1,
            crate::pcs::multiopen::OpeningQuery::new(Slot::new(SlotKind::Advice, 0), 64),
        );
        assert!(
            opening_report(&OpeningPlan::new(&alias).unwrap(), 64, 5)
                .unwrap_err()
                .contains("rotation alias")
        );
    }

    #[test]
    fn s7_and_direct_instance_profile_are_enforced_without_sampled_points() {
        use crate::pcs::multiopen::OpeningQuery;
        let mut queries = plan_queries();
        queries.insert(1, OpeningQuery::new(Slot::new(SlotKind::Advice, 0), 3));
        assert!(
            opening_report(&OpeningPlan::new(&queries).unwrap(), 64, 5)
                .unwrap_err()
                .contains("S7")
        );
        let mut queries = plan_queries();
        queries.insert(0, OpeningQuery::new(Slot::new(SlotKind::Instance, 0), 0));
        assert!(
            opening_report(&OpeningPlan::new(&queries).unwrap(), 64, 5)
                .unwrap_err()
                .contains("Direct")
        );
        // Independent check through the production descriptor->Protocol path.
        let (mut d, _) = fixture();
        d.k = 6;
        d.degree = 4;
        d.quotient_pieces = 3;
        d.blinding_factors = 5;
        let protocol = Protocol::new(&d).unwrap();
        check_zero_knowledge_budget(&protocol).unwrap();
        opening_report(protocol.plan(), 64, 5).unwrap();
        d.blinding_factors = 4;
        assert!(check_zero_knowledge_budget(&Protocol::new(&d).unwrap()).is_err());
    }
    #[test]
    fn public_capture_requires_matching_field_and_bounded_work() {
        let (mut d, _) = fixture();
        assert!(dimensions::<Fp>(&d).is_err());
        d.advice_queries = vec![
            QueryV1 {
                column: 0,
                rotation: 1
            };
            MAX_CAPTURE_ROWS
        ];
        assert!(
            boundary_rows(&d, 8, 6)
                .unwrap_err()
                .contains("bounded boundary work")
        );
        d.advice_queries.clear();
        d.fixed_queries = vec![
            QueryV1 {
                column: 0,
                rotation: 0
            };
            MAX_CAPTURE_ROWS
        ];
        assert!(
            public_table_rows(&d, 8, 6)
                .unwrap_err()
                .contains("bounded public-row work")
        );
    }
}
