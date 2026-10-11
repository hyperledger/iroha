//! Node-major evaluation with nonblocking, explicitly charged scratch expansion.

use std::{ops::Index, sync::OnceLock};

use iroha_pasta::msm::{ScratchReservation, SharedMemoryBudget};

use super::{BoundColumns, CompiledExpressions, Node, PastaField, ROWS_PER_TASK};

/// Four lanes amortize public node dispatch while retaining small worker buffers.
const TILE_ROWS: usize = 4;
/// Additional bytes beyond the existing scalar scratch, across concurrent calls.
const EXPANSION_LIMIT: usize = 16 << 20;
static TILE_BUDGET: OnceLock<SharedMemoryBudget> = OnceLock::new();

/// A row view preserves root order without transposing the complete scratch DAG.
#[derive(Clone, Copy)]
pub(super) struct EvaluatedRow<'a, F> {
    values: &'a [F],
    stride: usize,
    lane: usize,
}

impl<'a, F> EvaluatedRow<'a, F> {
    pub(super) fn new(values: &'a [F], stride: usize, lane: usize) -> Self {
        debug_assert!(stride > 0 && lane < stride && values.len().is_multiple_of(stride));
        Self {
            values,
            stride,
            lane,
        }
    }
}

impl<F> Index<usize> for EvaluatedRow<'_, F> {
    type Output = F;
    fn index(&self, index: usize) -> &F {
        &self.values[index * self.stride + self.lane]
    }
}

/// The reservation outlives all Rayon tasks and their zeroizing scratch owners.
pub(super) struct TilePlan<'a> {
    pub(super) width: usize,
    _reservation: Option<ScratchReservation<'a>>,
}

fn expansion_bytes<F>(nodes: usize, rows: usize, workers: usize) -> Option<usize> {
    if nodes == 0 || rows < TILE_ROWS || workers == 0 {
        return None;
    }
    nodes
        .checked_mul(TILE_ROWS - 1)?
        .checked_mul(workers.min(rows.div_ceil(ROWS_PER_TASK)))?
        .checked_mul(core::mem::size_of::<F>())
        .filter(|&bytes| bytes <= EXPANSION_LIMIT)
}

impl TilePlan<'static> {
    pub(super) fn new<F>(nodes: usize, rows: usize) -> Self {
        let budget = TILE_BUDGET.get_or_init(|| SharedMemoryBudget::new(EXPANSION_LIMIT));
        Self::with_budget::<F>(nodes, rows, rayon::current_num_threads(), budget)
    }
}

impl<'a> TilePlan<'a> {
    fn with_budget<F>(
        nodes: usize,
        rows: usize,
        workers: usize,
        budget: &'a SharedMemoryBudget,
    ) -> Self {
        // The existing shared reservation also charges the global 64 MiB ceiling.
        // No wait, second global counter or increase of that limit is introduced.
        let reservation =
            expansion_bytes::<F>(nodes, rows, workers).and_then(|bytes| budget.try_reserve(bytes));
        Self {
            width: if reservation.is_some() { TILE_ROWS } else { 1 },
            _reservation: reservation,
        }
    }
}

impl<F: PastaField> CompiledExpressions<F> {
    /// Evaluate consecutive rows; arithmetic and rotation order match the scalar path.
    pub(super) fn evaluate_tile(
        &self,
        columns: &BoundColumns<'_, F>,
        row: usize,
        width: usize,
        scratch: &mut [F],
    ) {
        if width == 1 {
            self.evaluate_row(columns, row, scratch);
            return;
        }
        debug_assert_eq!(width, TILE_ROWS);
        assert_eq!(scratch.len(), self.nodes.len() * width);
        for (index, node) in self.nodes.iter().enumerate() {
            let (prior, rest) = scratch.split_at_mut(index * width);
            let output = &mut rest[..width];
            match *node {
                Node::Constant(value) => output.fill(value),
                Node::Fixed(query) | Node::Advice(query) | Node::Instance(query) => {
                    let (values, rotation) = match *node {
                        Node::Fixed(_) => columns.fixed[query as usize],
                        Node::Advice(_) => columns.advice[query as usize],
                        Node::Instance(_) => columns.instance[query as usize],
                        _ => unreachable!(),
                    };
                    for (lane, value) in output.iter_mut().enumerate() {
                        *value = values[(row + lane + rotation) & columns.mask];
                    }
                }
                Node::Negated(a) => {
                    for (lane, value) in output.iter_mut().enumerate() {
                        *value = -prior[a as usize * width + lane];
                    }
                }
                Node::Doubled(a) => {
                    for (lane, value) in output.iter_mut().enumerate() {
                        *value = prior[a as usize * width + lane].double();
                    }
                }
                Node::Squared(a) => {
                    for (lane, value) in output.iter_mut().enumerate() {
                        *value = prior[a as usize * width + lane].square();
                    }
                }
                Node::Sum(a, b) => {
                    for (lane, value) in output.iter_mut().enumerate() {
                        *value =
                            prior[a as usize * width + lane] + prior[b as usize * width + lane];
                    }
                }
                Node::Product(a, b) => {
                    for (lane, value) in output.iter_mut().enumerate() {
                        *value =
                            prior[a as usize * width + lane] * prior[b as usize * width + lane];
                    }
                }
                Node::Scaled(a, factor) => {
                    for (lane, value) in output.iter_mut().enumerate() {
                        *value = prior[a as usize * width + lane] * factor;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
