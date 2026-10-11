//! The step-relation circuit [`SigmaCircuit`], its configuration parameters
//! ([`SigmaParams`]) and the lane plan.
//!
//! # Columns
//!
//! - `L` Pow5 sponge lanes (`iroha_plonk_gadgets::poseidon`), four advice
//!   columns each, sharing one set of six round-constant columns. The hash
//!   sites of the relation (a single hash, or a tree leaf with its path) are
//!   spread over the lanes by a static plan ([`LanePlan`]): longest site
//!   first, each onto the least loaded lane.
//! - The glue chip shares the four columns of the least loaded lane: its
//!   rows start right after that lane's last permutation block. Its standard
//!   gate is off wherever its coefficient columns are zero (every Pow5 row),
//!   and the Pow5 gates are selector-gated, so the two never constrain each
//!   other's rows.
//! - One running-sum column with a `2^b`-row limb table (`b = limb_bits`).
//! - One fixed constants column and one instance column (the statement
//!   digest).
//!
//! With [`PrefixMode::Folded`] each lane starts its domain-prefixed hashes
//! from the constant post-prefix state (one permutation fewer per hash),
//! except the few prefixes [`RelationShape::unfolded`] keeps absorbed so
//! that the start selectors fill whole compressed selector columns (each
//! column is a 32-byte proof evaluation); with [`PrefixMode::Absorbed`] the
//! `[domain, arity]` prefix is absorbed in circuit. Both compute the same
//! digests.

use iroha_pasta::poseidon::PoseidonField;
use iroha_plonk::{
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner},
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig, LimbBits, Pow5Columns, RoundConstantColumns, RunningSumChip,
    RunningSumConfig, SpongeChip, SpongeConfig, Word,
    poseidon::{ROWS_PER_PERMUTATION, domain_permutations},
    statement::{STATEMENT_DOMAIN, STATEMENT_FIELDS, StepRelation},
};

use crate::{
    controls::{QUOTA_CHARGES, SEGMENT_POSITIONS},
    relation::{self, Chips},
    tree::{
        BLACKLIST_DEPTH, BLACKLIST_LEAF_DOMAIN, BLACKLIST_NODE_DOMAIN, QUOTA_DEPTH,
        QUOTA_NODE_DOMAIN, QUOTA_USAGE_DOMAIN, QUOTA_USAGE_NODE_DOMAIN, QUOTA_WINDOW_DOMAIN,
        WINDOW_KINDS,
    },
    witness::{
        COMMITMENT_ARITY, CONTROL_BLACKLIST, CONTROL_QUOTAS, CORE_DOMAIN, CREDIT_DOMAIN,
        NativeStep, RECEIVE_CHAIN_DOMAIN, RECEIVE_CHAIN_FIELDS, REQUEST_FIELDS, SEND_CHAIN_DOMAIN,
        SEND_CHAIN_FIELDS, SigmaRelation, StepDigests, StepWitness,
    },
};

/// The most Pow5 lanes a step circuit configures.
pub const MAX_LANES: usize = 4;
/// The default limb width (`k = 11` with a `2^(k - 1)`-row table).
pub const DEFAULT_LIMB_BITS: usize = 10;
/// The public outputs of every step relation: the statement digest.
pub const PUBLIC_OUTPUTS: usize = 1;
/// The Pow5 start selectors (degree-2 gates under degree 6) that selector
/// compression combines into one fixed column (`6 - 2 + 1`).
pub const STARTS_PER_SELECTOR_COLUMN: usize = 5;
/// The most permutations [`RelationShape::unfolded`] adds to save a
/// selector column.
pub const MAX_UNFOLDED_PERMUTATIONS: usize = 4;

/// How domain-prefixed hashes start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrefixMode {
    /// From the constant state after the `[domain, arity]` block (a start
    /// gate; one permutation fewer per hash).
    #[default]
    Folded,
    /// From the raw sponge state, absorbing `[domain, arity]` in circuit.
    Absorbed,
}

impl PrefixMode {
    /// A short label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Folded => "folded",
            Self::Absorbed => "absorbed",
        }
    }
}

/// The relation a circuit proves: the step relation with its
/// enabled-controls mask (the verifying-key selector) and the Poseidon
/// prefix mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RelationShape {
    /// The step relation and the controls it enforces.
    pub relation: SigmaRelation,
    /// The Poseidon prefix mode.
    pub prefix: PrefixMode,
}

impl Default for RelationShape {
    fn default() -> Self {
        Self::new(SigmaRelation::SEND, PrefixMode::Folded)
    }
}

/// One path of a fixed-array quota charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UsagePath {
    /// Old usage leaf to the running root.
    LeafBefore,
    /// Updated usage leaf to the successor root.
    LeafAfter,
}
impl UsagePath {
    /// Both paths in layout order.
    pub const ALL: [Self; 2] = [Self::LeafBefore, Self::LeafAfter];
}

/// A hash site of the relation: one hash, or a tree leaf with its path
/// (all on one lane).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashSite {
    /// The predecessor commitment.
    Predecessor,
    /// The successor commitment.
    Successor,
    /// The credit identifier: the Request body under the credit domain.
    Credit,
    /// The chain append.
    Chain,
    /// The statement digest.
    Statement,
    /// The blacklist control: the gap leaf and its 16-node path.
    BlacklistGap,
    /// The quota control: the window leaf and 6-node path of a segment
    /// position `(kind index, position)`.
    QuotaWindow(u8, u8),
    /// The quota control: the old and new usage values of a charge.
    UsageValues(u8),
    /// The quota control: one six-level usage-array path of a charge.
    UsagePath(u8, UsagePath),
}

impl RelationShape {
    /// A relation shape.
    #[must_use]
    pub const fn new(relation: SigmaRelation, prefix: PrefixMode) -> Self {
        Self { relation, prefix }
    }

    /// The step.
    #[must_use]
    pub const fn step(self) -> StepRelation {
        self.relation.step()
    }

    /// The case label, `sigma_<relation>_<prefix>`.
    #[must_use]
    pub fn label(self) -> String {
        format!("sigma_{}_{}", self.relation.label(), self.prefix.label())
    }

    /// The hashes every relation computes, in layout order (the same for
    /// both steps).
    pub const BASE_SITES: [HashSite; 5] = [
        HashSite::Credit,
        HashSite::Chain,
        HashSite::Predecessor,
        HashSite::Successor,
        HashSite::Statement,
    ];

    /// The hash sites of the relation, in layout order: the base sites,
    /// then the blacklist gap (with the blacklist control) and the quota
    /// windows, values and paths (`sigma_send` with the quota control).
    #[must_use]
    pub fn sites(self) -> Vec<HashSite> {
        let mut sites = Self::BASE_SITES.to_vec();
        if self.relation.enforces(CONTROL_BLACKLIST) {
            sites.push(HashSite::BlacklistGap);
        }
        if self.relation.step() == StepRelation::Send && self.relation.enforces(CONTROL_QUOTAS) {
            for kind in 0..WINDOW_KINDS.len() {
                for position in 0..SEGMENT_POSITIONS {
                    sites.push(HashSite::QuotaWindow(
                        u8::try_from(kind).unwrap_or(u8::MAX),
                        u8::try_from(position).unwrap_or(u8::MAX),
                    ));
                }
            }
            for charge in 0..QUOTA_CHARGES {
                let charge = u8::try_from(charge).unwrap_or(u8::MAX);
                sites.push(HashSite::UsageValues(charge));
                for path in UsagePath::ALL {
                    sites.push(HashSite::UsagePath(charge, path));
                }
            }
        }
        sites
    }

    /// The `(domain, arity)` of every hash of a site, in order.
    #[must_use]
    pub fn site_hashes(self, site: HashSite) -> Vec<(u64, usize)> {
        let path = |leaf: Option<(u64, usize)>, node: u64, depth: usize| {
            leaf.into_iter()
                .chain(core::iter::repeat_n((node, 2), depth))
                .collect()
        };
        match (site, self.relation.step()) {
            (HashSite::Predecessor | HashSite::Successor, _) => {
                vec![(CORE_DOMAIN, COMMITMENT_ARITY)]
            }
            (HashSite::Chain, StepRelation::Send) => vec![(SEND_CHAIN_DOMAIN, SEND_CHAIN_FIELDS)],
            (HashSite::Chain, StepRelation::Receive) => {
                vec![(RECEIVE_CHAIN_DOMAIN, RECEIVE_CHAIN_FIELDS)]
            }
            (HashSite::Credit, _) => vec![(CREDIT_DOMAIN, REQUEST_FIELDS)],
            (HashSite::Statement, _) => vec![(STATEMENT_DOMAIN, STATEMENT_FIELDS)],
            (HashSite::BlacklistGap, _) => path(
                Some((BLACKLIST_LEAF_DOMAIN, 4)),
                BLACKLIST_NODE_DOMAIN,
                BLACKLIST_DEPTH,
            ),
            (HashSite::QuotaWindow(..), _) => path(
                Some((QUOTA_WINDOW_DOMAIN, 4)),
                QUOTA_NODE_DOMAIN,
                QUOTA_DEPTH,
            ),
            (HashSite::UsageValues(_), _) => vec![(QUOTA_USAGE_DOMAIN, 4); 2],
            (HashSite::UsagePath(..), _) => path(None, QUOTA_USAGE_NODE_DOMAIN, QUOTA_DEPTH),
        }
    }

    /// The `(domain, arity)` prefixes of the relation's hashes in order of
    /// first use (layout order), each with the number of hashes using it.
    #[must_use]
    pub fn prefix_uses(self) -> Vec<((u64, usize), usize)> {
        let mut uses: Vec<((u64, usize), usize)> = Vec::new();
        for site in self.sites() {
            for prefix in self.site_hashes(site) {
                match uses.iter_mut().find(|(known, _)| *known == prefix) {
                    Some((_, count)) => *count += 1,
                    None => uses.push((prefix, 1)),
                }
            }
        }
        uses
    }

    /// The prefixes a [`PrefixMode::Folded`] relation still absorbs in
    /// circuit, to save a selector column.
    ///
    /// Each folded prefix is a start gate of degree 2 with its own
    /// selector, and so is the raw start state every lane configures;
    /// selector compression under the Pow5 degree 6 combines at most
    /// [`STARTS_PER_SELECTOR_COLUMN`] of them into one fixed column, and
    /// every fixed column adds one 32-byte evaluation to the proof. When the
    /// starts of a relation overflow a column by a few, the prefixes with
    /// the fewest hashes (the latest first on ties) are absorbed instead, at
    /// one permutation per hash and at most [`MAX_UNFOLDED_PERMUTATIONS`] in
    /// all. The rule reads the relation's prefixes, not the lane plan: on
    /// one lane it removes the column exactly.
    #[must_use]
    pub fn unfolded(self) -> Vec<(u64, usize)> {
        if self.prefix == PrefixMode::Absorbed {
            return Vec::new();
        }
        let uses = self.prefix_uses();
        let starts = uses.len() + 1;
        let surplus = starts % STARTS_PER_SELECTOR_COLUMN;
        if starts <= STARTS_PER_SELECTOR_COLUMN || surplus == 0 {
            return Vec::new();
        }
        let mut candidates: Vec<(usize, core::cmp::Reverse<usize>, (u64, usize))> = uses
            .iter()
            .enumerate()
            .map(|(order, (prefix, count))| (*count, core::cmp::Reverse(order), *prefix))
            .collect();
        candidates.sort_unstable();
        let chosen = &candidates[..surplus];
        let cost: usize = chosen.iter().map(|(count, _, _)| count).sum();
        if cost > MAX_UNFOLDED_PERMUTATIONS {
            return Vec::new();
        }
        chosen.iter().map(|(_, _, prefix)| *prefix).collect()
    }

    /// Whether the relation's hashes under `prefix` start from its folded
    /// state.
    #[must_use]
    pub fn is_folded(self, prefix: (u64, usize)) -> bool {
        self.prefix == PrefixMode::Folded && !self.unfolded().contains(&prefix)
    }

    /// The Pow5 permutations of a site.
    #[must_use]
    pub fn site_permutations(self, site: HashSite) -> usize {
        let unfolded = self.unfolded();
        let folded = matches!(self.prefix, PrefixMode::Folded);
        self.site_hashes(site)
            .into_iter()
            .map(|prefix| domain_permutations(prefix.1, folded && !unfolded.contains(&prefix)))
            .sum()
    }

    /// The Pow5 permutations of the relation (folded prefixes: `sigma_send`
    /// 69, with the blacklist control 106, with the quota control 309
    /// and with every control 345; `sigma_recv` 67 and with the
    /// blacklist bit 104).
    #[must_use]
    pub fn permutations(self) -> usize {
        self.sites()
            .into_iter()
            .map(|site| self.site_permutations(site))
            .sum()
    }
}

/// Why circuit parameters were rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamsError {
    /// The lane count is outside `1..=MAX_LANES`.
    Lanes(usize),
    /// The limb width is outside `1..=24`.
    LimbBits(usize),
    /// The relation enables an undefined control.
    Relation(SigmaRelation),
}

impl core::fmt::Display for ParamsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Lanes(lanes) => write!(f, "{lanes} Pow5 lanes (1..={MAX_LANES} supported)"),
            Self::LimbBits(bits) => write!(f, "{bits}-bit limbs (1..=24 supported)"),
            Self::Relation(relation) => write!(
                f,
                "relation selector {:?} enables an undefined control",
                relation.selector()
            ),
        }
    }
}

impl std::error::Error for ParamsError {}

/// The configuration-time parameters of a [`SigmaCircuit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SigmaParams {
    relation: RelationShape,
    lanes: usize,
    limb_bits: LimbBits,
}

impl Default for SigmaParams {
    fn default() -> Self {
        Self {
            relation: RelationShape::default(),
            lanes: 1,
            limb_bits: LimbBits::new(DEFAULT_LIMB_BITS)
                .unwrap_or_else(|| unreachable!("10-bit limbs are valid")),
        }
    }
}

impl SigmaParams {
    /// Parameters for `relation` on `lanes` Pow5 lanes with `limb_bits`-bit
    /// range-check limbs.
    ///
    /// # Errors
    ///
    /// [`ParamsError`] for a relation with an undefined control, a lane
    /// count outside `1..=MAX_LANES` or a limb width outside `1..=24`.
    pub fn new(
        relation: RelationShape,
        lanes: usize,
        limb_bits: usize,
    ) -> Result<Self, ParamsError> {
        if !relation.relation.is_supported() {
            return Err(ParamsError::Relation(relation.relation));
        }
        if lanes == 0 || lanes > MAX_LANES {
            return Err(ParamsError::Lanes(lanes));
        }
        let limb_bits = LimbBits::new(limb_bits).ok_or(ParamsError::LimbBits(limb_bits))?;
        Ok(Self {
            relation,
            lanes,
            limb_bits,
        })
    }

    /// The relation.
    #[must_use]
    pub const fn relation(&self) -> RelationShape {
        self.relation
    }

    /// The Pow5 lanes.
    #[must_use]
    pub const fn lanes(&self) -> usize {
        self.lanes
    }

    /// The range-check limb width.
    #[must_use]
    pub const fn limb_bits(&self) -> usize {
        self.limb_bits.get()
    }

    /// The lane plan.
    #[must_use]
    pub fn plan(&self) -> LanePlan {
        LanePlan::new(self.relation, self.lanes)
    }
}

/// Which lane computes each hash, and which lane the glue rows follow.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LanePlan {
    sites: Vec<(HashSite, usize)>,
    lane_permutations: Vec<usize>,
    glue_lane: usize,
}

impl LanePlan {
    /// The plan of `relation` on `lanes >= 1` lanes: sites by decreasing
    /// permutation count (layout order on ties), each onto the least loaded
    /// lane (lowest index on ties); the glue follows the least loaded lane.
    #[must_use]
    pub fn new(relation: RelationShape, lanes: usize) -> Self {
        let lanes = lanes.max(1);
        let mut order: Vec<(HashSite, usize)> = relation
            .sites()
            .into_iter()
            .map(|site| (site, relation.site_permutations(site)))
            .collect();
        // A stable sort keeps layout order on ties.
        order.sort_by_key(|(_, permutations)| core::cmp::Reverse(*permutations));
        let mut lane_permutations = vec![0_usize; lanes];
        let mut sites = Vec::with_capacity(order.len());
        for (site, permutations) in order {
            let lane = least_loaded(&lane_permutations);
            lane_permutations[lane] = lane_permutations[lane].saturating_add(permutations);
            sites.push((site, lane));
        }
        let glue_lane = least_loaded(&lane_permutations);
        Self {
            sites,
            lane_permutations,
            glue_lane,
        }
    }

    /// The lane of `site` (lane 0 for a site the relation does not have).
    #[must_use]
    pub fn lane_of(&self, site: HashSite) -> usize {
        self.sites
            .iter()
            .find(|(candidate, _)| *candidate == site)
            .map_or(0, |(_, lane)| *lane)
    }

    /// The permutations of each lane.
    #[must_use]
    pub fn lane_permutations(&self) -> &[usize] {
        &self.lane_permutations
    }

    /// The lane whose columns the glue chip shares.
    #[must_use]
    pub const fn glue_lane(&self) -> usize {
        self.glue_lane
    }

    /// The first glue row: the end of the glue lane's permutation blocks.
    ///
    /// # Errors
    ///
    /// [`Error::BoundsFailure`] on overflow.
    pub fn glue_start(&self) -> Result<usize, Error> {
        self.lane_permutations
            .get(self.glue_lane)
            .and_then(|blocks| blocks.checked_mul(ROWS_PER_PERMUTATION))
            .ok_or(Error::BoundsFailure)
    }

    /// The `(domain, arity)` prefixes lane `lane` folds under `relation`
    /// (every prefix of its sites but [`RelationShape::unfolded`]).
    #[must_use]
    pub fn folded(&self, relation: RelationShape, lane: usize) -> Vec<(u64, usize)> {
        if relation.prefix == PrefixMode::Absorbed {
            return Vec::new();
        }
        let unfolded = relation.unfolded();
        let mut folded = Vec::new();
        for (site, site_lane) in &self.sites {
            if *site_lane != lane {
                continue;
            }
            for prefix in relation.site_hashes(*site) {
                if !folded.contains(&prefix) && !unfolded.contains(&prefix) {
                    folded.push(prefix);
                }
            }
        }
        folded
    }
}

/// The index of the smallest load (the first on ties).
fn least_loaded(loads: &[usize]) -> usize {
    loads
        .iter()
        .enumerate()
        .min_by_key(|(index, load)| (**load, *index))
        .map_or(0, |(index, _)| index)
}

/// The columns and chips of a [`SigmaCircuit`].
#[derive(Clone, Debug)]
pub struct SigmaConfig<F> {
    params: SigmaParams,
    plan: LanePlan,
    glue: GlueConfig,
    range: RunningSumConfig,
    sponges: Vec<SpongeConfig<F>>,
    instance: Column<Instance>,
}

impl<F> SigmaConfig<F> {
    /// The parameters.
    #[must_use]
    pub const fn params(&self) -> &SigmaParams {
        &self.params
    }

    /// The lane plan.
    #[must_use]
    pub const fn plan(&self) -> &LanePlan {
        &self.plan
    }

    /// The running-sum chip configuration.
    #[must_use]
    pub const fn range(&self) -> &RunningSumConfig {
        &self.range
    }

    /// The glue chip configuration.
    #[must_use]
    pub const fn glue(&self) -> &GlueConfig {
        &self.glue
    }
}

/// Rows and permutations a synthesis used.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Pow5 permutations per lane.
    pub lane_permutations: Vec<usize>,
    /// Rows per lane, glue rows included on the glue lane.
    pub lane_rows: Vec<usize>,
    /// Glue rows.
    pub glue_rows: usize,
    /// Running-sum rows.
    pub range_rows: usize,
    /// Advice cells assigned in the lane and running-sum columns: Pow5
    /// blocks are counted at 148 cells, glue rows at 4.
    pub cells: usize,
}

impl Inventory {
    /// The total Pow5 permutations.
    #[must_use]
    pub fn permutations(&self) -> usize {
        self.lane_permutations.iter().sum()
    }

    /// The tallest advice column.
    #[must_use]
    pub fn rows(&self) -> usize {
        self.lane_rows
            .iter()
            .copied()
            .chain([self.range_rows])
            .max()
            .unwrap_or(0)
    }
}

/// What a synthesis of the relation produced.
#[derive(Clone, Debug)]
pub struct RelationOutput<F: PoseidonField> {
    /// The public outputs, in instance order.
    pub public: Vec<Word<F>>,
    /// The in-circuit digests (unknown during key generation).
    pub digests: iroha_plonk::frontend::Value<StepDigests<F>>,
    /// The rows used.
    pub inventory: Inventory,
}

/// A step relation (`sigma_send` or `sigma_recv`) of the split-lineage
/// design.
///
/// A circuit with a witness carries the witness's native reference
/// evaluation under its relation ([`StepWitness::evaluate`], computed once):
/// synthesis checks every in-circuit digest against it, and the prover reads
/// the public outputs and violations from it.
#[derive(Clone, Debug)]
pub struct SigmaCircuit<F> {
    params: SigmaParams,
    witness: Option<StepWitness<F>>,
    native: Option<NativeStep<F>>,
}

impl<F: PoseidonField> SigmaCircuit<F> {
    /// The circuit proving `witness` under `params`.
    #[must_use]
    pub fn new(params: SigmaParams, witness: StepWitness<F>) -> Self {
        let native = witness.evaluate(params.relation.relation);
        Self {
            params,
            witness: Some(witness),
            native: Some(native),
        }
    }

    /// The circuit without a witness (key generation, shape selection).
    #[must_use]
    pub const fn keygen(params: SigmaParams) -> Self {
        Self {
            params,
            witness: None,
            native: None,
        }
    }

    /// The native reference evaluation of the witness, if any.
    #[must_use]
    pub const fn native(&self) -> Option<&NativeStep<F>> {
        self.native.as_ref()
    }

    /// The parameters.
    #[must_use]
    pub const fn sigma_params(&self) -> &SigmaParams {
        &self.params
    }

    /// The witness, if any.
    #[must_use]
    pub const fn witness(&self) -> Option<&StepWitness<F>> {
        self.witness.as_ref()
    }

    /// Lays out the relation and returns its outputs (the body of
    /// [`Circuit::synthesize`]).
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] when the witness belongs to another step, or an
    /// in-circuit digest differs from the native reference (a bug, not a
    /// relation violation: both compute the same field arithmetic), and
    /// [`Error`] from the layout (for example rows beyond the usable rows).
    pub fn lay_out<L: Layouter<F>>(
        &self,
        config: SigmaConfig<F>,
        layouter: &mut L,
    ) -> Result<RelationOutput<F>, Error> {
        let glue_start = config.plan.glue_start()?;
        let mut chips = Chips {
            glue: GlueChip::starting_at(config.glue, glue_start),
            range: RunningSumChip::new(config.range),
            sponges: config.sponges.into_iter().map(SpongeChip::new).collect(),
        };
        chips.range.load_table(layouter)?;
        let relation = config.params.relation;
        let plan = config.plan;
        let witness = self.witness.as_ref().zip(self.native.as_ref());
        let output = layouter.assign_region(
            || "sigma step",
            |mut region| relation::assign(&mut chips, &mut region, relation, &plan, witness),
        )?;
        for (row, word) in output.public.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.instance, row)?;
        }
        Ok(output)
    }
}

impl<F: PoseidonField> Circuit<F> for SigmaCircuit<F> {
    type Config = SigmaConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = SigmaParams;

    fn without_witnesses(&self) -> Self {
        Self::keygen(self.params)
    }

    fn params(&self) -> SigmaParams {
        self.params
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, SigmaParams::default())
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: SigmaParams) -> Self::Config {
        let plan = params.plan();
        let lanes: Vec<Pow5Columns> = (0..params.lanes)
            .map(|_| Pow5Columns::allocate(meta))
            .collect();
        let round_constants = RoundConstantColumns::allocate(meta);
        let constants = meta.fixed_column();
        let shared = lanes
            .get(plan.glue_lane())
            .copied()
            .unwrap_or_else(|| Pow5Columns::allocate(meta));
        let glue = GlueConfig::configure(
            meta,
            [
                shared.state[0],
                shared.state[1],
                shared.state[2],
                shared.aux,
            ],
            constants,
        );
        let z = meta.advice_column();
        let range = RunningSumConfig::configure(meta, z, params.limb_bits);
        let sponges = lanes
            .iter()
            .enumerate()
            .map(|(lane, columns)| {
                SpongeConfig::configure(
                    meta,
                    *columns,
                    round_constants,
                    &plan.folded(params.relation, lane),
                )
            })
            .collect();
        let instance = meta.instance_column(PUBLIC_OUTPUTS);
        meta.enable_equality(instance);
        SigmaConfig {
            params,
            plan,
            glue,
            range,
            sponges,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.lay_out(config, &mut layouter).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::CONTROL_BLACKLIST;

    fn shape(relation: SigmaRelation, prefix: PrefixMode) -> RelationShape {
        RelationShape::new(relation, prefix)
    }

    #[test]
    fn permutation_counts_of_the_g1_core_and_the_controls() {
        use PrefixMode::{Absorbed, Folded};
        let blacklist = SigmaRelation::send(CONTROL_BLACKLIST);
        let quotas = SigmaRelation::send(CONTROL_QUOTAS);
        let every = SigmaRelation::send(crate::witness::CONTROLS_DEFINED);
        let lease = SigmaRelation::send(crate::witness::CONTROL_ATTESTATION_LEASE);
        let receive_blacklist = SigmaRelation::receive(CONTROL_BLACKLIST);
        // Absorbed prefixes: openings 19 (34 inputs), credit 15 (26),
        // send chain 6, receive chain 4, statement 15 (26 inputs).
        assert_eq!(shape(SigmaRelation::SEND, Absorbed).permutations(), 74);
        assert_eq!(shape(SigmaRelation::RECEIVE, Absorbed).permutations(), 72);
        // Folding saves one permutation per hash; the lease adds none, the
        // blacklist gap 35 (leaf 3, 16 nodes of 2), the quota rule 240
        // (8 window openings of 15, 4 charges of 30). With the gap, two
        // single-hash prefixes stay absorbed (two permutations) so the
        // start selectors fill whole columns.
        assert_eq!(shape(SigmaRelation::SEND, Folded).permutations(), 69);
        assert_eq!(shape(lease, Folded).permutations(), 69);
        assert_eq!(shape(blacklist, Folded).permutations(), 106);
        assert_eq!(shape(quotas, Folded).permutations(), 309);
        assert_eq!(shape(every, Folded).permutations(), 345);
        assert_eq!(shape(SigmaRelation::RECEIVE, Folded).permutations(), 67);
        assert_eq!(shape(receive_blacklist, Folded).permutations(), 104);
        assert_eq!(shape(blacklist, Absorbed).permutations(), 74 + 52);
        assert_eq!(shape(every, Absorbed).permutations(), 74 + 52 + 352);
        let send = shape(SigmaRelation::SEND, Folded);
        assert_eq!(send.site_permutations(HashSite::Statement), 14);
        assert_eq!(send.site_permutations(HashSite::Credit), 14);
        assert_eq!(send.site_permutations(HashSite::Predecessor), 18);
        assert_eq!(send.site_permutations(HashSite::Chain), 5);
        let quota = shape(quotas, Folded);
        assert_eq!(quota.site_permutations(HashSite::QuotaWindow(1, 3)), 15);
        assert_eq!(quota.site_permutations(HashSite::UsageValues(2)), 6);
        assert_eq!(
            quota.site_permutations(HashSite::UsagePath(0, UsagePath::LeafBefore)),
            12
        );
        assert_eq!(
            quota.site_permutations(HashSite::UsagePath(0, UsagePath::LeafAfter)),
            12
        );
        assert_eq!(
            shape(SigmaRelation::RECEIVE, Folded).site_permutations(HashSite::Chain),
            3
        );
        assert_eq!(
            send.site_hashes(HashSite::Predecessor),
            vec![(CORE_DOMAIN, 34)]
        );
        assert_eq!(send.step(), StepRelation::Send);
        assert_eq!(send.label(), "sigma_send_m0_folded");
        assert_eq!(shape(blacklist, Folded).label(), "sigma_send_m1_folded");
        assert_eq!(
            shape(SigmaRelation::RECEIVE, Absorbed).label(),
            "sigma_recv_m0_absorbed"
        );
        assert_eq!(send.sites().len(), 5);
        assert_eq!(shape(receive_blacklist, Folded).sites().len(), 6);
        assert_eq!(quota.sites().len(), 5 + 8 + 4 * 3);
        assert_eq!(RelationShape::default(), send);
    }

    #[test]
    fn lane_plan_balances_longest_first() {
        let send = shape(SigmaRelation::SEND, PrefixMode::Folded);
        let one = LanePlan::new(send, 1);
        assert_eq!(one.lane_permutations(), &[69]);
        assert_eq!(one.glue_lane(), 0);
        assert_eq!(one.glue_start(), Ok(69 * 37));
        let two = LanePlan::new(send, 2);
        // 18 | 18, then 14 onto 18 (lane 0 on the tie), 14 onto 18, 5 onto
        // the tie 32 | 32.
        assert_eq!(two.lane_permutations(), &[37, 32]);
        assert_eq!(two.lane_of(HashSite::Predecessor), 0);
        assert_eq!(two.lane_of(HashSite::Successor), 1);
        assert_eq!(two.lane_of(HashSite::Statement), 1);
        assert_eq!(two.lane_of(HashSite::Credit), 0);
        assert_eq!(two.lane_of(HashSite::Chain), 0);
        assert_eq!(two.glue_lane(), 1);
        assert_eq!(
            two.folded(send, 0),
            vec![
                (CORE_DOMAIN, 34),
                (CREDIT_DOMAIN, 26),
                (SEND_CHAIN_DOMAIN, 8)
            ]
        );
        assert_eq!(
            two.folded(send, 1),
            vec![(CORE_DOMAIN, 34), (STATEMENT_DOMAIN, 26)]
        );
        // A tree site folds its node prefix on its lane; the gap leaf and
        // the statement stay absorbed (`RelationShape::unfolded`).
        let gap = shape(SigmaRelation::send(CONTROL_BLACKLIST), PrefixMode::Folded);
        let plan = LanePlan::new(gap, 1);
        assert_eq!(plan.lane_permutations(), &[106]);
        let folded = plan.folded(gap, 0);
        assert!(!folded.contains(&(BLACKLIST_LEAF_DOMAIN, 4)));
        assert!(!folded.contains(&(STATEMENT_DOMAIN, 26)));
        assert!(folded.contains(&(BLACKLIST_NODE_DOMAIN, 2)));
        assert_eq!(folded.len(), 4);
        let absorbed = shape(SigmaRelation::SEND, PrefixMode::Absorbed);
        assert!(LanePlan::new(absorbed, 2).folded(absorbed, 0).is_empty());
        assert_eq!(LanePlan::new(send, 0).lane_permutations(), &[69]);
        assert_eq!(least_loaded(&[3, 1, 1]), 1);
        assert_eq!(least_loaded(&[]), 0);
    }

    #[test]
    fn start_selectors_fill_whole_columns() {
        use PrefixMode::{Absorbed, Folded};
        let every = shape(
            SigmaRelation::send(crate::witness::CONTROLS_DEFINED),
            Folded,
        );
        // Base relations: the raw start and four prefixes fill one column.
        for relation in [
            SigmaRelation::SEND,
            SigmaRelation::RECEIVE,
            SigmaRelation::send(crate::witness::CONTROL_ATTESTATION_LEASE),
        ] {
            let relation = shape(relation, Folded);
            assert_eq!(relation.prefix_uses().len() + 1, STARTS_PER_SELECTOR_COLUMN);
            assert!(relation.unfolded().is_empty());
        }
        // The gap adds two prefixes: the gap leaf and the statement (one
        // hash each, the latest first) are absorbed.
        for relation in [
            SigmaRelation::send(CONTROL_BLACKLIST),
            SigmaRelation::receive(CONTROL_BLACKLIST),
        ] {
            let relation = shape(relation, Folded);
            assert_eq!(
                relation.unfolded(),
                vec![(BLACKLIST_LEAF_DOMAIN, 4), (STATEMENT_DOMAIN, 26)]
            );
            assert!(!relation.is_folded((BLACKLIST_LEAF_DOMAIN, 4)));
            assert!(relation.is_folded((BLACKLIST_NODE_DOMAIN, 2)));
            assert_eq!(relation.site_permutations(HashSite::BlacklistGap), 36);
            assert_eq!(relation.site_permutations(HashSite::Statement), 15);
        }
        // The quota rule's nine prefixes fill two columns; every control
        // overflows by two again.
        let quotas = shape(SigmaRelation::send(CONTROL_QUOTAS), Folded);
        assert_eq!(
            quotas.prefix_uses().len() + 1,
            2 * STARTS_PER_SELECTOR_COLUMN - 1
        );
        assert!(quotas.unfolded().is_empty());
        assert_eq!(every.unfolded(), vec![(BLACKLIST_LEAF_DOMAIN, 4)]);
        assert_eq!(
            every.prefix_uses().last(),
            Some(&((QUOTA_USAGE_NODE_DOMAIN, 2), 4 * 2 * QUOTA_DEPTH))
        );
        // Absorbed relations fold nothing.
        let absorbed = shape(SigmaRelation::send(CONTROL_BLACKLIST), Absorbed);
        assert!(absorbed.unfolded().is_empty());
        assert!(!absorbed.is_folded((CORE_DOMAIN, 34)));
    }

    #[test]
    fn params_are_validated() {
        let relation = RelationShape::default();
        assert_eq!(SigmaParams::new(relation, 0, 9), Err(ParamsError::Lanes(0)));
        assert_eq!(
            SigmaParams::new(relation, MAX_LANES + 1, 9),
            Err(ParamsError::Lanes(MAX_LANES + 1))
        );
        assert_eq!(
            SigmaParams::new(relation, 1, 25),
            Err(ParamsError::LimbBits(25))
        );
        let undefined = SigmaRelation::send(8);
        assert_eq!(
            SigmaParams::new(shape(undefined, PrefixMode::Folded), 1, 9),
            Err(ParamsError::Relation(undefined))
        );
        let receive_quota = SigmaRelation::receive(CONTROL_QUOTAS);
        assert_eq!(
            SigmaParams::new(shape(receive_quota, PrefixMode::Folded), 1, 9),
            Err(ParamsError::Relation(receive_quota))
        );
        assert!(
            SigmaParams::new(
                shape(SigmaRelation::send(CONTROL_BLACKLIST), PrefixMode::Folded),
                1,
                9
            )
            .is_ok()
        );
        let params = SigmaParams::new(relation, 2, 9).expect("valid");
        assert_eq!(params.lanes(), 2);
        assert_eq!(params.limb_bits(), 9);
        assert_eq!(params.relation(), relation);
        assert_eq!(SigmaParams::default().limb_bits(), DEFAULT_LIMB_BITS);
        assert!(ParamsError::Lanes(0).to_string().contains("lanes"));
        assert!(ParamsError::LimbBits(30).to_string().contains("limbs"));
        assert!(
            ParamsError::Relation(undefined)
                .to_string()
                .contains("(3, 8)")
        );
        assert_eq!(PrefixMode::Absorbed.label(), "absorbed");
    }

    #[test]
    fn circuits_carry_their_native_reference() {
        use iroha_pasta::Fp;

        use crate::vectors::{Mutation, sample_witness};

        let relation = shape(SigmaRelation::RECEIVE, PrefixMode::Folded);
        let params = SigmaParams::new(relation, 1, 10).expect("params");
        let witness = sample_witness::<Fp>(2, SigmaRelation::RECEIVE, Mutation::None);
        let circuit = SigmaCircuit::new(params, witness.clone());
        assert_eq!(
            circuit.native(),
            Some(&witness.evaluate(SigmaRelation::RECEIVE))
        );
        assert_eq!(circuit.witness(), Some(&witness));
        assert_eq!(circuit.sigma_params(), &params);
        let keygen = circuit.without_witnesses();
        assert!(keygen.native().is_none() && keygen.witness().is_none());
    }

    #[test]
    fn configuration_exposes_its_plan_and_chips() {
        use iroha_pasta::Fp;

        let relation = shape(SigmaRelation::SEND, PrefixMode::Folded);
        let params = SigmaParams::new(relation, 2, 9).expect("params");
        let mut meta = ConstraintSystem::<Fp>::new();
        let config = SigmaCircuit::<Fp>::configure_with_params(&mut meta, params);
        assert_eq!(config.params(), &params);
        assert_eq!(config.plan(), &params.plan());
        assert_eq!(config.range().limb_bits().get(), 9);
        // The glue chip shares the glue lane's four columns.
        assert_eq!(config.glue().advice().len(), 4);
        // Two lanes of four columns plus the running-sum column.
        assert_eq!(meta.num_advice_queries().len(), 9);
        assert_eq!(meta.instance_lengths(), &[PUBLIC_OUTPUTS]);
        assert!(meta.check().is_ok());
    }

    #[test]
    fn inventory_totals() {
        let inventory = Inventory {
            lane_permutations: vec![3, 4],
            lane_rows: vec![111, 160],
            glue_rows: 12,
            range_rows: 200,
            cells: 0,
        };
        assert_eq!(inventory.permutations(), 7);
        assert_eq!(inventory.rows(), 200);
        assert_eq!(Inventory::default().rows(), 0);
    }
}
