//! The step-relation circuit [`SigmaCircuit`], its configuration parameters
//! ([`SigmaParams`]) and the lane plan.
//!
//! # Columns
//!
//! - `L` Pow5 sponge lanes (`iroha_plonk_gadgets::poseidon`), four advice
//!   columns each, sharing one set of six round-constant columns. The hashes
//!   of the relation are spread over the lanes by a static plan
//!   ([`LanePlan`]): longest hash first, each onto the least loaded lane.
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
//! from the constant post-prefix state (one permutation fewer per hash);
//! with [`PrefixMode::Absorbed`] the `[domain, arity]` prefix is absorbed in
//! circuit. Both compute the same digests.

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
    relation::{self, Chips},
    witness::{
        COMMITMENT_ARITY, CORE_DOMAIN, CREDIT_DOMAIN, NativeStep, RECEIVE_CHAIN_DOMAIN,
        RECEIVE_CHAIN_FIELDS, REQUEST_FIELDS, SEND_CHAIN_DOMAIN, SEND_CHAIN_FIELDS, SigmaRelation,
        StepDigests, StepWitness,
    },
};

/// The most Pow5 lanes a step circuit configures.
pub const MAX_LANES: usize = 4;
/// The default limb width (`k = 11` with a `2^(k - 1)`-row table).
pub const DEFAULT_LIMB_BITS: usize = 10;
/// The public outputs of every step relation: the statement digest.
pub const PUBLIC_OUTPUTS: usize = 1;

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

/// A hash the relation computes.
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

    /// The hashes of every relation, in layout order (the same for both
    /// steps).
    pub const HASH_SITES: [HashSite; 5] = [
        HashSite::Credit,
        HashSite::Chain,
        HashSite::Predecessor,
        HashSite::Successor,
        HashSite::Statement,
    ];

    /// The `(domain, arity)` of a hash.
    #[must_use]
    pub const fn site_domain(self, site: HashSite) -> (u64, usize) {
        match (site, self.relation.step()) {
            (HashSite::Predecessor | HashSite::Successor, _) => (CORE_DOMAIN, COMMITMENT_ARITY),
            (HashSite::Chain, StepRelation::Send) => (SEND_CHAIN_DOMAIN, SEND_CHAIN_FIELDS),
            (HashSite::Chain, StepRelation::Receive) => {
                (RECEIVE_CHAIN_DOMAIN, RECEIVE_CHAIN_FIELDS)
            }
            (HashSite::Credit, _) => (CREDIT_DOMAIN, REQUEST_FIELDS),
            (HashSite::Statement, _) => (STATEMENT_DOMAIN, STATEMENT_FIELDS),
        }
    }

    /// The Pow5 permutations of a hash.
    #[must_use]
    pub const fn site_permutations(self, site: HashSite) -> usize {
        let (_, arity) = self.site_domain(site);
        domain_permutations(arity, matches!(self.prefix, PrefixMode::Folded))
    }

    /// The Pow5 permutations of the relation (`sigma_send` 67 and
    /// `sigma_recv` 65 with folded prefixes, one more per hash absorbed).
    #[must_use]
    pub fn permutations(self) -> usize {
        Self::HASH_SITES
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
    /// The relation enables a control this crate does not implement.
    Relation(SigmaRelation),
}

impl core::fmt::Display for ParamsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Lanes(lanes) => write!(f, "{lanes} Pow5 lanes (1..={MAX_LANES} supported)"),
            Self::LimbBits(bits) => write!(f, "{bits}-bit limbs (1..=24 supported)"),
            Self::Relation(relation) => write!(
                f,
                "relation selector {:?} enables an unsupported control",
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
    /// [`ParamsError`] for a relation with an unsupported control, a lane
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
    /// The plan of `relation` on `lanes >= 1` lanes: hashes by decreasing
    /// permutation count (layout order on ties), each onto the least loaded
    /// lane (lowest index on ties); the glue follows the least loaded lane.
    #[must_use]
    pub fn new(relation: RelationShape, lanes: usize) -> Self {
        let lanes = lanes.max(1);
        let mut order = RelationShape::HASH_SITES.to_vec();
        order.sort_by_key(|site| core::cmp::Reverse(relation.site_permutations(*site)));
        let mut lane_permutations = vec![0_usize; lanes];
        let mut sites = Vec::with_capacity(order.len());
        for site in order {
            let lane = least_loaded(&lane_permutations);
            lane_permutations[lane] =
                lane_permutations[lane].saturating_add(relation.site_permutations(site));
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

    /// The `(domain, arity)` prefixes lane `lane` folds under `relation`.
    #[must_use]
    pub fn folded(&self, relation: RelationShape, lane: usize) -> Vec<(u64, usize)> {
        if relation.prefix == PrefixMode::Absorbed {
            return Vec::new();
        }
        let mut folded = Vec::new();
        for (site, site_lane) in &self.sites {
            let prefix = relation.site_domain(*site);
            if *site_lane == lane && !folded.contains(&prefix) {
                folded.push(prefix);
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
    fn permutation_counts_of_the_g1_core() {
        use PrefixMode::{Absorbed, Folded};
        let blacklist = SigmaRelation::send(CONTROL_BLACKLIST);
        // Absorbed prefixes: openings 18 (33 inputs), credit 14, send chain
        // 6, receive chain 4, statement 16 (28 inputs).
        assert_eq!(shape(SigmaRelation::SEND, Absorbed).permutations(), 72);
        assert_eq!(shape(SigmaRelation::RECEIVE, Absorbed).permutations(), 70);
        // Folding saves one permutation per hash; the controls add none.
        assert_eq!(shape(SigmaRelation::SEND, Folded).permutations(), 67);
        assert_eq!(shape(blacklist, Folded).permutations(), 67);
        assert_eq!(shape(SigmaRelation::RECEIVE, Folded).permutations(), 65);
        let send = shape(SigmaRelation::SEND, Folded);
        assert_eq!(send.site_permutations(HashSite::Statement), 15);
        assert_eq!(send.site_permutations(HashSite::Credit), 13);
        assert_eq!(send.site_permutations(HashSite::Predecessor), 17);
        assert_eq!(send.site_permutations(HashSite::Chain), 5);
        assert_eq!(
            shape(SigmaRelation::RECEIVE, Folded).site_permutations(HashSite::Chain),
            3
        );
        assert_eq!(send.site_domain(HashSite::Predecessor), (CORE_DOMAIN, 33));
        assert_eq!(send.step(), StepRelation::Send);
        assert_eq!(send.label(), "sigma_send_m0_folded");
        assert_eq!(shape(blacklist, Folded).label(), "sigma_send_m1_folded");
        assert_eq!(
            shape(SigmaRelation::RECEIVE, Absorbed).label(),
            "sigma_recv_absorbed"
        );
        assert_eq!(RelationShape::HASH_SITES.len(), 5);
        assert_eq!(RelationShape::default(), send);
    }

    #[test]
    fn lane_plan_balances_longest_first() {
        let send = shape(SigmaRelation::SEND, PrefixMode::Folded);
        let one = LanePlan::new(send, 1);
        assert_eq!(one.lane_permutations(), &[67]);
        assert_eq!(one.glue_lane(), 0);
        assert_eq!(one.glue_start(), Ok(67 * 37));
        let two = LanePlan::new(send, 2);
        // 17 | 17, then 15 onto 17, 13 onto 17, 5 onto 30.
        assert_eq!(two.lane_permutations(), &[32, 35]);
        assert_eq!(two.lane_of(HashSite::Predecessor), 0);
        assert_eq!(two.lane_of(HashSite::Successor), 1);
        assert_eq!(two.lane_of(HashSite::Statement), 0);
        assert_eq!(two.lane_of(HashSite::Credit), 1);
        assert_eq!(two.lane_of(HashSite::Chain), 1);
        assert_eq!(two.glue_lane(), 0);
        assert_eq!(
            two.folded(send, 0),
            vec![(CORE_DOMAIN, 33), (STATEMENT_DOMAIN, 28)]
        );
        assert_eq!(
            two.folded(send, 1),
            vec![
                (CORE_DOMAIN, 33),
                (CREDIT_DOMAIN, 24),
                (SEND_CHAIN_DOMAIN, 9)
            ]
        );
        let absorbed = shape(SigmaRelation::SEND, PrefixMode::Absorbed);
        assert!(LanePlan::new(absorbed, 2).folded(absorbed, 0).is_empty());
        assert_eq!(LanePlan::new(send, 0).lane_permutations(), &[67]);
        assert_eq!(least_loaded(&[3, 1, 1]), 1);
        assert_eq!(least_loaded(&[]), 0);
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
        let quota = SigmaRelation::send(crate::witness::CONTROL_QUOTAS);
        assert_eq!(
            SigmaParams::new(shape(quota, PrefixMode::Folded), 1, 9),
            Err(ParamsError::Relation(quota))
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
        assert!(ParamsError::Relation(quota).to_string().contains("(3, 2)"));
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
