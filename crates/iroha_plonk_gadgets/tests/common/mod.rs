//! Shared test circuits: one configurable circuit that lays out every chip
//! of the crate and runs a "program" (a function over the chips) whose
//! returned words become the public instance, in order.
//!
//! Programs read their witness inputs from [`Inputs`]; during key
//! generation every input is unknown. A program may compare an intermediate
//! value with its native reference and fail with [`Error::Synthesis`] when
//! they differ, so a successful synthesis also proves native parity.

#![allow(dead_code)]

use std::path::PathBuf;

use iroha_pasta::{PastaCurve, msm::MemoryBudget, poseidon::PoseidonField};
use iroha_plonk::{
    ProverConfig, ProverRandomness, VerifyError,
    check::{CheckMode, check_circuit},
    cs::{Advice, Column, ConstraintSystem, Instance, InstanceModeV1, ProofSuffixV1, TranscriptV1},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value, synthesize},
    keys::{KeygenConfig, ProvingKey, keygen_pk},
    pcs::ipa::PinnedParams,
    prove_circuit, verify_full,
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig, LimbBits, Pow5Columns, RoundConstantColumns, RunningSumChip,
    RunningSumConfig, SpongeChip, SpongeConfig, Word,
};

/// The chips a program drives.
pub struct Chips<F: PoseidonField> {
    /// The glue chip.
    pub glue: GlueChip<F>,
    /// The running-sum chip.
    pub range: RunningSumChip<F>,
    /// One sponge per lane.
    pub sponges: Vec<SpongeChip<F>>,
}

/// The witness inputs of a program, and its configuration-time arguments.
pub struct Inputs<F> {
    values: Vec<F>,
    known: bool,
    args: Vec<u64>,
}

impl<F: Copy> Inputs<F> {
    /// Input `index` (unknown during key generation).
    pub fn get(&self, index: usize) -> Value<F> {
        match self.values.get(index) {
            Some(value) if self.known => Value::known(*value),
            _ => Value::unknown(),
        }
    }

    /// The native value of input `index` (for native cross-checks).
    pub fn native(&self, index: usize) -> Option<F> {
        self.values.get(index).copied().filter(|_| self.known)
    }

    /// The number of inputs.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Every input.
    pub fn all(&self) -> Vec<Value<F>> {
        (0..self.len()).map(|index| self.get(index)).collect()
    }

    /// Configuration-time argument `index` (known during key generation;
    /// 0 when absent).
    pub fn arg(&self, index: usize) -> u64 {
        self.args.get(index).copied().unwrap_or(0)
    }
}

/// A program over the chips; its words are exposed publicly in order.
pub type Program<F> =
    fn(&mut Chips<F>, &mut Region<'_, F>, &Inputs<F>) -> Result<Vec<Word<F>>, Error>;

/// The configuration-time shape of a circuit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shape {
    /// Sponge lanes.
    pub lanes: usize,
    /// Whether lanes share one set of round-constant columns.
    pub shared_round_constants: bool,
    /// Folded `(domain, arity)` prefixes of every lane.
    pub folded: Vec<(u64, usize)>,
    /// The running-sum limb width.
    pub limb_bits: usize,
    /// Public outputs.
    pub public: usize,
    /// Program arguments fixed at configuration time (domains, counts).
    pub args: Vec<u64>,
}

impl Shape {
    /// `lanes` lanes, `limb_bits`-bit limbs, `public` outputs, no folding.
    pub fn new(lanes: usize, limb_bits: usize, public: usize) -> Self {
        Self {
            lanes,
            shared_round_constants: true,
            folded: Vec::new(),
            limb_bits,
            public,
            args: Vec::new(),
        }
    }

    /// With program arguments.
    pub fn with_args(mut self, args: &[u64]) -> Self {
        self.args = args.to_vec();
        self
    }

    /// With folded prefixes.
    pub fn folding(mut self, folded: &[(u64, usize)]) -> Self {
        self.folded = folded.to_vec();
        self
    }

    /// With one set of round-constant columns per lane.
    pub fn unshared(mut self) -> Self {
        self.shared_round_constants = false;
        self
    }
}

/// The columns of [`GadgetCircuit`].
#[derive(Clone, Debug)]
pub struct GadgetConfig<F> {
    /// The glue chip.
    pub glue: GlueConfig,
    /// The running-sum chip.
    pub range: RunningSumConfig,
    /// The sponge lanes.
    pub sponges: Vec<SpongeConfig<F>>,
    /// The public outputs.
    pub instance: Column<Instance>,
}

/// A circuit running `program` over every chip.
#[derive(Clone)]
pub struct GadgetCircuit<F: PoseidonField> {
    /// The shape.
    pub shape: Shape,
    /// The program.
    pub program: Program<F>,
    /// The witness inputs.
    pub inputs: Vec<F>,
    /// Whether the inputs are known (false for key generation).
    pub known: bool,
}

impl<F: PoseidonField> GadgetCircuit<F> {
    /// A circuit with known inputs.
    pub fn new(shape: Shape, program: Program<F>, inputs: Vec<F>) -> Self {
        Self {
            shape,
            program,
            inputs,
            known: true,
        }
    }
}

impl<F: PoseidonField> Circuit<F> for GadgetCircuit<F> {
    type Config = GadgetConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Shape;

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }

    fn params(&self) -> Shape {
        self.shape.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, Shape::new(1, 4, 1))
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, shape: Shape) -> Self::Config {
        let advice: [Column<Advice>; 4] = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let z = meta.advice_column();
        let limb_bits = LimbBits::new(shape.limb_bits).unwrap_or_else(|| {
            LimbBits::new(4).unwrap_or_else(|| unreachable!("4 is a valid limb width"))
        });
        let range = RunningSumConfig::configure(meta, z, limb_bits);
        let shared = RoundConstantColumns::allocate(meta);
        let sponges = (0..shape.lanes)
            .map(|lane| {
                let round_constants = if shape.shared_round_constants || lane == 0 {
                    shared
                } else {
                    RoundConstantColumns::allocate(meta)
                };
                let columns = Pow5Columns::allocate(meta);
                SpongeConfig::configure(meta, columns, round_constants, &shape.folded)
            })
            .collect();
        let instance = meta.instance_column(shape.public);
        meta.enable_equality(instance);
        GadgetConfig {
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
        let mut chips = Chips {
            glue: GlueChip::new(config.glue),
            range: RunningSumChip::new(config.range),
            sponges: config.sponges.into_iter().map(SpongeChip::new).collect(),
        };
        chips.range.load_table(&mut layouter)?;
        let inputs = Inputs {
            values: self.inputs.clone(),
            known: self.known,
            args: self.shape.args.clone(),
        };
        let program = self.program;
        let outputs = layouter.assign_region(
            || "gadgets",
            |mut region| program(&mut chips, &mut region, &inputs),
        )?;
        if outputs.len() != self.shape.public {
            return Err(Error::Synthesis);
        }
        for (row, word) in outputs.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.instance, row)?;
        }
        Ok(())
    }
}

/// Whether the strict constraint checker accepts `circuit` with the public
/// outputs `public` (computed natively by each test).
pub fn accepts<F: PoseidonField>(circuit: &GadgetCircuit<F>, k: u32, public: &[F]) -> bool {
    check_circuit(circuit, k, &[public.to_vec()], CheckMode::Strict)
        .is_ok_and(|report| report.is_satisfied())
}

/// The strict checker report as text (for assertion messages).
pub fn report<F: PoseidonField>(circuit: &GadgetCircuit<F>, k: u32, public: &[F]) -> String {
    check_circuit(circuit, k, &[public.to_vec()], CheckMode::Strict).map_or_else(
        |error| format!("synthesis error: {error}"),
        |report| report.to_string(),
    )
}

/// Synthesizes `circuit` and returns the advice tables.
pub fn advice<F: PoseidonField>(circuit: &GadgetCircuit<F>, k: u32, public: &[F]) -> Vec<Vec<F>> {
    let synthesized = synthesize(circuit, k, Some(&[public.to_vec()][..])).expect("synthesis");
    synthesized
        .tables
        .advice()
        .expect("witness tables")
        .to_vec()
}

/// Synthesizes `circuit` and returns, per advice column, the assigned
/// flags.
pub fn assigned<F: PoseidonField>(
    circuit: &GadgetCircuit<F>,
    k: u32,
    public: &[F],
) -> Vec<Vec<bool>> {
    let synthesized = synthesize(circuit, k, Some(&[public.to_vec()][..])).expect("synthesis");
    synthesized.tables.advice_assigned().to_vec()
}

/// Rows `0..` assigned in an advice column: one past the last assigned row.
pub fn extent(flags: &[bool]) -> usize {
    flags
        .iter()
        .rposition(|flag| *flag)
        .map_or(0, |row| row + 1)
}

/// The number of assigned cells in an advice column.
pub fn count(flags: &[bool]) -> usize {
    flags.iter().filter(|flag| **flag).count()
}

/// Advice column indices of the configuration built by [`GadgetCircuit`]:
/// glue `0..4`, running sum `4`, then four columns per lane.
pub const GLUE_COLUMNS: [usize; 4] = [0, 1, 2, 3];
/// The running-sum column index.
pub const RANGE_COLUMN: usize = 4;

/// The four advice column indices of `lane`.
pub const fn lane_columns(lane: usize) -> [usize; 4] {
    let base = 5 + 4 * lane;
    [base, base + 1, base + 2, base + 3]
}

/// The repository root.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The MSM budget of the tests.
pub const BUDGET: MemoryBudget = MemoryBudget::DEFAULT;

/// Keys of a circuit at `k`.
pub struct Keys<C: PastaCurve> {
    /// The parameters.
    pub params: PinnedParams<C>,
    /// The proving key.
    pub pk: ProvingKey<C>,
}

/// Generates keys for `circuit` with `transcript` (Direct instances and the
/// folded-generator suffix with the KAGEMUSHA transcript, Committed
/// instances otherwise).
pub fn keys<C: PastaCurve>(
    circuit: &GadgetCircuit<C::ScalarExt>,
    k: u32,
    transcript: TranscriptV1,
) -> Keys<C>
where
    C::ScalarExt: PoseidonField,
{
    let params = PinnedParams::<C>::derive(k).expect("params");
    let mut config = KeygenConfig::new(transcript);
    if transcript == TranscriptV1::KagemushaPoseidonRp57 {
        config.instance_mode = InstanceModeV1::Direct;
        config.proof_suffix = ProofSuffixV1::FoldedGenerator;
    }
    let pk = keygen_pk(&params, &circuit.without_witnesses(), &config).expect("proving key");
    Keys { params, pk }
}

impl<C: PastaCurve> Keys<C>
where
    C::ScalarExt: PoseidonField,
{
    /// Proves with fresh OS-backed hedged randomness.
    pub fn prove(&self, circuit: &GadgetCircuit<C::ScalarExt>, public: &[C::ScalarExt]) -> Vec<u8> {
        let randomness = ProverRandomness::hedged();
        prove_circuit(
            &self.params,
            &self.pk,
            circuit,
            &[public.to_vec()],
            randomness,
            ProverConfig::default(),
        )
        .expect("proof")
    }

    /// Verifies a proof in full.
    pub fn verify(&self, public: &[C::ScalarExt], proof: &[u8]) -> Result<(), VerifyError> {
        verify_full(
            &self.params,
            self.pk.binding(),
            self.pk.vk(),
            &[public.to_vec()],
            proof,
            BUDGET,
        )
    }
}
