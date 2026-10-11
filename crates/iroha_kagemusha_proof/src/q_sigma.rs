//! Descriptor-fixed `Q_sigma` relation over Fq (Lambda §§2.2–2.7 and §5.2).
//!
//! One shared verifier lane checks the own sigma hard and an optional incoming
//! sigma soft. Witness keys are authorized by their complete `kgwvkey1` digest.
//! The exact LE32 length and fixed descriptor-sized proof buffer are exported
//! as 31-byte chunks from the same byte tape used by verification. The owning A
//! relation checks the selected operation/mask, recomputes the 26-element
//! statement digest, and enforces the global incoming-mode rule; Q binds those
//! exported values and modes to its local claims. A single claim is forwarded
//! with its source k; two claims are folded with an explicit k16 trivial slot.
//!
//! TODO: qualify the composed Q/A/Omega artifacts and their final shared layouts.

pub mod native;

use ff::Field;
use iroha_pasta::{Eq, Fp, Fq, PastaCurve};
use iroha_plonk::{
    VerifyingKey,
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value},
    pcs::ipa::PinnedParams,
    transcript::{TranscriptRepr, decode_point},
};
use iroha_plonk_gadgets::{
    GlueChip, Word,
    bytes::{
        element::{LeElement, decode_le_element, le_message_segments},
        tape::{BytesChip, BytesConfig, SegmentSpec},
    },
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    FOLD_WITNESS_BYTES, K, VESTA_TRIVIAL_GENERATOR,
    accumulation_circuit::{FoldInputCells, FoldPlan, FoldSource},
    codec::ScalarCells,
    obligation::ModeCells,
    verifier::{VerificationMode, VerifierChip, VerifierConfig, VerifierPlan},
};

/// One descriptor class and its entries in the global sigma allowlist.
#[derive(Clone, Debug)]
pub struct SigmaClass {
    verifier: VerifierPlan<Eq>,
    entries: Vec<(u8, Fq)>,
}
impl SigmaClass {
    /// Binds a PIPA-R sigma descriptor and 1..=16 distinct global indices and
    /// key digests. The one public sigma instance is a bounded Fp statement.
    ///
    /// # Errors
    /// Wrong instance schema, duplicate/out-of-range entries or unsupported k.
    pub fn new(verifier: VerifierPlan<Eq>, entries: Vec<(u8, Fq)>) -> Result<Self, Error> {
        let descriptor = verifier.binding().descriptor();
        if !matches!(descriptor.k, 12 | 14)
            || descriptor.instance_lengths != [1]
            || descriptor.instance_types.as_deref() != Some(&[InstanceType::Bounded])
            || entries.is_empty()
            || entries.len() > 16
            || entries
                .iter()
                .enumerate()
                .any(|(position, (index, digest))| {
                    *index >= 16
                        || entries[..position]
                            .iter()
                            .any(|(other_index, other_digest)| {
                                other_index == index || other_digest == digest
                            })
                })
        {
            return Err(Error::Synthesis);
        }
        Ok(Self { verifier, entries })
    }
    /// The fixed inner proof program.
    pub const fn verifier(&self) -> &VerifierPlan<Eq> {
        &self.verifier
    }
    /// Actual complete native key digest authorized for this global sigma selector.
    /// Installation uses this metadata to require every frozen operation/mask entry;
    /// it is not a proof verdict or a witness-selected key.
    #[must_use]
    pub fn selector_key_digest(&self, selector: u8) -> Option<Fq> {
        self.entries
            .iter()
            .find(|(index, _)| *index == selector)
            .map(|(_, digest)| *digest)
    }

    /// Number of exported 31-byte chunks, including the four-byte length.
    pub fn chunks(&self) -> usize {
        (4 + self.verifier.proof_length()).div_ceil(31)
    }
}

/// Fixed `Q_sigma` program: one own slot and optionally one incoming slot.
#[derive(Clone, Debug)]
pub struct QSigmaPlan {
    own: SigmaClass,
    incoming: Option<SigmaClass>,
    fold: Option<FoldPlan<Eq>>,
    trivial: Eq,
}
impl QSigmaPlan {
    /// Fixed number of sigma slots, own first and optional incoming second.
    pub fn slot_count(&self) -> usize {
        1 + usize::from(self.incoming.is_some())
    }
    /// Descriptor class of a fixed slot; indices outside the schema return None.
    pub fn class(&self, slot: usize) -> Option<&SigmaClass> {
        match slot {
            0 => Some(&self.own),
            1 => self.incoming.as_ref(),
            _ => None,
        }
    }
    /// The slot's chunk interval in public column zero. Its statement occupies
    /// row `slot`, its key index column two, and verdict column three.
    pub fn chunk_range(&self, slot: usize) -> Option<core::ops::Range<usize>> {
        let count = self.class(slot)?.chunks();
        let start = self.slot_count() + if slot == 0 { 0 } else { self.own.chunks() };
        Some(start..start + count)
    }
    /// The sixteen normalized part challenges in public column zero.
    pub fn challenge_range(&self) -> core::ops::Range<usize> {
        let end = self.instance_lengths()[0];
        end - K..end
    }
    /// Fixed source k of the forwarded or folded output part.
    pub fn part_source_k(&self) -> u32 {
        if self.incoming.is_some() {
            16
        } else {
            u32::from(self.own.verifier.binding().descriptor().k)
        }
    }
    /// Fixes every slot and its descriptor. The two-sigma program explicitly
    /// includes the pinned trivial k16 input as its third fold slot.
    ///
    /// # Errors
    /// Insufficient k16 parameters or an invalid fixed fold schema.
    pub fn new(
        own: SigmaClass,
        incoming: Option<SigmaClass>,
        params: &PinnedParams<Eq>,
    ) -> Result<Self, Error> {
        params.require_k(16).map_err(|_| Error::Synthesis)?;
        if incoming.as_ref().is_some_and(|incoming| {
            own.entries.iter().any(|(index, digest)| {
                incoming.entries.iter().any(|(other_index, other_digest)| {
                    (index == other_index) != (digest == other_digest)
                })
            })
        }) {
            return Err(Error::Synthesis);
        }
        let trivial =
            Eq::from(decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).map_err(|_| Error::Synthesis)?);
        let fold = incoming
            .as_ref()
            .map(|incoming| {
                FoldPlan::with_sources(
                    params,
                    vec![
                        FoldSource::Fixed(u32::from(own.verifier.binding().descriptor().k)),
                        FoldSource::Incoming(u32::from(incoming.verifier.binding().descriptor().k)),
                        FoldSource::Fixed(16),
                    ],
                )
                .map_err(|_| Error::Synthesis)
            })
            .transpose()?;
        Ok(Self {
            own,
            incoming,
            fold,
            trivial,
        })
    }
    /// Fixed public-column lengths, in [`Self::instance_types`] order.
    /// Bounded is statements, own/incoming chunks, then sixteen challenges;
    /// Field is G.x/G.y; Bits4 is key indices; Bits1 is proof verdicts then
    /// incoming Accept/Trivial/Corrected; Bits5 is the selected part's source k.
    pub fn instance_lengths(&self) -> [usize; 5] {
        let count = 1 + usize::from(self.incoming.is_some());
        [
            count + self.own.chunks() + self.incoming.as_ref().map_or(0, SigmaClass::chunks) + K,
            2,
            count,
            count + 3 * usize::from(self.incoming.is_some()),
            1,
        ]
    }
    /// Homogeneous public-column types for the outer PIPA-R descriptor.
    pub const fn instance_types() -> [InstanceType; 5] {
        [
            InstanceType::Bounded,
            InstanceType::Field,
            InstanceType::Bits(4),
            InstanceType::Bits(1),
            InstanceType::Bits(5),
        ]
    }
}

/// One sigma witness. `proof` is exactly the descriptor-sized buffer; `length`
/// is the original LE32 carrier length, linked to the exported byte tape.
/// Native-equivalent verification rejects any unequal length. The parent A
/// independently checks the same carrier class and final chunk padding.
#[derive(Clone, Debug)]
pub struct SigmaSlotWitness {
    /// Authorized witness key; its cells, rather than this host object, bind verification.
    pub key: VerifyingKey<Eq>,
    /// The sigma instance, compared by A with its recomputed statement digest.
    pub statement: Fp,
    /// Fixed-size retained bytes, never truncated by this relation.
    pub proof: Vec<u8>,
    /// Original carrier length.
    pub length: u32,
}
/// The incoming sigma slot and its locally bound global mode.
#[derive(Clone, Debug)]
pub struct IncomingSigmaWitness {
    /// The soft sigma proof.
    pub sigma: SigmaSlotWitness,
    /// Accept, Trivial and Corrected bits, checked one-hot.
    pub mode: [bool; 3],
    /// Finite replacement point; constrained different when Corrected is selected.
    pub corrected: Eq,
    /// Exact local AS witness over own, selected incoming and explicit trivial.
    pub fold: [u8; FOLD_WITNESS_BYTES],
}
/// Complete local relation witness, with fixed slot presence determined by the plan.
#[derive(Clone, Debug)]
pub struct QSigmaWitness {
    /// Own step, always verified hard.
    pub own: SigmaSlotWitness,
    /// Present exactly when the fixed program has an incoming sigma slot.
    pub incoming: Option<IncomingSigmaWitness>,
}

/// One shared verifier/FF/ECC/glue/range/transcript lane and one shared byte tape.
#[derive(Clone, Debug)]
pub struct QSigmaConfig {
    verifier: VerifierConfig<Eq>,
    bytes: BytesConfig,
    output: [Column<Instance>; 5],
}
/// The concrete `Q_sigma` circuit. This component binds its local obligations;
/// acceptance still requires the parent A/Ω composition and both final decisions.
#[derive(Clone, Debug)]
pub struct QSigmaCircuit {
    /// Circuit-fixed descriptor classes, allowlist and slot schedule.
    pub plan: QSigmaPlan,
    /// Prover inputs; discarded by `without_witnesses` without changing layout.
    pub witness: QSigmaWitness,
    known: bool,
}
impl QSigmaCircuit {
    /// Builds a concrete circuit, rejecting structural buffer/slot mismatches.
    ///
    /// # Errors
    /// A buffer or optional slot differs from the circuit-fixed program.
    pub fn new(plan: QSigmaPlan, witness: QSigmaWitness) -> Result<Self, Error> {
        Self::check_structure(&plan, &witness)?;
        Ok(Self {
            plan,
            witness,
            known: true,
        })
    }

    /// Selects an explicit artifact profile with shared integer/foreign range
    /// buses. The complete relation and fixed byte-prefix reservation are
    /// unchanged; its descriptor and keys are distinct from this circuit's
    /// default profile. There is no runtime profile fallback.
    ///
    /// # Errors
    /// The fixed number of range buses is outside `1..=8`.
    pub fn with_serialized_foreign(
        self,
        range_buses: usize,
    ) -> Result<SerializedQSigmaCircuit, Error> {
        if !(1..=8).contains(&range_buses) {
            return Err(Error::Synthesis);
        }
        Ok(SerializedQSigmaCircuit {
            circuit: self,
            range_buses,
        })
    }
    fn check_structure(plan: &QSigmaPlan, witness: &QSigmaWitness) -> Result<(), Error> {
        if witness.own.proof.len() != plan.own.verifier.proof_length()
            || plan.incoming.is_some() != witness.incoming.is_some()
            || plan
                .incoming
                .as_ref()
                .zip(witness.incoming.as_ref())
                .is_some_and(|(class, witness)| {
                    witness.sigma.proof.len() != class.verifier.proof_length()
                })
        {
            return Err(Error::Synthesis);
        }
        Ok(())
    }
    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn slot(
        &self,
        chip: &mut VerifierChip<Eq>,
        tape: TapedProof,
        region: &mut iroha_plonk::frontend::Region<'_, Fq>,
        class: &SigmaClass,
        witness: &SigmaSlotWitness,
        mode: VerificationMode,
    ) -> Result<SlotOutput, Error> {
        let TranscriptRepr::Base(repr) = *witness.key.transcript_repr() else {
            return Err(Error::Synthesis);
        };
        let points = |points: &[<Eq as PastaCurve>::AffineExt]| {
            points
                .iter()
                .map(|point| self.value(Eq::from(*point)))
                .collect::<Vec<_>>()
        };
        let key = chip.witness_key(
            region,
            self.value(repr),
            &points(witness.key.fixed_commitments()),
            &points(witness.key.permutation_commitments()),
        )?;
        let [lo, hi] = foreign_limbs(&witness.statement);
        let lo = chip.uint().assign::<128>(region, self.value(lo))?;
        let hi = chip.uint().assign::<127>(region, self.value(hi))?;
        let statement = ScalarCells::<Eq>::from_limbs(&mut chip.uint(), region, &lo, &hi)?;
        let TapedProof {
            messages,
            length,
            chunks,
        } = tape;
        let output = chip.verify(
            region,
            &class.verifier,
            &key,
            &[vec![statement.clone()]],
            &messages,
            &length,
            mode,
        )?;
        let mut sum = chip.uint().glue().constant(region, Fq::ZERO)?;
        let mut index = sum.clone();
        for (entry_index, digest) in &class.entries {
            let digest = chip.uint().glue().constant(region, *digest)?;
            let matches = chip
                .uint()
                .glue()
                .is_equal(region, &output.key_digest, &digest)?;
            sum = chip.uint().glue().add(region, &sum, matches.word())?;
            index = chip.uint().glue().linear(
                region,
                &[
                    (Fq::ONE, &index),
                    (Fq::from(u64::from(*entry_index)), matches.word()),
                ],
                Fq::ZERO,
            )?;
        }
        GlueChip::assert_constant(region, &sum, Fq::ONE)?;
        let claim = FoldInputCells::from_claim(chip, region, &output.claim)?;
        Ok(SlotOutput {
            statement: statement.native_word().ok_or(Error::Synthesis)?.clone(),
            chunks,
            index,
            valid: output.valid.word().clone(),
            claim,
        })
    }
    fn proof_tape(
        &self,
        chip: &mut VerifierChip<Eq>,
        bytes: &mut BytesChip<Fq>,
        region: &mut iroha_plonk::frontend::Region<'_, Fq>,
        proof: &[u8],
        length: u32,
    ) -> Result<TapedProof, Error> {
        if !proof.len().is_multiple_of(32) {
            return Err(Error::Synthesis);
        }
        let input: Vec<_> = length
            .to_le_bytes()
            .iter()
            .chain(proof)
            .map(|byte| self.value(*byte))
            .collect();
        let primary: Vec<_> = input.chunks(31).map(<[Value<u8>]>::len).collect();
        let mut secondary = vec![SegmentSpec::little(0, 4)];
        secondary.extend(le_message_segments(4, proof.len() / 32));
        let run = bytes.run(region, &input, &primary, &secondary)?;
        let length = chip.uint().range_check::<32>(
            region,
            run.secondary_segment(SegmentSpec::little(0, 4))?.word(),
        )?;
        let messages = (0..proof.len() / 32)
            .map(|index| decode_le_element(&mut chip.uint(), region, &run, 4 + 32 * index))
            .collect::<Result<Vec<_>, _>>()?;
        // A short final segment is the integer with canonical high zero padding.
        let chunks = run
            .primary()
            .iter()
            .map(|segment| segment.word().clone())
            .collect();
        Ok(TapedProof {
            messages,
            length,
            chunks,
        })
    }
}

/// The exact `Q_sigma` relation with an explicitly selected serialized foreign
/// arithmetic profile. Its range-bus count is immutable circuit metadata.
///
/// TODO: qualify the largest two-sigma/fold layout and composed A/Ω artifacts
/// before selecting this profile for the released key catalog.
#[derive(Clone, Debug)]
pub struct SerializedQSigmaCircuit {
    circuit: QSigmaCircuit,
    range_buses: usize,
}

impl Circuit<Fq> for SerializedQSigmaCircuit {
    type Config = QSigmaConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = (<QSigmaCircuit as Circuit<Fq>>::Params, usize);

    fn without_witnesses(&self) -> Self {
        Self {
            circuit: self.circuit.without_witnesses(),
            range_buses: self.range_buses,
        }
    }

    fn params(&self) -> Self::Params {
        (self.circuit.params(), self.range_buses)
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        Self::configure_with_params(meta, (([0; 5], 0), 1))
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<Fq>,
        ((lengths, byte_rows), range_buses): Self::Params,
    ) -> Self::Config {
        let (verifier, bytes) =
            VerifierConfig::configure_serialized_with_byte_tape(meta, range_buses, byte_rows)
                .expect("constructor checked the circuit-fixed range-bus count");
        let output = lengths.map(|length| {
            let column = meta.instance_column(length);
            meta.enable_equality(column);
            column
        });
        QSigmaConfig {
            verifier,
            bytes,
            output,
        }
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fq>) -> Result<(), Error> {
        self.circuit.synthesize(config, layouter)
    }
}
struct TapedProof {
    messages: Vec<LeElement<Fq>>,
    length: iroha_plonk_gadgets::Uint<Fq, 32>,
    chunks: Vec<Word<Fq>>,
}
struct SlotOutput {
    statement: Word<Fq>,
    chunks: Vec<Word<Fq>>,
    index: Word<Fq>,
    valid: Word<Fq>,
    claim: FoldInputCells<Eq>,
}
impl Circuit<Fq> for QSigmaCircuit {
    type Config = QSigmaConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ([usize; 5], usize);
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn params(&self) -> Self::Params {
        let bytes = 4
            + self.plan.own.verifier.proof_length()
            + self.plan.incoming.as_ref().map_or(0, |class| {
                4 + class.verifier.proof_length() + 4 + FOLD_WITNESS_BYTES
            });
        (self.plan.instance_lengths(), bytes)
    }
    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        Self::configure_with_params(meta, ([0; 5], 0))
    }
    fn configure_with_params(
        meta: &mut ConstraintSystem<Fq>,
        (lengths, byte_rows): Self::Params,
    ) -> Self::Config {
        let (verifier, bytes) = VerifierConfig::configure_with_byte_tape(meta, byte_rows);
        let output = lengths.map(|length| {
            let column = meta.instance_column(length);
            meta.enable_equality(column);
            column
        });
        QSigmaConfig {
            verifier,
            bytes,
            output,
        }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        Self::check_structure(&self.plan, &self.witness)?;
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let columns = layouter.assign_region(
            || "Q sigma fixed obligations",
            |mut region| {
                // All byte rows precede the curve lane in its shared columns.
                // Integer decoding uses the independent glue/range lanes.
                let own_tape = self.proof_tape(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    &self.witness.own.proof,
                    self.witness.own.length,
                )?;
                let incoming_tapes = self
                    .witness
                    .incoming
                    .as_ref()
                    .map(|incoming| {
                        let sigma = self.proof_tape(
                            &mut chip,
                            &mut bytes,
                            &mut region,
                            &incoming.sigma.proof,
                            incoming.sigma.length,
                        )?;
                        let fold = self.proof_tape(
                            &mut chip,
                            &mut bytes,
                            &mut region,
                            &incoming.fold,
                            u32::try_from(FOLD_WITNESS_BYTES).map_err(|_| Error::BoundsFailure)?,
                        )?;
                        Ok::<_, Error>((sigma, fold))
                    })
                    .transpose()?;
                let own = self.slot(
                    &mut chip,
                    own_tape,
                    &mut region,
                    &self.plan.own,
                    &self.witness.own,
                    VerificationMode::Hard,
                )?;
                let mut statements = vec![own.statement];
                let mut chunks = own.chunks;
                let mut indices = vec![own.index];
                let mut verdicts = vec![own.valid];
                let part = if let Some(incoming) = &self.witness.incoming {
                    let class = self.plan.incoming.as_ref().ok_or(Error::Synthesis)?;
                    let (incoming_tape, fold_tape) = incoming_tapes.ok_or(Error::Synthesis)?;
                    let slot = self.slot(
                        &mut chip,
                        incoming_tape,
                        &mut region,
                        class,
                        &incoming.sigma,
                        VerificationMode::Soft,
                    )?;
                    statements.push(slot.statement);
                    chunks.extend(slot.chunks);
                    indices.push(slot.index);
                    verdicts.push(slot.valid);
                    let modes = incoming
                        .mode
                        .map(|value| {
                            chip.uint()
                                .glue()
                                .witness(&mut region, self.value(Fq::from(u64::from(value))))
                        })
                        .into_iter()
                        .collect::<Result<Vec<_>, _>>()?;
                    let modes: [Word<Fq>; 3] = modes.try_into().map_err(|_| Error::Synthesis)?;
                    let mode = ModeCells::constrain(chip.uint().glue(), &mut region, &modes)?;
                    verdicts.extend(modes);
                    let corrected =
                        chip.witness_point(&mut region, self.value(incoming.corrected))?;
                    let selected = FoldInputCells::select_incoming(
                        &mut chip,
                        &mut region,
                        &slot.claim,
                        &corrected,
                        &mode,
                    )?;
                    let g = chip.constant_point(&mut region, &self.plan.trivial)?;
                    let one = chip.uint().constant::<128>(&mut region, 1)?;
                    let zero = chip.uint().constant::<127>(&mut region, 0)?;
                    let one = ScalarCells::from_limbs(&mut chip.uint(), &mut region, &one, &zero)?;
                    let trivial = FoldInputCells::from_normalized(
                        &mut chip,
                        &mut region,
                        16,
                        g,
                        core::array::from_fn(|_| one.clone()),
                    )?;
                    let TapedProof {
                        messages, length, ..
                    } = fold_tape;
                    let folded = chip.verify_fold(
                        &mut region,
                        self.plan.fold.as_ref().ok_or(Error::Synthesis)?,
                        &[own.claim, selected, trivial],
                        &messages,
                        &length,
                        VerificationMode::Hard,
                    )?;
                    FoldInputCells::from_claim(&mut chip, &mut region, &folded.claim)?
                } else {
                    own.claim
                };
                statements.extend(chunks);
                statements.extend(
                    part.challenges()
                        .iter()
                        .map(|challenge| challenge.native_word().cloned().ok_or(Error::Synthesis))
                        .collect::<Result<Vec<_>, _>>()?,
                );
                Ok([
                    statements,
                    vec![part.g().x().clone(), part.g().y().clone()],
                    indices,
                    verdicts,
                    vec![part.source_k().clone()],
                ])
            },
        )?;
        for (column, values) in config.output.into_iter().zip(columns) {
            for (row, value) in values.into_iter().enumerate() {
                layouter.constrain_instance(value.cell(), column, row)?;
            }
        }
        Ok(())
    }
}
