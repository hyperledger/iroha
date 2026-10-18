//! Unregistered native AIR for the seven public scalar shift/rotate opcodes.
//!
//! Three radix-four barrel stages select shifts by 0/1/2/3, 0/4/8/12 and
//! 0/16/32/48 bits. Two Boolean amount bits constrain each stage's four
//! selector columns with quadratic equations. Dynamic opcode selector × stage
//! selector × input bit has degree three. Fixed-opcode single-step equations
//! have degree two; the declared degree-four native envelope is conservative.
//! Stage outputs are uniquely Boolean by induction. The high amount bits
//! remain bound to the source word but never select a stage, proving
//! exact six-bit masking. Arithmetic right shifts copy the input sign bit;
//! logical shifts insert zero, and rotations wrap the bit position.
//!
//! This public single-step relation constrains source pre/post values, destination
//! writes, tags, r0, aliases, PC, cycles and the opcode's base gas. It does not
//! authenticate fetch, the other registers, memory, private trace values, host
//! effects or complete invocation continuity. No production profile uses it.

use super::super::stark::{
    aggregate_stark::{AggregateStarkDomainsV1, AggregateStarkParametersV1},
    proof_managed_note_stark::{
        NOTE_COPY_AUX_WIDTH_V1, NOTE_COPY_FIXED_WIDTH_V1, NOTE_COPY_WIDTH_V1, NoteCopyCellPolicyV1,
        NoteCopyChallengesV1, NoteCopyScheduleV1, ProofManagedNoteStarkAdapterV1,
        ProofManagedNoteStarkErrorV1, ProofManagedNoteStarkProtocolV1,
    },
};
use super::{
    F, GoldilocksDigest384V1, TRACE_LOG2, TRACE_SIZE, TransparentStarkDigestContextV1,
    TransparentTranscriptV1, gas, goldilocks_digest384_frame_v1, wide,
    word::{self, Sources},
};

const COUNTERS: usize = 6;
const WORD_LIMBS: usize = 4;
const LEFT_OFFSET: usize = COUNTERS;
const AMOUNT_OFFSET: usize = LEFT_OFFSET + WORD_LIMBS;
const RESULT_OFFSET: usize = AMOUNT_OFFSET + WORD_LIMBS;
const DESTINATION_OFFSET: usize = RESULT_OFFSET + WORD_LIMBS;
const LEFT_AFTER_OFFSET: usize = DESTINATION_OFFSET + WORD_LIMBS;
const AMOUNT_AFTER_OFFSET: usize = LEFT_AFTER_OFFSET + WORD_LIMBS;
const TAG_OFFSET: usize = AMOUNT_AFTER_OFFSET + WORD_LIMBS;
const TAGS: usize = 5;
const PUBLIC_WIDTH: usize = TAG_OFFSET + TAGS;
const FIXED_WIDTH: usize = PUBLIC_WIDTH;
const WORD_BITS: usize = 64;
const STAGES: usize = 3;
const SOURCE_OFFSET: usize = PUBLIC_WIDTH;
const BANK_OFFSET: usize = SOURCE_OFFSET + word::WIDTH;
pub(super) const RESULT: usize = 0;
const STAGE: usize = 4;
const SELECTORS: usize = STAGE + STAGES * WORD_BITS;
pub(super) const BANK_WIDTH: usize = SELECTORS + 4 * STAGES;
pub(super) const BANK_CONSTRAINTS: usize = 208;
const ROW_WIDTH: usize = BANK_OFFSET + BANK_WIDTH;
const MAXIMUM_DEGREE: u8 = 4;
const CONSTRAINT_COUNT: usize =
    PUBLIC_WIDTH + 3 + TAGS + word::WIDTH + 3 * WORD_LIMBS + BANK_CONSTRAINTS + 7 * WORD_LIMBS;
#[cfg(test)]
const STAGE_OFFSET: usize = BANK_OFFSET + STAGE;
#[cfg(test)]
const STAGE_SELECTORS_OFFSET: usize = BANK_OFFSET + SELECTORS;

const CONTEXT: TransparentStarkDigestContextV1 =
    TransparentStarkDigestContextV1::execution_v1(b"ivm-shift-step-air-v1");
const DOMAINS: AggregateStarkDomainsV1 = AggregateStarkDomainsV1 {
    digest_context: CONTEXT,
    base_leaf: b"ivm-shift-base-leaf-v1",
    base_node: b"ivm-shift-base-node-v1",
    aux_leaf: b"ivm-shift-aux-leaf-v1",
    aux_node: b"ivm-shift-aux-node-v1",
    composition_leaf: b"ivm-shift-composition-leaf-v1",
    composition_node: b"ivm-shift-composition-node-v1",
    fri_leaf: b"ivm-shift-fri-leaf-v1",
    fri_node: b"ivm-shift-fri-node-v1",
    layout_label: b"ivm-shift-layout-v1",
    base_root_label: b"ivm-shift-base-root-v1",
    aux_root_label: b"ivm-shift-aux-root-v1",
    composition_root_label: b"ivm-shift-composition-root-v1",
    fri_root_label: b"ivm-shift-fri-root-v1",
    fri_beta_label: b"ivm-shift-fri-beta-v1",
    query_seed: b"ivm-shift-query-seed-v1",
};
const PROFILE: &[u8] = b"ivm-shift-step-air-v1:public-single-step:sll-srl-sra:rotl-rotr:rotl-imm-rotr-imm:unsigned-imm8:amount-mask=63:radix4-barrel-stages=1,4,16:quadratic-stage-selectors:input-boolean:arithmetic-sign-fill:degree4:pre-read:post-write:r0:aliases:public-tags:pc+4:cycles+1:shift-gas=1:rotate-gas=2:no-machine-admission";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShiftKind {
    Left,
    RightLogical,
    RightArithmetic,
    RotateLeft,
    RotateRight,
}

impl ShiftKind {
    fn from_word(word: u32) -> Option<Self> {
        match wide::opcode(word) {
            wide::arithmetic::SLL => Some(Self::Left),
            wide::arithmetic::SRL => Some(Self::RightLogical),
            wide::arithmetic::SRA => Some(Self::RightArithmetic),
            wide::arithmetic::ROTL | wide::arithmetic::ROTL_IMM => Some(Self::RotateLeft),
            wide::arithmetic::ROTR | wide::arithmetic::ROTR_IMM => Some(Self::RotateRight),
            _ => None,
        }
    }

    const fn gas(self) -> u64 {
        match self {
            Self::Left | Self::RightLogical | Self::RightArithmetic => 1,
            Self::RotateLeft | Self::RotateRight => 2,
        }
    }

    /// Native witness construction only; the verifier uses bit equations below.
    fn apply(self, value: u64, amount: u32) -> u64 {
        let amount = amount & 63;
        match self {
            Self::Left => value << amount,
            Self::RightLogical => value >> amount,
            Self::RightArithmetic => i64::cast_unsigned(u64::cast_signed(value) >> amount),
            Self::RotateLeft => value.rotate_left(amount),
            Self::RotateRight => value.rotate_right(amount),
        }
    }
}

/// The two admitted immediate rotations zero-extend the raw eight-bit field.
fn immediate_amount(word: u32) -> Option<u64> {
    matches!(
        wide::opcode(word),
        wide::arithmetic::ROTL_IMM | wide::arithmetic::ROTR_IMM
    )
    .then(|| u64::from(i8::cast_unsigned(wide::imm8(word))))
}

#[derive(Clone, Copy, Debug)]
struct ShiftStepStatement {
    word: u32,
    before_pc: u32,
    after_pc: u32,
    before_gas: u32,
    after_gas: u32,
    before_cycles: u32,
    after_cycles: u32,
    left: u64,
    amount: u64,
    result: u64,
    destination_after: u64,
    left_after: u64,
    /// For RI this is the unchanged synthetic unsigned immediate, not a register.
    amount_after: u64,
    left_tag: bool,
    amount_tag: bool,
    destination_tag: bool,
    left_tag_after: bool,
    /// RI's synthetic immediate has no private register tag and is always public.
    amount_tag_after: bool,
}

impl ShiftStepStatement {
    fn validate(self) -> Result<(), ProofManagedNoteStarkErrorV1> {
        let kind =
            ShiftKind::from_word(self.word).ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)?;
        if gas::cost_of(self.word) != Some(kind.gas())
            || immediate_amount(self.word).is_some_and(|amount| self.amount != amount)
            || !self.before_pc.is_multiple_of(4)
            || !self.after_pc.is_multiple_of(4)
            || self.tags().into_iter().any(|tag| tag)
        {
            return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
        }
        Ok(())
    }

    fn tags(self) -> [bool; TAGS] {
        [
            self.left_tag,
            self.amount_tag,
            self.destination_tag,
            self.left_tag_after,
            self.amount_tag_after,
        ]
    }

    fn fixed(self) -> [F; FIXED_WIDTH] {
        let mut fixed = [F::ZERO; FIXED_WIDTH];
        fixed[..COUNTERS].copy_from_slice(&[
            F(u64::from(self.before_pc)),
            F(u64::from(self.after_pc)),
            F(u64::from(self.before_gas)),
            F(u64::from(self.after_gas)),
            F(u64::from(self.before_cycles)),
            F(u64::from(self.after_cycles)),
        ]);
        for (operand, value) in [
            self.left,
            immediate_amount(self.word).unwrap_or(self.amount),
            self.result,
            self.destination_after,
            self.left_after,
            self.amount_after,
        ]
        .into_iter()
        .enumerate()
        {
            for limb in 0..WORD_LIMBS {
                fixed[LEFT_OFFSET + operand * WORD_LIMBS + limb] =
                    F((value >> (16 * limb)) & 0xffff);
            }
        }
        for (index, tag) in self.tags().into_iter().enumerate() {
            fixed[TAG_OFFSET + index] = F(u64::from(tag));
        }
        fixed
    }

    fn witness(self) -> [F; ROW_WIDTH] {
        let mut row = [F::ZERO; ROW_WIDTH];
        row[..PUBLIC_WIDTH].copy_from_slice(&self.fixed());
        let amount = immediate_amount(self.word).unwrap_or(self.amount);
        row[SOURCE_OFFSET..BANK_OFFSET].copy_from_slice(&word::witness(self.left, amount));
        let opcode = match ShiftKind::from_word(self.word).expect("validated shift") {
            ShiftKind::Left => wide::arithmetic::SLL,
            ShiftKind::RightLogical => wide::arithmetic::SRL,
            ShiftKind::RightArithmetic => wide::arithmetic::SRA,
            ShiftKind::RotateLeft => wide::arithmetic::ROTL,
            ShiftKind::RotateRight => wide::arithmetic::ROTR,
        };
        row[BANK_OFFSET..].copy_from_slice(&bank_witness(opcode, self.left, amount));
        row
    }

    fn digest(self) -> Result<GoldilocksDigest384V1, ProofManagedNoteStarkErrorV1> {
        let word = self.word.to_be_bytes();
        let counters = [
            self.before_pc.to_be_bytes(),
            self.after_pc.to_be_bytes(),
            self.before_gas.to_be_bytes(),
            self.after_gas.to_be_bytes(),
            self.before_cycles.to_be_bytes(),
            self.after_cycles.to_be_bytes(),
        ];
        let operands = [
            self.left.to_be_bytes(),
            self.amount.to_be_bytes(),
            self.result.to_be_bytes(),
            self.destination_after.to_be_bytes(),
            self.left_after.to_be_bytes(),
            self.amount_after.to_be_bytes(),
        ];
        let tags = self.tags().map(u8::from);
        goldilocks_digest384_frame_v1(
            CONTEXT,
            b"ivm-shift-public-step-v1",
            b"statement",
            0,
            0,
            0,
            &[
                &word,
                &counters[0],
                &counters[1],
                &counters[2],
                &counters[3],
                &counters[4],
                &counters[5],
                &operands[0],
                &operands[1],
                &operands[2],
                &operands[3],
                &operands[4],
                &operands[5],
                &tags,
            ],
        )
        .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)
    }
}

/// Quadratic selectors of two Boolean bits, also used with dynamic opcode dispatch.
fn stage_selectors(low: F, high: F) -> [F; 4] {
    [
        F::ONE.sub(low).mul(F::ONE.sub(high)),
        low.mul(F::ONE.sub(high)),
        F::ONE.sub(low).mul(high),
        low.mul(high),
    ]
}

const KINDS: [ShiftKind; 5] = [
    ShiftKind::Left,
    ShiftKind::RightLogical,
    ShiftKind::RightArithmetic,
    ShiftKind::RotateLeft,
    ShiftKind::RotateRight,
];

fn kind_selectors(kind: ShiftKind) -> [F; 5] {
    KINDS.map(|candidate| F(u64::from(candidate == kind)))
}

/// Public opcode/position determines the wire selected at a barrel-stage input.
fn stage_input(kind: ShiftKind, previous: &[F], sign: F, position: usize, shift: usize) -> F {
    match kind {
        ShiftKind::Left => position
            .checked_sub(shift)
            .map_or(F::ZERO, |index| previous[index]),
        ShiftKind::RightLogical => previous.get(position + shift).copied().unwrap_or(F::ZERO),
        ShiftKind::RightArithmetic => previous.get(position + shift).copied().unwrap_or(sign),
        ShiftKind::RotateLeft => previous[(position + WORD_BITS - shift) % WORD_BITS],
        ShiftKind::RotateRight => previous[(position + shift) % WORD_BITS],
    }
}

fn residues(row: &[F], fixed: &[F], word: u32) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1> {
    if row.len() != ROW_WIDTH || fixed.len() != FIXED_WIDTH {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    let kind = ShiftKind::from_word(word).ok_or(ProofManagedNoteStarkErrorV1::InvalidProfile)?;
    let mut out = Vec::with_capacity(CONSTRAINT_COUNT);
    for index in 0..PUBLIC_WIDTH {
        out.push(row[index].sub(fixed[index]));
    }
    out.push(row[1].sub(row[0]).sub(F(4)));
    out.push(row[2].sub(row[3]).sub(F(kind.gas())));
    out.push(row[5].sub(row[4]).sub(F::ONE));
    for tag in 0..TAGS {
        out.push(row[TAG_OFFSET + tag]);
    }
    let sources = Sources::new(&row[SOURCE_OFFSET..BANK_OFFSET]);
    sources.append_residues(&mut out);
    for limb in 0..4 {
        out.push(row[LEFT_OFFSET + limb].sub(sources.limb(0, limb)));
        out.push(row[AMOUNT_OFFSET + limb].sub(sources.limb(1, limb)));
        out.push(row[RESULT_OFFSET + limb].sub(row[BANK_OFFSET + RESULT + limb]));
    }
    out.extend(bank_residues(
        &row[BANK_OFFSET..],
        sources,
        kind_selectors(kind),
    ));
    let rd = wide::rd(word);
    let left_register = wide::rs1(word);
    let amount_register = wide::rs2(word);
    let immediate = immediate_amount(word);
    let left_zero = F(u64::from(left_register == 0));
    let amount_zero = F(u64::from(immediate.is_none() && amount_register == 0));
    let sources_alias = F(u64::from(
        immediate.is_none() && left_register == amount_register,
    ));
    let destination_live = F(u64::from(rd != 0));
    for limb in 0..WORD_LIMBS {
        let result = row[BANK_OFFSET + RESULT + limb];
        let left = row[LEFT_OFFSET + limb];
        let amount = row[AMOUNT_OFFSET + limb];
        out.push(left_zero.mul(left));
        out.push(amount_zero.mul(amount));
        out.push(sources_alias.mul(left.sub(amount)));
        out.push(row[DESTINATION_OFFSET + limb].sub(destination_live.mul(result)));
        let left_after = if rd != 0 && rd == left_register {
            result
        } else {
            left
        };
        let amount_after = if immediate.is_none() && rd != 0 && rd == amount_register {
            result
        } else {
            amount
        };
        out.push(row[LEFT_AFTER_OFFSET + limb].sub(left_after));
        out.push(row[AMOUNT_AFTER_OFFSET + limb].sub(amount_after));
        out.push(immediate.map_or(F::ZERO, |value| {
            amount.sub(F((value >> (16 * limb)) & 0xffff))
        }));
    }
    debug_assert_eq!(out.len(), CONSTRAINT_COUNT);
    Ok(out)
}

/// Barrel stages are shared unchanged between single-step and segment adapters.
pub(super) fn bank_residues(bank: &[F], sources: Sources<'_>, kinds: [F; 5]) -> Vec<F> {
    let mut out = Vec::with_capacity(BANK_CONSTRAINTS);
    append_bank_residues(&mut out, bank, sources, kinds);
    debug_assert_eq!(out.len(), BANK_CONSTRAINTS);
    out
}

/// Append directly into the caller-owned private residual allocation.
pub(super) fn append_bank_residues(
    out: &mut impl crate::execution_proofs::ivm_step_air::residues::Sink,
    bank: &[F],
    sources: Sources<'_>,
    kinds: [F; 5],
) {
    let start = out.len();
    for stage in 0..STAGES {
        let previous = if stage == 0 {
            sources.bits(0)
        } else {
            &bank[STAGE + (stage - 1) * WORD_BITS..STAGE + stage * WORD_BITS]
        };
        let sign = sources.sign(0);
        let low = sources.bits(1)[2 * stage];
        let high = sources.bits(1)[2 * stage + 1];
        for (index, expected) in stage_selectors(low, high).into_iter().enumerate() {
            out.push(bank[SELECTORS + 4 * stage + index].sub(expected));
        }
        let selectors = &bank[SELECTORS + 4 * stage..SELECTORS + 4 * stage + 4];
        for position in 0..WORD_BITS {
            let selected = selectors
                .iter()
                .enumerate()
                .fold(F::ZERO, |sum, (digit, selector)| {
                    let source =
                        KINDS
                            .into_iter()
                            .zip(kinds)
                            .fold(F::ZERO, |source, (kind, selector)| {
                                source.add(selector.mul(stage_input(
                                    kind,
                                    previous,
                                    sign,
                                    position,
                                    digit << (2 * stage),
                                )))
                            });
                    sum.add(selector.mul(source))
                });
            // Dynamic opcode selector × stage selector × previous source is cubic.
            out.push(bank[STAGE + stage * WORD_BITS + position].sub(selected));
        }
    }
    for limb in 0..WORD_LIMBS {
        let bits = &bank[STAGE + (STAGES - 1) * WORD_BITS + 16 * limb
            ..STAGE + (STAGES - 1) * WORD_BITS + 16 * (limb + 1)];
        out.push(bank[RESULT + limb].sub(word::pack(bits, 1)));
    }
    debug_assert_eq!(out.len() - start, BANK_CONSTRAINTS);
}

pub(super) fn bank_witness(opcode: u8, left: u64, amount: u64) -> [F; BANK_WIDTH] {
    let kind = ShiftKind::from_word(ivm::encoding::wide::encode_rr(opcode, 3, 1, 2))
        .expect("validated shift kind");
    let mut bank = [F::ZERO; BANK_WIDTH];
    let mut value = left;
    for stage in 0..STAGES {
        let digit = (amount >> (2 * stage)) & 3;
        // Write all four positions; a private amount must not choose an address.
        bank[SELECTORS + 4 * stage..SELECTORS + 4 * (stage + 1)]
            .copy_from_slice(&stage_selectors(F(digit & 1), F(digit >> 1)));
        value = kind.apply(value, (digit << (2 * stage)) as u32);
        for position in 0..WORD_BITS {
            bank[STAGE + stage * WORD_BITS + position] = F((value >> position) & 1);
        }
    }
    for limb in 0..4 {
        bank[RESULT + limb] = F((value >> (16 * limb)) & 0xffff);
    }
    bank
}

struct ShiftStepAdapter(ShiftStepStatement);

impl ProofManagedNoteStarkAdapterV1 for ShiftStepAdapter {
    type ProfileChallenges = ();

    fn protocol_v1(&self) -> ProofManagedNoteStarkProtocolV1 {
        ProofManagedNoteStarkProtocolV1 {
            parameters: AggregateStarkParametersV1 {
                proof_magic: *b"ISH1",
                proof_version: 1,
                security_lanes: 1,
                query_count: 136,
                blowup_log2: 3,
                terminal_log2: 10,
                terminal_degree_bound: 143,
                composition_degree_chunks: 4,
                minimum_trace_log2: TRACE_LOG2,
                maximum_trace_log2: TRACE_LOG2,
                maximum_trace_groups: 1,
                maximum_segment_instances: 1,
                maximum_base_columns_per_instance: NOTE_COPY_WIDTH_V1 + ROW_WIDTH,
                maximum_aux_columns_per_instance: NOTE_COPY_AUX_WIDTH_V1,
                maximum_proof_bytes: 4 * 1024 * 1024,
            },
            domains: DOMAINS,
            maximum_constraint_degree: MAXIMUM_DEGREE,
            profile_binding_label: b"ivm-shift-profile-binding-v1",
            profile_descriptor: PROFILE,
            relation_layout_domain: b"ivm-shift-relation-layout-v1",
        }
    }

    fn public_input_digest_v1(
        &self,
    ) -> Result<GoldilocksDigest384V1, ProofManagedNoteStarkErrorV1> {
        self.0.validate()?;
        self.0.digest()
    }

    fn trace_log2_v1(&self) -> u8 {
        TRACE_LOG2
    }

    fn base_width_v1(&self) -> usize {
        NOTE_COPY_WIDTH_V1 + ROW_WIDTH
    }

    fn profile_aux_width_v1(&self) -> usize {
        0
    }

    fn profile_fixed_width_v1(&self) -> usize {
        FIXED_WIDTH
    }

    fn profile_constraint_count_v1(&self) -> usize {
        CONSTRAINT_COUNT
    }

    fn copy_schedule_v1(&self) -> Result<NoteCopyScheduleV1, ProofManagedNoteStarkErrorV1> {
        Ok(NoteCopyScheduleV1 {
            policies: vec![[NoteCopyCellPolicyV1::Inactive; NOTE_COPY_WIDTH_V1]; TRACE_SIZE],
            sigma: (0..TRACE_SIZE)
                .map(|row| {
                    std::array::from_fn(|column| (row * NOTE_COPY_WIDTH_V1 + column + 1) as u32)
                })
                .collect(),
        })
    }

    fn profile_fixed_columns_v1(&self) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        self.0.validate()?;
        Ok(self.0.fixed().map(|value| vec![value; TRACE_SIZE]).into())
    }

    fn derive_profile_challenges_v1(
        &self,
        _: &mut TransparentTranscriptV1,
        _: NoteCopyChallengesV1,
    ) -> Result<(), ProofManagedNoteStarkErrorV1> {
        Ok(())
    }

    fn build_profile_aux_columns_v1(
        &self,
        _: &[Vec<F>],
        _: &[Vec<F>],
        _: &[Vec<F>],
        _: NoteCopyChallengesV1,
        (): &(),
    ) -> Result<Vec<Vec<F>>, ProofManagedNoteStarkErrorV1> {
        Ok(Vec::new())
    }

    fn profile_constraint_residues_v1(
        &self,
        current: &[F],
        _: &[F],
        _: &[F],
        _: &[F],
        fixed: &[F],
        _: NoteCopyChallengesV1,
        (): &(),
    ) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1> {
        residues(
            current
                .get(NOTE_COPY_WIDTH_V1..)
                .ok_or(ProofManagedNoteStarkErrorV1::InvalidTrace)?,
            fixed
                .get(NOTE_COPY_FIXED_WIDTH_V1..)
                .ok_or(ProofManagedNoteStarkErrorV1::InvalidTrace)?,
            self.0.word,
        )
    }
}

#[cfg(test)]
mod tests;
