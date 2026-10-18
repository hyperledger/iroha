//! Unregistered native-STARK AIR chips for public IVM scalar steps.
//!
//! The ALU chip is a bounded, public-input relation substrate. It proves the exact
//! wrapping 64-bit arithmetic and bitwise results, sign-extended immediates,
//! public privacy tags, and public control and base-gas transitions for every
//! register shape, including aliases and hardwired `r0`.
//! Secret-tagged operands are rejected because the operands are public inputs.
//! It does not prove fetch, the other registers, memory, host effects, or a
//! complete invocation. The sibling branch chip proves all six conditional
//! branch predicates and their public PC, operand, gas, and cycle transitions.
//! The shift chip proves masked shifts/rotations and all operand/write aliases.
//! The internal scalar-segment adapter composes the same arithmetic banks with
//! canonical artifact fetch, all 256 registers, public tags, u64 gas/cycles and
//! explicit boundaries for at most 64 steps. It remains a segment substrate;
//! memory, private/host/state relations and invocation completion are absent.
//! The sibling typed packet bus constrains staged cell consistency and a
//! transcript-challenged multiset relation for public qualification events;
//! request, initialization and frame authorization are still absent.
//! In particular, no production IVM proof admission uses these chips until the
//! complete machine relation owns those dependencies.

// TODO: Compose this chip into the sole IVM AIR with authenticated instruction
// fetch, complete register continuity, memory/syscall/state relations, and
// terminal constraints before exposing a production prover or verifier.

mod alu;
mod bitwise;
mod branch;
mod machine_bus;
mod memory_address;
mod residues;
mod shift;
mod trace;
mod word;

use super::stark::{
    aggregate_stark::{AggregateStarkDomainsV1, AggregateStarkParametersV1},
    proof_managed_note_stark::{
        NOTE_COPY_AUX_WIDTH_V1, NOTE_COPY_FIXED_WIDTH_V1, NOTE_COPY_WIDTH_V1, NoteCopyCellPolicyV1,
        NoteCopyChallengesV1, NoteCopyScheduleV1, ProofManagedNoteStarkAdapterV1,
        ProofManagedNoteStarkErrorV1, ProofManagedNoteStarkProtocolV1,
    },
    transparent_stark::{
        GoldilocksDigest384V1, GoldilocksFieldV1 as F, TransparentStarkDigestContextV1,
        TransparentTranscriptV1, goldilocks_digest384_frame_v1,
    },
};
use alu::{
    CONSTRAINTS as ALU_BANK_CONSTRAINTS, WIDTH as ALU_BANK_WIDTH, residues as alu_bank_residues,
    witness as alu_bank_witness,
};
use ivm::{gas, instruction::wide};
use word::Sources;

/// Map the immediate forms to the register forms whose exact ALU equations
/// they share. Unknown opcodes remain unknown and fail profile validation.
fn semantic_opcode(opcode: u8) -> u8 {
    match opcode {
        wide::arithmetic::ADDI => wide::arithmetic::ADD,
        wide::arithmetic::ANDI => wide::arithmetic::AND,
        wide::arithmetic::ORI => wide::arithmetic::OR,
        wide::arithmetic::XORI => wide::arithmetic::XOR,
        other => other,
    }
}

/// The interpreter sign-extends all four eight-bit immediates to a full word.
fn immediate_operand(word: u32) -> Option<u64> {
    matches!(
        wide::opcode(word),
        wide::arithmetic::ADDI
            | wide::arithmetic::ANDI
            | wide::arithmetic::ORI
            | wide::arithmetic::XORI
    )
    .then(|| i64::cast_unsigned(i64::from(wide::imm8(word))))
}

const TRACE_LOG2: u8 = 13;
const TRACE_SIZE: usize = 1 << TRACE_LOG2;
const COUNTERS: usize = 6;
const LIMBS: usize = 12;
const TAGS: usize = 3;
const POST_LIMBS: usize = 4;
const SHAPE_SELECTORS: usize = 8;
const LIMB_OFFSET: usize = COUNTERS;
const TAG_OFFSET: usize = LIMB_OFFSET + LIMBS;
const POST_OFFSET: usize = TAG_OFFSET + TAGS;
const PUBLIC_WIDTH: usize = POST_OFFSET + POST_LIMBS;
const SELECTOR_OFFSET: usize = PUBLIC_WIDTH;
const SOURCE_OFFSET: usize = PUBLIC_WIDTH;
const BANK_OFFSET: usize = SOURCE_OFFSET + word::WIDTH;
const ROW_WIDTH: usize = BANK_OFFSET + ALU_BANK_WIDTH;
const FIXED_WIDTH: usize = PUBLIC_WIDTH + SHAPE_SELECTORS;
#[cfg(test)]
const TRANSFER_OFFSET: usize = BANK_OFFSET + alu::TRANSFER;
#[cfg(test)]
const DIGIT_OFFSET: usize = BANK_OFFSET + alu::DIGITS;
const CONSTRAINT_COUNT: usize =
    PUBLIC_WIDTH + 3 + TAGS + 2 + 3 + word::WIDTH + 12 + ALU_BANK_CONSTRAINTS + POST_LIMBS + 3 * 4;
const CONTEXT: TransparentStarkDigestContextV1 =
    TransparentStarkDigestContextV1::execution_v1(b"ivm-alu-all-shapes-air-v1");
const DOMAINS: AggregateStarkDomainsV1 = AggregateStarkDomainsV1 {
    digest_context: CONTEXT,
    base_leaf: b"ivm-alu-base-leaf-v1",
    base_node: b"ivm-alu-base-node-v1",
    aux_leaf: b"ivm-alu-aux-leaf-v1",
    aux_node: b"ivm-alu-aux-node-v1",
    composition_leaf: b"ivm-alu-composition-leaf-v1",
    composition_node: b"ivm-alu-composition-node-v1",
    fri_leaf: b"ivm-alu-fri-leaf-v1",
    fri_node: b"ivm-alu-fri-node-v1",
    layout_label: b"ivm-alu-layout-v1",
    base_root_label: b"ivm-alu-base-root-v1",
    aux_root_label: b"ivm-alu-aux-root-v1",
    composition_root_label: b"ivm-alu-composition-root-v1",
    fri_root_label: b"ivm-alu-fri-root-v1",
    fri_beta_label: b"ivm-alu-fri-beta-v1",
    query_seed: b"ivm-alu-query-seed-v1",
};
const PROFILE: &[u8] = b"ivm-alu-all-shapes-air-v1:public-single-step:add-sub-and-or-xor:addi-andi-ori-xori:signed-imm8:pre-read:post-write:r0:aliases:64-bit-wrap:shared-boolean-sources:radix4-results:degree4:tag-match:pc+4:cycles+1:base-gas=1:no-machine-admission";

#[derive(Clone, Copy)]
struct AluStepStatement {
    word: u32,
    before_pc: u32,
    after_pc: u32,
    before_gas: u32,
    after_gas: u32,
    before_cycles: u32,
    after_cycles: u32,
    left: u64,
    right: u64,
    /// ALU result before the destination write is conditionally ignored for `r0`.
    result: u64,
    /// Observable value of `rd` after the instruction.
    destination_after: u64,
    left_tag: bool,
    right_tag: bool,
    result_tag: bool,
}

impl AluStepStatement {
    fn validate(self) -> Result<(), ProofManagedNoteStarkErrorV1> {
        if !matches!(
            semantic_opcode(wide::opcode(self.word)),
            wide::arithmetic::ADD
                | wide::arithmetic::SUB
                | wide::arithmetic::AND
                | wide::arithmetic::OR
                | wide::arithmetic::XOR
        ) || gas::cost_of(self.word) != Some(1)
            || immediate_operand(self.word).is_some_and(|immediate| self.right != immediate)
            || !self.before_pc.is_multiple_of(4)
            || !self.after_pc.is_multiple_of(4)
            || self.left_tag
            || self.right_tag
            || self.result_tag
        {
            return Err(ProofManagedNoteStarkErrorV1::InvalidProfile);
        }
        Ok(())
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
        // The verifier derives RI's second operand from the public instruction
        // word; a supplied witness cannot choose a different register value.
        let right = immediate_operand(self.word).unwrap_or(self.right);
        for (operand, value) in [self.left, right, self.result].into_iter().enumerate() {
            for limb in 0..4 {
                fixed[LIMB_OFFSET + operand * 4 + limb] = F((value >> (limb * 16)) & 0xffff);
            }
        }
        for (index, tag) in [self.left_tag, self.right_tag, self.result_tag]
            .into_iter()
            .enumerate()
        {
            fixed[TAG_OFFSET + index] = F(u64::from(tag));
        }
        for limb in 0..POST_LIMBS {
            fixed[POST_OFFSET + limb] = F((self.destination_after >> (limb * 16)) & 0xffff);
        }
        let opcode = semantic_opcode(wide::opcode(self.word));
        let register_right = immediate_operand(self.word).is_none();
        for (index, condition) in [
            wide::rd(self.word) == 0,
            wide::rs1(self.word) == 0,
            register_right && wide::rs2(self.word) == 0,
            register_right && wide::rs1(self.word) == wide::rs2(self.word),
            opcode == wide::arithmetic::SUB,
            opcode == wide::arithmetic::AND,
            opcode == wide::arithmetic::OR,
            opcode == wide::arithmetic::XOR,
        ]
        .into_iter()
        .enumerate()
        {
            fixed[SELECTOR_OFFSET + index] = F(u64::from(condition));
        }
        fixed
    }

    fn witness(self) -> [F; ROW_WIDTH] {
        let mut row = [F::ZERO; ROW_WIDTH];
        row[..PUBLIC_WIDTH].copy_from_slice(&self.fixed()[..PUBLIC_WIDTH]);
        row[SOURCE_OFFSET..BANK_OFFSET].copy_from_slice(&word::witness(self.left, self.right));
        row[BANK_OFFSET..].copy_from_slice(&alu_bank_witness(
            wide::opcode(self.word),
            self.left,
            self.right,
        ));
        row
    }

    fn digest(self) -> Result<GoldilocksDigest384V1, ProofManagedNoteStarkErrorV1> {
        let word = self.word.to_be_bytes();
        let before_pc = self.before_pc.to_be_bytes();
        let after_pc = self.after_pc.to_be_bytes();
        let before_gas = self.before_gas.to_be_bytes();
        let after_gas = self.after_gas.to_be_bytes();
        let before_cycles = self.before_cycles.to_be_bytes();
        let after_cycles = self.after_cycles.to_be_bytes();
        let left = self.left.to_be_bytes();
        let right = self.right.to_be_bytes();
        let result = self.result.to_be_bytes();
        let destination_after = self.destination_after.to_be_bytes();
        let tags = [
            u8::from(self.left_tag),
            u8::from(self.right_tag),
            u8::from(self.result_tag),
        ];
        goldilocks_digest384_frame_v1(
            CONTEXT,
            b"ivm-alu-public-step-v1",
            b"statement",
            0,
            0,
            0,
            &[
                &word,
                &before_pc,
                &after_pc,
                &before_gas,
                &after_gas,
                &before_cycles,
                &after_cycles,
                &left,
                &right,
                &result,
                &destination_after,
                &tags,
            ],
        )
        .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)
    }
}

fn bit(value: F) -> F {
    value.mul(value.sub(F::ONE))
}

fn residues(row: &[F], fixed: &[F]) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1> {
    if row.len() != ROW_WIDTH || fixed.len() != FIXED_WIDTH {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    let mut out = Vec::with_capacity(CONSTRAINT_COUNT);
    for index in 0..PUBLIC_WIDTH {
        out.push(row[index].sub(fixed[index]));
    }
    out.push(row[1].sub(row[0]).sub(F(4)));
    out.push(row[2].sub(row[3]).sub(F::ONE));
    out.push(row[5].sub(row[4]).sub(F::ONE));
    for index in 0..TAGS {
        out.push(bit(row[TAG_OFFSET + index]));
    }
    out.push(row[TAG_OFFSET].sub(row[TAG_OFFSET + 1]));
    let rd_is_zero = fixed[SELECTOR_OFFSET];
    let rs1_is_zero = fixed[SELECTOR_OFFSET + 1];
    let rs2_is_zero = fixed[SELECTOR_OFFSET + 2];
    let sources_equal = fixed[SELECTOR_OFFSET + 3];
    out.push(row[TAG_OFFSET + 2].sub(F::ONE.sub(rd_is_zero).mul(row[TAG_OFFSET])));
    out.push(rs1_is_zero.mul(row[TAG_OFFSET]));
    out.push(rs2_is_zero.mul(row[TAG_OFFSET + 1]));
    out.push(rd_is_zero.mul(row[TAG_OFFSET + 2]));
    let sources = Sources::new(&row[SOURCE_OFFSET..BANK_OFFSET]);
    sources.append_residues(&mut out);
    for limb in 0..4 {
        out.push(row[LIMB_OFFSET + limb].sub(sources.limb(0, limb)));
        out.push(row[LIMB_OFFSET + 4 + limb].sub(sources.limb(1, limb)));
        out.push(row[LIMB_OFFSET + 8 + limb].sub(row[BANK_OFFSET + alu::RESULT + limb]));
    }
    out.extend(alu_bank_residues(
        &row[BANK_OFFSET..],
        sources,
        std::array::from_fn(|index| fixed[SELECTOR_OFFSET + 4 + index]),
    ));
    for limb in 0..4 {
        out.push(
            row[POST_OFFSET + limb].sub(F::ONE.sub(rd_is_zero).mul(row[LIMB_OFFSET + 8 + limb])),
        );
        out.push(rs1_is_zero.mul(row[LIMB_OFFSET + limb]));
        out.push(rs2_is_zero.mul(row[LIMB_OFFSET + 4 + limb]));
        out.push(sources_equal.mul(row[LIMB_OFFSET + limb].sub(row[LIMB_OFFSET + 4 + limb])));
    }
    debug_assert_eq!(out.len(), CONSTRAINT_COUNT);
    Ok(out)
}

struct AluStepAdapter(AluStepStatement);

impl ProofManagedNoteStarkAdapterV1 for AluStepAdapter {
    type ProfileChallenges = ();

    fn protocol_v1(&self) -> ProofManagedNoteStarkProtocolV1 {
        ProofManagedNoteStarkProtocolV1 {
            parameters: AggregateStarkParametersV1 {
                proof_magic: *b"IAL1",
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
            maximum_constraint_degree: 4,
            profile_binding_label: b"ivm-alu-profile-binding-v1",
            profile_descriptor: PROFILE,
            relation_layout_domain: b"ivm-alu-relation-layout-v1",
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
        )
    }
}

#[cfg(test)]
mod tests;
