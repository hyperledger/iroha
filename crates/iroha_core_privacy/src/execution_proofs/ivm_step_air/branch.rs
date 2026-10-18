//! Public, single-step native AIR for all six V1 conditional branches.
//!
//! A branch reads two public scalar registers and writes none. This chip
//! constrains both operand values and tags across the step, including `r0`
//! and aliased sources. It range-checks the operands and their subtraction,
//! then derives equality, unsigned less-than, signed less-than, and the PC
//! edge from the opcode and signed eight-bit offset. Fetch, the other 254
//! registers, instruction boundaries, and complete invocation continuity
//! belong to the unfinished machine relation; this profile is not registered.

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
    TransparentTranscriptV1, bit, gas, goldilocks_digest384_frame_v1, wide,
    word::{self, Sources},
};

const COUNTERS: usize = 6;
const OPERAND_LIMBS: usize = 4 * 4;
const TAGS: usize = 4;
const LEFT_OFFSET: usize = COUNTERS;
const RIGHT_OFFSET: usize = LEFT_OFFSET + 4;
const LEFT_AFTER_OFFSET: usize = RIGHT_OFFSET + 4;
const RIGHT_AFTER_OFFSET: usize = LEFT_AFTER_OFFSET + 4;
const TAG_OFFSET: usize = COUNTERS + OPERAND_LIMBS;
const PUBLIC_WIDTH: usize = TAG_OFFSET + TAGS;
const SELECTOR_OFFSET: usize = PUBLIC_WIDTH;
const BRANCH_SELECTORS: usize = 6;
const SHAPE_SELECTORS: usize = 3;
const FIXED_WIDTH: usize = PUBLIC_WIDTH + BRANCH_SELECTORS + SHAPE_SELECTORS;
const SOURCE_OFFSET: usize = PUBLIC_WIDTH;
const BANK_OFFSET: usize = SOURCE_OFFSET + word::WIDTH;
const DIFF: usize = 0;
const DIGITS: usize = 4;
pub(super) const BORROW: usize = DIGITS + 32;
const ZERO: usize = BORROW + 4;
const INVERSE: usize = ZERO + 4;
const EQUALITY: usize = INVERSE + 4;
pub(super) const TAKEN_BANK_OFFSET: usize = EQUALITY + 1;
pub(super) const BANK_WIDTH: usize = TAKEN_BANK_OFFSET + 1;
pub(super) const BANK_CONSTRAINTS: usize = 63;

/// Equality already constrained from all four exact subtraction limbs.
pub(super) fn bank_equality(bank: &[F]) -> F {
    bank[EQUALITY]
}
const TAKEN_OFFSET: usize = BANK_OFFSET + TAKEN_BANK_OFFSET;
const ROW_WIDTH: usize = BANK_OFFSET + BANK_WIDTH;
const CONSTRAINT_COUNT: usize =
    PUBLIC_WIDTH + 3 + TAGS + 8 + 12 + word::WIDTH + 8 + BANK_CONSTRAINTS;
#[cfg(test)]
const DIFF_OFFSET: usize = BANK_OFFSET + DIFF;
#[cfg(test)]
const BORROW_OFFSET: usize = BANK_OFFSET + BORROW;
#[cfg(test)]
const ZERO_OFFSET: usize = BANK_OFFSET + ZERO;
#[cfg(test)]
const INVERSE_OFFSET: usize = BANK_OFFSET + INVERSE;
#[cfg(test)]
const DIGIT_OFFSET: usize = BANK_OFFSET + DIGITS;
#[cfg(test)]
const EQUALITY_OFFSET: usize = BANK_OFFSET + EQUALITY;

const CONTEXT: TransparentStarkDigestContextV1 =
    TransparentStarkDigestContextV1::execution_v1(b"ivm-branch-step-air-v1");
const DOMAINS: AggregateStarkDomainsV1 = AggregateStarkDomainsV1 {
    digest_context: CONTEXT,
    base_leaf: b"ivm-branch-base-leaf-v1",
    base_node: b"ivm-branch-base-node-v1",
    aux_leaf: b"ivm-branch-aux-leaf-v1",
    aux_node: b"ivm-branch-aux-node-v1",
    composition_leaf: b"ivm-branch-composition-leaf-v1",
    composition_node: b"ivm-branch-composition-node-v1",
    fri_leaf: b"ivm-branch-fri-leaf-v1",
    fri_node: b"ivm-branch-fri-node-v1",
    layout_label: b"ivm-branch-layout-v1",
    base_root_label: b"ivm-branch-base-root-v1",
    aux_root_label: b"ivm-branch-aux-root-v1",
    composition_root_label: b"ivm-branch-composition-root-v1",
    fri_root_label: b"ivm-branch-fri-root-v1",
    fri_beta_label: b"ivm-branch-fri-beta-v1",
    query_seed: b"ivm-branch-query-seed-v1",
};
const PROFILE: &[u8] = b"ivm-branch-step-air-v1:public-single-step:beq-bne-blt-bge-bltu-bgeu:signed-imm8:64-bit-signed-unsigned-compare:read-only-registers:r0:aliases:pc-conditional:cycles+1:base-gas=1:no-machine-admission";

#[derive(Clone, Copy, Debug)]
struct BranchStepStatement {
    word: u32,
    before_pc: u32,
    after_pc: u32,
    before_gas: u32,
    after_gas: u32,
    before_cycles: u32,
    after_cycles: u32,
    left: u64,
    right: u64,
    left_after: u64,
    right_after: u64,
    left_tag: bool,
    right_tag: bool,
    left_tag_after: bool,
    right_tag_after: bool,
}

impl BranchStepStatement {
    fn validate(self) -> Result<(), ProofManagedNoteStarkErrorV1> {
        if !matches!(
            wide::opcode(self.word),
            wide::control::BEQ
                | wide::control::BNE
                | wide::control::BLT
                | wide::control::BGE
                | wide::control::BLTU
                | wide::control::BGEU
        ) || gas::cost_of(self.word) != Some(1)
            || !self.before_pc.is_multiple_of(4)
            || !self.after_pc.is_multiple_of(4)
            || self.left_tag
            || self.right_tag
            || self.left_tag_after
            || self.right_tag_after
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
        for (operand, value) in [self.left, self.right, self.left_after, self.right_after]
            .into_iter()
            .enumerate()
        {
            for limb in 0..4 {
                fixed[LEFT_OFFSET + operand * 4 + limb] = F((value >> (16 * limb)) & 0xffff);
            }
        }
        for (index, tag) in [
            self.left_tag,
            self.right_tag,
            self.left_tag_after,
            self.right_tag_after,
        ]
        .into_iter()
        .enumerate()
        {
            fixed[TAG_OFFSET + index] = F(u64::from(tag));
        }
        let op = wide::opcode(self.word);
        for (index, opcode) in [
            wide::control::BEQ,
            wide::control::BNE,
            wide::control::BLT,
            wide::control::BGE,
            wide::control::BLTU,
            wide::control::BGEU,
        ]
        .into_iter()
        .enumerate()
        {
            fixed[SELECTOR_OFFSET + index] = F(u64::from(op == opcode));
        }
        fixed[SELECTOR_OFFSET + BRANCH_SELECTORS] = F(u64::from(wide::rd(self.word) == 0));
        fixed[SELECTOR_OFFSET + BRANCH_SELECTORS + 1] = F(u64::from(wide::rs1(self.word) == 0));
        fixed[SELECTOR_OFFSET + BRANCH_SELECTORS + 2] =
            F(u64::from(wide::rd(self.word) == wide::rs1(self.word)));
        fixed
    }

    fn witness(self) -> [F; ROW_WIDTH] {
        let mut row = [F::ZERO; ROW_WIDTH];
        row[..PUBLIC_WIDTH].copy_from_slice(&self.fixed()[..PUBLIC_WIDTH]);
        row[SOURCE_OFFSET..BANK_OFFSET].copy_from_slice(&word::witness(self.left, self.right));
        row[BANK_OFFSET..].copy_from_slice(&bank_witness(
            wide::opcode(self.word),
            self.left,
            self.right,
        ));
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
            self.right.to_be_bytes(),
            self.left_after.to_be_bytes(),
            self.right_after.to_be_bytes(),
        ];
        let tags = [
            u8::from(self.left_tag),
            u8::from(self.right_tag),
            u8::from(self.left_tag_after),
            u8::from(self.right_tag_after),
        ];
        goldilocks_digest384_frame_v1(
            CONTEXT,
            b"ivm-branch-public-step-v1",
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
                &tags,
            ],
        )
        .map_err(|_| ProofManagedNoteStarkErrorV1::InvalidProfile)
    }
}

fn branch_taken(opcode: u8, left: u64, right: u64) -> bool {
    match opcode {
        wide::control::BEQ => left == right,
        wide::control::BNE => left != right,
        wide::control::BLT => u64::cast_signed(left) < u64::cast_signed(right),
        wide::control::BGE => u64::cast_signed(left) >= u64::cast_signed(right),
        wide::control::BLTU => left < right,
        wide::control::BGEU => left >= right,
        _ => false,
    }
}

fn signed_field(value: i64) -> F {
    if value < 0 {
        F::ZERO.sub(F(value.unsigned_abs()))
    } else {
        F(i64::cast_unsigned(value))
    }
}

fn residues(row: &[F], fixed: &[F], word: u32) -> Result<Vec<F>, ProofManagedNoteStarkErrorV1> {
    if row.len() != ROW_WIDTH || fixed.len() != FIXED_WIDTH {
        return Err(ProofManagedNoteStarkErrorV1::InvalidTrace);
    }
    let mut out = Vec::with_capacity(CONSTRAINT_COUNT);
    for index in 0..PUBLIC_WIDTH {
        out.push(row[index].sub(fixed[index]));
    }
    let taken = row[TAKEN_OFFSET];
    let displacement = signed_field(i64::from(wide::imm8(word)) * 4);
    out.push(
        row[1]
            .sub(row[0])
            .sub(F(4))
            .sub(taken.mul(displacement.sub(F(4)))),
    );
    out.push(row[2].sub(row[3]).sub(F::ONE));
    out.push(row[5].sub(row[4]).sub(F::ONE));
    for index in 0..TAGS {
        out.push(row[TAG_OFFSET + index]);
    }
    let left_zero = fixed[SELECTOR_OFFSET + BRANCH_SELECTORS];
    let right_zero = fixed[SELECTOR_OFFSET + BRANCH_SELECTORS + 1];
    let aliased = fixed[SELECTOR_OFFSET + BRANCH_SELECTORS + 2];
    for limb in 0..4 {
        let left = row[LEFT_OFFSET + limb];
        let right = row[RIGHT_OFFSET + limb];
        out.push(row[LEFT_AFTER_OFFSET + limb].sub(left));
        out.push(row[RIGHT_AFTER_OFFSET + limb].sub(right));
        out.push(left_zero.mul(left));
        out.push(right_zero.mul(right));
        out.push(aliased.mul(left.sub(right)));
    }
    let sources = Sources::new(&row[SOURCE_OFFSET..BANK_OFFSET]);
    sources.append_residues(&mut out);
    for limb in 0..4 {
        out.push(row[LEFT_OFFSET + limb].sub(sources.limb(0, limb)));
        out.push(row[RIGHT_OFFSET + limb].sub(sources.limb(1, limb)));
    }
    out.extend(bank_residues(
        &row[BANK_OFFSET..],
        std::array::from_fn(|operand| std::array::from_fn(|limb| sources.limb(operand, limb))),
        [sources.sign(0), sources.sign(1)],
        std::array::from_fn(|index| fixed[SELECTOR_OFFSET + index]),
    ));
    debug_assert_eq!(out.len(), CONSTRAINT_COUNT);
    Ok(out)
}

/// The same comparison equations serve branches, comparisons, move predicates and
/// division remainder bounds. The caller owns canonical limb and sign routing.
pub(super) fn bank_residues(
    bank: &[F],
    limbs: [[F; 4]; 2],
    signs: [F; 2],
    selectors: [F; 6],
) -> Vec<F> {
    let mut out = Vec::with_capacity(BANK_CONSTRAINTS);
    append_bank_residues(&mut out, bank, limbs, signs, selectors);
    out
}

/// Append the same exact comparisons to the caller's original residual owner.
/// The caller retains canonical source limbs/signs and private fetch selectors.
pub(super) fn append_bank_residues(
    out: &mut impl crate::execution_proofs::ivm_step_air::residues::Sink,
    bank: &[F],
    limbs: [[F; 4]; 2],
    signs: [F; 2],
    selectors: [F; 6],
) {
    let start = out.len();
    out.extend(bank[DIGITS..BORROW].iter().copied().map(word::radix4));
    for limb in 0..4 {
        out.push(bank[DIFF + limb].sub(word::pack(
            &bank[DIGITS + 8 * limb..DIGITS + 8 * (limb + 1)],
            2,
        )));
        let difference = bank[DIFF + limb];
        let borrow_in = if limb == 0 {
            F::ZERO
        } else {
            bank[BORROW + limb - 1]
        };
        let borrow_out = bank[BORROW + limb];
        let zero = bank[ZERO + limb];
        let inverse = bank[INVERSE + limb];
        out.push(bit(borrow_out));
        out.push(
            limbs[0][limb]
                .sub(limbs[1][limb])
                .sub(borrow_in)
                .sub(difference)
                .add(borrow_out.mul(F(1 << 16))),
        );
        out.push(bit(zero));
        out.push(difference.mul(inverse).sub(F::ONE.sub(zero)));
        out.push(difference.mul(zero));
        out.push(zero.mul(inverse));
    }
    let equality_from_limbs = (0..4).fold(F::ONE, |product, limb| product.mul(bank[ZERO + limb]));
    let equality = bank[EQUALITY];
    let unsigned_less = bank[BORROW + 3];
    let left_sign = signs[0];
    let right_sign = signs[1];
    let sign_diff = left_sign
        .add(right_sign)
        .sub(left_sign.mul(right_sign).mul(F(2)));
    let signed_less = sign_diff
        .mul(left_sign)
        .add(F::ONE.sub(sign_diff).mul(unsigned_less));
    let expected_taken = selectors[0]
        .mul(equality)
        .add(selectors[1].mul(F::ONE.sub(equality)))
        .add(selectors[2].mul(signed_less))
        .add(selectors[3].mul(F::ONE.sub(signed_less)))
        .add(selectors[4].mul(unsigned_less))
        .add(selectors[5].mul(F::ONE.sub(unsigned_less)));
    out.push(equality.sub(equality_from_limbs));
    out.push(bit(bank[TAKEN_BANK_OFFSET]));
    out.push(bank[TAKEN_BANK_OFFSET].sub(expected_taken));
    debug_assert_eq!(out.len() - start, BANK_CONSTRAINTS);
}

pub(super) fn bank_witness(opcode: u8, left: u64, right: u64) -> [F; BANK_WIDTH] {
    let mut bank = [F::ZERO; BANK_WIDTH];
    let mut borrow = 0;
    for limb in 0..4 {
        let a = (left >> (16 * limb)) & 0xffff;
        let b = (right >> (16 * limb)) & 0xffff;
        let difference = a.wrapping_sub(b).wrapping_sub(borrow) & 0xffff;
        borrow = u64::from(a < b + borrow);
        bank[DIFF + limb] = F(difference);
        bank[BORROW + limb] = F(borrow);
        bank[ZERO + limb] = F(u64::from(difference == 0));
        bank[INVERSE + limb] = if difference == 0 {
            F::ZERO
        } else {
            F(difference).inv().expect("nonzero limb")
        };
        word::fill_digits(
            &mut bank[DIGITS + 8 * limb..DIGITS + 8 * (limb + 1)],
            difference,
        );
    }
    bank[EQUALITY] = F(u64::from(left == right));
    bank[TAKEN_BANK_OFFSET] = F(u64::from(branch_taken(opcode, left, right)));
    bank
}

struct BranchStepAdapter(BranchStepStatement);

impl ProofManagedNoteStarkAdapterV1 for BranchStepAdapter {
    type ProfileChallenges = ();

    fn protocol_v1(&self) -> ProofManagedNoteStarkProtocolV1 {
        ProofManagedNoteStarkProtocolV1 {
            parameters: AggregateStarkParametersV1 {
                proof_magic: *b"IBR1",
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
            profile_binding_label: b"ivm-branch-profile-binding-v1",
            profile_descriptor: PROFILE,
            relation_layout_domain: b"ivm-branch-relation-layout-v1",
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
