//! Canonical private-note witness and deterministic execution relation.
use super::{codec::encode_private_program_v1, wallet::validate_ivm_private_encrypted_output_v1};
use iroha_data_model::privacy::{
    IrohaIvmPrivateNoteStarkStatementV1, PrivacyCommitmentV1, PrivacyNamespaceScopeV1,
    PrivacyNamespaceV1, PrivacyNullifierV1, PrivacyPoolProgramNamespaceV1, PrivacyProgramIdV1,
    PrivacyProtocolIdV1, PrivacyRootV1, PrivacyValueBalanceDirectionV1, PrivacyValueBalanceV1,
};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeSet, fmt};
use thiserror::Error;
use zeroize::Zeroize;
/// Maximum consumed notes in the sole compiled relation.
pub const PRIVATE_NOTE_MAX_INPUTS_V1: usize = 2;
/// Maximum created notes in the sole compiled relation.
pub const PRIVATE_NOTE_MAX_OUTPUTS_V1: usize = 2;
/// Exact output count admitted by the crate-private three-output relation seam.
pub const PRIVATE_NOTE_THREE_OUTPUT_COUNT_V1: usize = 3;
/// Exact depth of the ledger's proof-managed note tree.
pub const PRIVATE_NOTE_TREE_DEPTH_V1: usize = 32;
/// Number of deterministic bytecode instructions.
pub const PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1: usize = 16;
/// Width of one canonical instruction.
pub const PRIVATE_PROGRAM_INSTRUCTION_BYTES_V1: usize = 8;
/// Number of checked 128-bit VM registers.
pub const PRIVATE_PROGRAM_REGISTER_COUNT_V1: usize = 8;
pub(super) const HASH_FRAME_DOMAIN_V1: &[u8] = b"iroha:privacy:ivm-private-note:hash-frame:v1";
pub(super) const PROGRAM_ID_DOMAIN_V1: &[u8] = b"iroha:privacy:ivm-private-note:program-id:v1";
pub(super) const NOTE_AUTHORITY_DOMAIN_V1: &[u8] = b"iroha:privacy:ivm-private-note:authority:v1";
pub(super) const NOTE_COMMITMENT_DOMAIN_V1: &[u8] = b"iroha:privacy:ivm-private-note:commitment:v1";
pub(super) const NOTE_NULLIFIER_DOMAIN_V1: &[u8] = b"iroha:privacy:ivm-private-note:nullifier:v1";
pub(super) const ACCUMULATOR_LEAF_DOMAIN_V1: &[u8] =
    b"iroha.privacy.proof-managed-note-tree.leaf.v1";
pub(super) const ACCUMULATOR_NODE_DOMAIN_V1: &[u8] =
    b"iroha.privacy.proof-managed-note-tree.node.v1";
/// Exact relation and wire-independent engine descriptor.
pub const IVM_PRIVATE_NOTE_ENGINE_DESCRIPTOR_V1: &[u8] = b"iroha-ivm-private-note-stark-v1:native-rust:first-release:inputs=1..2:outputs=1..2:values=u128-checked:tree=sha256-depth32-exact-ledger-domains:program=IPN1-v1-fixed16x8:registers=8xu128:r4=reserved-zero:producer=typed-redacted-witness+relation-preflight+rand0.9-trycrypto-fixed64-reservoir-zeroize-poison-error-or-unwind-policy-v1+self-verify:wallet=x25519+xchacha20poly1305:wallet-rng=prover-rng:fixed64-reservoir:fallible-refill:reject-initial-constant-half+periods-1,2,4,8,16,32:retain-tail-max63:zeroize+poison-on-error-or-unwind:v1:successor=validator-derived-only:legacy=unrepresentable";
/// Exact hash framing used inside the AIR and native differential oracle.
pub const IVM_PRIVATE_NOTE_HASH_PROFILE_DESCRIPTOR_V1: &[u8] = b"sha256:frame-domain-len-u16be-field-count-u16be-field-len-u64be:program-id+authority+commitment+stable-pool-program-nullifier:proof-managed-leaf-and-level-node-exact-v1";
/// Closed relation controls shared with the atomic private-settlement adapter.
///
/// The public IVM private-note API always selects [`Self::IvmPrivateNote`]. The
/// crate-private three-output variant retains the same hash, VM, tree, and AIR
/// machinery while fixing the only intentional semantic differences: exact
/// two-input/three-output geometry, balanced-only value flow, zero-valued
/// input/output cover notes, and verifier-selected output memo digests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateNoteRelationProfileV1 {
    /// Canonical public one-or-two input/output IVM private-note relation.
    IvmPrivateNote,
    /// Exact balanced two-input/three-output relation with fixed output memos.
    ExactThreeOutputBalanced {
        /// Verifier-fixed memo digest for each canonical output slot.
        output_memo_digests: [[u8; 32]; PRIVATE_NOTE_THREE_OUTPUT_COUNT_V1],
        /// Hiding commitment to the exact two private input openings.
        audit_input_commitment: [u8; 32],
    },
}
impl PrivateNoteRelationProfileV1 {
    /// Canonical public IVM private-note relation profile.
    pub(crate) const IVM_PRIVATE_NOTE: Self = Self::IvmPrivateNote;

    /// Construct the exact three-output balanced profile.
    pub(crate) const fn exact_three_output_balanced(
        output_memo_digests: [[u8; 32]; PRIVATE_NOTE_THREE_OUTPUT_COUNT_V1],
        audit_input_commitment: [u8; 32],
    ) -> Self {
        Self::ExactThreeOutputBalanced {
            output_memo_digests,
            audit_input_commitment,
        }
    }

    pub(super) const fn allows_zero_output_values(self) -> bool {
        matches!(self, Self::ExactThreeOutputBalanced { .. })
    }

    pub(super) const fn allows_zero_input_values(self) -> bool {
        matches!(self, Self::ExactThreeOutputBalanced { .. })
    }

    fn accepts_shape(self, input_count: usize, output_count: usize) -> bool {
        match self {
            Self::IvmPrivateNote => {
                (1..=PRIVATE_NOTE_MAX_INPUTS_V1).contains(&input_count)
                    && (1..=PRIVATE_NOTE_MAX_OUTPUTS_V1).contains(&output_count)
            }
            Self::ExactThreeOutputBalanced { .. } => {
                input_count == PRIVATE_NOTE_MAX_INPUTS_V1
                    && output_count == PRIVATE_NOTE_THREE_OUTPUT_COUNT_V1
            }
        }
    }

    pub(super) fn fixed_output_memo(self, output: usize) -> Option<[u8; 32]> {
        match self {
            Self::IvmPrivateNote => None,
            Self::ExactThreeOutputBalanced {
                output_memo_digests,
                ..
            } => output_memo_digests.get(output).copied(),
        }
    }

    fn requires_balanced_value(self) -> bool {
        matches!(self, Self::ExactThreeOutputBalanced { .. })
    }

    pub(super) const fn audit_input_commitment(self) -> Option<[u8; 32]> {
        match self {
            Self::IvmPrivateNote => None,
            Self::ExactThreeOutputBalanced {
                audit_input_commitment,
                ..
            } => Some(audit_input_commitment),
        }
    }
}
/// Deterministic private-program opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivateOpcodeV1 {
    /// Stop execution. Every later instruction must be this exact zero word.
    Halt = 0,
    /// `dst = immediate`.
    MoveImmediate = 1,
    /// `dst = lhs`.
    Move = 2,
    /// `dst = lhs + rhs`, rejecting `u128` overflow.
    AddChecked = 3,
    /// `dst = lhs - rhs`, rejecting `u128` underflow.
    SubChecked = 4,
    /// Require `lhs == rhs`.
    AssertEqual = 5,
    /// Require `lhs <= rhs`.
    AssertLessOrEqual = 6,
    /// Load one of the two big-endian 128-bit action-digest limbs into `dst`.
    LoadActionLimb = 7,
    /// Load the statement execution epoch into `dst`.
    LoadExecutionEpoch = 8,
}
impl PrivateOpcodeV1 {
    fn from_byte(value: u8) -> Result<Self, IvmPrivateNoteRelationErrorV1> {
        match value {
            0 => Ok(Self::Halt),
            1 => Ok(Self::MoveImmediate),
            2 => Ok(Self::Move),
            3 => Ok(Self::AddChecked),
            4 => Ok(Self::SubChecked),
            5 => Ok(Self::AssertEqual),
            6 => Ok(Self::AssertLessOrEqual),
            7 => Ok(Self::LoadActionLimb),
            8 => Ok(Self::LoadExecutionEpoch),
            _ => Err(IvmPrivateNoteRelationErrorV1::NonCanonicalProgram),
        }
    }
}
/// One exact eight-byte private instruction.
///
/// Encoding is `(opcode, dst, lhs, rhs, immediate_be_u32)`. Fields unused by
/// an opcode must be zero, preventing semantic aliases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateInstructionV1 {
    /// Closed opcode.
    pub(crate) opcode: PrivateOpcodeV1,
    /// Destination register.
    pub(crate) destination: u8,
    /// First source register.
    pub(crate) left: u8,
    /// Second source register.
    pub(crate) right: u8,
    /// Exact immediate.
    pub(crate) immediate: u32,
}
impl PrivateInstructionV1 {
    /// Canonical halt instruction and post-halt padding word.
    pub const HALT: Self = Self {
        opcode: PrivateOpcodeV1::Halt,
        destination: 0,
        left: 0,
        right: 0,
        immediate: 0,
    };
    /// Encode one instruction.
    pub const fn to_bytes(self) -> [u8; PRIVATE_PROGRAM_INSTRUCTION_BYTES_V1] {
        let immediate = self.immediate.to_be_bytes();
        [
            self.opcode as u8,
            self.destination,
            self.left,
            self.right,
            immediate[0],
            immediate[1],
            immediate[2],
            immediate[3],
        ]
    }
    /// Decode one instruction and reject unknown opcodes.
    pub fn from_bytes(
        bytes: [u8; PRIVATE_PROGRAM_INSTRUCTION_BYTES_V1],
    ) -> Result<Self, IvmPrivateNoteRelationErrorV1> {
        let immediate = bytes
            .get(4..8)
            .ok_or(IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)?
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)?;
        Ok(Self {
            opcode: PrivateOpcodeV1::from_byte(bytes[0])?,
            destination: bytes[1],
            left: bytes[2],
            right: bytes[3],
            immediate,
        })
    }
    /// Construct one canonical instruction.
    ///
    /// # Errors
    ///
    /// Returns [`IvmPrivateNoteRelationErrorV1::NonCanonicalProgram`] when an
    /// operand is out of range or a field unused by the opcode is nonzero.
    pub fn new(
        opcode: PrivateOpcodeV1,
        destination: u8,
        left: u8,
        right: u8,
        immediate: u32,
    ) -> Result<Self, IvmPrivateNoteRelationErrorV1> {
        let instruction = Self {
            opcode,
            destination,
            left,
            right,
            immediate,
        };
        instruction.validate()?;
        Ok(instruction)
    }
    /// Return the closed opcode.
    #[must_use]
    pub const fn opcode(self) -> PrivateOpcodeV1 {
        self.opcode
    }
    /// Return the destination-register index.
    #[must_use]
    pub const fn destination(self) -> u8 {
        self.destination
    }
    /// Return the first source-register index.
    #[must_use]
    pub const fn left(self) -> u8 {
        self.left
    }
    /// Return the second source-register index.
    #[must_use]
    pub const fn right(self) -> u8 {
        self.right
    }
    /// Return the exact immediate operand.
    #[must_use]
    pub const fn immediate(self) -> u32 {
        self.immediate
    }
    fn validate(self) -> Result<(), IvmPrivateNoteRelationErrorV1> {
        let register_count = PRIVATE_PROGRAM_REGISTER_COUNT_V1 as u8;
        let register = |value: u8| value < register_count;
        let valid = match self.opcode {
            PrivateOpcodeV1::Halt => self == Self::HALT,
            PrivateOpcodeV1::MoveImmediate => {
                register(self.destination) && self.left == 0 && self.right == 0
            }
            PrivateOpcodeV1::Move => {
                register(self.destination)
                    && register(self.left)
                    && self.right == 0
                    && self.immediate == 0
            }
            PrivateOpcodeV1::AddChecked | PrivateOpcodeV1::SubChecked => {
                register(self.destination)
                    && register(self.left)
                    && register(self.right)
                    && self.immediate == 0
            }
            PrivateOpcodeV1::AssertEqual | PrivateOpcodeV1::AssertLessOrEqual => {
                self.destination == 0
                    && register(self.left)
                    && register(self.right)
                    && self.immediate == 0
            }
            PrivateOpcodeV1::LoadActionLimb => {
                register(self.destination)
                    && self.left == 0
                    && self.right == 0
                    && self.immediate < 2
            }
            PrivateOpcodeV1::LoadExecutionEpoch => {
                register(self.destination)
                    && self.left == 0
                    && self.right == 0
                    && self.immediate == 0
            }
        };
        if valid {
            Ok(())
        } else {
            Err(IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)
        }
    }
}
/// Fixed-size canonical private program.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateProgramV1 {
    /// Exact instruction tape. The first halt terminates the active prefix.
    pub(crate) instructions: [PrivateInstructionV1; PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1],
}
impl fmt::Debug for PrivateProgramV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateProgramV1(<redacted>)")
    }
}
impl Drop for PrivateProgramV1 {
    fn drop(&mut self) {
        self.instructions.fill(PrivateInstructionV1::HALT);
    }
}
impl PrivateProgramV1 {
    /// Construct and validate the sole fixed-width private program.
    ///
    /// # Errors
    ///
    /// Rejects non-canonical operands, instructions after the first halt, or a tape without a halt.
    pub fn new(
        instructions: [PrivateInstructionV1; PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1],
    ) -> Result<Self, IvmPrivateNoteRelationErrorV1> {
        let program = Self { instructions };
        program.validate()?;
        Ok(program)
    }
    /// Borrow the complete canonical instruction tape.
    #[must_use]
    pub const fn instructions(
        &self,
    ) -> &[PrivateInstructionV1; PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1] {
        &self.instructions
    }
    /// Validate the unique instruction encoding and post-halt padding.
    pub fn validate(&self) -> Result<(), IvmPrivateNoteRelationErrorV1> {
        let mut halted = false;
        for instruction in self.instructions {
            instruction.validate()?;
            if halted && instruction != PrivateInstructionV1::HALT {
                return Err(IvmPrivateNoteRelationErrorV1::NonCanonicalProgram);
            }
            if instruction.opcode == PrivateOpcodeV1::Halt {
                halted = true;
            }
        }
        if !halted {
            return Err(IvmPrivateNoteRelationErrorV1::ProgramDoesNotHalt);
        }
        Ok(())
    }
}
/// Plaintext committed by one private note.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateNotePlaintextV1 {
    /// Atomic value.
    pub(crate) value: u128,
    /// Digest of the spending authority.
    pub(crate) spending_authority: [u8; 32],
    /// Unique note nonce.
    pub(crate) rho: [u8; 32],
    /// Commitment blinding.
    pub(crate) blinding: [u8; 32],
    /// Wallet-defined payload digest.
    pub(crate) memo_digest: [u8; 32],
}
impl PrivateNotePlaintextV1 {
    /// Construct one canonical nonzero private-note plaintext.
    ///
    /// `memo_digest` may be zero because an empty wallet memo is valid.
    ///
    /// # Errors
    ///
    /// Rejects zero value, authority, nonce, or blinding.
    pub fn new(
        value: u128,
        spending_authority: [u8; 32],
        rho: [u8; 32],
        blinding: [u8; 32],
        memo_digest: [u8; 32],
    ) -> Result<Self, IvmPrivateNoteRelationErrorV1> {
        let note = Self {
            value,
            spending_authority,
            rho,
            blinding,
            memo_digest,
        };
        validate_note(&note)?;
        Ok(note)
    }
    /// Construct an output note under one crate-private relation profile.
    ///
    /// The three-output profile permits a zero atomic value for a cover slot,
    /// but never permits a zero authority, `rho`, or blinding. Its memo must
    /// equal the verifier-fixed digest for `output_index`.
    pub(crate) fn new_profiled_output_v1(
        value: u128,
        spending_authority: [u8; 32],
        rho: [u8; 32],
        blinding: [u8; 32],
        memo_digest: [u8; 32],
        output_index: usize,
        profile: PrivateNoteRelationProfileV1,
    ) -> Result<Self, IvmPrivateNoteRelationErrorV1> {
        let note = Self {
            value,
            spending_authority,
            rho,
            blinding,
            memo_digest,
        };
        validate_output_note_v1(&note, output_index, profile)?;
        Ok(note)
    }

    /// Construct an input note under one crate-private relation profile.
    pub(crate) fn new_profiled_input_v1(
        value: u128,
        spending_authority: [u8; 32],
        rho: [u8; 32],
        blinding: [u8; 32],
        memo_digest: [u8; 32],
        profile: PrivateNoteRelationProfileV1,
    ) -> Result<Self, IvmPrivateNoteRelationErrorV1> {
        let note = Self {
            value,
            spending_authority,
            rho,
            blinding,
            memo_digest,
        };
        validate_input_note_v1(&note, profile)?;
        Ok(note)
    }
    /// Return the atomic value.
    #[must_use]
    pub const fn value(&self) -> u128 {
        self.value
    }
    /// Return the committed spending-authority digest.
    #[must_use]
    pub const fn spending_authority(&self) -> &[u8; 32] {
        &self.spending_authority
    }
    /// Return the unique note nonce.
    #[must_use]
    pub const fn rho(&self) -> &[u8; 32] {
        &self.rho
    }
    /// Return the commitment blinding.
    #[must_use]
    pub const fn blinding(&self) -> &[u8; 32] {
        &self.blinding
    }
    /// Return the wallet-defined memo digest.
    #[must_use]
    pub const fn memo_digest(&self) -> &[u8; 32] {
        &self.memo_digest
    }
}
impl fmt::Debug for PrivateNotePlaintextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateNotePlaintextV1(<redacted>)")
    }
}
impl Drop for PrivateNotePlaintextV1 {
    fn drop(&mut self) {
        self.value = 0;
        self.spending_authority.zeroize();
        self.rho.zeroize();
        self.blinding.zeroize();
        self.memo_digest.zeroize();
    }
}
/// Wallet-local consumed-note witness.
#[derive(Clone, PartialEq, Eq)]
pub struct IvmPrivateNoteInputWitnessV1 {
    /// Committed plaintext.
    pub(crate) note: PrivateNotePlaintextV1,
    /// Secret whose authority digest is committed by `note`.
    pub(crate) spending_secret: [u8; 32],
    /// Zero-based leaf position.
    pub(crate) leaf_position: u32,
    /// Exact depth-32 sibling path from leaf to root.
    pub(crate) authentication_path: [[u8; 32]; PRIVATE_NOTE_TREE_DEPTH_V1],
}
impl IvmPrivateNoteInputWitnessV1 {
    /// Construct one typed consumed-note witness.
    ///
    /// # Errors
    ///
    /// Rejects malformed note material, zero or mismatched spending secrets,
    /// and reserved-zero authentication siblings.
    pub fn new(
        note: PrivateNotePlaintextV1,
        spending_secret: [u8; 32],
        leaf_position: u32,
        authentication_path: [[u8; 32]; PRIVATE_NOTE_TREE_DEPTH_V1],
    ) -> Result<Self, IvmPrivateNoteRelationErrorV1> {
        validate_note(&note)?;
        if is_zero(&spending_secret) || authentication_path.iter().any(|sibling| is_zero(sibling)) {
            return Err(IvmPrivateNoteRelationErrorV1::ZeroWitnessComponent);
        }
        if derive_note_authority_v1(&spending_secret)? != note.spending_authority {
            return Err(IvmPrivateNoteRelationErrorV1::SpendingAuthorityMismatch);
        }
        Ok(Self {
            note,
            spending_secret,
            leaf_position,
            authentication_path,
        })
    }
    /// Construct one input under a crate-private relation profile.
    pub(crate) fn new_with_profile_v1(
        note: PrivateNotePlaintextV1,
        spending_secret: [u8; 32],
        leaf_position: u32,
        authentication_path: [[u8; 32]; PRIVATE_NOTE_TREE_DEPTH_V1],
        profile: PrivateNoteRelationProfileV1,
    ) -> Result<Self, IvmPrivateNoteRelationErrorV1> {
        validate_input_note_v1(&note, profile)?;
        if is_zero(&spending_secret) || authentication_path.iter().any(|sibling| is_zero(sibling)) {
            return Err(IvmPrivateNoteRelationErrorV1::ZeroWitnessComponent);
        }
        if derive_note_authority_v1(&spending_secret)? != note.spending_authority {
            return Err(IvmPrivateNoteRelationErrorV1::SpendingAuthorityMismatch);
        }
        Ok(Self {
            note,
            spending_secret,
            leaf_position,
            authentication_path,
        })
    }
    /// Borrow the committed plaintext.
    #[must_use]
    pub const fn note(&self) -> &PrivateNotePlaintextV1 {
        &self.note
    }
    /// Return the zero-based leaf position.
    #[must_use]
    pub const fn leaf_position(&self) -> u32 {
        self.leaf_position
    }
    /// Borrow the exact depth-32 authentication path.
    #[must_use]
    pub const fn authentication_path(&self) -> &[[u8; 32]; PRIVATE_NOTE_TREE_DEPTH_V1] {
        &self.authentication_path
    }
    /// Derive the public commitment opened by this input witness.
    pub fn commitment_v1(&self) -> Result<PrivacyCommitmentV1, IvmPrivateNoteRelationErrorV1> {
        derive_note_commitment_v1(&self.note)
    }
    /// Derive the public commitment opened by this input under a crate-private profile.
    pub(crate) fn commitment_with_profile_v1(
        &self,
        profile: PrivateNoteRelationProfileV1,
    ) -> Result<PrivacyCommitmentV1, IvmPrivateNoteRelationErrorV1> {
        derive_profiled_input_commitment_v1(&self.note, profile)
    }
    /// Derive the stable public nullifier for this input and pool/program.
    ///
    /// The spending secret remains encapsulated by the redacted witness and is
    /// never returned to wallet adapters.
    pub fn nullifier_v1(
        &self,
        statement: &IrohaIvmPrivateNoteStarkStatementV1,
    ) -> Result<PrivacyNullifierV1, IvmPrivateNoteRelationErrorV1> {
        let commitment = self.commitment_v1()?;
        derive_note_nullifier_v1(
            statement,
            &self.spending_secret,
            self.note.rho(),
            commitment,
        )
    }
    /// Derive the public nullifier under a crate-private relation profile.
    pub(crate) fn nullifier_with_profile_v1(
        &self,
        statement: &IrohaIvmPrivateNoteStarkStatementV1,
        profile: PrivateNoteRelationProfileV1,
    ) -> Result<PrivacyNullifierV1, IvmPrivateNoteRelationErrorV1> {
        let commitment = self.commitment_with_profile_v1(profile)?;
        derive_note_nullifier_v1(
            statement,
            &self.spending_secret,
            self.note.rho(),
            commitment,
        )
    }
}
impl fmt::Debug for IvmPrivateNoteInputWitnessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IvmPrivateNoteInputWitnessV1(<redacted>)")
    }
}
impl Drop for IvmPrivateNoteInputWitnessV1 {
    fn drop(&mut self) {
        self.spending_secret.zeroize();
        self.authentication_path.zeroize();
    }
}
/// Wallet-local created-note witness.
#[derive(Clone, PartialEq, Eq)]
pub struct IvmPrivateNoteOutputWitnessV1 {
    /// Committed plaintext.
    pub(crate) note: PrivateNotePlaintextV1,
}
impl IvmPrivateNoteOutputWitnessV1 {
    /// Construct one typed created-note witness.
    ///
    /// # Errors
    ///
    /// Rejects malformed note material.
    pub fn new(note: PrivateNotePlaintextV1) -> Result<Self, IvmPrivateNoteRelationErrorV1> {
        validate_note(&note)?;
        Ok(Self { note })
    }
    /// Construct one output under a crate-private relation profile.
    pub(crate) fn new_with_profile_v1(
        note: PrivateNotePlaintextV1,
        output_index: usize,
        profile: PrivateNoteRelationProfileV1,
    ) -> Result<Self, IvmPrivateNoteRelationErrorV1> {
        validate_output_note_v1(&note, output_index, profile)?;
        Ok(Self { note })
    }
    /// Borrow the committed plaintext.
    #[must_use]
    pub const fn note(&self) -> &PrivateNotePlaintextV1 {
        &self.note
    }
}
impl fmt::Debug for IvmPrivateNoteOutputWitnessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IvmPrivateNoteOutputWitnessV1(<redacted>)")
    }
}
/// Complete bounded wallet-local witness.
///
/// The sole first-release `IPNE` wallet codec is structurally checked by the data model and native
/// verifier, while the action digest binds its exact public fields and bytes into this proof
/// statement. The recipient wallet authenticates and decrypts the XChaCha20-Poly1305 payload. As
/// with the FCMP wallet codec, the STARK proves the output commitment opening; it does not
/// duplicate the recipient-local AEAD computation inside the arithmetic relation.
#[derive(Clone, PartialEq, Eq)]
pub struct IvmPrivateNoteWitnessV1 {
    /// Exact governed program preimage.
    pub(crate) program: PrivateProgramV1,
    /// Consumed notes in statement-nullifier order.
    pub(crate) inputs: Vec<IvmPrivateNoteInputWitnessV1>,
    /// Created notes in statement-commitment order.
    pub(crate) outputs: Vec<IvmPrivateNoteOutputWitnessV1>,
}
impl IvmPrivateNoteWitnessV1 {
    /// Construct one exact first-release private-note witness.
    ///
    /// # Errors
    ///
    /// Rejects a non-canonical program or input/output cardinality outside the
    /// closed one-to-two bounds before any proof allocation.
    pub fn new(
        program: PrivateProgramV1,
        inputs: Vec<IvmPrivateNoteInputWitnessV1>,
        outputs: Vec<IvmPrivateNoteOutputWitnessV1>,
    ) -> Result<Self, IvmPrivateNoteRelationErrorV1> {
        program.validate()?;
        if inputs.is_empty()
            || inputs.len() > PRIVATE_NOTE_MAX_INPUTS_V1
            || outputs.is_empty()
            || outputs.len() > PRIVATE_NOTE_MAX_OUTPUTS_V1
        {
            return Err(IvmPrivateNoteRelationErrorV1::WitnessShape);
        }
        Ok(Self {
            program,
            inputs,
            outputs,
        })
    }
    /// Construct a witness for one crate-private relation profile.
    pub(crate) fn new_with_profile_v1(
        program: PrivateProgramV1,
        inputs: Vec<IvmPrivateNoteInputWitnessV1>,
        outputs: Vec<IvmPrivateNoteOutputWitnessV1>,
        profile: PrivateNoteRelationProfileV1,
    ) -> Result<Self, IvmPrivateNoteRelationErrorV1> {
        program.validate()?;
        if !profile.accepts_shape(inputs.len(), outputs.len()) {
            return Err(IvmPrivateNoteRelationErrorV1::WitnessShape);
        }
        for input in &inputs {
            validate_input_note_v1(&input.note, profile)?;
            if is_zero(&input.spending_secret)
                || input
                    .authentication_path
                    .iter()
                    .any(|sibling| is_zero(sibling))
            {
                return Err(IvmPrivateNoteRelationErrorV1::ZeroWitnessComponent);
            }
        }
        for (index, output) in outputs.iter().enumerate() {
            validate_output_note_v1(&output.note, index, profile)?;
        }
        Ok(Self {
            program,
            inputs,
            outputs,
        })
    }
    /// Borrow the governed program preimage.
    #[must_use]
    pub const fn program(&self) -> &PrivateProgramV1 {
        &self.program
    }
    /// Borrow consumed notes in public-nullifier order.
    #[must_use]
    pub fn inputs(&self) -> &[IvmPrivateNoteInputWitnessV1] {
        &self.inputs
    }
    /// Borrow created notes in public-commitment order.
    #[must_use]
    pub fn outputs(&self) -> &[IvmPrivateNoteOutputWitnessV1] {
        &self.outputs
    }
}
impl fmt::Debug for IvmPrivateNoteWitnessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IvmPrivateNoteWitnessV1")
            .field("program", &self.program)
            .field("input_count", &self.inputs.len())
            .field("output_count", &self.outputs.len())
            .finish_non_exhaustive()
    }
}
/// One native SHA-256 invocation consumed by the STARK witness compiler.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Sha256InvocationV1 {
    pub(super) role: Sha256InvocationRoleV1,
    pub(super) preimage: Vec<u8>,
    pub(super) digest: [u8; 32],
}
impl fmt::Debug for Sha256InvocationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Sha256InvocationV1")
            .field("role", &self.role)
            .field("preimage", &"<redacted>")
            .finish_non_exhaustive()
    }
}
impl Drop for Sha256InvocationV1 {
    fn drop(&mut self) {
        self.preimage.zeroize();
        self.digest.zeroize();
    }
}
/// Fixed semantic role for a SHA invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Sha256InvocationRoleV1 {
    Program,
    Authority { input: u8 },
    InputCommitment { input: u8 },
    AuditInputOpenings,
    Nullifier { input: u8 },
    AccumulatorLeaf { input: u8 },
    AccumulatorNode { input: u8, level: u8 },
    OutputCommitment { output: u8 },
}
/// Fully checked relation material. This remains prover-local.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct ValidatedPrivateNoteRelationV1 {
    pub(super) invocations: Vec<Sha256InvocationV1>,
    pub(super) input_sum: u128,
    pub(super) output_sum: u128,
    pub(super) final_registers: [u128; PRIVATE_PROGRAM_REGISTER_COUNT_V1],
}
impl fmt::Debug for ValidatedPrivateNoteRelationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedPrivateNoteRelationV1")
            .field("invocation_count", &self.invocations.len())
            .field("private_values", &"<redacted>")
            .finish_non_exhaustive()
    }
}
/// Native relation or witness failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum IvmPrivateNoteRelationErrorV1 {
    /// The statement is not the sole canonical first-release shape.
    #[error("private-note public statement is invalid")]
    InvalidStatement,
    /// Wallet witness cardinality differs from the public statement.
    #[error("private-note witness shape does not match the statement")]
    WitnessShape,
    /// A secret, authority, nonce, blinding, commitment, or path node is zero.
    #[error("private-note witness contains a reserved zero value")]
    ZeroWitnessComponent,
    /// Program bytecode has an unknown opcode or semantic alias.
    #[error("private-note program bytecode is non-canonical")]
    NonCanonicalProgram,
    /// Program has no canonical halt.
    #[error("private-note program does not halt")]
    ProgramDoesNotHalt,
    /// Program digest differs from the governed statement program identifier.
    #[error("private-note program identifier mismatch")]
    ProgramIdMismatch,
    /// An input spending secret does not derive the committed authority.
    #[error("private-note spending authority mismatch")]
    SpendingAuthorityMismatch,
    /// A note commitment differs from its public statement commitment.
    #[error("private-note commitment relation is invalid")]
    CommitmentMismatch,
    /// A nullifier differs from its public statement nullifier.
    #[error("private-note nullifier relation is invalid")]
    NullifierMismatch,
    /// An input authentication path does not reach the statement root.
    #[error("private-note accumulator membership is invalid")]
    Membership,
    /// Duplicate private input or output material was supplied.
    #[error("private-note witness contains duplicate spend or output material")]
    Duplicate,
    /// Checked `u128` value arithmetic overflowed.
    #[error("private-note value arithmetic overflow")]
    ValueOverflow,
    /// Private and public values are not conserved.
    #[error("private-note values are not conserved")]
    ValueConservation,
    /// Deterministic program arithmetic overflowed or underflowed.
    #[error("private-note program arithmetic failed")]
    ProgramArithmetic,
    /// A program assertion failed.
    #[error("private-note program assertion failed")]
    ProgramAssertion,
    /// Canonical Norito encoding required by the statement/tree failed.
    #[error("private-note canonical encoding failed")]
    Encoding,
    /// A bounded allocation failed.
    #[error("private-note bounded allocation failed")]
    AllocationFailure,
}
pub(super) fn frame_preimage_v1(
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<Vec<u8>, IvmPrivateNoteRelationErrorV1> {
    let domain_len =
        u16::try_from(domain.len()).map_err(|_| IvmPrivateNoteRelationErrorV1::Encoding)?;
    let field_count =
        u16::try_from(fields.len()).map_err(|_| IvmPrivateNoteRelationErrorV1::Encoding)?;
    let capacity = HASH_FRAME_DOMAIN_V1
        .len()
        .checked_add(2)
        .and_then(|value| value.checked_add(domain.len()))
        .and_then(|value| value.checked_add(2))
        .and_then(|value| {
            fields.iter().try_fold(value, |length, field| {
                length.checked_add(8)?.checked_add(field.len())
            })
        })
        .ok_or(IvmPrivateNoteRelationErrorV1::Encoding)?;
    let mut preimage = Vec::new();
    preimage
        .try_reserve_exact(capacity)
        .map_err(|_| IvmPrivateNoteRelationErrorV1::AllocationFailure)?;
    preimage.extend_from_slice(HASH_FRAME_DOMAIN_V1);
    preimage.extend_from_slice(&domain_len.to_be_bytes());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&field_count.to_be_bytes());
    for field in fields {
        preimage.extend_from_slice(
            &u64::try_from(field.len())
                .map_err(|_| IvmPrivateNoteRelationErrorV1::Encoding)?
                .to_be_bytes(),
        );
        preimage.extend_from_slice(field);
    }
    debug_assert_eq!(preimage.len(), capacity);
    Ok(preimage)
}
fn sha256_invocation_v1(
    role: Sha256InvocationRoleV1,
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<Sha256InvocationV1, IvmPrivateNoteRelationErrorV1> {
    let preimage = frame_preimage_v1(domain, fields)?;
    let digest = Sha256::digest(&preimage).into();
    Ok(Sha256InvocationV1 {
        role,
        preimage,
        digest,
    })
}

/// Domain for the circuit-bound input openings disclosed only to auditors.
pub(super) const AUDIT_INPUT_OPENINGS_DOMAIN_V1: &[u8] =
    b"iroha.atomic-private-settlement.input-openings.v1";

fn audit_input_openings_invocation_v1(
    notes: &[PrivateNotePlaintextV1],
) -> Result<Sha256InvocationV1, IvmPrivateNoteRelationErrorV1> {
    if notes.len() != PRIVATE_NOTE_MAX_INPUTS_V1 {
        return Err(IvmPrivateNoteRelationErrorV1::WitnessShape);
    }
    let values = zeroize::Zeroizing::new(
        notes
            .iter()
            .map(|note| note.value.to_be_bytes())
            .collect::<Vec<_>>(),
    );
    let mut fields: Vec<&[u8]> = Vec::with_capacity(PRIVATE_NOTE_MAX_INPUTS_V1 * 5);
    for (note, value) in notes.iter().zip(values.iter()) {
        fields.extend([
            value.as_slice(),
            &note.spending_authority,
            &note.rho,
            &note.blinding,
            &note.memo_digest,
        ]);
    }
    sha256_invocation_v1(
        Sha256InvocationRoleV1::AuditInputOpenings,
        AUDIT_INPUT_OPENINGS_DOMAIN_V1,
        &fields,
    )
}

/// Commit both ordered input openings, including their private entropy.
///
/// Hashing only public note commitments would permit enumerating candidate
/// pairs. The opening includes the secret rho and blinding. Activity is
/// canonical: precisely a nonzero value denotes an active input.
pub fn derive_private_note_input_openings_commitment_v1(
    notes: &[PrivateNotePlaintextV1],
) -> Result<[u8; 32], IvmPrivateNoteRelationErrorV1> {
    Ok(audit_input_openings_invocation_v1(notes)?.digest)
}
/// Derive the exact program identifier.
pub fn derive_private_program_id_v1(
    program: &PrivateProgramV1,
) -> Result<PrivacyProgramIdV1, IvmPrivateNoteRelationErrorV1> {
    let encoded = encode_private_program_v1(program)?;
    Ok(PrivacyProgramIdV1::new(
        sha256_invocation_v1(
            Sha256InvocationRoleV1::Program,
            PROGRAM_ID_DOMAIN_V1,
            &[&encoded],
        )?
        .digest,
    ))
}
/// Derive a note spending-authority digest from its secret.
pub fn derive_note_authority_v1(
    spending_secret: &[u8; 32],
) -> Result<[u8; 32], IvmPrivateNoteRelationErrorV1> {
    if is_zero(spending_secret) {
        return Err(IvmPrivateNoteRelationErrorV1::ZeroWitnessComponent);
    }
    Ok(sha256_invocation_v1(
        Sha256InvocationRoleV1::Authority { input: 0 },
        NOTE_AUTHORITY_DOMAIN_V1,
        &[spending_secret],
    )?
    .digest)
}
/// Derive the sole canonical note commitment.
pub fn derive_note_commitment_v1(
    note: &PrivateNotePlaintextV1,
) -> Result<PrivacyCommitmentV1, IvmPrivateNoteRelationErrorV1> {
    validate_note(note)?;
    derive_note_commitment_with_memo_v1(note, note.memo_digest)
}
/// Derive an output commitment under one crate-private relation profile.
pub fn derive_profiled_output_commitment_v1(
    note: &PrivateNotePlaintextV1,
    output_index: usize,
    profile: PrivateNoteRelationProfileV1,
) -> Result<PrivacyCommitmentV1, IvmPrivateNoteRelationErrorV1> {
    validate_output_note_v1(note, output_index, profile)?;
    let memo = profile
        .fixed_output_memo(output_index)
        .unwrap_or(note.memo_digest);
    derive_note_commitment_with_memo_v1(note, memo)
}
/// Derive an input commitment under one crate-private relation profile.
pub fn derive_profiled_input_commitment_v1(
    note: &PrivateNotePlaintextV1,
    profile: PrivateNoteRelationProfileV1,
) -> Result<PrivacyCommitmentV1, IvmPrivateNoteRelationErrorV1> {
    validate_input_note_v1(note, profile)?;
    derive_note_commitment_with_memo_v1(note, note.memo_digest)
}
fn derive_note_commitment_with_memo_v1(
    note: &PrivateNotePlaintextV1,
    memo_digest: [u8; 32],
) -> Result<PrivacyCommitmentV1, IvmPrivateNoteRelationErrorV1> {
    Ok(PrivacyCommitmentV1::new(
        sha256_invocation_v1(
            Sha256InvocationRoleV1::OutputCommitment { output: 0 },
            NOTE_COMMITMENT_DOMAIN_V1,
            &[
                &note.value.to_be_bytes(),
                &note.spending_authority,
                &note.rho,
                &note.blinding,
                &memo_digest,
            ],
        )?
        .digest,
    ))
}
/// Derive the sole canonical input nullifier.
///
/// The nullifier is deliberately independent of transaction context, action index, accumulator
/// root/position, and execution epoch. A committed note therefore has one stable nullifier in its
/// pool/program namespace and cannot acquire a fresh nullifier by being replayed in another action.
pub fn derive_note_nullifier_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    spending_secret: &[u8; 32],
    rho: &[u8; 32],
    commitment: PrivacyCommitmentV1,
) -> Result<PrivacyNullifierV1, IvmPrivateNoteRelationErrorV1> {
    if is_zero(spending_secret) || is_zero(rho) || commitment.is_zero() {
        return Err(IvmPrivateNoteRelationErrorV1::ZeroWitnessComponent);
    }
    Ok(PrivacyNullifierV1::new(
        sha256_invocation_v1(
            Sha256InvocationRoleV1::Nullifier { input: 0 },
            NOTE_NULLIFIER_DOMAIN_V1,
            &[
                spending_secret,
                rho,
                commitment.as_bytes(),
                statement.pool_id.as_bytes(),
                statement.program_id.as_bytes(),
            ],
        )?
        .digest,
    ))
}
fn validate_note(note: &PrivateNotePlaintextV1) -> Result<(), IvmPrivateNoteRelationErrorV1> {
    validate_note_material_v1(note, false)
}
fn validate_note_material_v1(
    note: &PrivateNotePlaintextV1,
    allow_zero_value: bool,
) -> Result<(), IvmPrivateNoteRelationErrorV1> {
    if (!allow_zero_value && note.value == 0)
        || is_zero(&note.spending_authority)
        || is_zero(&note.rho)
        || is_zero(&note.blinding)
    {
        return Err(IvmPrivateNoteRelationErrorV1::ZeroWitnessComponent);
    }
    Ok(())
}
fn validate_output_note_v1(
    note: &PrivateNotePlaintextV1,
    output_index: usize,
    profile: PrivateNoteRelationProfileV1,
) -> Result<(), IvmPrivateNoteRelationErrorV1> {
    validate_note_material_v1(note, profile.allows_zero_output_values())?;
    if profile
        .fixed_output_memo(output_index)
        .is_some_and(|expected| expected != note.memo_digest)
    {
        return Err(IvmPrivateNoteRelationErrorV1::CommitmentMismatch);
    }
    Ok(())
}
fn validate_input_note_v1(
    note: &PrivateNotePlaintextV1,
    profile: PrivateNoteRelationProfileV1,
) -> Result<(), IvmPrivateNoteRelationErrorV1> {
    validate_note_material_v1(note, profile.allows_zero_input_values())
}
fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
pub(super) fn namespace_v1(statement: &IrohaIvmPrivateNoteStarkStatementV1) -> PrivacyNamespaceV1 {
    PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        PrivacyNamespaceScopeV1::PoolProgram(PrivacyPoolProgramNamespaceV1 {
            pool_id: statement.pool_id,
            program_id: statement.program_id,
        }),
    )
}
pub(super) fn accumulator_leaf_invocation_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    input: u8,
    commitment: PrivacyCommitmentV1,
) -> Result<Sha256InvocationV1, IvmPrivateNoteRelationErrorV1> {
    let encoded_namespace = norito::to_bytes(&namespace_v1(statement))
        .map_err(|_| IvmPrivateNoteRelationErrorV1::Encoding)?;
    let capacity = ACCUMULATOR_LEAF_DOMAIN_V1
        .len()
        .checked_add(8)
        .and_then(|value| value.checked_add(encoded_namespace.len()))
        .and_then(|value| value.checked_add(32))
        .ok_or(IvmPrivateNoteRelationErrorV1::Encoding)?;
    let mut preimage = Vec::new();
    preimage
        .try_reserve_exact(capacity)
        .map_err(|_| IvmPrivateNoteRelationErrorV1::AllocationFailure)?;
    preimage.extend_from_slice(ACCUMULATOR_LEAF_DOMAIN_V1);
    preimage.extend_from_slice(
        &u64::try_from(encoded_namespace.len())
            .map_err(|_| IvmPrivateNoteRelationErrorV1::Encoding)?
            .to_be_bytes(),
    );
    preimage.extend_from_slice(&encoded_namespace);
    preimage.extend_from_slice(commitment.as_bytes());
    Ok(Sha256InvocationV1 {
        role: Sha256InvocationRoleV1::AccumulatorLeaf { input },
        digest: Sha256::digest(&preimage).into(),
        preimage,
    })
}
pub(super) fn accumulator_node_invocation_v1(
    input: u8,
    level: u8,
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<Sha256InvocationV1, IvmPrivateNoteRelationErrorV1> {
    let capacity = ACCUMULATOR_NODE_DOMAIN_V1.len() + 1 + 64;
    let mut preimage = Vec::new();
    preimage
        .try_reserve_exact(capacity)
        .map_err(|_| IvmPrivateNoteRelationErrorV1::AllocationFailure)?;
    preimage.extend_from_slice(ACCUMULATOR_NODE_DOMAIN_V1);
    preimage.push(level);
    preimage.extend_from_slice(left);
    preimage.extend_from_slice(right);
    Ok(Sha256InvocationV1 {
        role: Sha256InvocationRoleV1::AccumulatorNode { input, level },
        digest: Sha256::digest(&preimage).into(),
        preimage,
    })
}

#[cfg(test)]
pub fn accumulator_leaf_digest_for_testing_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    input: u8,
    commitment: PrivacyCommitmentV1,
) -> Result<[u8; 32], IvmPrivateNoteRelationErrorV1> {
    accumulator_leaf_invocation_v1(statement, input, commitment).map(|invocation| invocation.digest)
}

#[cfg(test)]
pub fn accumulator_node_digest_for_testing_v1(
    input: u8,
    level: u8,
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<[u8; 32], IvmPrivateNoteRelationErrorV1> {
    accumulator_node_invocation_v1(input, level, left, right).map(|invocation| invocation.digest)
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn validate_statement_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
) -> Result<(), IvmPrivateNoteRelationErrorV1> {
    validate_statement_with_profile_v1(statement, PrivateNoteRelationProfileV1::IVM_PRIVATE_NOTE)
}
/// Validate a statement against one crate-private relation profile.
pub fn validate_statement_with_profile_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    profile: PrivateNoteRelationProfileV1,
) -> Result<(), IvmPrivateNoteRelationErrorV1> {
    if statement.context.transaction_intent_digest.is_zero()
        || statement.context.parameter_id.is_zero()
        || statement.context.parameter_digest.is_zero()
        || statement.context.verifier_digest.is_zero()
        || statement.context.statement_schema_digest.is_zero()
        || statement.context.engine_manifest_digest.is_zero()
        || statement.pool_id.is_zero()
        || statement.program_id.is_zero()
        || statement.action_digest.is_zero()
        || statement.state_root.is_zero()
        || statement.root_epoch == 0
        || statement.execution_epoch != statement.root_epoch
        || profile
            .audit_input_commitment()
            .is_some_and(|digest| is_zero(&digest))
        || !profile.accepts_shape(
            statement.nullifiers.len(),
            statement.output_commitments.len(),
        )
        || statement.encrypted_outputs.len() != statement.output_commitments.len()
        || statement.value_balance.validate().is_err()
        || (profile.requires_balanced_value()
            && statement.value_balance != PrivacyValueBalanceV1::balanced())
        || statement
            .computed_action_digest()
            .map_err(|_| IvmPrivateNoteRelationErrorV1::Encoding)?
            != statement.action_digest
    {
        return Err(IvmPrivateNoteRelationErrorV1::InvalidStatement);
    }
    let mut nullifiers = BTreeSet::new();
    if statement
        .nullifiers
        .iter()
        .any(|value| value.is_zero() || !nullifiers.insert(*value))
    {
        return Err(IvmPrivateNoteRelationErrorV1::InvalidStatement);
    }
    let mut commitments = BTreeSet::new();
    if statement
        .output_commitments
        .iter()
        .any(|value| value.is_zero() || !commitments.insert(*value))
    {
        return Err(IvmPrivateNoteRelationErrorV1::InvalidStatement);
    }
    for (encrypted, commitment) in statement
        .encrypted_outputs
        .iter()
        .zip(&statement.output_commitments)
    {
        if validate_ivm_private_encrypted_output_v1(
            statement.pool_id,
            statement.program_id,
            *commitment,
            encrypted,
        )
        .is_err()
        {
            return Err(IvmPrivateNoteRelationErrorV1::InvalidStatement);
        }
    }
    namespace_v1(statement)
        .validate()
        .map_err(|_| IvmPrivateNoteRelationErrorV1::InvalidStatement)
}
fn execute_program_v1(
    program: &PrivateProgramV1,
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    input_sum: u128,
    output_sum: u128,
) -> Result<[u128; PRIVATE_PROGRAM_REGISTER_COUNT_V1], IvmPrivateNoteRelationErrorV1> {
    program.validate()?;
    let (public_in, public_out) = public_balance_sides(statement.value_balance);
    let mut registers = [
        input_sum,
        output_sum,
        public_in,
        public_out,
        0,
        u128::from(statement.execution_epoch),
        0,
        1,
    ];
    for instruction in program.instructions {
        instruction.validate()?;
        let dst = usize::from(instruction.destination);
        let left = usize::from(instruction.left);
        let right = usize::from(instruction.right);
        match instruction.opcode {
            PrivateOpcodeV1::Halt => return Ok(registers),
            PrivateOpcodeV1::MoveImmediate => {
                registers[dst] = u128::from(instruction.immediate);
            }
            PrivateOpcodeV1::Move => registers[dst] = registers[left],
            PrivateOpcodeV1::AddChecked => {
                registers[dst] = registers[left]
                    .checked_add(registers[right])
                    .ok_or(IvmPrivateNoteRelationErrorV1::ProgramArithmetic)?;
            }
            PrivateOpcodeV1::SubChecked => {
                registers[dst] = registers[left]
                    .checked_sub(registers[right])
                    .ok_or(IvmPrivateNoteRelationErrorV1::ProgramArithmetic)?;
            }
            PrivateOpcodeV1::AssertEqual => {
                if registers[left] != registers[right] {
                    return Err(IvmPrivateNoteRelationErrorV1::ProgramAssertion);
                }
            }
            PrivateOpcodeV1::AssertLessOrEqual => {
                if registers[left] > registers[right] {
                    return Err(IvmPrivateNoteRelationErrorV1::ProgramAssertion);
                }
            }
            PrivateOpcodeV1::LoadActionLimb => {
                let start = usize::try_from(instruction.immediate)
                    .map_err(|_| IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)?
                    .checked_mul(16)
                    .ok_or(IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)?;
                let limb = statement
                    .action_digest
                    .as_bytes()
                    .get(start..start + 16)
                    .ok_or(IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)?
                    .try_into()
                    .map_err(|_| IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)?;
                registers[dst] = u128::from_be_bytes(limb);
            }
            PrivateOpcodeV1::LoadExecutionEpoch => {
                registers[dst] = u128::from(statement.execution_epoch);
            }
        }
    }
    Err(IvmPrivateNoteRelationErrorV1::ProgramDoesNotHalt)
}
pub(super) fn public_balance_sides(balance: PrivacyValueBalanceV1) -> (u128, u128) {
    match balance.direction {
        PrivacyValueBalanceDirectionV1::Balanced => (0, 0),
        PrivacyValueBalanceDirectionV1::IntoPool => (balance.amount, 0),
        PrivacyValueBalanceDirectionV1::OutOfPool => (0, balance.amount),
    }
}
/// Validate the complete witness relation and build the sole STARK witness schedule.
///
/// Register four is canonically reserved as zero. Transaction fees live only in the separately
/// authorized `FeePaymentIntent`, which is already bound by the statement's transaction-intent
/// digest; duplicating a fee here would create an unreconciled, potentially uncharged public input.
pub(super) fn validate_private_note_relation_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    witness: &IvmPrivateNoteWitnessV1,
) -> Result<ValidatedPrivateNoteRelationV1, IvmPrivateNoteRelationErrorV1> {
    validate_private_note_relation_with_profile_v1(
        statement,
        witness,
        PrivateNoteRelationProfileV1::IVM_PRIVATE_NOTE,
    )
}
/// Preflight a witness under one crate-private relation profile.
pub fn preflight_private_note_relation_with_profile_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    witness: &IvmPrivateNoteWitnessV1,
    profile: PrivateNoteRelationProfileV1,
) -> Result<(), IvmPrivateNoteRelationErrorV1> {
    validate_private_note_relation_with_profile_v1(statement, witness, profile).map(|_| ())
}
pub(super) fn validate_private_note_relation_with_profile_v1(
    statement: &IrohaIvmPrivateNoteStarkStatementV1,
    witness: &IvmPrivateNoteWitnessV1,
    profile: PrivateNoteRelationProfileV1,
) -> Result<ValidatedPrivateNoteRelationV1, IvmPrivateNoteRelationErrorV1> {
    validate_statement_with_profile_v1(statement, profile)?;
    if witness.inputs.len() != statement.nullifiers.len()
        || witness.outputs.len() != statement.output_commitments.len()
        || !profile.accepts_shape(witness.inputs.len(), witness.outputs.len())
    {
        return Err(IvmPrivateNoteRelationErrorV1::WitnessShape);
    }
    witness.program.validate()?;
    let mut invocations = Vec::new();
    let maximum_invocations = 1_usize
        .checked_add(
            witness
                .inputs
                .len()
                .checked_mul(4 + PRIVATE_NOTE_TREE_DEPTH_V1)
                .ok_or(IvmPrivateNoteRelationErrorV1::AllocationFailure)?,
        )
        .and_then(|value| value.checked_add(witness.outputs.len()))
        .and_then(|value| {
            value.checked_add(usize::from(profile.audit_input_commitment().is_some()))
        })
        .ok_or(IvmPrivateNoteRelationErrorV1::AllocationFailure)?;
    invocations
        .try_reserve_exact(maximum_invocations)
        .map_err(|_| IvmPrivateNoteRelationErrorV1::AllocationFailure)?;
    let program_bytes = encode_private_program_v1(&witness.program)?;
    let program_invocation = sha256_invocation_v1(
        Sha256InvocationRoleV1::Program,
        PROGRAM_ID_DOMAIN_V1,
        &[&program_bytes],
    )?;
    if PrivacyProgramIdV1::new(program_invocation.digest) != statement.program_id {
        return Err(IvmPrivateNoteRelationErrorV1::ProgramIdMismatch);
    }
    invocations.push(program_invocation);
    let mut input_sum = 0_u128;
    let mut seen_input_commitments = BTreeSet::new();
    let mut seen_positions = BTreeSet::new();
    for (index, (input, public_nullifier)) in
        witness.inputs.iter().zip(&statement.nullifiers).enumerate()
    {
        validate_input_note_v1(&input.note, profile)?;
        let input_u8 =
            u8::try_from(index).map_err(|_| IvmPrivateNoteRelationErrorV1::WitnessShape)?;
        let authority_invocation = sha256_invocation_v1(
            Sha256InvocationRoleV1::Authority { input: input_u8 },
            NOTE_AUTHORITY_DOMAIN_V1,
            &[&input.spending_secret],
        )?;
        if authority_invocation.digest != input.note.spending_authority {
            return Err(IvmPrivateNoteRelationErrorV1::SpendingAuthorityMismatch);
        }
        invocations.push(authority_invocation);
        let commitment_invocation = sha256_invocation_v1(
            Sha256InvocationRoleV1::InputCommitment { input: input_u8 },
            NOTE_COMMITMENT_DOMAIN_V1,
            &[
                &input.note.value.to_be_bytes(),
                &input.note.spending_authority,
                &input.note.rho,
                &input.note.blinding,
                &input.note.memo_digest,
            ],
        )?;
        let commitment = PrivacyCommitmentV1::new(commitment_invocation.digest);
        if !seen_input_commitments.insert(commitment) || !seen_positions.insert(input.leaf_position)
        {
            return Err(IvmPrivateNoteRelationErrorV1::Duplicate);
        }
        invocations.push(commitment_invocation);
        let nullifier_invocation = sha256_invocation_v1(
            Sha256InvocationRoleV1::Nullifier { input: input_u8 },
            NOTE_NULLIFIER_DOMAIN_V1,
            &[
                &input.spending_secret,
                &input.note.rho,
                commitment.as_bytes(),
                statement.pool_id.as_bytes(),
                statement.program_id.as_bytes(),
            ],
        )?;
        if PrivacyNullifierV1::new(nullifier_invocation.digest) != *public_nullifier {
            return Err(IvmPrivateNoteRelationErrorV1::NullifierMismatch);
        }
        invocations.push(nullifier_invocation);
        let leaf_invocation = accumulator_leaf_invocation_v1(statement, input_u8, commitment)?;
        let mut current = leaf_invocation.digest;
        invocations.push(leaf_invocation);
        let mut position = input.leaf_position;
        for (level, sibling) in input.authentication_path.iter().enumerate() {
            if is_zero(sibling) {
                return Err(IvmPrivateNoteRelationErrorV1::ZeroWitnessComponent);
            }
            let level_u8 =
                u8::try_from(level).map_err(|_| IvmPrivateNoteRelationErrorV1::WitnessShape)?;
            let invocation = if position & 1 == 0 {
                accumulator_node_invocation_v1(input_u8, level_u8, &current, sibling)?
            } else {
                accumulator_node_invocation_v1(input_u8, level_u8, sibling, &current)?
            };
            current = invocation.digest;
            invocations.push(invocation);
            position >>= 1;
        }
        if position != 0
            || ((input.note.value != 0 || !profile.allows_zero_input_values())
                && PrivacyRootV1::new(current) != statement.state_root)
        {
            return Err(IvmPrivateNoteRelationErrorV1::Membership);
        }
        input_sum = input_sum
            .checked_add(input.note.value)
            .ok_or(IvmPrivateNoteRelationErrorV1::ValueOverflow)?;
    }
    if let Some(expected) = profile.audit_input_commitment() {
        let notes = witness
            .inputs
            .iter()
            .map(|input| input.note.clone())
            .collect::<Vec<_>>();
        let invocation = audit_input_openings_invocation_v1(&notes)?;
        if invocation.digest != expected {
            return Err(IvmPrivateNoteRelationErrorV1::CommitmentMismatch);
        }
        invocations.push(invocation);
    }
    let mut output_sum = 0_u128;
    let mut seen_outputs = BTreeSet::new();
    for (index, (output, public_commitment)) in witness
        .outputs
        .iter()
        .zip(&statement.output_commitments)
        .enumerate()
    {
        validate_output_note_v1(&output.note, index, profile)?;
        let output_u8 =
            u8::try_from(index).map_err(|_| IvmPrivateNoteRelationErrorV1::WitnessShape)?;
        let memo_digest = profile
            .fixed_output_memo(index)
            .unwrap_or(output.note.memo_digest);
        let invocation = sha256_invocation_v1(
            Sha256InvocationRoleV1::OutputCommitment { output: output_u8 },
            NOTE_COMMITMENT_DOMAIN_V1,
            &[
                &output.note.value.to_be_bytes(),
                &output.note.spending_authority,
                &output.note.rho,
                &output.note.blinding,
                &memo_digest,
            ],
        )?;
        let commitment = PrivacyCommitmentV1::new(invocation.digest);
        if commitment != *public_commitment {
            return Err(IvmPrivateNoteRelationErrorV1::CommitmentMismatch);
        }
        if !seen_outputs.insert(commitment) || seen_input_commitments.contains(&commitment) {
            return Err(IvmPrivateNoteRelationErrorV1::Duplicate);
        }
        invocations.push(invocation);
        output_sum = output_sum
            .checked_add(output.note.value)
            .ok_or(IvmPrivateNoteRelationErrorV1::ValueOverflow)?;
    }
    let (public_in, public_out) = public_balance_sides(statement.value_balance);
    let conserved_input = input_sum
        .checked_add(public_in)
        .ok_or(IvmPrivateNoteRelationErrorV1::ValueOverflow)?;
    let conserved_output = output_sum
        .checked_add(public_out)
        .ok_or(IvmPrivateNoteRelationErrorV1::ValueOverflow)?;
    if conserved_input != conserved_output {
        return Err(IvmPrivateNoteRelationErrorV1::ValueConservation);
    }
    let final_registers = execute_program_v1(&witness.program, statement, input_sum, output_sum)?;
    if invocations.len() != maximum_invocations {
        return Err(IvmPrivateNoteRelationErrorV1::WitnessShape);
    }
    Ok(ValidatedPrivateNoteRelationV1 {
        invocations,
        input_sum,
        output_sum,
        final_registers,
    })
}
