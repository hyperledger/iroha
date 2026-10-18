//! Exact private-program bytecode codec.
use super::relation::{
    IvmPrivateNoteRelationErrorV1, PRIVATE_PROGRAM_INSTRUCTION_BYTES_V1,
    PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1, PrivateInstructionV1, PrivateProgramV1,
};
const PRIVATE_PROGRAM_MAGIC_V1: [u8; 4] = *b"IPN1";
const PRIVATE_PROGRAM_VERSION_V1: u16 = 1;
const PRIVATE_PROGRAM_RESERVED_V1: u16 = 0;
const PRIVATE_PROGRAM_HEADER_BYTES_V1: usize = 8;
/// Exact byte length of the sole canonical first-release private program.
pub const PRIVATE_PROGRAM_BYTES_V1: usize = PRIVATE_PROGRAM_HEADER_BYTES_V1
    + PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1 * PRIVATE_PROGRAM_INSTRUCTION_BYTES_V1;
/// Encode one validated private program into its only canonical byte form.
///
/// # Errors
///
/// Rejects invalid opcodes, non-zero reserved operands, register indices outside the compiled bank,
/// a missing halt, or non-zero instructions after the first halt.
pub fn encode_private_program_v1(
    program: &PrivateProgramV1,
) -> Result<[u8; PRIVATE_PROGRAM_BYTES_V1], IvmPrivateNoteRelationErrorV1> {
    program.validate()?;
    let mut encoded = [0_u8; PRIVATE_PROGRAM_BYTES_V1];
    encoded[..4].copy_from_slice(&PRIVATE_PROGRAM_MAGIC_V1);
    encoded[4..6].copy_from_slice(&PRIVATE_PROGRAM_VERSION_V1.to_be_bytes());
    encoded[6..8].copy_from_slice(&PRIVATE_PROGRAM_RESERVED_V1.to_be_bytes());
    for (index, instruction) in program.instructions.iter().copied().enumerate() {
        let offset = PRIVATE_PROGRAM_HEADER_BYTES_V1 + index * PRIVATE_PROGRAM_INSTRUCTION_BYTES_V1;
        encoded[offset..offset + PRIVATE_PROGRAM_INSTRUCTION_BYTES_V1]
            .copy_from_slice(&instruction.to_bytes());
    }
    Ok(encoded)
}
/// Decode exactly one canonical private program.
///
/// # Errors
///
/// Rejects every truncation, suffix, alternate magic/version, non-zero
/// reserved header, invalid instruction, or non-canonical post-halt encoding.
pub fn decode_private_program_v1(
    encoded: &[u8],
) -> Result<PrivateProgramV1, IvmPrivateNoteRelationErrorV1> {
    if encoded.len() != PRIVATE_PROGRAM_BYTES_V1 {
        return Err(IvmPrivateNoteRelationErrorV1::NonCanonicalProgram);
    }
    let magic = encoded
        .get(..4)
        .ok_or(IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)?;
    let version = encoded
        .get(4..6)
        .ok_or(IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)?
        .try_into()
        .map(u16::from_be_bytes)
        .map_err(|_| IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)?;
    let reserved = encoded
        .get(6..8)
        .ok_or(IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)?
        .try_into()
        .map(u16::from_be_bytes)
        .map_err(|_| IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)?;
    if magic != PRIVATE_PROGRAM_MAGIC_V1
        || version != PRIVATE_PROGRAM_VERSION_V1
        || reserved != PRIVATE_PROGRAM_RESERVED_V1
    {
        return Err(IvmPrivateNoteRelationErrorV1::NonCanonicalProgram);
    }
    let mut instructions = [PrivateInstructionV1::HALT; PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1];
    for (index, instruction) in instructions.iter_mut().enumerate() {
        let offset = PRIVATE_PROGRAM_HEADER_BYTES_V1 + index * PRIVATE_PROGRAM_INSTRUCTION_BYTES_V1;
        let bytes = encoded
            .get(offset..offset + PRIVATE_PROGRAM_INSTRUCTION_BYTES_V1)
            .ok_or(IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)?
            .try_into()
            .map_err(|_| IvmPrivateNoteRelationErrorV1::NonCanonicalProgram)?;
        *instruction = PrivateInstructionV1::from_bytes(bytes)?;
    }
    let program = PrivateProgramV1 { instructions };
    program.validate()?;
    if encode_private_program_v1(&program)?.as_slice() != encoded {
        return Err(IvmPrivateNoteRelationErrorV1::NonCanonicalProgram);
    }
    Ok(program)
}
