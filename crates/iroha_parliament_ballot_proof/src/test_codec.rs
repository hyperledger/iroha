//! **Test-only** statement and record codec (evaluation record section 6.6).
//!
//! **This is not a production schema and introduces none.** It exists so that
//! tests and cross-implementation vectors can carry a statement and a proof in
//! one byte string. Production records are header-framed Norito envelopes that
//! are not specified yet; nothing on a wire or in storage may use this module.
//! The naked proof carries no prefix of its own here either.
//!
//! ```text
//! TEST_STATEMENT_REG  = Frame("PARL/TEST/REG/v1";  D, fields of F_REG in order)
//! TEST_STATEMENT_VOTE = Frame("PARL/TEST/VOTE/v1"; D, fields of F_VOTE in order)
//! TEST_RECORD = u32_le(len(TEST_STATEMENT)) || TEST_STATEMENT || u32_le(len(proof)) || proof
//! ```
//!
//! The decoder checks the tag, the exact field count, the expected `D` of the
//! row, all bounds and the absence of trailing bytes. For a registration
//! statement it also refuses a `B` field that is not the digest of the
//! body-context field; for a vote statement it runs the complete public
//! validation.

use thiserror::Error;

use crate::{
    credential::RegistrationContext,
    framing::{BodyContext, Commitment, Digest64, FramingError, OpaqueField, frame_bytes},
    profile::{Profile, Role},
    proving::StatementError,
    registration::RegistrationStatement,
    sealed_list,
    vote::VoteStatement,
};

/// The tag of a test registration statement.
pub const REGISTRATION_TAG: &[u8] = b"PARL/TEST/REG/v1";
/// The tag of a test vote statement.
pub const VOTE_TAG: &[u8] = b"PARL/TEST/VOTE/v1";
/// Fields of a test registration statement: `D` and the ten of `F_REG`.
const REGISTRATION_FIELDS: usize = 11;
/// Fields of a test vote statement: `D` and the eight of `F_VOTE`.
const VOTE_FIELDS: usize = 9;

/// Why test-codec bytes were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TestCodecError {
    /// The bytes do not start with the expected tag.
    #[error("the test statement does not carry the expected tag")]
    Tag,
    /// The field count is not the exact one.
    #[error("the test statement must have {expected} fields, got {actual}")]
    FieldCount {
        /// The exact count.
        expected: usize,
        /// The count found.
        actual: usize,
    },
    /// The bytes end inside a length prefix or a field.
    #[error("the test bytes are truncated")]
    Truncated,
    /// Bytes follow the last field or the proof.
    #[error("{extra} trailing bytes")]
    TrailingBytes {
        /// Number of trailing bytes.
        extra: usize,
    },
    /// The descriptor digest is not the `D` of the row.
    #[error("the descriptor digest is not that of the row")]
    DescriptorDigest,
    /// A field has a length its definition does not allow.
    #[error(transparent)]
    Field(#[from] FramingError),
    /// The `B` field of a registration statement is not the digest of its
    /// body-context field.
    #[error("B is not the digest of the body context")]
    BodyDigest,
    /// The statement fails public validation.
    #[error(transparent)]
    Statement(#[from] StatementError),
    /// The proof of a record does not have the exact length of the row and
    /// relation.
    #[error("the proof of the record must be {expected} bytes long, got {actual}")]
    ProofLength {
        /// The exact length.
        expected: usize,
        /// The length found.
        actual: usize,
    },
}

/// `TEST_STATEMENT_REG` of `statement` on the row of `profile`.
///
/// # Errors
/// Only if a frame cannot be built, which a statement never causes.
pub fn encode_registration(
    profile: &Profile,
    statement: &RegistrationStatement,
) -> Result<Vec<u8>, TestCodecError> {
    let [network, authority, assignment, governance, election, role] = statement.context().fields();
    Ok(frame_bytes(
        REGISTRATION_TAG,
        &[
            profile.descriptor_digest().as_bytes(),
            statement.body_context().as_bytes(),
            network,
            authority,
            assignment,
            governance,
            election,
            role,
            statement.body_digest().as_bytes(),
            statement.commitment().as_bytes(),
            statement.auth().as_bytes(),
        ],
    )?)
}

/// `TEST_STATEMENT_VOTE` of `statement`, as it is, on the row of `profile`.
///
/// # Errors
/// [`TestCodecError::Field`] if the list is too long for a frame field.
pub fn encode_vote(
    profile: &Profile,
    statement: &VoteStatement,
) -> Result<Vec<u8>, TestCodecError> {
    Ok(frame_bytes(
        VOTE_TAG,
        &[
            profile.descriptor_digest().as_bytes(),
            statement.body_digest.as_bytes(),
            statement.scope.as_bytes(),
            statement.list_digest.as_bytes(),
            &statement.size.to_le_bytes(),
            &sealed_list::concat(&statement.list),
            statement.nullifier.as_bytes(),
            &[statement.vote],
            statement.policy_hash.as_bytes(),
        ],
    )?)
}

/// `TEST_RECORD` of an encoded statement and a proof.
///
/// # Errors
/// [`TestCodecError::Field`] if either part exceeds `u32::MAX` bytes.
pub fn encode_record(statement: &[u8], proof: &[u8]) -> Result<Vec<u8>, TestCodecError> {
    let mut out = Vec::with_capacity(8 + statement.len() + proof.len());
    for part in [statement, proof] {
        let len = u32::try_from(part.len()).map_err(|_| FramingError::FieldTooLong {
            actual: u64::try_from(part.len()).unwrap_or(u64::MAX),
        })?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(part);
    }
    Ok(out)
}

/// Take the next `len` bytes of `rest`.
fn take<'a>(rest: &mut &'a [u8], len: usize) -> Result<&'a [u8], TestCodecError> {
    let (head, tail) = rest
        .split_at_checked(len)
        .ok_or(TestCodecError::Truncated)?;
    *rest = tail;
    Ok(head)
}

/// Take a little-endian `u32` length.
fn take_len(rest: &mut &[u8]) -> Result<usize, TestCodecError> {
    let bytes = take(rest, 4)?;
    let mut word = [0u8; 4];
    word.copy_from_slice(bytes);
    usize::try_from(u32::from_le_bytes(word)).map_err(|_| TestCodecError::Truncated)
}

/// Split a frame with the tag `tag` and exactly `count` fields.
fn parse_frame<'a>(
    mut data: &'a [u8],
    tag: &[u8],
    count: usize,
) -> Result<Vec<&'a [u8]>, TestCodecError> {
    let rest = &mut data;
    let tag_len = take(rest, 2).map_err(|_| TestCodecError::Tag)?;
    if usize::from(u16::from_le_bytes([tag_len[0], tag_len[1]])) != tag.len()
        || take(rest, tag.len()).map_err(|_| TestCodecError::Tag)? != tag
    {
        return Err(TestCodecError::Tag);
    }
    let field_count = take(rest, 2)?;
    let actual = usize::from(u16::from_le_bytes([field_count[0], field_count[1]]));
    if actual != count {
        return Err(TestCodecError::FieldCount {
            expected: count,
            actual,
        });
    }
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let len = take_len(rest)?;
        fields.push(take(rest, len)?);
    }
    if !rest.is_empty() {
        return Err(TestCodecError::TrailingBytes { extra: rest.len() });
    }
    Ok(fields)
}

/// Check the descriptor field against the row.
fn check_descriptor(profile: &Profile, field: &[u8]) -> Result<(), TestCodecError> {
    if field == profile.descriptor_digest().as_bytes() {
        Ok(())
    } else {
        Err(TestCodecError::DescriptorDigest)
    }
}

/// Decode `TEST_STATEMENT_REG` for the row of `profile`.
///
/// # Errors
/// [`TestCodecError`] for anything but a canonical encoding of a statement of
/// that row.
pub fn decode_registration(
    profile: &Profile,
    data: &[u8],
) -> Result<RegistrationStatement, TestCodecError> {
    let fields = parse_frame(data, REGISTRATION_TAG, REGISTRATION_FIELDS)?;
    let [
        descriptor,
        body_context,
        network,
        authority,
        assignment,
        governance,
        election,
        role,
        body_digest,
        commitment,
        auth,
    ] = fields[..]
    else {
        return Err(TestCodecError::FieldCount {
            expected: REGISTRATION_FIELDS,
            actual: fields.len(),
        });
    };
    check_descriptor(profile, descriptor)?;
    let statement = RegistrationStatement::new(
        BodyContext::new(body_context)?,
        RegistrationContext {
            network_id: OpaqueField::new(network)?,
            authority: OpaqueField::new(authority)?,
            assignment_id: OpaqueField::new(assignment)?,
            governance_attempt_id: OpaqueField::new(governance)?,
            election_attempt_id: OpaqueField::new(election)?,
            body_role: OpaqueField::new(role)?,
        },
        Commitment::from_slice(commitment)?,
        Digest64::from_slice(auth)?,
    )?;
    if Digest64::from_slice(body_digest)? != *statement.body_digest() {
        return Err(TestCodecError::BodyDigest);
    }
    Ok(statement)
}

/// Decode `TEST_STATEMENT_VOTE` for the row of `profile` and run the public
/// validation.
///
/// # Errors
/// [`TestCodecError`] for anything but a canonical encoding of a publicly valid
/// statement of that row.
pub fn decode_vote(profile: &Profile, data: &[u8]) -> Result<VoteStatement, TestCodecError> {
    let fields = parse_frame(data, VOTE_TAG, VOTE_FIELDS)?;
    let [
        descriptor,
        body_digest,
        scope,
        list_digest,
        size,
        list,
        nullifier,
        vote,
        policy_hash,
    ] = fields[..]
    else {
        return Err(TestCodecError::FieldCount {
            expected: VOTE_FIELDS,
            actual: fields.len(),
        });
    };
    check_descriptor(profile, descriptor)?;
    let &[size_low, size_high] = size else {
        return Err(FramingError::FixedLength {
            expected: 2,
            actual: size.len(),
        }
        .into());
    };
    let &[vote] = vote else {
        return Err(FramingError::FixedLength {
            expected: 1,
            actual: vote.len(),
        }
        .into());
    };
    let statement = VoteStatement {
        body_digest: Digest64::from_slice(body_digest)?,
        scope: Digest64::from_slice(scope)?,
        list_digest: Digest64::from_slice(list_digest)?,
        size: u16::from_le_bytes([size_low, size_high]),
        list: sealed_list::split(list).map_err(StatementError::List)?,
        nullifier: Digest64::from_slice(nullifier)?,
        vote,
        policy_hash: Digest64::from_slice(policy_hash)?,
    };
    statement.validate()?;
    Ok(statement)
}

/// Split `TEST_RECORD` for the row of `profile` and the relation `role` into the
/// encoded statement and the proof. The statement bytes are not decoded here.
///
/// # Errors
/// [`TestCodecError::Truncated`], [`TestCodecError::TrailingBytes`] or
/// [`TestCodecError::ProofLength`].
pub fn decode_record<'a>(
    profile: &Profile,
    role: Role,
    data: &'a [u8],
) -> Result<(&'a [u8], &'a [u8]), TestCodecError> {
    let mut data = data;
    let rest = &mut data;
    let statement_len = take_len(rest)?;
    let statement = take(rest, statement_len)?;
    let proof_len = take_len(rest)?;
    let expected = profile.proof_bytes(role);
    if proof_len != expected {
        return Err(TestCodecError::ProofLength {
            expected,
            actual: proof_len,
        });
    }
    let proof = take(rest, proof_len)?;
    if !rest.is_empty() {
        return Err(TestCodecError::TrailingBytes { extra: rest.len() });
    }
    Ok((statement, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        credential::CredentialSecret,
        profile::Row,
        sealed_list::{ListError, SealedList},
        vote::Vote,
    };

    fn opaque(bytes: &[u8]) -> OpaqueField {
        OpaqueField::new(bytes).expect("within the bound")
    }

    fn registration(profile: &Profile) -> RegistrationStatement {
        RegistrationStatement::for_secret(
            profile,
            &CredentialSecret::from_bytes(&[1; 48]),
            BodyContext::new(b"body").expect("within the bound"),
            RegistrationContext {
                network_id: opaque(b"net"),
                authority: opaque(b""),
                assignment_id: opaque(b"a"),
                governance_attempt_id: opaque(b"g"),
                election_attempt_id: opaque(b"e"),
                body_role: opaque(b"role"),
            },
        )
        .expect("statement")
    }

    fn vote() -> VoteStatement {
        let body = Digest64([3; 64]);
        let list = SealedList::from_unsorted(
            (1..=4u8)
                .map(|member| CredentialSecret::from_bytes(&[member; 48]).commitment(&body))
                .collect(),
        )
        .expect("distinct");
        VoteStatement::new(
            body,
            Digest64([4; 64]),
            &list,
            Digest64([5; 64]),
            Vote::Abstain,
            Digest64([6; 64]),
        )
        .expect("statement")
    }

    /// Re-frame `fields` under `tag`, for malformed inputs.
    fn reframe(tag: &[u8], fields: &[&[u8]]) -> Vec<u8> {
        frame_bytes(tag, fields).expect("frame")
    }

    #[test]
    fn statements_round_trip_on_their_row_only() {
        let fast = Profile::new(Row::Candidate).expect("tables");
        let small = Profile::new(Row::Comparator).expect("tables");
        let statement = registration(&fast);
        let bytes = encode_registration(&fast, &statement).expect("encodes");
        assert!(bytes.starts_with(b"\x10\x00PARL/TEST/REG/v1\x0b\x00\x40\x00\x00\x00"));
        assert_eq!(decode_registration(&fast, &bytes), Ok(statement));
        assert_eq!(
            decode_registration(&small, &bytes),
            Err(TestCodecError::DescriptorDigest)
        );
        let statement = vote();
        let bytes = encode_vote(&fast, &statement).expect("encodes");
        assert!(bytes.starts_with(b"\x11\x00PARL/TEST/VOTE/v1\x09\x00\x40\x00\x00\x00"));
        assert_eq!(decode_vote(&fast, &bytes), Ok(statement));
        assert_eq!(
            decode_vote(&small, &bytes),
            Err(TestCodecError::DescriptorDigest)
        );
        // The two statement kinds do not decode as each other.
        assert_eq!(decode_registration(&fast, &bytes), Err(TestCodecError::Tag));
    }

    #[test]
    fn malformed_frames_are_refused_with_their_reason() {
        let profile = Profile::new(Row::Candidate).expect("tables");
        let bytes = encode_registration(&profile, &registration(&profile)).expect("encodes");
        let fields = parse_frame(&bytes, REGISTRATION_TAG, 11).expect("canonical");
        assert_eq!(
            decode_registration(&profile, &bytes[..bytes.len() - 1]),
            Err(TestCodecError::Truncated)
        );
        assert_eq!(decode_registration(&profile, &[]), Err(TestCodecError::Tag));
        assert_eq!(
            decode_registration(&profile, &bytes[..10]),
            Err(TestCodecError::Tag)
        );
        let mut extended = bytes.clone();
        extended.push(0);
        assert_eq!(
            decode_registration(&profile, &extended),
            Err(TestCodecError::TrailingBytes { extra: 1 })
        );
        assert_eq!(
            decode_registration(&profile, &reframe(REGISTRATION_TAG, &fields[..10])),
            Err(TestCodecError::FieldCount {
                expected: 11,
                actual: 10
            })
        );
        let mut more = fields.clone();
        more.push(b"");
        assert_eq!(
            decode_registration(&profile, &reframe(REGISTRATION_TAG, &more)),
            Err(TestCodecError::FieldCount {
                expected: 11,
                actual: 12
            })
        );
        // Bounds: the body context, an opaque field, C, auth and B.
        let long = vec![0u8; 4097];
        let mut bad = fields.clone();
        bad[1] = &long;
        assert_eq!(
            decode_registration(&profile, &reframe(REGISTRATION_TAG, &bad)),
            Err(TestCodecError::Field(FramingError::BoundExceeded {
                bound: 4096,
                actual: 4097
            }))
        );
        for index in 2..8 {
            let mut bad = fields.clone();
            bad[index] = &long[..257];
            assert_eq!(
                decode_registration(&profile, &reframe(REGISTRATION_TAG, &bad)),
                Err(TestCodecError::Field(FramingError::BoundExceeded {
                    bound: 256,
                    actual: 257
                }))
            );
        }
        for (index, expected) in [(8usize, 64usize), (9, 128), (10, 64)] {
            let mut bad = fields.clone();
            bad[index] = &long[..=expected];
            assert_eq!(
                decode_registration(&profile, &reframe(REGISTRATION_TAG, &bad)),
                Err(TestCodecError::Field(FramingError::FixedLength {
                    expected,
                    actual: expected + 1
                }))
            );
        }
        // A B field that is not the digest of the body-context field.
        let mut bad = fields.clone();
        bad[8] = &long[..64];
        assert_eq!(
            decode_registration(&profile, &reframe(REGISTRATION_TAG, &bad)),
            Err(TestCodecError::BodyDigest)
        );
        let mut bad = fields;
        bad[1] = b"another body";
        assert_eq!(
            decode_registration(&profile, &reframe(REGISTRATION_TAG, &bad)),
            Err(TestCodecError::BodyDigest)
        );
    }

    #[test]
    fn vote_statements_are_publicly_validated_by_the_decoder() {
        let profile = Profile::new(Row::Candidate).expect("tables");
        let statement = vote();
        let bytes = encode_vote(&profile, &statement).expect("encodes");
        let fields = parse_frame(&bytes, VOTE_TAG, 9).expect("canonical");
        let refused = |index: usize, replacement: &[u8]| {
            let mut bad = fields.clone();
            bad[index] = replacement;
            decode_vote(&profile, &reframe(VOTE_TAG, &bad))
        };
        assert_eq!(
            refused(4, &[4]),
            Err(TestCodecError::Field(FramingError::FixedLength {
                expected: 2,
                actual: 1
            }))
        );
        assert_eq!(
            refused(7, &[]),
            Err(TestCodecError::Field(FramingError::FixedLength {
                expected: 1,
                actual: 0
            }))
        );
        assert_eq!(
            refused(7, &[3]),
            Err(TestCodecError::Statement(StatementError::VoteValue {
                value: 3
            }))
        );
        assert_eq!(
            refused(5, &fields[5][..511]),
            Err(TestCodecError::Statement(StatementError::List(
                ListError::EntryLength { actual: 511 }
            )))
        );
        assert_eq!(
            refused(5, &fields[5][..256]),
            Err(TestCodecError::Statement(StatementError::List(
                ListError::Size { actual: 2 }
            )))
        );
        assert_eq!(
            refused(4, &5u16.to_le_bytes()),
            Err(TestCodecError::Statement(StatementError::ListLength {
                declared: 5,
                actual: 4
            }))
        );
        assert_eq!(
            refused(3, &[0u8; 64]),
            Err(TestCodecError::Statement(StatementError::ListDigest))
        );
        for index in [1usize, 2, 3, 6, 8] {
            assert_eq!(
                refused(index, &[0u8; 63]),
                Err(TestCodecError::Field(FramingError::FixedLength {
                    expected: 64,
                    actual: 63
                }))
            );
        }
        assert_eq!(
            decode_vote(&profile, &reframe(VOTE_TAG, &fields[..8])),
            Err(TestCodecError::FieldCount {
                expected: 9,
                actual: 8
            })
        );
        // An invalid statement still encodes: the encoder does not validate.
        let mut invalid = statement;
        invalid.vote = 9;
        let bytes = encode_vote(&profile, &invalid).expect("encodes");
        assert_eq!(
            decode_vote(&profile, &bytes),
            Err(TestCodecError::Statement(StatementError::VoteValue {
                value: 9
            }))
        );
    }

    #[test]
    fn records_carry_exactly_one_statement_and_one_proof_of_the_exact_length() {
        let profile = Profile::new(Row::Candidate).expect("tables");
        let statement = b"statement bytes";
        for role in Role::ALL {
            let proof = vec![0xabu8; profile.proof_bytes(role)];
            let record = encode_record(statement, &proof).expect("encodes");
            assert_eq!(record.len(), 8 + statement.len() + proof.len());
            assert_eq!(record[..4], 15u32.to_le_bytes());
            assert_eq!(
                decode_record(&profile, role, &record),
                Ok((&statement[..], &proof[..]))
            );
            let mut extended = record.clone();
            extended.extend_from_slice(&[0, 0]);
            assert_eq!(
                decode_record(&profile, role, &extended),
                Err(TestCodecError::TrailingBytes { extra: 2 })
            );
            assert_eq!(
                decode_record(&profile, role, &record[..record.len() - 1]),
                Err(TestCodecError::Truncated)
            );
            assert_eq!(
                decode_record(&profile, role, &record[..3]),
                Err(TestCodecError::Truncated)
            );
            let short = encode_record(statement, &proof[1..]).expect("encodes");
            assert_eq!(
                decode_record(&profile, role, &short),
                Err(TestCodecError::ProofLength {
                    expected: proof.len(),
                    actual: proof.len() - 1
                })
            );
        }
        // A record of the other relation has the wrong proof length.
        let proof = vec![0u8; profile.proof_bytes(Role::Vote)];
        let record = encode_record(statement, &proof).expect("encodes");
        assert!(matches!(
            decode_record(&profile, Role::Registration, &record),
            Err(TestCodecError::ProofLength { .. })
        ));
        let mut rest: &[u8] = &[1, 0, 0, 0, 9];
        assert_eq!(take_len(&mut rest), Ok(1));
        assert_eq!(take(&mut rest, 1), Ok(&[9u8][..]));
        assert_eq!(take(&mut rest, 1), Err(TestCodecError::Truncated));
        assert_eq!(
            check_descriptor(&profile, &[0; 64]),
            Err(TestCodecError::DescriptorDigest)
        );
    }
}
