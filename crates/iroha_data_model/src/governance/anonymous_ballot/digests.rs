//! The public digests fixed by the integration decisions of 2026-10-18 that need no
//! proof-profile constant.
//!
//! `H = SHA3-512`, `Frame` is profile §6.1 and `Enc` is the pinned canonical frame of
//! [`super::framing`]:
//!
//! ```text
//! envelope_digest  = H(Frame("PARL/ENVELOPE/v1"; canonical_envelope_bytes))
//! leaf_i           = H(Frame("PARL/CORPUS-ENTRY/v1"; Enc(entry_i)))
//! root_0           = H(Frame("PARL/CORPUS-EMPTY/v1"; profile_id, scope, R, policy_hash))
//! root_(i+1)       = H(Frame("PARL/CORPUS-APPEND/v1"; root_i, u32_le(i), leaf_i))
//! registration_mapping_digest
//!                  = H(Frame("PARL/REGMAP/v1"; profile_id, B, R, u16_le(S), Enc(sorted_pairs)))
//! roster_root      = H(Frame("PARL/ROSTER/v1"; Enc(roster_preimage)))
//! result_root      = H(Frame("PARL/RESULT/v1"; Enc(closure_record)))
//! payload_digest   = H(Frame("PARL/STAMP-PAYLOAD/v1"; Enc(authorization), Enc(context)))
//! work_digest      = H(Frame("PARL/STAMP-WORK/v1"; payload_digest, nonce))
//! authority_binding= H(Frame("PARL/AUTHORITY/v1"; Enc(AccountId)))
//! proposal_digest  = H(Frame("PARL/PROPOSAL/v1"; Enc(ProposalKind)))
//! ```
//!
//! Every 64-, 32- and 128-byte operand is its raw bytes. `B`, `R`, `scope`, `policy_hash`
//! and the authorization digests bind the construction domain `P16` and are computed by
//! `iroha_parliament_ballot_proof`; they enter here as inputs.

use std::collections::BTreeSet;

use super::{
    AdmissionNonceV1, AnonymousBallotAuthorizationV1, AnonymousBallotCorpusEntryV1,
    AnonymousParliamentRosterRootPreimageV1, AuthenticatedBallotContextV1,
    BALLOT_CONTEXT_MAX_BYTES_V1, BallotAuthorityBindingV1, BallotClosureRecordV1,
    BallotContextErrorV1, BallotScopeV1, Digest512, MAX_SEALED_SEATS_V1, ProofProfileIdV1,
    SealedCredentialListV1, SealedRegistrationPairV1,
    framing::{AnonymousBallotCodecErrorV1, enc, enc_bounded, frame_digest},
};
use crate::{account::AccountId, governance::types::ProposalKind};

/// Frame tag of the envelope digest.
pub const ENVELOPE_TAG_V1: &[u8] = b"PARL/ENVELOPE/v1";
/// Frame tag of a corpus leaf.
pub const CORPUS_ENTRY_TAG_V1: &[u8] = b"PARL/CORPUS-ENTRY/v1";
/// Frame tag of the empty corpus root.
pub const CORPUS_EMPTY_TAG_V1: &[u8] = b"PARL/CORPUS-EMPTY/v1";
/// Frame tag of a corpus append.
pub const CORPUS_APPEND_TAG_V1: &[u8] = b"PARL/CORPUS-APPEND/v1";
/// Frame tag of the registration-mapping digest.
pub const REGISTRATION_MAPPING_TAG_V1: &[u8] = b"PARL/REGMAP/v1";
/// Frame tag of the roster root.
pub const ROSTER_TAG_V1: &[u8] = b"PARL/ROSTER/v1";
/// Frame tag of the result root.
pub const RESULT_TAG_V1: &[u8] = b"PARL/RESULT/v1";
/// Frame tag of the stamp payload digest.
pub const STAMP_PAYLOAD_TAG_V1: &[u8] = b"PARL/STAMP-PAYLOAD/v1";
/// Frame tag of the stamp work digest.
pub const STAMP_WORK_TAG_V1: &[u8] = b"PARL/STAMP-WORK/v1";
/// Frame tag of the registration authority binding.
pub const AUTHORITY_TAG_V1: &[u8] = b"PARL/AUTHORITY/v1";
/// Frame tag of the proposal digest (the profile's frame, without `P16`).
pub const PROPOSAL_TAG_V1: &[u8] = b"PARL/PROPOSAL/v1";
/// Frame tag of the qualification-record digest.
pub const QUALIFICATION_TAG_V1: &[u8] = b"PARL/QUALIFICATION/v1";

/// Why a corpus is not the canonical accepted corpus of one scope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnonymousBallotCorpusErrorV1 {
    /// An entry has height zero.
    #[error("a corpus entry must have a nonzero height")]
    ZeroHeight,
    /// An entry belongs to another scope.
    #[error("corpus entry {index} belongs to another scope")]
    ForeignScope {
        /// Index of the entry.
        index: usize,
    },
    /// An entry names another proof profile.
    #[error("corpus entry {index} names another proof profile")]
    ForeignProfile {
        /// Index of the entry.
        index: usize,
    },
    /// An entry does not follow its predecessor in `(height, input_index)` order.
    #[error("corpus entry {index} is not strictly after its predecessor")]
    Order {
        /// Index of the entry.
        index: usize,
    },
    /// An entry repeats an earlier entry's nullifier.
    #[error("corpus entry {index} repeats an accepted nullifier")]
    DuplicateNullifier {
        /// Index of the entry.
        index: usize,
    },
    /// The corpus has more entries than any sealed list has seats.
    #[error("a corpus of {count} entries exceeds the {MAX_SEALED_SEATS_V1}-seat maximum")]
    TooManyEntries {
        /// Number of entries supplied.
        count: usize,
    },
    /// A digest could not be computed.
    #[error(transparent)]
    Codec(#[from] AnonymousBallotCodecErrorV1),
}

/// `envelope_digest = H(Frame("PARL/ENVELOPE/v1"; canonical_envelope_bytes))`.
///
/// The bytes must be the exact canonical envelope frame (see
/// [`super::CanonicalAnonymousBallotEnvelopeV1`]); this function hashes what it is given.
///
/// # Errors
/// [`AnonymousBallotCodecErrorV1::FieldTooLong`] above `u32::MAX` bytes.
pub fn envelope_digest_v1(
    canonical_envelope_bytes: &[u8],
) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
    frame_digest(ENVELOPE_TAG_V1, &[canonical_envelope_bytes])
}

/// `leaf_i = H(Frame("PARL/CORPUS-ENTRY/v1"; Enc(entry_i)))`.
///
/// # Errors
/// [`AnonymousBallotCodecErrorV1`] if `Enc(entry)` cannot be produced.
pub fn corpus_leaf_v1(
    entry: &AnonymousBallotCorpusEntryV1,
) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
    frame_digest(CORPUS_ENTRY_TAG_V1, &[&enc(entry)?])
}

/// `root_0 = H(Frame("PARL/CORPUS-EMPTY/v1"; profile_id, scope, R, policy_hash))`.
///
/// # Errors
/// Never in practice: every field is 64 bytes.
pub fn corpus_empty_root_v1(
    profile_id: &ProofProfileIdV1,
    scope: &BallotScopeV1,
    list_digest: &Digest512,
    policy_hash: &Digest512,
) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
    frame_digest(
        CORPUS_EMPTY_TAG_V1,
        &[
            profile_id.as_bytes(),
            scope.as_bytes(),
            list_digest.as_bytes(),
            policy_hash.as_bytes(),
        ],
    )
}

/// `root_(i+1) = H(Frame("PARL/CORPUS-APPEND/v1"; root_i, u32_le(i), leaf_i))`, where `i`
/// is the zero-based index of the appended accepted ballot.
///
/// # Errors
/// Never in practice: the fields are 64, 4 and 64 bytes.
pub fn corpus_append_root_v1(
    root: &Digest512,
    index: u32,
    leaf: &Digest512,
) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
    frame_digest(
        CORPUS_APPEND_TAG_V1,
        &[root.as_bytes(), &index.to_le_bytes(), leaf.as_bytes()],
    )
}

/// `root_M` of the accepted corpus `entries` of one scope, folded from `root_0`.
///
/// The entries must be the scope's accepted ballots in canonical order: nonzero heights,
/// strictly increasing `(height, input_index)`, the given scope and profile, distinct
/// nullifiers, and at most [`MAX_SEALED_SEATS_V1`] of them. Restore and full verification
/// recompute the root with this function.
///
/// # Errors
/// [`AnonymousBallotCorpusErrorV1`] naming the first offending entry.
pub fn corpus_root_v1(
    profile_id: &ProofProfileIdV1,
    scope: &BallotScopeV1,
    list_digest: &Digest512,
    policy_hash: &Digest512,
    entries: &[AnonymousBallotCorpusEntryV1],
) -> Result<Digest512, AnonymousBallotCorpusErrorV1> {
    if entries.len() > usize::from(MAX_SEALED_SEATS_V1) {
        return Err(AnonymousBallotCorpusErrorV1::TooManyEntries {
            count: entries.len(),
        });
    }
    let mut root = corpus_empty_root_v1(profile_id, scope, list_digest, policy_hash)?;
    let mut previous: Option<(u64, u32)> = None;
    let mut nullifiers = BTreeSet::new();
    for (index, entry) in entries.iter().enumerate() {
        entry.validate()?;
        if entry.scope != *scope {
            return Err(AnonymousBallotCorpusErrorV1::ForeignScope { index });
        }
        if entry.profile_id != *profile_id {
            return Err(AnonymousBallotCorpusErrorV1::ForeignProfile { index });
        }
        if previous.is_some_and(|previous| previous >= entry.position()) {
            return Err(AnonymousBallotCorpusErrorV1::Order { index });
        }
        if !nullifiers.insert(entry.nullifier) {
            return Err(AnonymousBallotCorpusErrorV1::DuplicateNullifier { index });
        }
        previous = Some(entry.position());
        let position =
            u32::try_from(index).map_err(|_| AnonymousBallotCorpusErrorV1::TooManyEntries {
                count: entries.len(),
            })?;
        root = corpus_append_root_v1(&root, position, &corpus_leaf_v1(entry)?)?;
    }
    Ok(root)
}

/// `registration_mapping_digest = H(Frame("PARL/REGMAP/v1"; profile_id, B, R, u16_le(S),
/// Enc(sorted_pairs)))` of a sealed list.
///
/// `list` supplies `profile_id`, `B` and `S`, and `list_digest` is its `R` (computed by
/// the proof crate). `pairs` may come in any order: they are sorted by raw
/// [`crate::governance::types::AssignmentId`] bytes, the assignments must be distinct,
/// there must be exactly `S` of them, and their commitments must be exactly the list's
/// commitments (a multiset equality; the list has no duplicates).
///
/// # Errors
/// [`BallotContextErrorV1`] for an invalid list or mapping, or a codec failure.
pub fn registration_mapping_digest_v1(
    list: &SealedCredentialListV1,
    list_digest: &Digest512,
    pairs: &[SealedRegistrationPairV1],
) -> Result<Digest512, BallotContextErrorV1> {
    list.validate()?;
    let mut sorted = pairs.to_vec();
    sorted.sort_unstable_by(|left, right| {
        left.assignment_id
            .as_bytes()
            .cmp(right.assignment_id.as_bytes())
    });
    if sorted
        .windows(2)
        .any(|pair| pair[0].assignment_id == pair[1].assignment_id)
    {
        return Err(BallotContextErrorV1::DuplicateAssignment);
    }
    if sorted.len() != list.commitments.len() {
        return Err(BallotContextErrorV1::MappingSize {
            pairs: sorted.len(),
            seats: list.seats,
        });
    }
    let mut commitments: Vec<_> = sorted.iter().map(|pair| pair.commitment).collect();
    commitments.sort_unstable();
    if commitments != list.commitments {
        return Err(BallotContextErrorV1::MappingCommitments);
    }
    let encoded = enc(&sorted)?;
    Ok(frame_digest(
        REGISTRATION_MAPPING_TAG_V1,
        &[
            list.profile_id.as_bytes(),
            list.body_context_digest.as_bytes(),
            list_digest.as_bytes(),
            &list.seats.to_le_bytes(),
            &encoded,
        ],
    )?)
}

/// `roster_root = H(Frame("PARL/ROSTER/v1"; Enc(roster_preimage)))`, the 64-byte roster
/// root of the extended preimage (integration decision 3).
///
/// # Errors
/// [`BallotContextErrorV1`] if the preimage is not canonical (see
/// [`AnonymousParliamentRosterRootPreimageV1::validate`]) or cannot be encoded.
pub fn anonymous_roster_root_v1(
    preimage: &AnonymousParliamentRosterRootPreimageV1,
) -> Result<Digest512, BallotContextErrorV1> {
    preimage.validate()?;
    Ok(frame_digest(ROSTER_TAG_V1, &[&enc(preimage)?])?)
}

/// `result_root = H(Frame("PARL/RESULT/v1"; Enc(closure_record)))`.
///
/// The caller validates the record (see [`BallotClosureRecordV1::validate`]); this function
/// hashes what it is given.
///
/// # Errors
/// [`AnonymousBallotCodecErrorV1`] if `Enc(record)` cannot be produced.
pub fn result_root_v1(
    record: &BallotClosureRecordV1,
) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
    frame_digest(RESULT_TAG_V1, &[&enc(record)?])
}

/// `Enc(context)` of one scope's authenticated context, computed once, with the context's
/// frozen stamp difficulty.
///
/// The stamp payload digest frames `Enc(authorization)` before `Enc(context)`, so no hash
/// midstate of the context can be reused; the reusable part is the canonical context
/// encoding (up to 163,840 bytes). Core encodes a scope's context once per scope and checks
/// every stamp of that scope against it with [`stamp_payload_digest_encoded_v1`] and
/// [`verify_stamp_encoded_v1`]. The only constructor encodes a context, so the bytes are
/// always exactly `Enc(context)`.
#[derive(Clone, PartialEq, Eq)]
pub struct EncodedBallotContextV1 {
    bytes: Vec<u8>,
    stamp_difficulty_bits: u8,
}

impl EncodedBallotContextV1 {
    /// Encode `context` once, checking its byte cap before allocating the output frame.
    /// The caller remains responsible for structural validation and authentication.
    ///
    /// # Errors
    /// [`AnonymousBallotCodecErrorV1`] if `Enc(context)` cannot be produced or exceeds
    /// [`BALLOT_CONTEXT_MAX_BYTES_V1`].
    pub fn new(
        context: &AuthenticatedBallotContextV1,
    ) -> Result<Self, AnonymousBallotCodecErrorV1> {
        Ok(Self {
            bytes: enc_bounded(
                context,
                "authenticated ballot context",
                BALLOT_CONTEXT_MAX_BYTES_V1,
            )?,
            stamp_difficulty_bits: context.policy.binding.stamp_difficulty_bits,
        })
    }

    /// The exact `Enc(context)` bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Leading zero bits a stamp of this scope needs: the context's frozen difficulty.
    #[must_use]
    pub const fn stamp_difficulty_bits(&self) -> u8 {
        self.stamp_difficulty_bits
    }
}

impl core::fmt::Debug for EncodedBallotContextV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncodedBallotContextV1")
            .field("bytes", &self.bytes.len())
            .field("stamp_difficulty_bits", &self.stamp_difficulty_bits)
            .finish()
    }
}

/// `payload_digest = H(Frame("PARL/STAMP-PAYLOAD/v1"; Enc(authorization), Enc(context)))`.
///
/// `context` is the authenticated context of the ballot's scope; it never comes from the
/// submitter. This simple form encodes the context on every call; see
/// [`stamp_payload_digest_encoded_v1`].
///
/// # Errors
/// [`AnonymousBallotCodecErrorV1`] if an `Enc` cannot be produced.
pub fn stamp_payload_digest_v1(
    authorization: &AnonymousBallotAuthorizationV1,
    context: &AuthenticatedBallotContextV1,
) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
    stamp_payload_digest_encoded_v1(authorization, &EncodedBallotContextV1::new(context)?)
}

/// [`stamp_payload_digest_v1`] with the scope's context encoded once.
///
/// # Errors
/// [`AnonymousBallotCodecErrorV1`] if `Enc(authorization)` cannot be produced.
pub fn stamp_payload_digest_encoded_v1(
    authorization: &AnonymousBallotAuthorizationV1,
    context: &EncodedBallotContextV1,
) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
    frame_digest(
        STAMP_PAYLOAD_TAG_V1,
        &[&enc(authorization)?, context.as_bytes()],
    )
}

/// `work_digest = H(Frame("PARL/STAMP-WORK/v1"; payload_digest, nonce))`.
///
/// # Errors
/// Never in practice: the fields are 64 and 32 bytes.
pub fn stamp_work_digest_v1(
    payload_digest: &Digest512,
    nonce: &AdmissionNonceV1,
) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
    frame_digest(
        STAMP_WORK_TAG_V1,
        &[payload_digest.as_bytes(), nonce.as_bytes()],
    )
}

/// Leading zero bits of `digest`, counted most-significant bit first from byte zero.
#[must_use]
pub fn leading_zero_bits_v1(digest: &Digest512) -> u32 {
    let mut count = 0;
    for byte in digest.as_bytes() {
        count += byte.leading_zeros();
        if *byte != 0 {
            break;
        }
    }
    count
}

/// Whether `work_digest` has at least `difficulty_bits` leading zero bits.
#[must_use]
pub fn stamp_meets_difficulty_v1(work_digest: &Digest512, difficulty_bits: u8) -> bool {
    leading_zero_bits_v1(work_digest) >= u32::from(difficulty_bits)
}

/// Whether the envelope's stamp reaches the context's frozen difficulty: the
/// authorization payload of `authorization` with `context`, then `nonce`.
///
/// This simple form encodes the context on every call; [`verify_stamp_encoded_v1`] takes
/// the scope's context encoded once and decides identically.
///
/// # Errors
/// As [`stamp_payload_digest_v1`].
pub fn verify_stamp_v1(
    authorization: &AnonymousBallotAuthorizationV1,
    context: &AuthenticatedBallotContextV1,
    nonce: &AdmissionNonceV1,
) -> Result<bool, AnonymousBallotCodecErrorV1> {
    verify_stamp_encoded_v1(authorization, &EncodedBallotContextV1::new(context)?, nonce)
}

/// [`verify_stamp_v1`] with the scope's context encoded once.
///
/// # Errors
/// As [`stamp_payload_digest_encoded_v1`].
pub fn verify_stamp_encoded_v1(
    authorization: &AnonymousBallotAuthorizationV1,
    context: &EncodedBallotContextV1,
    nonce: &AdmissionNonceV1,
) -> Result<bool, AnonymousBallotCodecErrorV1> {
    let payload = stamp_payload_digest_encoded_v1(authorization, context)?;
    let work = stamp_work_digest_v1(&payload, nonce)?;
    Ok(stamp_meets_difficulty_v1(
        &work,
        context.stamp_difficulty_bits(),
    ))
}

/// `authority_binding = H(Frame("PARL/AUTHORITY/v1"; Enc(AccountId)))`, whose `Enc` is the
/// proof input `Enc(authority)` of a registration (integration decision 7).
///
/// # Errors
/// [`AnonymousBallotCodecErrorV1`] if `Enc(account)` cannot be produced.
pub fn authority_binding_v1(
    account: &AccountId,
) -> Result<BallotAuthorityBindingV1, AnonymousBallotCodecErrorV1> {
    frame_digest(AUTHORITY_TAG_V1, &[&enc(account)?])
        .map(|digest| BallotAuthorityBindingV1::new(digest.into_bytes()))
}

/// `proposal_digest = H(Frame("PARL/PROPOSAL/v1"; Enc(ProposalKind)))` over the full
/// canonical typed proposal, never its 32-byte content identifier (integration decision 7).
///
/// # Errors
/// [`AnonymousBallotCodecErrorV1`] if `Enc(proposal)` cannot be produced or exceeds the
/// 32-bit `Frame` field length.
pub fn proposal_digest_v1(
    proposal: &ProposalKind,
) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
    frame_digest(PROPOSAL_TAG_V1, &[&enc(proposal)?])
}

#[cfg(test)]
mod tests {
    use sha3::{Digest as _, Sha3_512};

    use super::*;
    use crate::governance::{
        anonymous_ballot::{
            AnonymousRosterBindingV1, BallotChoiceV1, CredentialCommitmentV1,
            framing::frame_bytes,
            test_fixtures::{
                account, assignment, closure, commitment, context, envelope, proposal, sealed_list,
            },
        },
        types::{BodyElectionAttemptId, ParliamentSeatAssignmentV1},
    };

    fn sha3(bytes: &[u8]) -> Digest512 {
        Digest512::new(Sha3_512::digest(bytes).into())
    }

    fn entry(height: u64, input_index: u32, nullifier: u8) -> AnonymousBallotCorpusEntryV1 {
        AnonymousBallotCorpusEntryV1::from_envelope(
            &envelope(BallotChoiceV1::Aye, nullifier),
            Digest512::new([nullifier; 64]),
            height,
            input_index,
        )
        .expect("entry")
    }

    #[test]
    fn the_envelope_digest_frames_the_exact_bytes() {
        let bytes = envelope(BallotChoiceV1::Aye, 1)
            .encode_canonical_bounded()
            .expect("frame");
        assert_eq!(
            envelope_digest_v1(&bytes),
            Ok(sha3(
                &frame_bytes(b"PARL/ENVELOPE/v1", &[&bytes]).expect("frame")
            ))
        );
        assert_ne!(envelope_digest_v1(&bytes), envelope_digest_v1(&bytes[1..]));
    }

    #[test]
    fn corpus_digests_follow_their_formulas() {
        let profile = ProofProfileIdV1::V1;
        let scope = BallotScopeV1::new([0x44; 64]);
        let list = Digest512::new([0x99; 64]);
        let policy = Digest512::new([0xaa; 64]);
        let root_0 = corpus_empty_root_v1(&profile, &scope, &list, &policy).expect("root");
        assert_eq!(
            root_0,
            sha3(
                &frame_bytes(
                    b"PARL/CORPUS-EMPTY/v1",
                    &[profile.as_bytes(), &[0x44; 64], &[0x99; 64], &[0xaa; 64]]
                )
                .expect("frame")
            )
        );
        let first = entry(10, 0, 1);
        let leaf = corpus_leaf_v1(&first).expect("leaf");
        assert_eq!(
            leaf,
            sha3(
                &frame_bytes(b"PARL/CORPUS-ENTRY/v1", &[&enc(&first).expect("enc")])
                    .expect("frame")
            )
        );
        let root_1 = corpus_append_root_v1(&root_0, 0, &leaf).expect("root");
        assert_eq!(
            root_1,
            sha3(
                &frame_bytes(
                    b"PARL/CORPUS-APPEND/v1",
                    &[root_0.as_bytes(), &0_u32.to_le_bytes(), leaf.as_bytes()]
                )
                .expect("frame")
            )
        );
        assert_ne!(corpus_append_root_v1(&root_0, 1, &leaf), Ok(root_1));
        // The fold reproduces the appends.
        let second = entry(10, 4, 2);
        let third = entry(11, 0, 3);
        let root_3 = corpus_append_root_v1(
            &corpus_append_root_v1(&root_1, 1, &corpus_leaf_v1(&second).expect("leaf"))
                .expect("root"),
            2,
            &corpus_leaf_v1(&third).expect("leaf"),
        )
        .expect("root");
        assert_eq!(
            corpus_root_v1(&profile, &scope, &list, &policy, &[first, second, third]),
            Ok(root_3)
        );
        assert_eq!(
            corpus_root_v1(&profile, &scope, &list, &policy, &[]),
            Ok(root_0)
        );
    }

    #[test]
    fn the_corpus_fold_rejects_every_noncanonical_corpus() {
        let profile = ProofProfileIdV1::V1;
        let scope = BallotScopeV1::new([0x44; 64]);
        let digest = Digest512::new([0; 64]);
        let fold = |entries: &[AnonymousBallotCorpusEntryV1]| {
            corpus_root_v1(&profile, &scope, &digest, &digest, entries)
        };
        let (a, b) = (entry(10, 1, 1), entry(10, 2, 2));
        // Reordered, repeated position, repeated nullifier.
        assert_eq!(
            fold(&[b, a]),
            Err(AnonymousBallotCorpusErrorV1::Order { index: 1 })
        );
        assert_eq!(
            fold(&[a, entry(10, 1, 2)]),
            Err(AnonymousBallotCorpusErrorV1::Order { index: 1 })
        );
        assert_eq!(
            fold(&[a, entry(10, 2, 1)]),
            Err(AnonymousBallotCorpusErrorV1::DuplicateNullifier { index: 1 })
        );
        let mut foreign = b;
        foreign.scope = BallotScopeV1::new([0x45; 64]);
        assert_eq!(
            fold(&[a, foreign]),
            Err(AnonymousBallotCorpusErrorV1::ForeignScope { index: 1 })
        );
        let mut foreign = b;
        foreign.profile_id = ProofProfileIdV1::new([0; 64]);
        assert_eq!(
            fold(&[a, foreign]),
            Err(AnonymousBallotCorpusErrorV1::ForeignProfile { index: 1 })
        );
        let mut zero = a;
        zero.height = 0;
        assert_eq!(fold(&[zero]), Err(AnonymousBallotCorpusErrorV1::ZeroHeight));
        let many: Vec<_> = (0..=1_000_u32)
            .map(|index| {
                let mut entry = a;
                entry.input_index = index;
                entry
            })
            .collect();
        assert_eq!(
            fold(&many),
            Err(AnonymousBallotCorpusErrorV1::TooManyEntries { count: 1_001 })
        );
    }

    fn pairs(count: u8) -> Vec<SealedRegistrationPairV1> {
        // Assignment order is the reverse of commitment order, to exercise sorting.
        (0..count)
            .map(|index| SealedRegistrationPairV1 {
                assignment_id: assignment(count - index),
                commitment: commitment(u16::from(index)),
            })
            .collect()
    }

    #[test]
    fn the_registration_mapping_digest_sorts_by_assignment_and_frames_the_pairs() {
        let list = sealed_list(4);
        let list_digest = Digest512::new([0x99; 64]);
        let given = pairs(4);
        let mut sorted = given.clone();
        sorted.sort_by_key(|pair| pair.assignment_id);
        let expected = sha3(
            &frame_bytes(
                b"PARL/REGMAP/v1",
                &[
                    list.profile_id.as_bytes(),
                    list.body_context_digest.as_bytes(),
                    list_digest.as_bytes(),
                    &4_u16.to_le_bytes(),
                    &enc(&sorted).expect("enc"),
                ],
            )
            .expect("frame"),
        );
        assert_eq!(
            registration_mapping_digest_v1(&list, &list_digest, &given),
            Ok(expected)
        );
        let mut shuffled = given.clone();
        shuffled.rotate_left(1);
        assert_eq!(
            registration_mapping_digest_v1(&list, &list_digest, &shuffled),
            Ok(expected)
        );
        // `Enc(sorted_pairs)` is the frame of the vector type.
        assert_eq!(
            <Vec<SealedRegistrationPairV1> as norito::NoritoSchema>::frame_name(),
            "alloc::vec::Vec<iroha_data_model::governance::anonymous_ballot::SealedRegistrationPairV1>"
        );
    }

    #[test]
    fn the_registration_mapping_must_be_exactly_the_sealed_list() {
        let list = sealed_list(4);
        let digest = Digest512::new([0x99; 64]);
        let mut repeated = pairs(4);
        repeated[1].assignment_id = repeated[0].assignment_id;
        assert_eq!(
            registration_mapping_digest_v1(&list, &digest, &repeated),
            Err(BallotContextErrorV1::DuplicateAssignment)
        );
        assert_eq!(
            registration_mapping_digest_v1(&list, &digest, &pairs(3)),
            Err(BallotContextErrorV1::MappingSize { pairs: 3, seats: 4 })
        );
        let mut foreign = pairs(4);
        foreign[2].commitment = CredentialCommitmentV1::new([0xfe; 128]);
        assert_eq!(
            registration_mapping_digest_v1(&list, &digest, &foreign),
            Err(BallotContextErrorV1::MappingCommitments)
        );
        let mut doubled = pairs(4);
        doubled[2].commitment = doubled[1].commitment;
        assert_eq!(
            registration_mapping_digest_v1(&list, &digest, &doubled),
            Err(BallotContextErrorV1::MappingCommitments)
        );
    }

    fn roster(
        count: u8,
        binding: Option<AnonymousRosterBindingV1>,
    ) -> AnonymousParliamentRosterRootPreimageV1 {
        let member = account();
        AnonymousParliamentRosterRootPreimageV1 {
            election_attempt_id: BodyElectionAttemptId::new([0x22; 32]),
            assignments: (1..=count)
                .map(|tag| ParliamentSeatAssignmentV1 {
                    assignment_id: assignment(tag),
                    member: member.clone(),
                })
                .collect(),
            anonymous_ballot: binding,
        }
    }

    #[test]
    fn the_roster_root_frames_the_extended_preimage() {
        let binding = AnonymousRosterBindingV1 {
            list_digest: Digest512::new([0x99; 64]),
            seats: 3,
            profile_id: ProofProfileIdV1::V1,
        };
        let binding_preimage = roster(3, Some(binding));
        let root = anonymous_roster_root_v1(&binding_preimage).expect("root");
        assert_eq!(
            root,
            sha3(
                &frame_bytes(b"PARL/ROSTER/v1", &[&enc(&binding_preimage).expect("enc")])
                    .expect("frame")
            )
        );
        // Public-finding bodies have no binding, and the binding moves the root.
        let public = roster(3, None);
        assert_ne!(anonymous_roster_root_v1(&public).expect("root"), root);
        let mut other = binding;
        other.list_digest = Digest512::new([0x98; 64]);
        assert_ne!(
            anonymous_roster_root_v1(&roster(3, Some(other))).expect("root"),
            root
        );
        // An invalid preimage has no root.
        assert!(anonymous_roster_root_v1(&roster(4, Some(binding))).is_err());
    }

    #[test]
    fn the_result_root_frames_the_closure_record() {
        let record = closure(9, 6, 2, 1);
        assert_eq!(
            result_root_v1(&record),
            Ok(sha3(
                &frame_bytes(b"PARL/RESULT/v1", &[&enc(&record).expect("enc")]).expect("frame")
            ))
        );
        let mut changed = record;
        changed.abstain += 1;
        assert_ne!(result_root_v1(&changed), result_root_v1(&record));
    }

    #[test]
    fn stamp_digests_follow_their_formulas_and_count_leading_zeros() {
        let envelope = envelope(BallotChoiceV1::Aye, 7);
        let authorization = envelope.authorization();
        let context = context();
        let payload = stamp_payload_digest_v1(&authorization, &context).expect("payload");
        assert_eq!(
            payload,
            sha3(
                &frame_bytes(
                    b"PARL/STAMP-PAYLOAD/v1",
                    &[
                        &enc(&authorization).expect("enc"),
                        &enc(&context).expect("enc")
                    ]
                )
                .expect("frame")
            )
        );
        let nonce = AdmissionNonceV1::new([3; 32]);
        let work = stamp_work_digest_v1(&payload, &nonce).expect("work");
        assert_eq!(
            work,
            sha3(
                &frame_bytes(b"PARL/STAMP-WORK/v1", &[payload.as_bytes(), &[3; 32]])
                    .expect("frame")
            )
        );
        // Leading zero bits, most significant first from byte zero.
        let mut bytes = [0xff_u8; 64];
        assert_eq!(leading_zero_bits_v1(&Digest512::new(bytes)), 0);
        bytes[0] = 0x00;
        bytes[1] = 0x00;
        bytes[2] = 0x00;
        bytes[3] = 0x0f;
        assert_eq!(leading_zero_bits_v1(&Digest512::new(bytes)), 28);
        assert!(stamp_meets_difficulty_v1(&Digest512::new(bytes), 28));
        assert!(!stamp_meets_difficulty_v1(&Digest512::new(bytes), 29));
        bytes[3] = 0x08;
        assert_eq!(leading_zero_bits_v1(&Digest512::new(bytes)), 28);
        bytes[3] = 0x07;
        assert_eq!(leading_zero_bits_v1(&Digest512::new(bytes)), 29);
        assert_eq!(leading_zero_bits_v1(&Digest512::new([0; 64])), 512);
        let mut low = [0_u8; 64];
        low[63] = 1;
        assert_eq!(leading_zero_bits_v1(&Digest512::new(low)), 511);
        // A tiny difficulty is met by some nonce; the stamp covers the proof bytes.
        let mut easy = context.clone();
        easy.policy.binding.stamp_difficulty_bits = 4;
        let nonce = (0_u8..=255)
            .map(|byte| AdmissionNonceV1::new([byte; 32]))
            .find(|nonce| verify_stamp_v1(&authorization, &easy, nonce).expect("stamp"))
            .expect("a nonce meets four bits");
        assert!(stamp_meets_difficulty_v1(
            &stamp_work_digest_v1(
                &stamp_payload_digest_v1(&authorization, &easy).expect("payload"),
                &nonce
            )
            .expect("work"),
            4
        ));
        let mut altered = authorization.clone();
        let mut proof = altered.proof.clone().into_bytes();
        proof[0] ^= 1;
        altered.proof =
            crate::governance::anonymous_ballot::BallotProofBytesV1::new(proof).expect("exact");
        assert_ne!(
            stamp_payload_digest_v1(&altered, &easy),
            stamp_payload_digest_v1(&authorization, &easy)
        );
    }

    #[test]
    fn the_encoded_context_constructor_enforces_its_byte_cap() {
        let mut oversized = context();
        // The public constructor must enforce its own bound even when its caller
        // has not yet checked the roster or policy. The caller owns this vector.
        oversized.commitments = vec![commitment(1); 1_261];
        let actual = norito::canonical_frame_len(&oversized).expect("count frame");
        assert!(actual > BALLOT_CONTEXT_MAX_BYTES_V1);
        let expected = AnonymousBallotCodecErrorV1::TooLarge {
            kind: "authenticated ballot context",
            actual,
            max: BALLOT_CONTEXT_MAX_BYTES_V1,
        };
        assert_eq!(
            EncodedBallotContextV1::new(&oversized),
            Err(expected.clone())
        );
        assert_eq!(
            stamp_payload_digest_v1(
                &envelope(BallotChoiceV1::Aye, 1).authorization(),
                &oversized
            ),
            Err(expected)
        );

        let ordinary = context();
        assert_eq!(
            EncodedBallotContextV1::new(&ordinary)
                .expect("bounded context")
                .as_bytes(),
            enc(&ordinary).expect("same canonical bytes")
        );
    }

    #[test]
    fn the_encoded_context_form_decides_exactly_as_the_simple_form() {
        let authorization = envelope(BallotChoiceV1::Nay, 9).authorization();
        let mut context = context();
        context.policy.binding.stamp_difficulty_bits = 3;
        let encoded = EncodedBallotContextV1::new(&context).expect("encoded");
        assert_eq!(encoded.as_bytes(), &enc(&context).expect("enc")[..]);
        assert_eq!(encoded.stamp_difficulty_bits(), 3);
        assert!(format!("{encoded:?}").contains("stamp_difficulty_bits: 3"));
        assert_eq!(
            stamp_payload_digest_encoded_v1(&authorization, &encoded),
            stamp_payload_digest_v1(&authorization, &context)
        );
        // Both forms agree on every nonce, accepted or not.
        let mut accepted = 0;
        for byte in 0_u8..=255 {
            let nonce = AdmissionNonceV1::new([byte; 32]);
            let simple = verify_stamp_v1(&authorization, &context, &nonce).expect("stamp");
            assert_eq!(
                verify_stamp_encoded_v1(&authorization, &encoded, &nonce),
                Ok(simple)
            );
            accepted += usize::from(simple);
        }
        assert!(accepted > 0 && accepted < 256, "{accepted}");
        // Another context encodes another payload.
        let mut other = context;
        other.policy_hash = Digest512::new([0xab; 64]);
        assert_ne!(
            EncodedBallotContextV1::new(&other).expect("encoded"),
            encoded
        );
        assert_ne!(
            stamp_payload_digest_v1(&authorization, &other),
            stamp_payload_digest_encoded_v1(&authorization, &encoded)
        );
    }

    #[test]
    fn the_authority_binding_and_proposal_digest_frame_their_typed_values() {
        let account = account();
        let binding = authority_binding_v1(&account).expect("binding");
        assert_eq!(
            binding.as_bytes(),
            sha3(
                &frame_bytes(b"PARL/AUTHORITY/v1", &[&enc(&account).expect("enc")]).expect("frame")
            )
            .as_bytes()
        );
        let proposal = proposal();
        assert_eq!(
            proposal_digest_v1(&proposal),
            Ok(sha3(
                &frame_bytes(b"PARL/PROPOSAL/v1", &[&enc(&proposal).expect("enc")]).expect("frame")
            ))
        );
    }

    #[test]
    fn the_frame_tags_are_distinct_ascii() {
        let tags = [
            ENVELOPE_TAG_V1,
            CORPUS_ENTRY_TAG_V1,
            CORPUS_EMPTY_TAG_V1,
            CORPUS_APPEND_TAG_V1,
            REGISTRATION_MAPPING_TAG_V1,
            ROSTER_TAG_V1,
            RESULT_TAG_V1,
            STAMP_PAYLOAD_TAG_V1,
            STAMP_WORK_TAG_V1,
            AUTHORITY_TAG_V1,
            PROPOSAL_TAG_V1,
            QUALIFICATION_TAG_V1,
        ];
        assert_eq!(tags.iter().collect::<BTreeSet<_>>().len(), tags.len());
        assert!(
            tags.iter()
                .all(|tag| tag.is_ascii() && tag.starts_with(b"PARL/"))
        );
    }
}
