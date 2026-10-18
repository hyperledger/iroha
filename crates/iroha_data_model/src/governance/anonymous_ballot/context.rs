//! Body context, credential registration, the sealed list and its publication bytes, the
//! registration mapping, the extended roster preimage and the authenticated ballot
//! context (design §3.1–§3.5, integration decisions 3, 4 and 7).

use iroha_schema::IntoSchema;
use norito::{
    codec::{Decode, Encode},
    json::{self, JsonDeserialize, Parser},
};

use super::{
    BALLOT_CONTEXT_MAX_BYTES_V1, CredentialCommitmentV1, Digest512, FrozenBallotPolicyErrorV1,
    FrozenBallotPolicyV1, MAX_SEALED_SEATS_V1, MIN_SEALED_SEATS_V1, ProofProfileIdV1,
    RegistrationAuthorizationV1, RegistrationProofBytesV1,
    framing::{AnonymousBallotCodecErrorV1, decode_enc_bounded, enc_bounded},
};
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, NetworkId,
    governance::types::{
        AssignmentId, BodyElectionAttemptId, GovernanceAttemptId, ParliamentBody,
        ParliamentSeatAssignmentV1,
    },
};

/// Why a body context, list, mapping, roster preimage or authenticated context is not
/// canonical.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BallotContextErrorV1 {
    /// The body is not a binding jury (Policy or Confirmation).
    #[error("{body:?} is not a binding jury")]
    NotBindingBody {
        /// The body supplied.
        body: ParliamentBody,
    },
    /// A sealed list has a number of entries outside `3..=1000`.
    #[error("a sealed list has 3 to 1000 entries, got {actual}")]
    ListSize {
        /// Number of entries.
        actual: usize,
    },
    /// The declared seat count is not the number of entries.
    #[error("{seats} sealed seats do not match {entries} entries")]
    SeatCount {
        /// Declared seats `S`.
        seats: u16,
        /// Number of entries.
        entries: usize,
    },
    /// An entry is not strictly greater than its predecessor (out of order or repeated).
    #[error("sealed-list entry {index} is not strictly greater than the entry before it")]
    ListOrder {
        /// Index of the offending entry.
        index: usize,
    },
    /// The proof profile is not [`ProofProfileIdV1::V1`].
    #[error("the proof profile is not the V1 profile")]
    UnknownProfile,
    /// A roster has no assignment.
    #[error("a sealed roster has at least one assignment")]
    EmptyRoster,
    /// An assignment is not strictly after its predecessor in raw identifier order.
    #[error("roster assignment {index} is not strictly after the one before it")]
    RosterOrder {
        /// Index of the offending assignment.
        index: usize,
    },
    /// The anonymous binding's seat count is not the number of sealed assignments.
    #[error("the anonymous binding names {seats} seats but the roster has {assignments}")]
    RosterSeats {
        /// Seats `S` of the binding.
        seats: u16,
        /// Sealed assignments.
        assignments: usize,
    },
    /// Two registration pairs name the same assignment.
    #[error("two registration pairs name the same assignment")]
    DuplicateAssignment,
    /// The mapping does not have one pair per sealed seat.
    #[error("{pairs} registration pairs do not match {seats} sealed seats")]
    MappingSize {
        /// Number of pairs.
        pairs: usize,
        /// Sealed seats `S`.
        seats: u16,
    },
    /// The pairs' commitments are not exactly the sealed list's commitments.
    #[error("the registered commitments are not exactly the sealed list")]
    MappingCommitments,
    /// Two fields of an authenticated context disagree.
    #[error("the authenticated context's {field} disagrees with its frozen policy")]
    ContextMismatch {
        /// The disagreeing field.
        field: &'static str,
    },
    /// The frozen policy is invalid.
    #[error(transparent)]
    Policy(#[from] FrozenBallotPolicyErrorV1),
    /// An encoding could not be produced, read or bounded.
    #[error(transparent)]
    Codec(#[from] AnonymousBallotCodecErrorV1),
}

/// Whether `body` is a binding jury, the only bodies that cast anonymous ballots.
#[must_use]
pub fn is_binding_body(body: ParliamentBody) -> bool {
    matches!(
        body,
        ParliamentBody::PolicyJury | ParliamentBody::ConfirmationJury
    )
}

/// Check `S` and the ordered commitments `L`: `3 ≤ S ≤ 1000` entries, `S` matching the
/// entries, strictly increasing unsigned bytewise (hence no duplicates).
fn validate_commitments(
    seats: u16,
    commitments: &[CredentialCommitmentV1],
) -> Result<(), BallotContextErrorV1> {
    let range = usize::from(MIN_SEALED_SEATS_V1)..=usize::from(MAX_SEALED_SEATS_V1);
    if !range.contains(&commitments.len()) {
        return Err(BallotContextErrorV1::ListSize {
            actual: commitments.len(),
        });
    }
    if usize::from(seats) != commitments.len() {
        return Err(BallotContextErrorV1::SeatCount {
            seats,
            entries: commitments.len(),
        });
    }
    if let Some(index) = commitments.windows(2).position(|pair| pair[0] >= pair[1]) {
        return Err(BallotContextErrorV1::ListOrder { index: index + 1 });
    }
    Ok(())
}

/// The authoritative body context `(network_id, governance_attempt_id,
/// election_attempt_id, body_role)` whose `Enc` is the profile input `Enc(body_context)`
/// (design §3.1, integration decision 7). It exists when seats are accepted; it excludes
/// the body instance identifier, which is derived at seal.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::BallotBodyContextV1")]
pub struct BallotBodyContextV1 {
    /// Genesis-bound network identity.
    pub network_id: NetworkId,
    /// Governance attempt the body serves.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Body-election attempt whose seats register credentials.
    pub election_attempt_id: BodyElectionAttemptId,
    /// Binding jury role: Policy or Confirmation.
    pub body_role: ParliamentBody,
}

impl BallotBodyContextV1 {
    /// Check that the role is a binding jury.
    ///
    /// # Errors
    /// [`BallotContextErrorV1::NotBindingBody`] for any other body.
    pub fn validate(&self) -> Result<(), BallotContextErrorV1> {
        if is_binding_body(self.body_role) {
            Ok(())
        } else {
            Err(BallotContextErrorV1::NotBindingBody {
                body: self.body_role,
            })
        }
    }
}

/// The credential registration carried by a binding seat's acceptance (design §3.2): the
/// commitment `C`, the authorization value `auth` and the registration proof `pi_reg`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::CredentialRegistrationV1")]
pub struct CredentialRegistrationV1 {
    /// Credential commitment `C`.
    pub commitment: CredentialCommitmentV1,
    /// Registration authorization value `auth`.
    pub authorization: RegistrationAuthorizationV1,
    /// Registration proof `pi_reg`, exactly 160,148 bytes.
    pub proof: RegistrationProofBytesV1,
}

/// The canonical sealed credential list `SealedCredentialListV1 { profile_id,
/// body_context_digest, S, commitments[S] }` (design §3.3).
///
/// Every construction and decode checks `3 ≤ S ≤ 1000`, `S` equal to the number of
/// commitments, strictly increasing unsigned bytewise order (so no duplicates), the V1
/// profile and an encoded frame of at most [`BALLOT_CONTEXT_MAX_BYTES_V1`] bytes. Entries
/// are never sorted except by [`Self::from_unsorted`]. The list digest
/// `R = SHA3-512(Frame("PARL/LIST/v1"; P16, B, u16_le(S), concat(L)))` is the proof
/// crate's.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    norito::NoritoSchema,
)]
#[norito(validate = "Self::checked")]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::SealedCredentialListV1")]
pub struct SealedCredentialListV1 {
    /// Proof profile of the list; must be [`ProofProfileIdV1::V1`].
    pub profile_id: ProofProfileIdV1,
    /// Body-context digest `B` of the sealed body.
    pub body_context_digest: Digest512,
    /// Sealed seats `S`, the number of commitments.
    pub seats: u16,
    /// The sealed commitments `L` in strictly increasing bytewise order.
    pub commitments: Vec<CredentialCommitmentV1>,
}

impl SealedCredentialListV1 {
    /// The list of exactly `commitments`, in the order given; `S` is their number.
    ///
    /// # Errors
    /// As [`Self::validate`]; entries are never sorted or deduplicated here.
    pub fn new(
        profile_id: ProofProfileIdV1,
        body_context_digest: Digest512,
        commitments: Vec<CredentialCommitmentV1>,
    ) -> Result<Self, BallotContextErrorV1> {
        let seats =
            u16::try_from(commitments.len()).map_err(|_| BallotContextErrorV1::ListSize {
                actual: commitments.len(),
            })?;
        let list = Self {
            profile_id,
            body_context_digest,
            seats,
            commitments,
        };
        list.validate()?;
        Ok(list)
    }

    /// The list of the sealed commitments `commitments`, sorted. For the sealer.
    ///
    /// # Errors
    /// As [`Self::new`]; a duplicate commitment is [`BallotContextErrorV1::ListOrder`].
    pub fn from_unsorted(
        profile_id: ProofProfileIdV1,
        body_context_digest: Digest512,
        mut commitments: Vec<CredentialCommitmentV1>,
    ) -> Result<Self, BallotContextErrorV1> {
        commitments.sort_unstable();
        Self::new(profile_id, body_context_digest, commitments)
    }

    /// Check the profile, the size, the seat count, the strict order and the encoded size.
    ///
    /// # Errors
    /// The first violated rule as a [`BallotContextErrorV1`].
    pub fn validate(&self) -> Result<(), BallotContextErrorV1> {
        if !self.profile_id.is_v1() {
            return Err(BallotContextErrorV1::UnknownProfile);
        }
        validate_commitments(self.seats, &self.commitments)?;
        let actual = norito::canonical_frame_len(self)
            .map_err(|error| AnonymousBallotCodecErrorV1::codec(&error))?;
        if actual > BALLOT_CONTEXT_MAX_BYTES_V1 {
            return Err(AnonymousBallotCodecErrorV1::TooLarge {
                kind: SealedCredentialListBytesV1::KIND,
                actual,
                max: BALLOT_CONTEXT_MAX_BYTES_V1,
            }
            .into());
        }
        Ok(())
    }

    /// Norito decode hook: no invalid list survives a decode.
    fn checked(self) -> Result<Self, norito::Error> {
        self.validate()
            .map_err(|error| norito::Error::Message(error.to_string()))?;
        Ok(self)
    }
}

impl JsonDeserialize for SealedCredentialListV1 {
    fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, json::Error> {
        #[derive(DeriveJsonDeserialize)]
        #[norito(deny_unknown_fields, no_fast_from_json)]
        struct Fields {
            profile_id: ProofProfileIdV1,
            body_context_digest: Digest512,
            seats: u16,
            commitments: Vec<CredentialCommitmentV1>,
        }
        let fields = <Fields as JsonDeserialize>::json_deserialize(parser)?;
        let list = Self {
            profile_id: fields.profile_id,
            body_context_digest: fields.body_context_digest,
            seats: fields.seats,
            commitments: fields.commitments,
        };
        list.validate()
            .map_err(|error| json::Error::Message(error.to_string()))?;
        Ok(list)
    }
}

/// The exact canonical `Enc` frame of a [`SealedCredentialListV1`] as published in the
/// seal's committed block-start output (integration decision 3), at most
/// [`BALLOT_CONTEXT_MAX_BYTES_V1`] bytes.
///
/// Construction and every decode check that the bytes are one canonical frame of a valid
/// list. Norito encodes it as a byte string; JSON as `{"bytes": "<base64>"}`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    norito::NoritoSchema,
)]
#[norito(validate = "Self::checked")]
#[norito_schema(
    name = "iroha_data_model::governance::anonymous_ballot::SealedCredentialListBytesV1"
)]
pub struct SealedCredentialListBytesV1 {
    /// The exact canonical frame of the list.
    #[norito(json = "crate::json_helpers::base64_vec")]
    bytes: Vec<u8>,
}

impl SealedCredentialListBytesV1 {
    /// Kind named in size errors.
    const KIND: &'static str = "sealed credential list";

    /// Largest published list frame.
    pub const MAX_BYTES: usize = BALLOT_CONTEXT_MAX_BYTES_V1;

    /// The canonical frame of `list`.
    ///
    /// # Errors
    /// [`BallotContextErrorV1`] for an invalid list or a codec failure.
    pub fn from_list(list: &SealedCredentialListV1) -> Result<Self, BallotContextErrorV1> {
        list.validate()?;
        let bytes = enc_bounded(list, Self::KIND, Self::MAX_BYTES)?;
        Ok(Self { bytes })
    }

    /// Accept `bytes` only if they are exactly one canonical frame of a valid list.
    ///
    /// # Errors
    /// As [`Self::decode_list`].
    pub fn from_canonical_bytes(bytes: Vec<u8>) -> Result<Self, BallotContextErrorV1> {
        Self::decode_bytes(&bytes)?;
        Ok(Self { bytes })
    }

    /// The exact canonical frame.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The validated list.
    ///
    /// # Errors
    /// Never for a value obtained through a constructor or a Norito decode; otherwise a
    /// [`BallotContextErrorV1`] for oversize, non-canonical or invalid list bytes.
    pub fn decode_list(&self) -> Result<SealedCredentialListV1, BallotContextErrorV1> {
        Self::decode_bytes(&self.bytes)
    }

    fn decode_bytes(bytes: &[u8]) -> Result<SealedCredentialListV1, BallotContextErrorV1> {
        let list: SealedCredentialListV1 = decode_enc_bounded(bytes, Self::KIND, Self::MAX_BYTES)?;
        list.validate()?;
        Ok(list)
    }

    /// Norito decode hook: the bytes must be one canonical frame of a valid list.
    fn checked(self) -> Result<Self, norito::Error> {
        Self::decode_bytes(&self.bytes)
            .map_err(|error| norito::Error::Message(error.to_string()))?;
        Ok(self)
    }
}

impl JsonDeserialize for SealedCredentialListBytesV1 {
    fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, json::Error> {
        #[derive(DeriveJsonDeserialize)]
        #[norito(deny_unknown_fields, no_fast_from_json)]
        struct Fields {
            #[norito(json = "crate::json_helpers::base64_vec")]
            bytes: Vec<u8>,
        }
        let fields = <Fields as JsonDeserialize>::json_deserialize(parser)?;
        Self::from_canonical_bytes(fields.bytes)
            .map_err(|error| json::Error::Message(error.to_string()))
    }
}

/// One sealed `(assignment_id, C)` pair of the registration mapping (design §3.3,
/// integration decision 3).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::SealedRegistrationPairV1")]
pub struct SealedRegistrationPairV1 {
    /// Sealed assignment that registered the commitment.
    pub assignment_id: AssignmentId,
    /// Commitment it registered.
    pub commitment: CredentialCommitmentV1,
}

/// The anonymous-ballot binding of a binding body's roster root: `(R, S, profile_id)`
/// (integration decision 3).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::AnonymousRosterBindingV1")]
pub struct AnonymousRosterBindingV1 {
    /// Sealed-list digest `R`.
    pub list_digest: Digest512,
    /// Sealed seats `S`.
    pub seats: u16,
    /// Proof profile of the list.
    pub profile_id: ProofProfileIdV1,
}

/// The extended roster-root preimage of integration decision 3:
/// `{ election_attempt_id, assignments, anonymous_ballot }`.
///
/// `anonymous_ballot` is mandatory for binding bodies and absent for public-finding
/// bodies. The roster root is `H(Frame("PARL/ROSTER/v1"; Enc(preimage)))`, 64 bytes
/// ([`super::digests::anonymous_roster_root_v1`]).
///
/// TODO: the Core integration replaces the 32-byte `ParliamentRosterRootPreimageV1` and
/// `BodyInstanceId::derive_v1` with this preimage and the 64-byte root directly; this
/// type keeps a distinct name until then, and the replacement must keep this nominal
/// schema identity or recompute every roster root.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::governance::anonymous_ballot::AnonymousParliamentRosterRootPreimageV1"
)]
pub struct AnonymousParliamentRosterRootPreimageV1 {
    /// Election attempt whose roster is sealed.
    pub election_attempt_id: BodyElectionAttemptId,
    /// Sealed assignments in strictly increasing raw assignment-identifier order.
    pub assignments: Vec<ParliamentSeatAssignmentV1>,
    /// `(R, S, profile_id)` of a binding body; `None` for a public-finding body.
    pub anonymous_ballot: Option<AnonymousRosterBindingV1>,
}

impl AnonymousParliamentRosterRootPreimageV1 {
    /// Check a nonempty roster in canonical order and, for a binding body, one sealed
    /// seat per assignment with `3 ≤ S ≤ 1000` and the V1 profile.
    ///
    /// # Errors
    /// The first violated rule as a [`BallotContextErrorV1`].
    pub fn validate(&self) -> Result<(), BallotContextErrorV1> {
        if self.assignments.is_empty() {
            return Err(BallotContextErrorV1::EmptyRoster);
        }
        if let Some(index) = self
            .assignments
            .windows(2)
            .position(|pair| pair[0].assignment_id.as_bytes() >= pair[1].assignment_id.as_bytes())
        {
            return Err(BallotContextErrorV1::RosterOrder { index: index + 1 });
        }
        if let Some(binding) = &self.anonymous_ballot {
            if !binding.profile_id.is_v1() {
                return Err(BallotContextErrorV1::UnknownProfile);
            }
            if !(MIN_SEALED_SEATS_V1..=MAX_SEALED_SEATS_V1).contains(&binding.seats) {
                return Err(BallotContextErrorV1::ListSize {
                    actual: usize::from(binding.seats),
                });
            }
            if usize::from(binding.seats) != self.assignments.len() {
                return Err(BallotContextErrorV1::RosterSeats {
                    seats: binding.seats,
                    assignments: self.assignments.len(),
                });
            }
        }
        Ok(())
    }
}

/// The immutable verification context derived from authenticated state for one
/// scope (integration decision 4), in order: body context, proposal digest, `B`, `R`,
/// `S`, the complete ordered commitments, the profile, the frozen policy snapshot and its
/// hash.
///
/// It excludes `s0` and `closing_ms`, which do not exist when an opening-block ballot can
/// be prepared. Its canonical frame, the copied verifier context, is at most
/// [`BALLOT_CONTEXT_MAX_BYTES_V1`] bytes. [`Self::validate`] checks its structure only:
/// `B`, `R` and `policy_hash` must be recomputed through the proof crate before the
/// context is trusted.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::governance::anonymous_ballot::AuthenticatedBallotContextV1"
)]
pub struct AuthenticatedBallotContextV1 {
    /// Authoritative body context.
    pub body_context: BallotBodyContextV1,
    /// `proposal_digest` of the full canonical proposal.
    pub proposal_digest: Digest512,
    /// Body-context digest `B`.
    pub body_context_digest: Digest512,
    /// Sealed-list digest `R`.
    pub list_digest: Digest512,
    /// Sealed seats `S`.
    pub seats: u16,
    /// The complete sealed list `L`, strictly increasing.
    pub commitments: Vec<CredentialCommitmentV1>,
    /// Proof profile.
    pub profile_id: ProofProfileIdV1,
    /// The body's frozen ballot-policy snapshot.
    pub policy: FrozenBallotPolicyV1,
    /// `policy_hash` of that snapshot.
    pub policy_hash: Digest512,
}

impl AuthenticatedBallotContextV1 {
    /// Kind named in size errors.
    const KIND: &'static str = "authenticated ballot context";

    /// Check the structure, the frozen policy, their agreement and the encoded size.
    ///
    /// # Errors
    /// The first violated rule as a [`BallotContextErrorV1`].
    pub fn validate(&self) -> Result<(), BallotContextErrorV1> {
        self.body_context.validate()?;
        if !self.profile_id.is_v1() {
            return Err(BallotContextErrorV1::UnknownProfile);
        }
        validate_commitments(self.seats, &self.commitments)?;
        self.policy.validate()?;
        if self.policy.body_role != self.body_context.body_role {
            return Err(BallotContextErrorV1::ContextMismatch { field: "body_role" });
        }
        if self.policy.profile_id != self.profile_id {
            return Err(BallotContextErrorV1::ContextMismatch {
                field: "profile_id",
            });
        }
        let actual = norito::canonical_frame_len(self)
            .map_err(|error| AnonymousBallotCodecErrorV1::codec(&error))?;
        if actual > BALLOT_CONTEXT_MAX_BYTES_V1 {
            return Err(AnonymousBallotCodecErrorV1::TooLarge {
                kind: Self::KIND,
                actual,
                max: BALLOT_CONTEXT_MAX_BYTES_V1,
            }
            .into());
        }
        Ok(())
    }

    /// The sealed-list object this context authenticates.
    ///
    /// # Errors
    /// As [`SealedCredentialListV1::new`].
    pub fn sealed_list(&self) -> Result<SealedCredentialListV1, BallotContextErrorV1> {
        let list = SealedCredentialListV1 {
            profile_id: self.profile_id,
            body_context_digest: self.body_context_digest,
            seats: self.seats,
            commitments: self.commitments.clone(),
        };
        list.validate()?;
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use norito::codec::{Decode as _, Encode as _};

    use super::*;
    use crate::governance::anonymous_ballot::{
        framing::{decode_enc, enc},
        test_fixtures::{
            account, assignment, body_context, commitment, commitments, context, policy,
            sealed_list,
        },
    };

    #[test]
    fn body_contexts_are_binding_juries() {
        let context = body_context();
        assert_eq!(context.validate(), Ok(()));
        let mut confirmation = context;
        confirmation.body_role = ParliamentBody::ConfirmationJury;
        assert_eq!(confirmation.validate(), Ok(()));
        let mut public = context;
        public.body_role = ParliamentBody::ReviewPanel;
        assert_eq!(
            public.validate(),
            Err(BallotContextErrorV1::NotBindingBody {
                body: ParliamentBody::ReviewPanel
            })
        );
        assert!(is_binding_body(ParliamentBody::PolicyJury));
        assert!(!is_binding_body(ParliamentBody::OversightCommittee));
        assert_eq!(
            decode_enc::<BallotBodyContextV1>(&enc(&context).expect("enc")),
            Ok(context)
        );
        let json = norito::json::to_json(&context).expect("json");
        assert_eq!(
            norito::json::from_str::<BallotBodyContextV1>(&json).expect("json"),
            context
        );
    }

    #[test]
    fn sealed_lists_enforce_size_order_profile_and_seats() {
        for count in [0_u16, 1, 2, 1_001] {
            assert_eq!(
                SealedCredentialListV1::new(
                    ProofProfileIdV1::V1,
                    Digest512::new([0; 64]),
                    commitments(count)
                ),
                Err(BallotContextErrorV1::ListSize {
                    actual: usize::from(count)
                })
            );
        }
        for count in [3_u16, 4, 999, 1_000] {
            let list = sealed_list(count);
            assert_eq!(list.seats, count);
            assert_eq!(list.validate(), Ok(()));
        }
        // Out of order, repeated, wrong seat count, foreign profile.
        let mut swapped = commitments(5);
        swapped.swap(1, 2);
        assert_eq!(
            SealedCredentialListV1::new(
                ProofProfileIdV1::V1,
                Digest512::new([0; 64]),
                swapped.clone()
            ),
            Err(BallotContextErrorV1::ListOrder { index: 2 })
        );
        let sorted = SealedCredentialListV1::from_unsorted(
            ProofProfileIdV1::V1,
            Digest512::new([0; 64]),
            swapped,
        )
        .expect("sortable");
        assert_eq!(sorted.commitments, commitments(5));
        let mut repeated = commitments(5);
        repeated[4] = repeated[3];
        assert_eq!(
            SealedCredentialListV1::from_unsorted(
                ProofProfileIdV1::V1,
                Digest512::new([0; 64]),
                repeated
            ),
            Err(BallotContextErrorV1::ListOrder { index: 4 })
        );
        let mut wrong_seats = sealed_list(4);
        wrong_seats.seats = 5;
        assert_eq!(
            wrong_seats.validate(),
            Err(BallotContextErrorV1::SeatCount {
                seats: 5,
                entries: 4
            })
        );
        let mut foreign = sealed_list(4);
        foreign.profile_id = ProofProfileIdV1::new([0; 64]);
        assert_eq!(
            foreign.validate(),
            Err(BallotContextErrorV1::UnknownProfile)
        );
        // A difference in the last byte only decides the order.
        let mut low = commitment(1).into_bytes();
        let mut high = low;
        low[127] = 0;
        high[127] = 1;
        assert!(
            SealedCredentialListV1::new(
                ProofProfileIdV1::V1,
                Digest512::new([0; 64]),
                vec![
                    commitment(0),
                    CredentialCommitmentV1::new(low),
                    CredentialCommitmentV1::new(high)
                ]
            )
            .is_ok()
        );
    }

    #[test]
    fn the_largest_sealed_list_fits_the_context_cap_with_raw_commitments() {
        let list = sealed_list(1_000);
        let bytes = enc(&list).expect("enc");
        // 40-byte header, two 65-byte digests, a 3-byte seat field, and the vector:
        // a 3-byte field prefix, an 8-byte count and 130 bytes per commitment.
        assert_eq!(bytes.len(), 40 + 65 + 65 + 3 + 3 + 8 + 1_000 * 130);
        assert!(bytes.len() <= BALLOT_CONTEXT_MAX_BYTES_V1);
        assert_eq!(
            decode_enc::<SealedCredentialListV1>(&bytes),
            Ok(list.clone())
        );
        // Element-framed `[u8; 128]` would have needed 256 bytes per commitment.
        const { assert!(40 + 1_000 * (2 + 256) > BALLOT_CONTEXT_MAX_BYTES_V1) };
    }

    #[test]
    fn decoding_refuses_an_invalid_list() {
        let list = sealed_list(5);
        let mut invalid = list.clone();
        invalid.commitments.swap(0, 1);
        // The derived encoder does not validate, so an invalid list can be encoded...
        let bytes = invalid.encode();
        // ...but never decoded, bare, framed or from JSON.
        assert!(SealedCredentialListV1::decode(&mut &bytes[..]).is_err());
        let framed = norito::encode_canonical(&invalid).expect("frame");
        assert!(decode_enc::<SealedCredentialListV1>(&framed).is_err());
        let json = norito::json::to_json(&invalid).expect("json");
        assert!(norito::json::from_str::<SealedCredentialListV1>(&json).is_err());
        let json = norito::json::to_json(&list).expect("json");
        assert_eq!(
            norito::json::from_str::<SealedCredentialListV1>(&json).expect("json"),
            list
        );
        assert_eq!(
            SealedCredentialListV1::decode(&mut &list.encode()[..]).expect("decode"),
            list
        );
    }

    #[test]
    fn published_list_bytes_are_exactly_the_canonical_frame() {
        let list = sealed_list(7);
        let published = SealedCredentialListBytesV1::from_list(&list).expect("publish");
        assert_eq!(published.as_bytes(), &enc(&list).expect("enc")[..]);
        assert_eq!(published.decode_list(), Ok(list.clone()));
        assert_eq!(
            SealedCredentialListBytesV1::from_canonical_bytes(published.as_bytes().to_vec()),
            Ok(published.clone())
        );
        assert_eq!(SealedCredentialListBytesV1::MAX_BYTES, 163_840);
        let encoded = published.encode();
        assert_eq!(
            SealedCredentialListBytesV1::decode(&mut &encoded[..]).expect("decode"),
            published
        );
        let json = norito::json::to_json(&published).expect("json");
        assert_eq!(
            norito::json::from_str::<SealedCredentialListBytesV1>(&json).expect("json"),
            published
        );
        // Non-canonical, trailing and invalid-list bytes are refused everywhere.
        let mut trailing = published.as_bytes().to_vec();
        trailing.push(0);
        assert!(SealedCredentialListBytesV1::from_canonical_bytes(trailing.clone()).is_err());
        let forged = SealedCredentialListBytesV1 { bytes: trailing };
        assert!(SealedCredentialListBytesV1::decode(&mut &forged.encode()[..]).is_err());
        let forged_json = norito::json::to_json(&forged).expect("json");
        assert!(norito::json::from_str::<SealedCredentialListBytesV1>(&forged_json).is_err());
        let mut invalid = list;
        invalid.commitments.swap(0, 1);
        assert!(SealedCredentialListBytesV1::from_list(&invalid).is_err());
        let invalid_frame = norito::encode_canonical(&invalid).expect("frame");
        assert!(SealedCredentialListBytesV1::from_canonical_bytes(invalid_frame).is_err());
    }

    /// A record whose validated list fields are followed by more fields, so a decode hook
    /// that disturbed the enclosing decode would be caught.
    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    struct ListCarrier {
        list: SealedCredentialListV1,
        published: SealedCredentialListBytesV1,
        tail: u64,
    }

    #[test]
    fn validating_decode_hooks_leave_the_enclosing_decode_intact() {
        let carriers: Vec<_> = [3_u16, 5, 1_000]
            .into_iter()
            .map(|count| ListCarrier {
                list: sealed_list(count),
                published: SealedCredentialListBytesV1::from_list(&sealed_list(count))
                    .expect("publish"),
                tail: (u64::from(count) << 40) | 0x1234,
            })
            .collect();
        let bytes = carriers.encode();
        assert_eq!(
            Vec::<ListCarrier>::decode(&mut &bytes[..]).expect("decode"),
            carriers
        );
    }

    #[test]
    fn registrations_pairs_and_bindings_round_trip() {
        let registration = CredentialRegistrationV1 {
            commitment: commitment(9),
            authorization: RegistrationAuthorizationV1::new([0x19; 64]),
            proof: RegistrationProofBytesV1::new(vec![0x29; RegistrationProofBytesV1::LENGTH])
                .expect("exact"),
        };
        assert_eq!(
            decode_enc::<CredentialRegistrationV1>(&enc(&registration).expect("enc")),
            Ok(registration.clone())
        );
        let json = norito::json::to_json(&registration).expect("json");
        assert_eq!(
            norito::json::from_str::<CredentialRegistrationV1>(&json).expect("json"),
            registration
        );
        let pair = SealedRegistrationPairV1 {
            assignment_id: assignment(4),
            commitment: commitment(4),
        };
        assert_eq!(
            decode_enc::<SealedRegistrationPairV1>(&enc(&pair).expect("enc")),
            Ok(pair)
        );
        let json = norito::json::to_json(&pair).expect("json");
        assert_eq!(
            norito::json::from_str::<SealedRegistrationPairV1>(&json).expect("json"),
            pair
        );
        let binding = AnonymousRosterBindingV1 {
            list_digest: Digest512::new([0x99; 64]),
            seats: 3,
            profile_id: ProofProfileIdV1::V1,
        };
        assert_eq!(
            decode_enc::<AnonymousRosterBindingV1>(&enc(&binding).expect("enc")),
            Ok(binding)
        );
        let json = norito::json::to_json(&binding).expect("json");
        assert_eq!(
            norito::json::from_str::<AnonymousRosterBindingV1>(&json).expect("json"),
            binding
        );
    }

    fn roster(
        tags: &[u8],
        binding: Option<AnonymousRosterBindingV1>,
    ) -> AnonymousParliamentRosterRootPreimageV1 {
        AnonymousParliamentRosterRootPreimageV1 {
            election_attempt_id: BodyElectionAttemptId::new([0x22; 32]),
            assignments: tags
                .iter()
                .map(|tag| ParliamentSeatAssignmentV1 {
                    assignment_id: assignment(*tag),
                    member: account(),
                })
                .collect(),
            anonymous_ballot: binding,
        }
    }

    #[test]
    fn roster_preimages_are_canonical_and_bind_one_seat_per_assignment() {
        let binding = AnonymousRosterBindingV1 {
            list_digest: Digest512::new([0x99; 64]),
            seats: 3,
            profile_id: ProofProfileIdV1::V1,
        };
        let preimage = roster(&[1, 2, 3], Some(binding));
        assert_eq!(preimage.validate(), Ok(()));
        assert_eq!(roster(&[1], None).validate(), Ok(()));
        assert_eq!(
            roster(&[], None).validate(),
            Err(BallotContextErrorV1::EmptyRoster)
        );
        assert_eq!(
            roster(&[1, 3, 2], Some(binding)).validate(),
            Err(BallotContextErrorV1::RosterOrder { index: 2 })
        );
        assert_eq!(
            roster(&[1, 1, 2], Some(binding)).validate(),
            Err(BallotContextErrorV1::RosterOrder { index: 1 })
        );
        assert_eq!(
            roster(&[1, 2, 3, 4], Some(binding)).validate(),
            Err(BallotContextErrorV1::RosterSeats {
                seats: 3,
                assignments: 4
            })
        );
        let mut small = binding;
        small.seats = 2;
        assert_eq!(
            roster(&[1, 2], Some(small)).validate(),
            Err(BallotContextErrorV1::ListSize { actual: 2 })
        );
        let mut foreign = binding;
        foreign.profile_id = ProofProfileIdV1::new([0; 64]);
        assert_eq!(
            roster(&[1, 2, 3], Some(foreign)).validate(),
            Err(BallotContextErrorV1::UnknownProfile)
        );
        assert_eq!(
            decode_enc::<AnonymousParliamentRosterRootPreimageV1>(&enc(&preimage).expect("enc")),
            Ok(preimage.clone())
        );
        let json = norito::json::to_json(&preimage).expect("json");
        assert_eq!(
            norito::json::from_str::<AnonymousParliamentRosterRootPreimageV1>(&json).expect("json"),
            preimage
        );
    }

    #[test]
    fn authenticated_contexts_validate_and_fit_the_cap_at_one_thousand_seats() {
        let context = context();
        assert_eq!(context.validate(), Ok(()));
        assert_eq!(
            context.sealed_list().expect("list").commitments,
            context.commitments
        );
        assert_eq!(
            decode_enc::<AuthenticatedBallotContextV1>(&enc(&context).expect("enc")),
            Ok(context.clone())
        );
        let json = norito::json::to_json(&context).expect("json");
        assert_eq!(
            norito::json::from_str::<AuthenticatedBallotContextV1>(&json).expect("json"),
            context
        );
        // The largest list with the complete context still fits `C_max`.
        let mut largest = context.clone();
        largest.commitments = commitments(1_000);
        largest.seats = 1_000;
        assert_eq!(largest.validate(), Ok(()));
        let size = enc(&largest).expect("enc").len();
        assert!(size <= BALLOT_CONTEXT_MAX_BYTES_V1, "{size}");
        // Disagreements and structural errors are refused.
        let mut mismatch = context.clone();
        mismatch.body_context.body_role = ParliamentBody::ConfirmationJury;
        assert_eq!(
            mismatch.validate(),
            Err(BallotContextErrorV1::ContextMismatch { field: "body_role" })
        );
        let mut foreign = context.clone();
        foreign.profile_id = ProofProfileIdV1::new([0; 64]);
        assert_eq!(
            foreign.validate(),
            Err(BallotContextErrorV1::UnknownProfile)
        );
        let mut short = context.clone();
        short.seats = 4;
        assert_eq!(
            short.validate(),
            Err(BallotContextErrorV1::SeatCount {
                seats: 4,
                entries: 5
            })
        );
        let mut public = context.clone();
        public.body_context.body_role = ParliamentBody::AgendaCouncil;
        assert!(public.validate().is_err());
        let mut bad_policy = context;
        bad_policy.policy = policy();
        bad_policy.policy.minimum_turnout = 2;
        assert!(matches!(
            bad_policy.validate(),
            Err(BallotContextErrorV1::Policy(_))
        ));
    }
}
