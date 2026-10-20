//! The anonymous ballot, its envelope, the stamp preimage and the compact corpus entry
//! (design §3.5–§3.7, integration decisions 1, 2 and 4).

use core::fmt;

use iroha_schema::IntoSchema;
use norito::{
    codec::{Decode, Encode},
    json::{self, JsonDeserialize, Parser},
};

use super::{
    ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1, AdmissionNonceV1, BallotProofBytesV1, BallotScopeV1,
    Digest512, NullifierV1, ProofProfileIdV1, VoteAuthorizationV1,
    digests::{AnonymousBallotCorpusErrorV1, envelope_digest_v1},
    framing::{AnonymousBallotCodecErrorV1, decode_enc_bounded_with_limits, enc_bounded},
};
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, NetworkId};

/// One public ballot choice.
///
/// The proof profile encodes the choice as one byte, `0 = Aye`, `1 = Nay`, `2 = Abstain`
/// ([`BallotChoiceV1::proof_code`]); Norito uses the same indices as its discriminant.
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
#[norito(
    tag = "kind",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::BallotChoiceV1")]
pub enum BallotChoiceV1 {
    /// Approve the proposal.
    #[codec(index = 0)]
    Aye,
    /// Reject the proposal.
    #[codec(index = 1)]
    Nay,
    /// Count toward turnout without approving or rejecting.
    #[codec(index = 2)]
    Abstain,
}

impl BallotChoiceV1 {
    /// Every choice, in code order.
    pub const ALL: [Self; 3] = [Self::Aye, Self::Nay, Self::Abstain];

    /// The proof profile's one-byte code `u8(vote)`.
    #[must_use]
    pub const fn proof_code(self) -> u8 {
        match self {
            Self::Aye => 0,
            Self::Nay => 1,
            Self::Abstain => 2,
        }
    }

    /// The choice with the proof profile's code `code`, if any.
    #[must_use]
    pub const fn from_proof_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Aye),
            1 => Some(Self::Nay),
            2 => Some(Self::Abstain),
            _ => None,
        }
    }
}

/// The identity-free admission stamp: a 32-byte nonce whose work digest must reach the
/// frozen difficulty. There is no submitted difficulty field (integration decision 4).
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
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::AdmissionStampV1")]
pub struct AdmissionStampV1 {
    /// Nonce searched by the submitter; the only stamp input it controls.
    pub nonce: AdmissionNonceV1,
}

/// One anonymous ballot (design §3.5). It names no account; the proof authorizes it.
///
/// Ballots are identified by `(scope, nullifier)`, never by a transaction hash.
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
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::AnonymousBallotV1")]
pub struct AnonymousBallotV1 {
    /// Scope of the body instance's single ballot.
    pub scope: BallotScopeV1,
    /// The public choice.
    pub vote: BallotChoiceV1,
    /// Nullifier of the credential in this scope.
    pub nullifier: NullifierV1,
    /// Vote authorization value bound to the complete vote statement.
    pub auth_v: VoteAuthorizationV1,
    /// Proof profile; must be [`ProofProfileIdV1::V1`].
    pub profile_id: ProofProfileIdV1,
    /// Identity-free admission stamp.
    pub stamp: AdmissionStampV1,
    /// The ballot proof, exactly 233,012 bytes.
    pub proof: BallotProofBytesV1,
}

impl AnonymousBallotV1 {
    /// The ballot's identity in queues, state and APIs: `(scope, nullifier)`.
    #[must_use]
    pub fn identity(&self) -> (BallotScopeV1, NullifierV1) {
        (self.scope, self.nullifier)
    }
}

/// The signerless submission: one ballot bound to the executing network.
///
/// Its canonical `Enc` frame is at most [`ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1`] bytes.
/// It carries no creation time, TTL, account nonce or validity interval: validity is the
/// scope's authoritative casting window (integration decision 1).
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
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::AnonymousBallotEnvelopeV1")]
pub struct AnonymousBallotEnvelopeV1 {
    /// Genesis-bound identity of the network the ballot is cast on.
    pub network_id: NetworkId,
    /// The ballot.
    pub ballot: AnonymousBallotV1,
}

impl AnonymousBallotEnvelopeV1 {
    // Positional records and fixed byte fields borrow their input or stay inline.
    // The only owned decode allocation is one exact proof copy, charged by
    // BallotProofBytesV1 after its field length has been checked. There are no
    // sequence counts in this schema, including inside the raw proof bytes.
    const DECODE_LIMITS: norito::DecodeLimits = norito::DecodeLimits::new(
        0,
        ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1,
        0,
        BallotProofBytesV1::LENGTH,
        norito::core::MAX_VALUE_NESTING_DEPTH,
    );

    /// `Enc(self)`, refused above the envelope cap.
    ///
    /// # Errors
    /// [`AnonymousBallotCodecErrorV1`] if the frame cannot be produced or exceeds
    /// [`ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1`].
    pub fn encode_canonical_bounded(&self) -> Result<Vec<u8>, AnonymousBallotCodecErrorV1> {
        enc_bounded(
            self,
            "anonymous ballot envelope",
            ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1,
        )
    }

    /// Decode one exact canonical envelope frame of at most the envelope cap.
    ///
    /// The byte cap is checked before entering the decoder. Its schema budget
    /// permits no sequence elements and at most one 233,012-byte proof allocation;
    /// a narrower enclosing Norito budget remains in force. This is a cumulative
    /// nominal codec charge, not a bound on physical workspace, allocator overhead,
    /// codec controls or error storage. Generic Norito APIs do not apply this
    /// schema-specific boundary. Decoding does not verify the stamp or proof.
    ///
    /// # Errors
    /// [`AnonymousBallotCodecErrorV1`] for oversize input, another header or any
    /// non-canonical or wrong-length field. An enclosing-budget or allocator
    /// refusal is [`AnonymousBallotCodecErrorV1::DecodeUnavailable`], not malformed
    /// ballot evidence.
    pub fn decode_canonical_bounded(bytes: &[u8]) -> Result<Self, AnonymousBallotCodecErrorV1> {
        if bytes.len() > ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1 {
            return Err(AnonymousBallotCodecErrorV1::TooLarge {
                kind: "anonymous ballot envelope",
                actual: bytes.len(),
                max: ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1,
            });
        }
        decode_enc_bounded_with_limits(
            bytes,
            "anonymous ballot envelope",
            ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1,
            Self::DECODE_LIMITS,
        )
    }

    /// The stamp-free authorization payload: the network and every ballot field except
    /// the stamp, including the exact proof bytes.
    #[must_use]
    pub fn authorization(&self) -> AnonymousBallotAuthorizationV1 {
        AnonymousBallotAuthorizationV1 {
            network_id: self.network_id,
            scope: self.ballot.scope,
            vote: self.ballot.vote,
            nullifier: self.ballot.nullifier,
            auth_v: self.ballot.auth_v,
            profile_id: self.ballot.profile_id,
            proof: self.ballot.proof.clone(),
        }
    }
}

/// The exact canonical envelope frame carried by the anonymous-ballot transaction
/// entrypoint (integration decision 1).
///
/// It holds the bytes that were submitted and committed, so the envelope digest and the
/// entrypoint hash cover exactly them. Construction and every decode check that the bytes
/// are one canonical [`AnonymousBallotEnvelopeV1`] frame within the envelope cap. Norito
/// encodes it as a byte string; JSON as `{"bytes": "<base64>"}`.
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
    name = "iroha_data_model::governance::anonymous_ballot::CanonicalAnonymousBallotEnvelopeV1"
)]
pub struct CanonicalAnonymousBallotEnvelopeV1 {
    /// The exact canonical `Enc` frame of the envelope.
    #[norito(json = "crate::json_helpers::base64_vec")]
    bytes: Vec<u8>,
}

impl CanonicalAnonymousBallotEnvelopeV1 {
    /// The canonical frame of `envelope`.
    ///
    /// # Errors
    /// As [`AnonymousBallotEnvelopeV1::encode_canonical_bounded`].
    pub fn from_envelope(
        envelope: &AnonymousBallotEnvelopeV1,
    ) -> Result<Self, AnonymousBallotCodecErrorV1> {
        envelope
            .encode_canonical_bounded()
            .map(|bytes| Self { bytes })
    }

    /// Accept `bytes` only if they are exactly one canonical envelope frame.
    ///
    /// # Errors
    /// As [`AnonymousBallotEnvelopeV1::decode_canonical_bounded`].
    pub fn from_canonical_bytes(bytes: Vec<u8>) -> Result<Self, AnonymousBallotCodecErrorV1> {
        AnonymousBallotEnvelopeV1::decode_canonical_bounded(&bytes)?;
        Ok(Self { bytes })
    }

    /// The exact canonical frame.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The decoded envelope.
    ///
    /// # Errors
    /// Constructors and checked decoders guarantee canonical validity, but a
    /// local decode-budget or allocator refusal can still make this operation
    /// unavailable. See [`AnonymousBallotEnvelopeV1::decode_canonical_bounded`].
    pub fn envelope(&self) -> Result<AnonymousBallotEnvelopeV1, AnonymousBallotCodecErrorV1> {
        AnonymousBallotEnvelopeV1::decode_canonical_bounded(&self.bytes)
    }

    /// `envelope_digest = H(Frame("PARL/ENVELOPE/v1"; canonical_envelope_bytes))`.
    ///
    /// # Errors
    /// Only if the frame cannot be built, which a bounded envelope never causes.
    pub fn digest(&self) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
        envelope_digest_v1(&self.bytes)
    }

    /// Norito decode hook: check the frame and retain original local refusal ownership.
    fn checked(self) -> Result<Self, norito::Error> {
        AnonymousBallotEnvelopeV1::decode_canonical_bounded(&self.bytes).map_err(|error| {
            match error {
                AnonymousBallotCodecErrorV1::DecodeUnavailable(refusal) => refusal.into_error(),
                error => norito::Error::Message(error.to_string()),
            }
        })?;
        Ok(self)
    }
}

impl fmt::Display for CanonicalAnonymousBallotEnvelopeV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "anonymous ballot envelope ({} bytes)", self.bytes.len())
    }
}

impl JsonDeserialize for CanonicalAnonymousBallotEnvelopeV1 {
    fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, json::Error> {
        #[derive(DeriveJsonDeserialize)]
        #[norito(deny_unknown_fields, no_fast_from_json)]
        struct Fields {
            #[norito(json = "crate::json_helpers::base64_vec")]
            bytes: Vec<u8>,
        }
        let fields = <Fields as JsonDeserialize>::json_deserialize(parser)?;
        Self::from_canonical_bytes(fields.bytes).map_err(|error| match error {
            AnonymousBallotCodecErrorV1::DecodeUnavailable(refusal) => {
                json::Error::from_decode_resource(refusal.into_error())
            }
            error => json::Error::Message(error.to_string()),
        })
    }
}

/// The stamp-free authorization payload hashed into the admission stamp: the envelope's
/// network identity and every ballot field except the stamp, including the exact proof.
///
/// It is its own typed encoding, not an envelope with a zeroed stamp
/// (integration decision 4).
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
#[norito_schema(
    name = "iroha_data_model::governance::anonymous_ballot::AnonymousBallotAuthorizationV1"
)]
pub struct AnonymousBallotAuthorizationV1 {
    /// Network of the envelope.
    pub network_id: NetworkId,
    /// Ballot scope.
    pub scope: BallotScopeV1,
    /// Ballot choice.
    pub vote: BallotChoiceV1,
    /// Ballot nullifier.
    pub nullifier: NullifierV1,
    /// Vote authorization value.
    pub auth_v: VoteAuthorizationV1,
    /// Proof profile.
    pub profile_id: ProofProfileIdV1,
    /// The exact ballot proof bytes.
    pub proof: BallotProofBytesV1,
}

/// Why a ballot with a valid proof is recorded as rejected (integration decision 1).
///
/// Encoding, network, context, profile, stamp and proof failures are not rejections: a
/// block carrying such a ballot is invalid.
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
    thiserror::Error,
)]
#[norito(
    tag = "kind",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[norito_schema(
    name = "iroha_data_model::governance::anonymous_ballot::AnonymousBallotRejectionV1"
)]
pub enum AnonymousBallotRejectionV1 {
    /// The block's timestamp is outside the scope's half-open casting window. Checked
    /// before duplicates, so a closed-window replay is always this.
    #[codec(index = 0)]
    #[error("the ballot is outside its scope's casting window")]
    OutsideCastingWindow,
    /// An earlier ballot in canonical order already holds the `(scope, nullifier)`.
    #[codec(index = 1)]
    #[error("the ballot's nullifier was already accepted in its scope")]
    DuplicateNullifier,
}

/// One accepted ballot in World's compact corpus (integration decision 2).
///
/// The proof stays in the canonical envelope at `(height, input_index)` of the finalized
/// chain; the logical evidence corpus joins this entry with those bytes, whose digest is
/// `envelope_digest`. There is no block hash here: it would make the commitment circular.
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
#[norito_schema(
    name = "iroha_data_model::governance::anonymous_ballot::AnonymousBallotCorpusEntryV1"
)]
pub struct AnonymousBallotCorpusEntryV1 {
    /// Ballot scope.
    pub scope: BallotScopeV1,
    /// Ballot choice.
    pub vote: BallotChoiceV1,
    /// Ballot nullifier.
    pub nullifier: NullifierV1,
    /// Vote authorization value.
    pub auth_v: VoteAuthorizationV1,
    /// Proof profile.
    pub profile_id: ProofProfileIdV1,
    /// Admission stamp of the accepted envelope.
    pub stamp: AdmissionStampV1,
    /// `H(Frame("PARL/ENVELOPE/v1"; canonical_envelope_bytes))`.
    pub envelope_digest: Digest512,
    /// Nonzero height of the block that executed the ballot.
    pub height: u64,
    /// Position in that block's complete global network-input projection.
    pub input_index: u32,
}

impl AnonymousBallotCorpusEntryV1 {
    /// The entry of `envelope`, accepted at `(height, input_index)`, whose canonical frame
    /// has the digest `envelope_digest`.
    ///
    /// # Errors
    /// [`AnonymousBallotCorpusErrorV1::ZeroHeight`] for height zero.
    pub fn from_envelope(
        envelope: &AnonymousBallotEnvelopeV1,
        envelope_digest: Digest512,
        height: u64,
        input_index: u32,
    ) -> Result<Self, AnonymousBallotCorpusErrorV1> {
        let entry = Self {
            scope: envelope.ballot.scope,
            vote: envelope.ballot.vote,
            nullifier: envelope.ballot.nullifier,
            auth_v: envelope.ballot.auth_v,
            profile_id: envelope.ballot.profile_id,
            stamp: envelope.ballot.stamp,
            envelope_digest,
            height,
            input_index,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Check the entry's own invariant: a nonzero height.
    ///
    /// # Errors
    /// [`AnonymousBallotCorpusErrorV1::ZeroHeight`] for height zero.
    pub fn validate(&self) -> Result<(), AnonymousBallotCorpusErrorV1> {
        if self.height == 0 {
            return Err(AnonymousBallotCorpusErrorV1::ZeroHeight);
        }
        Ok(())
    }

    /// The canonical corpus position `(height, input_index)`.
    #[must_use]
    pub const fn position(&self) -> (u64, u32) {
        (self.height, self.input_index)
    }
}

#[cfg(test)]
#[path = "envelope_decode_tests.rs"]
mod envelope_decode_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::anonymous_ballot::{
        framing::{decode_enc, enc, frame_digest},
        test_fixtures::envelope,
    };

    /// Frame size of every envelope: all of its fields have fixed lengths.
    const ENVELOPE_FRAME_BYTES: usize = 233_455;

    #[test]
    fn choices_use_the_profile_codes() {
        for (choice, code) in BallotChoiceV1::ALL.into_iter().zip(0_u8..) {
            assert_eq!(choice.proof_code(), code);
            assert_eq!(BallotChoiceV1::from_proof_code(code), Some(choice));
            // The Norito discriminant is the same index.
            assert_eq!(choice.encode(), u32::from(code).to_le_bytes());
            assert_eq!(
                BallotChoiceV1::decode(&mut &choice.encode()[..]).expect("decode"),
                choice
            );
            let json = norito::json::to_json(&choice).expect("json");
            assert_eq!(
                norito::json::from_str::<BallotChoiceV1>(&json).expect("json"),
                choice
            );
        }
        assert_eq!(BallotChoiceV1::from_proof_code(3), None);
        assert!(BallotChoiceV1::decode(&mut &3_u32.to_le_bytes()[..]).is_err());
        assert_eq!(
            norito::json::to_json(&BallotChoiceV1::Abstain).expect("json"),
            r#"{"kind":"abstain","detail":null}"#
        );
    }

    #[test]
    fn the_envelope_has_a_fixed_canonical_size_within_its_cap() {
        let envelope = envelope(BallotChoiceV1::Nay, 0x10);
        let bytes = envelope.encode_canonical_bounded().expect("within the cap");
        assert_eq!(bytes.len(), ENVELOPE_FRAME_BYTES);
        assert!(bytes.len() <= ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1);
        assert_eq!(
            AnonymousBallotEnvelopeV1::decode_canonical_bounded(&bytes),
            Ok(envelope.clone())
        );
        assert_eq!(
            decode_enc::<AnonymousBallotEnvelopeV1>(&bytes),
            Ok(envelope.clone())
        );
        let mut oversize = bytes.clone();
        oversize.resize(ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1 + 1, 0);
        assert_eq!(
            AnonymousBallotEnvelopeV1::decode_canonical_bounded(&oversize),
            Err(AnonymousBallotCodecErrorV1::TooLarge {
                kind: "anonymous ballot envelope",
                actual: ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1 + 1,
                max: ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1
            })
        );
        let json = norito::json::to_json(&envelope).expect("json");
        assert_eq!(
            norito::json::from_str::<AnonymousBallotEnvelopeV1>(&json).expect("json"),
            envelope
        );
        assert_eq!(
            envelope.ballot.identity(),
            (envelope.ballot.scope, envelope.ballot.nullifier)
        );
    }

    /// A ballot and envelope with the real field order whose nullifier is a literal raw
    /// byte array of `$len` bytes, so every enclosing length stays consistent.
    macro_rules! mirror_envelope {
        ($ballot:ident, $envelope:ident, $len:literal) => {
            #[derive(Encode)]
            struct $ballot {
                scope: BallotScopeV1,
                vote: BallotChoiceV1,
                nullifier: [u8; $len],
                auth_v: VoteAuthorizationV1,
                profile_id: ProofProfileIdV1,
                stamp: AdmissionStampV1,
                proof: BallotProofBytesV1,
            }
            #[derive(Encode)]
            struct $envelope {
                network_id: NetworkId,
                ballot: $ballot,
            }
            impl $envelope {
                fn of(envelope: &AnonymousBallotEnvelopeV1) -> Self {
                    let mut nullifier = [0_u8; $len];
                    for (out, byte) in nullifier
                        .iter_mut()
                        .zip(envelope.ballot.nullifier.as_bytes())
                    {
                        *out = *byte;
                    }
                    Self {
                        network_id: envelope.network_id,
                        ballot: $ballot {
                            scope: envelope.ballot.scope,
                            vote: envelope.ballot.vote,
                            nullifier,
                            auth_v: envelope.ballot.auth_v,
                            profile_id: envelope.ballot.profile_id,
                            stamp: envelope.ballot.stamp,
                            proof: envelope.ballot.proof.clone(),
                        },
                    }
                }
            }
        };
    }
    mirror_envelope!(ExactBallot, ExactEnvelope, 128);
    mirror_envelope!(ShortBallot, ShortEnvelope, 127);
    mirror_envelope!(LongBallot, LongEnvelope, 129);

    #[test]
    fn a_wrong_length_ballot_field_is_rejected_at_decode() {
        let envelope = envelope(BallotChoiceV1::Aye, 0x10);
        // The mirror reproduces the real encoding at the real length...
        assert_eq!(ExactEnvelope::of(&envelope).encode(), envelope.encode());
        // ...and a consistent frame whose nullifier has one byte less or more is refused.
        for bare in [
            ShortEnvelope::of(&envelope).encode(),
            LongEnvelope::of(&envelope).encode(),
        ] {
            assert!(AnonymousBallotEnvelopeV1::decode(&mut &bare[..]).is_err());
        }
    }

    #[test]
    fn the_authorization_payload_is_every_field_but_the_stamp() {
        let envelope = envelope(BallotChoiceV1::Abstain, 0x21);
        let authorization = envelope.authorization();
        assert_eq!(authorization.network_id, envelope.network_id);
        assert_eq!(authorization.scope, envelope.ballot.scope);
        assert_eq!(authorization.vote, envelope.ballot.vote);
        assert_eq!(authorization.nullifier, envelope.ballot.nullifier);
        assert_eq!(authorization.auth_v, envelope.ballot.auth_v);
        assert_eq!(authorization.profile_id, envelope.ballot.profile_id);
        assert_eq!(authorization.proof, envelope.ballot.proof);
        // A different stamp leaves the payload unchanged.
        let mut restamped = envelope.clone();
        restamped.ballot.stamp.nonce = AdmissionNonceV1::new([0; 32]);
        assert_eq!(restamped.authorization(), authorization);
        let bytes = enc(&authorization).expect("enc");
        assert_eq!(
            decode_enc::<AnonymousBallotAuthorizationV1>(&bytes),
            Ok(authorization.clone())
        );
        let json = norito::json::to_json(&authorization).expect("json");
        assert_eq!(
            norito::json::from_str::<AnonymousBallotAuthorizationV1>(&json).expect("json"),
            authorization
        );
    }

    #[test]
    fn the_canonical_envelope_keeps_exactly_the_canonical_bytes() {
        let envelope = envelope(BallotChoiceV1::Aye, 0x31);
        let canonical =
            CanonicalAnonymousBallotEnvelopeV1::from_envelope(&envelope).expect("frame");
        let bytes = envelope.encode_canonical_bounded().expect("frame");
        assert_eq!(canonical.as_bytes(), &bytes[..]);
        assert_eq!(canonical.envelope(), Ok(envelope.clone()));
        assert_eq!(
            canonical.digest(),
            frame_digest(b"PARL/ENVELOPE/v1", &[&bytes])
        );
        assert_eq!(
            CanonicalAnonymousBallotEnvelopeV1::from_canonical_bytes(bytes.clone()),
            Ok(canonical.clone())
        );
        assert_eq!(
            canonical.to_string(),
            format!("anonymous ballot envelope ({ENVELOPE_FRAME_BYTES} bytes)")
        );
        // Norito and JSON round trips run the canonical check again.
        let encoded = canonical.encode();
        assert_eq!(
            CanonicalAnonymousBallotEnvelopeV1::decode(&mut &encoded[..]).expect("decode"),
            canonical
        );
        let framed = enc(&canonical).expect("enc");
        assert_eq!(
            decode_enc::<CanonicalAnonymousBallotEnvelopeV1>(&framed),
            Ok(canonical.clone())
        );
        let json = norito::json::to_json(&canonical).expect("json");
        assert_eq!(
            norito::json::from_str::<CanonicalAnonymousBallotEnvelopeV1>(&json).expect("json"),
            canonical
        );
        // Bytes that are not one canonical envelope frame are refused everywhere.
        let mut altered = bytes.clone();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        assert!(CanonicalAnonymousBallotEnvelopeV1::from_canonical_bytes(altered.clone()).is_err());
        let forged = CanonicalAnonymousBallotEnvelopeV1 { bytes: altered };
        assert!(CanonicalAnonymousBallotEnvelopeV1::decode(&mut &forged.encode()[..]).is_err());
        let forged_json = norito::json::to_json(&forged).expect("json");
        assert!(
            norito::json::from_str::<CanonicalAnonymousBallotEnvelopeV1>(&forged_json).is_err()
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(CanonicalAnonymousBallotEnvelopeV1::from_canonical_bytes(trailing).is_err());
    }

    /// Two canonical envelopes followed by another field, as in a block's input vector.
    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    struct EnvelopeCarrier {
        first: CanonicalAnonymousBallotEnvelopeV1,
        second: CanonicalAnonymousBallotEnvelopeV1,
        tail: u32,
    }

    #[test]
    fn the_canonical_envelope_check_leaves_the_enclosing_decode_intact() {
        let carrier = EnvelopeCarrier {
            first: CanonicalAnonymousBallotEnvelopeV1::from_envelope(&envelope(
                BallotChoiceV1::Aye,
                1,
            ))
            .expect("frame"),
            second: CanonicalAnonymousBallotEnvelopeV1::from_envelope(&envelope(
                BallotChoiceV1::Nay,
                2,
            ))
            .expect("frame"),
            tail: 0xdead_beef,
        };
        let bytes = carrier.encode();
        assert_eq!(
            EnvelopeCarrier::decode(&mut &bytes[..]).expect("decode"),
            carrier
        );
    }

    #[test]
    fn rejections_round_trip_and_explain_themselves() {
        for rejection in [
            AnonymousBallotRejectionV1::OutsideCastingWindow,
            AnonymousBallotRejectionV1::DuplicateNullifier,
        ] {
            let bytes = enc(&rejection).expect("enc");
            assert_eq!(
                decode_enc::<AnonymousBallotRejectionV1>(&bytes),
                Ok(rejection)
            );
            let json = norito::json::to_json(&rejection).expect("json");
            assert_eq!(
                norito::json::from_str::<AnonymousBallotRejectionV1>(&json).expect("json"),
                rejection
            );
            assert!(!rejection.to_string().is_empty());
        }
        assert_eq!(
            AnonymousBallotRejectionV1::OutsideCastingWindow.encode(),
            0_u32.to_le_bytes()
        );
        assert_eq!(
            AnonymousBallotRejectionV1::DuplicateNullifier.encode(),
            1_u32.to_le_bytes()
        );
    }

    #[test]
    fn corpus_entries_copy_the_public_fields_and_need_a_height() {
        let envelope = envelope(BallotChoiceV1::Nay, 0x41);
        let digest = Digest512::new([0xee; 64]);
        let entry =
            AnonymousBallotCorpusEntryV1::from_envelope(&envelope, digest, 7, 3).expect("entry");
        assert_eq!(entry.scope, envelope.ballot.scope);
        assert_eq!(entry.vote, BallotChoiceV1::Nay);
        assert_eq!(entry.nullifier, envelope.ballot.nullifier);
        assert_eq!(entry.auth_v, envelope.ballot.auth_v);
        assert_eq!(entry.profile_id, envelope.ballot.profile_id);
        assert_eq!(entry.stamp, envelope.ballot.stamp);
        assert_eq!(entry.envelope_digest, digest);
        assert_eq!(entry.position(), (7, 3));
        assert_eq!(entry.validate(), Ok(()));
        assert_eq!(
            AnonymousBallotCorpusEntryV1::from_envelope(&envelope, digest, 0, 3),
            Err(AnonymousBallotCorpusErrorV1::ZeroHeight)
        );
        let bytes = enc(&entry).expect("enc");
        assert_eq!(
            decode_enc::<AnonymousBallotCorpusEntryV1>(&bytes),
            Ok(entry)
        );
        let json = norito::json::to_json(&entry).expect("json");
        assert_eq!(
            norito::json::from_str::<AnonymousBallotCorpusEntryV1>(&json).expect("json"),
            entry
        );
        let stamp = AdmissionStampV1 {
            nonce: AdmissionNonceV1::new([9; 32]),
        };
        assert_eq!(
            decode_enc::<AdmissionStampV1>(&enc(&stamp).expect("enc")),
            Ok(stamp)
        );
        let json = norito::json::to_json(&stamp).expect("json");
        assert_eq!(
            norito::json::from_str::<AdmissionStampV1>(&json).expect("json"),
            stamp
        );
    }
}
