//! The credential secret and the public values derived from it or bound to it
//! (evaluation record sections 6.1 and 6.2).
//!
//! ```text
//! B     = SHA3-512(Frame("PARL/BODY/v1"; P16, Enc(body_context)))
//! C     = SHAKE256("PCR1" || P16 || sk[48] || B[64],      128 bytes)
//! D_reg = SHA3-512(Frame("PARL/REG-AUTH/v1"; P16, "REG", D, Enc(body_context),
//!             Enc(network_id), Enc(authority), Enc(assignment_id),
//!             Enc(governance_attempt_id), Enc(election_attempt_id),
//!             Enc(body_role), B, C))
//! auth  = SHAKE256("PAU1" || P16 || sk[48] || D_reg[64],   64 bytes)
//! nf    = SHAKE256("PNF1" || P16 || sk[48] || scope[64],  128 bytes)
//! ```
//!
//! The helpers for `policy_hash`, `proposal_digest` and `scope` reproduce the
//! frames of section 6.2 exactly, including where each places or omits `P16`.
//! Their preimages never reach a proof or a verifier, which see only the 64-byte
//! results; the helpers are optional conveniences.
//!
//! The secret is 48 bytes that the caller draws uniformly at random, fresh for
//! each body. Uniformity is a generation requirement that nothing here can check.

use iroha_zkp_vole::hash::Sha3_512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    framing::{
        BodyContext, COMMITMENT_BYTES, Commitment, DIGEST_BYTES, Digest64, Frame, FramingError,
        NULLIFIER_BYTES, Nullifier, OpaqueField, frame_digest,
    },
    keccak_relation::{SECRET_BYTES, evaluate, public_block},
    profile::P16,
};

/// The SHAKE256 tag of the credential commitment.
pub const COMMITMENT_TAG: [u8; 4] = *b"PCR1";
/// The SHAKE256 tag of the authorization value.
pub const AUTHORIZATION_TAG: [u8; 4] = *b"PAU1";
/// The SHAKE256 tag of the nullifier.
pub const NULLIFIER_TAG: [u8; 4] = *b"PNF1";
/// The SHAKE256 tag of the vote authorization value.
pub const VOTE_AUTHORIZATION_TAG: [u8; 4] = *b"PAV1";

/// The 48-byte credential secret `sk`.
///
/// Held on the heap and erased on drop; not `Clone`, and its `Debug` output shows
/// no byte of it.
pub struct CredentialSecret(Box<[u8; SECRET_BYTES]>);

impl core::fmt::Debug for CredentialSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CredentialSecret(<redacted>)")
    }
}

impl Drop for CredentialSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for CredentialSecret {}

impl CredentialSecret {
    /// The secret with the bytes `bytes`. The caller's copy is the caller's to
    /// erase; prefer [`CredentialSecret::fill_with`] for a new secret.
    pub fn from_bytes(bytes: &[u8; SECRET_BYTES]) -> Self {
        let mut secret = Self(Box::new([0u8; SECRET_BYTES]));
        secret.0.copy_from_slice(bytes);
        secret
    }

    /// A secret whose 48 bytes `fill` writes in place, for example from the
    /// caller's fallible cryptographic random-number generator.
    ///
    /// # Errors
    /// The error of `fill`; the partially written buffer is erased.
    pub fn fill_with<E>(
        fill: impl FnOnce(&mut [u8; SECRET_BYTES]) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut secret = Self(Box::new([0u8; SECRET_BYTES]));
        fill(&mut secret.0)?;
        Ok(secret)
    }

    /// The secret bytes, for the wallet's own storage and for witness generation.
    pub fn expose_bytes(&self) -> &[u8; SECRET_BYTES] {
        &self.0
    }

    /// The first `out.len()` bytes of `SHAKE256(tag || P16 || sk || input)`.
    fn shake(&self, tag: [u8; 4], input: &Digest64, out: &mut [u8]) {
        evaluate(&public_block(tag, input.as_bytes()), self.expose_bytes()).squeeze(out);
    }

    /// The credential commitment `C` for the body digest `body_digest`.
    pub fn commitment(&self, body_digest: &Digest64) -> Commitment {
        let mut out = [0u8; COMMITMENT_BYTES];
        self.shake(COMMITMENT_TAG, body_digest, &mut out);
        Commitment(out)
    }

    /// The authorization value `auth` for the registration digest `D_reg`.
    pub fn authorization(&self, registration_digest: &Digest64) -> Digest64 {
        let mut out = [0u8; DIGEST_BYTES];
        self.shake(AUTHORIZATION_TAG, registration_digest, &mut out);
        Digest64(out)
    }

    /// The vote authorization `auth_v` for the complete vote digest `D_v`.
    pub fn vote_authorization(&self, vote_digest: &Digest64) -> Digest64 {
        let mut out = [0u8; DIGEST_BYTES];
        self.shake(VOTE_AUTHORIZATION_TAG, vote_digest, &mut out);
        Digest64(out)
    }

    /// The nullifier `nf` for `scope`. It does not depend on the vote.
    pub fn nullifier(&self, scope: &Digest64) -> Nullifier {
        let mut out = [0u8; NULLIFIER_BYTES];
        self.shake(NULLIFIER_TAG, scope, &mut out);
        Nullifier(out)
    }
}

/// `B = SHA3-512(Frame("PARL/BODY/v1"; P16, Enc(body_context)))`.
///
/// # Errors
/// Only if the frame cannot be built, which a bounded input never causes.
pub fn body_digest(body_context: &BodyContext) -> Result<Digest64, FramingError> {
    frame_digest(b"PARL/BODY/v1", &[&P16, body_context.as_bytes()])
}

/// The six opaque inputs of a registration statement besides the body context,
/// in the order of `m_reg`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegistrationContext {
    /// `Enc(network_id)`.
    pub network_id: OpaqueField,
    /// `Enc(authority)`.
    pub authority: OpaqueField,
    /// `Enc(assignment_id)`.
    pub assignment_id: OpaqueField,
    /// `Enc(governance_attempt_id)`.
    pub governance_attempt_id: OpaqueField,
    /// `Enc(election_attempt_id)`.
    pub election_attempt_id: OpaqueField,
    /// `Enc(body_role)`.
    pub body_role: OpaqueField,
}

impl RegistrationContext {
    /// The six inputs in frame order.
    pub fn fields(&self) -> [&[u8]; 6] {
        [
            self.network_id.as_bytes(),
            self.authority.as_bytes(),
            self.assignment_id.as_bytes(),
            self.governance_attempt_id.as_bytes(),
            self.election_attempt_id.as_bytes(),
            self.body_role.as_bytes(),
        ]
    }
}

/// `D_reg`, the digest the authorization value is computed over.
///
/// `descriptor_digest` is exactly the 64 bytes `D` of the row; the body-context
/// field is the byte string that `body_digest` hashes.
///
/// # Errors
/// Only if the frame cannot be built, which bounded inputs never cause.
pub fn registration_digest(
    descriptor_digest: &Digest64,
    body_context: &BodyContext,
    context: &RegistrationContext,
    body_digest: &Digest64,
    commitment: &Commitment,
) -> Result<Digest64, FramingError> {
    let [network, authority, assignment, governance, election, role] = context.fields();
    frame_digest(
        b"PARL/REG-AUTH/v1",
        &[
            &P16,
            b"REG",
            descriptor_digest.as_bytes(),
            body_context.as_bytes(),
            network,
            authority,
            assignment,
            governance,
            election,
            role,
            body_digest.as_bytes(),
            commitment.as_bytes(),
        ],
    )
}

/// A streaming SHA3-512 of a frame whose last field is a preimage of declared
/// length up to `0xffff_ffff` bytes, for `policy_hash` and `proposal_digest`.
#[derive(Debug)]
pub struct PreimageDigest {
    sponge: Sha3_512,
    /// Bytes of the preimage still owed.
    left: u64,
}

impl PreimageDigest {
    fn start(tag: &[u8], leading: &[&[u8]], len: u64) -> Result<Self, FramingError> {
        let mut sponge = Sha3_512::new();
        let mut frame = Frame::begin(&mut sponge, tag, leading.len() + 1)?;
        for field in leading {
            frame.field(field)?;
        }
        frame.begin_field(len)?;
        Ok(Self { sponge, left: len })
    }

    /// `policy_hash = SHA3-512(Frame("PARL/POLICY/v1"; P16, Enc(complete_frozen_policy)))`
    /// for a policy encoding of exactly `len` bytes.
    ///
    /// # Errors
    /// [`FramingError::FieldTooLong`] if `len` exceeds `0xffff_ffff`.
    pub fn policy(len: u64) -> Result<Self, FramingError> {
        Self::start(b"PARL/POLICY/v1", &[&P16], len)
    }

    /// `proposal_digest = SHA3-512(Frame("PARL/PROPOSAL/v1"; Enc(canonical_proposal_content)))`
    /// for a proposal encoding of exactly `len` bytes. This frame has no `P16`.
    ///
    /// # Errors
    /// [`FramingError::FieldTooLong`] if `len` exceeds `0xffff_ffff`.
    pub fn proposal(len: u64) -> Result<Self, FramingError> {
        Self::start(b"PARL/PROPOSAL/v1", &[], len)
    }

    /// Absorb the next bytes of the preimage.
    ///
    /// # Errors
    /// [`FramingError::FieldOverrun`] if more bytes arrive than were declared;
    /// nothing is absorbed then.
    pub fn update(&mut self, chunk: &[u8]) -> Result<(), FramingError> {
        let len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        let Some(left) = self.left.checked_sub(len) else {
            return Err(FramingError::FieldOverrun {
                excess: len - self.left,
            });
        };
        self.left = left;
        self.sponge.update(chunk);
        Ok(())
    }

    /// The digest.
    ///
    /// # Errors
    /// [`FramingError::FieldIncomplete`] if fewer bytes arrived than were
    /// declared.
    pub fn finalize(self) -> Result<Digest64, FramingError> {
        if self.left != 0 {
            return Err(FramingError::FieldIncomplete { missing: self.left });
        }
        Ok(Digest64(self.sponge.finalize()))
    }
}

/// `policy_hash` of a policy encoding held in memory.
///
/// # Errors
/// [`FramingError::FieldTooLong`] if the encoding exceeds `0xffff_ffff` bytes.
pub fn policy_hash(policy: &[u8]) -> Result<Digest64, FramingError> {
    let mut digest = PreimageDigest::policy(u64::try_from(policy.len()).unwrap_or(u64::MAX))?;
    digest.update(policy)?;
    digest.finalize()
}

/// `proposal_digest` of a proposal encoding held in memory.
///
/// # Errors
/// [`FramingError::FieldTooLong`] if the encoding exceeds `0xffff_ffff` bytes.
pub fn proposal_digest(proposal: &[u8]) -> Result<Digest64, FramingError> {
    let mut digest = PreimageDigest::proposal(u64::try_from(proposal.len()).unwrap_or(u64::MAX))?;
    digest.update(proposal)?;
    digest.finalize()
}

/// `scope = SHA3-512(Frame("PARL/SCOPE/v1"; P16, Enc(network_id), proposal_digest,
/// Enc(governance_attempt_id), Enc(body_instance_id)))`.
///
/// # Errors
/// Only if the frame cannot be built, which bounded inputs never cause.
pub fn scope_digest(
    network_id: &OpaqueField,
    proposal_digest: &Digest64,
    governance_attempt_id: &OpaqueField,
    body_instance_id: &OpaqueField,
) -> Result<Digest64, FramingError> {
    frame_digest(
        b"PARL/SCOPE/v1",
        &[
            &P16,
            network_id.as_bytes(),
            proposal_digest.as_bytes(),
            governance_attempt_id.as_bytes(),
            body_instance_id.as_bytes(),
        ],
    )
}

#[cfg(test)]
mod tests {
    use sha3::{
        Digest,
        digest::{ExtendableOutput, Update, XofReader},
    };

    use super::*;

    fn shake256(parts: &[&[u8]], len: usize) -> Vec<u8> {
        let mut sponge = sha3::Shake256::default();
        for part in parts {
            sponge.update(part);
        }
        let mut out = vec![0u8; len];
        sponge.finalize_xof().read(&mut out);
        out
    }

    fn sha3(bytes: &[u8]) -> Digest64 {
        Digest64(sha3::Sha3_512::digest(bytes).into())
    }

    /// `Frame` written independently of the framing module.
    fn frame(tag: &[u8], fields: &[&[u8]]) -> Vec<u8> {
        let mut out = u16::try_from(tag.len())
            .expect("short")
            .to_le_bytes()
            .to_vec();
        out.extend_from_slice(tag);
        out.extend_from_slice(&u16::try_from(fields.len()).expect("few").to_le_bytes());
        for field in fields {
            out.extend_from_slice(&u32::try_from(field.len()).expect("short").to_le_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    fn opaque(bytes: &[u8]) -> OpaqueField {
        OpaqueField::new(bytes).expect("within the bound")
    }

    fn context() -> RegistrationContext {
        RegistrationContext {
            network_id: opaque(b"net"),
            authority: opaque(b"authority"),
            assignment_id: opaque(b""),
            governance_attempt_id: opaque(b"g-7"),
            election_attempt_id: opaque(b"e-3"),
            body_role: opaque(b"member"),
        }
    }

    #[test]
    fn the_secret_is_kept_out_of_debug_output_and_filled_in_place() {
        let secret = CredentialSecret::from_bytes(&[0xa5; 48]);
        assert_eq!(secret.expose_bytes(), &[0xa5; 48]);
        let shown = format!("{secret:?}");
        assert_eq!(shown, "CredentialSecret(<redacted>)");
        assert!(!shown.contains("a5") && !shown.contains("165"));
        let filled = CredentialSecret::fill_with(|buffer| {
            buffer.copy_from_slice(&[7; 48]);
            Ok::<(), ()>(())
        })
        .expect("filled");
        assert_eq!(filled.expose_bytes(), &[7; 48]);
        // An entropy failure produces no secret.
        assert_eq!(
            CredentialSecret::fill_with(|buffer| {
                buffer[0] = 1;
                Err::<(), &str>("no entropy")
            })
            .err(),
            Some("no entropy")
        );
    }

    #[test]
    fn the_three_values_are_shake256_of_their_messages() {
        let bytes: [u8; 48] = core::array::from_fn(|i| u8::try_from(3 * i + 1).expect("small"));
        let secret = CredentialSecret::from_bytes(&bytes);
        let input = Digest64(core::array::from_fn(|i| {
            u8::try_from(255 - i).expect("small")
        }));
        assert_eq!(
            secret.commitment(&input).as_bytes().to_vec(),
            shake256(&[b"PCR1", &P16, &bytes, input.as_bytes()], 128)
        );
        assert_eq!(
            secret.authorization(&input).as_bytes().to_vec(),
            shake256(&[b"PAU1", &P16, &bytes, input.as_bytes()], 64)
        );
        assert_eq!(
            secret.nullifier(&input).as_bytes().to_vec(),
            shake256(&[b"PNF1", &P16, &bytes, input.as_bytes()], 128)
        );
        assert_eq!(
            secret.vote_authorization(&input).as_bytes().to_vec(),
            shake256(&[b"PAV1", &P16, &bytes, input.as_bytes()], 64)
        );
        // The four domains are separate.
        assert_ne!(
            secret.authorization(&input).as_bytes()[..],
            secret.nullifier(&input).as_bytes()[..64]
        );
        assert_ne!(
            secret.commitment(&input).as_bytes()[..],
            secret.nullifier(&input).as_bytes()[..]
        );
    }

    #[test]
    fn the_body_and_registration_digests_are_their_frames() {
        let body_context = BodyContext::new(b"body context").expect("within the bound");
        let body = body_digest(&body_context).expect("frame");
        assert_eq!(
            body,
            sha3(&frame(b"PARL/BODY/v1", &[&P16, b"body context"]))
        );
        let commitment = Commitment([0x11; 128]);
        let descriptor = Digest64([0x22; 64]);
        let expected = sha3(&frame(
            b"PARL/REG-AUTH/v1",
            &[
                &P16,
                b"REG",
                &[0x22; 64],
                b"body context",
                b"net",
                b"authority",
                b"",
                b"g-7",
                b"e-3",
                b"member",
                body.as_bytes(),
                &[0x11; 128],
            ],
        ));
        assert_eq!(
            registration_digest(&descriptor, &body_context, &context(), &body, &commitment),
            Ok(expected)
        );
        assert_eq!(context().fields()[3], b"g-7");
        // Every input moves the digest.
        let mut other = context();
        other.assignment_id = opaque(b"x");
        assert_ne!(
            registration_digest(&descriptor, &body_context, &other, &body, &commitment),
            Ok(expected)
        );
        assert_ne!(
            registration_digest(
                &Digest64([0x23; 64]),
                &body_context,
                &context(),
                &body,
                &commitment
            ),
            Ok(expected)
        );
    }

    #[test]
    fn the_helpers_reproduce_the_frames_of_the_record() {
        let policy = vec![0x5a; 1000];
        assert_eq!(
            policy_hash(&policy),
            Ok(sha3(&frame(b"PARL/POLICY/v1", &[&P16, &policy])))
        );
        // The proposal frame has no P16.
        assert_eq!(
            proposal_digest(b"proposal"),
            Ok(sha3(&frame(b"PARL/PROPOSAL/v1", &[b"proposal"])))
        );
        assert_eq!(
            proposal_digest(b""),
            Ok(sha3(&frame(b"PARL/PROPOSAL/v1", &[b""])))
        );
        let proposal = proposal_digest(b"proposal").expect("frame");
        assert_eq!(
            scope_digest(
                &opaque(b"net"),
                &proposal,
                &opaque(b"g-7"),
                &opaque(b"instance")
            ),
            Ok(sha3(&frame(
                b"PARL/SCOPE/v1",
                &[&P16, b"net", proposal.as_bytes(), b"g-7", b"instance"]
            )))
        );
    }

    #[test]
    fn streaming_gives_the_one_shot_digest_and_checks_the_declared_length() {
        let policy: Vec<u8> = (0..5000u32)
            .map(|i| u8::try_from(i % 251).expect("small"))
            .collect();
        let mut streamed = PreimageDigest::policy(5000).expect("fits");
        for chunk in policy.chunks(777) {
            streamed.update(chunk).expect("within the declared length");
        }
        assert_eq!(streamed.finalize(), policy_hash(&policy));
        let mut streamed = PreimageDigest::proposal(5000).expect("fits");
        streamed.update(&policy[..4999]).expect("fits");
        assert_eq!(
            streamed.update(&policy[..2]),
            Err(FramingError::FieldOverrun { excess: 1 })
        );
        streamed.update(&policy[4999..]).expect("fits");
        assert_eq!(streamed.finalize(), proposal_digest(&policy));
        let mut short = PreimageDigest::policy(10).expect("fits");
        short.update(b"123").expect("fits");
        assert_eq!(
            short.finalize(),
            Err(FramingError::FieldIncomplete { missing: 7 })
        );
        // The declared length is bounded by the 32-bit field length of Frame.
        assert!(PreimageDigest::policy(0xffff_ffff).is_ok());
        assert_eq!(
            PreimageDigest::policy(0x1_0000_0000).err(),
            Some(FramingError::FieldTooLong {
                actual: 0x1_0000_0000
            })
        );
        assert_eq!(
            PreimageDigest::proposal(u64::MAX).err(),
            Some(FramingError::FieldTooLong { actual: u64::MAX })
        );
    }
}
