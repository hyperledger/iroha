//! The registration relation and its proof (evaluation record section 6.3):
//!
//! ```text
//! R_reg(x; sk)  <=>  C    = SHAKE256("PCR1" || P16 || sk || B,     1024 bits)
//!               and  auth = SHAKE256("PAU1" || P16 || sk || D_reg,  512 bits)
//! ```
//!
//! A statement holds exactly the fields of
//!
//! ```text
//! F_REG = Frame("PARL/MU/REG/v1";
//!     Enc(body_context), Enc(network_id), Enc(authority), Enc(assignment_id),
//!     Enc(governance_attempt_id), Enc(election_attempt_id), Enc(body_role),
//!     B, C, auth)
//! ```
//!
//! where `B` is always recomputed from the body context and never taken from the
//! caller; `D_reg` is recomputed likewise with the row's descriptor digest `D`.
//! The proof shows knowledge of a secret behind `C` and `auth`. It does not show
//! registration authority, invitation, eligibility, freshness or uniqueness;
//! those are checks of the caller.
//!
//! Witness (35,840 bits): pad, secret, the eleven committed states of the
//! commitment permutation, the eleven of the authorization permutation.
//! Constraints after Booleanity (36,736): commitment transitions, commitment
//! output (RC), authorization transitions, authorization output (RA).

use iroha_zkp_vole::{
    field::Gf256,
    quicksilver::{ConstraintSystem, Relation},
};
use zeroize::Zeroizing;

use crate::{
    credential::{
        AUTHORIZATION_TAG, COMMITMENT_TAG, CredentialSecret, RegistrationContext, body_digest,
        registration_digest,
    },
    framing::{BodyContext, Commitment, Digest64, frame_bytes},
    keccak_relation::{STATE_BYTES, Scratch, bit_of, emit_transitions, public_block},
    layout::{
        COMMITMENT_BITS, PERMUTATION_OFFSETS, REGISTRATION_RELATION_CONSTRAINTS,
        REGISTRATION_WITNESS_BITS, TAG_BITS,
    },
    profile::{Profile, Role, Row},
    proving::{
        MU_BYTES, PAD_BYTES, ProveError, ProvingTape, StatementError, VerifyError, build_witness,
        message_digest, prove_relation, verify_relation,
    },
};

/// The public statement of a registration proof: the fields of `F_REG`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationStatement {
    body_context: BodyContext,
    context: RegistrationContext,
    /// `B`, computed from `body_context` when the statement is built.
    body_digest: Digest64,
    commitment: Commitment,
    auth: Digest64,
}

impl RegistrationStatement {
    /// The statement with the given opaque inputs, commitment `C` and
    /// authorization value `auth`. `B` is computed here.
    ///
    /// # Errors
    /// Only if a frame cannot be built, which bounded inputs never cause.
    pub fn new(
        body_context: BodyContext,
        context: RegistrationContext,
        commitment: Commitment,
        auth: Digest64,
    ) -> Result<Self, StatementError> {
        let body_digest = body_digest(&body_context)?;
        Ok(Self {
            body_context,
            context,
            body_digest,
            commitment,
            auth,
        })
    }

    /// The statement of the holder of `secret` on the row of `profile`: `C` and
    /// `auth` are computed from the secret.
    ///
    /// # Errors
    /// As [`RegistrationStatement::new`].
    pub fn for_secret(
        profile: &Profile,
        secret: &CredentialSecret,
        body_context: BodyContext,
        context: RegistrationContext,
    ) -> Result<Self, StatementError> {
        let body = body_digest(&body_context)?;
        let commitment = secret.commitment(&body);
        let digest = registration_digest(
            profile.descriptor_digest(),
            &body_context,
            &context,
            &body,
            &commitment,
        )?;
        let auth = secret.authorization(&digest);
        Ok(Self {
            body_context,
            context,
            body_digest: body,
            commitment,
            auth,
        })
    }

    /// `Enc(body_context)`.
    pub const fn body_context(&self) -> &BodyContext {
        &self.body_context
    }

    /// The six other opaque inputs.
    pub const fn context(&self) -> &RegistrationContext {
        &self.context
    }

    /// `B`, the digest of the body context.
    pub const fn body_digest(&self) -> &Digest64 {
        &self.body_digest
    }

    /// The credential commitment `C`.
    pub const fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    /// The authorization value `auth`.
    pub const fn auth(&self) -> &Digest64 {
        &self.auth
    }

    /// `D_reg` of this statement on the row of `profile`.
    ///
    /// # Errors
    /// As [`RegistrationStatement::new`].
    pub fn registration_digest(&self, profile: &Profile) -> Result<Digest64, StatementError> {
        Ok(registration_digest(
            profile.descriptor_digest(),
            &self.body_context,
            &self.context,
            &self.body_digest,
            &self.commitment,
        )?)
    }

    /// `F_REG`.
    ///
    /// # Errors
    /// As [`RegistrationStatement::new`].
    pub fn frame(&self) -> Result<Vec<u8>, StatementError> {
        let [network, authority, assignment, governance, election, role] = self.context.fields();
        Ok(frame_bytes(
            b"PARL/MU/REG/v1",
            &[
                self.body_context.as_bytes(),
                network,
                authority,
                assignment,
                governance,
                election,
                role,
                self.body_digest.as_bytes(),
                self.commitment.as_bytes(),
                self.auth.as_bytes(),
            ],
        )?)
    }

    /// The public validation of the record, and what it derives: the relation's
    /// public input and `mu`.
    ///
    /// # Errors
    /// As [`RegistrationStatement::new`]; the bounds are enforced by the types.
    pub fn instance(&self, profile: &Profile) -> Result<RegistrationInstance, StatementError> {
        let digest = self.registration_digest(profile)?;
        let public = RegistrationPublic {
            commitment_block: public_block(COMMITMENT_TAG, self.body_digest.as_bytes()),
            authorization_block: public_block(AUTHORIZATION_TAG, digest.as_bytes()),
            commitment: self.commitment,
            auth: self.auth,
        };
        let mu = message_digest(profile, Role::Registration, &self.frame()?)?;
        Ok(RegistrationInstance { public, mu })
    }
}

/// What the registration constraints read besides the witness. Public.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationPublic {
    /// The public part of the commitment permutation's initial state (`B`).
    commitment_block: [u8; STATE_BYTES],
    /// The public part of the authorization permutation's initial state (`D_reg`).
    authorization_block: [u8; STATE_BYTES],
    commitment: Commitment,
    auth: Digest64,
}

/// A validated registration statement on one row: the relation's public input
/// and `mu`. Public.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationInstance {
    public: RegistrationPublic,
    mu: [u8; MU_BYTES],
}

impl RegistrationInstance {
    /// The public input of [`RegistrationRelation`].
    pub const fn public(&self) -> &RegistrationPublic {
        &self.public
    }

    /// `mu_REG`.
    pub const fn mu(&self) -> &[u8; MU_BYTES] {
        &self.mu
    }
}

/// The registration relation on the backend's constraint system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegistrationRelation;

impl Relation<Gf256> for RegistrationRelation {
    type PublicInput = RegistrationPublic;

    fn witness_bits(&self) -> usize {
        REGISTRATION_WITNESS_BITS
    }

    fn constraints(&self) -> usize {
        REGISTRATION_RELATION_CONSTRAINTS
    }

    fn emit<C: ConstraintSystem<Field = Gf256>>(&self, public: &RegistrationPublic, cs: &mut C) {
        let mut scratch = Scratch::new(cs.zero());
        let permutations: [(&[u8; STATE_BYTES], &[u8], usize); 2] = [
            (
                &public.commitment_block,
                public.commitment.as_bytes(),
                COMMITMENT_BITS,
            ),
            (
                &public.authorization_block,
                public.auth.as_bytes(),
                TAG_BITS,
            ),
        ];
        for ((block, expected, bits), offset) in permutations.into_iter().zip(PERMUTATION_OFFSETS) {
            emit_transitions(cs, &mut scratch, block, offset, bits);
            // (RC), (RA): O[t] + public bit t.
            for t in 0..bits {
                let constraint = cs.add_bit(scratch.state()[t], bit_of(expected, t));
                cs.constrain(constraint);
            }
        }
    }
}

/// The extended witness of `secret` for `public` with the pad `pad`, in the
/// frozen layout. **Secret**; erased on drop.
///
/// It is a valid witness exactly if `secret` is the secret behind the
/// statement's `C` and `auth`.
pub fn witness(
    public: &RegistrationPublic,
    secret: &CredentialSecret,
    pad: &[u8; PAD_BYTES],
) -> Zeroizing<Vec<u8>> {
    build_witness(
        REGISTRATION_WITNESS_BITS,
        pad,
        secret,
        [&public.commitment_block, &public.authorization_block],
    )
}

/// Prove knowledge of the secret behind `statement` on `row`.
///
/// `tape` is 80 fresh random bytes from the caller's generator; it is consumed
/// and erased, as are the witness and every transient copy of the secret, on
/// success and on every error. The proof is the naked proof of the record:
/// exactly [`Row::proof_bytes`] bytes, no header.
///
/// # Errors
/// * [`ProveError::WitnessRejected`] if `secret` is not the secret of the
///   statement; nothing is derived from the tape then;
/// * [`ProveError::GrindingExhausted`] if no counter is acceptable;
/// * [`ProveError::Statement`] or [`ProveError::Backend`] for a backend without
///   its tables.
pub fn prove(
    row: Row,
    statement: &RegistrationStatement,
    secret: &CredentialSecret,
    tape: ProvingTape,
) -> Result<Vec<u8>, ProveError> {
    let profile = Profile::new(row)?;
    let instance = statement.instance(&profile)?;
    let witness = build_witness(
        REGISTRATION_WITNESS_BITS,
        tape.pad(),
        secret,
        [
            &instance.public.commitment_block,
            &instance.public.authorization_block,
        ],
    );
    prove_relation(
        &profile,
        Role::Registration,
        &RegistrationRelation,
        &instance.public,
        &instance.mu,
        &witness,
        tape,
    )
}

/// Verify a registration proof for `statement` on `row`.
///
/// `proof` is untrusted. The row is the caller's choice and is never detected
/// from the bytes.
///
/// # Errors
/// [`VerifyError::ProofLength`] for any length but the exact one,
/// [`VerifyError::Rejected`] for a proof that does not verify, and
/// [`VerifyError::Statement`] or [`VerifyError::Backend`] for a backend without
/// its tables.
pub fn verify(
    row: Row,
    statement: &RegistrationStatement,
    proof: &[u8],
) -> Result<(), VerifyError> {
    // The length is a constant of the row: refused before the descriptor is
    // compiled.
    crate::proving::check_proof_length(row, Role::Registration, proof)?;
    let profile = Profile::new(row)?;
    let instance = statement.instance(&profile)?;
    verify_relation(
        &profile,
        Role::Registration,
        &RegistrationRelation,
        &instance.public,
        &instance.mu,
        proof,
    )
}

#[cfg(test)]
mod tests {
    use iroha_zkp_vole::quicksilver::{is_satisfied, total_constraints, violated_constraints};

    use super::*;
    use crate::{
        framing::OpaqueField,
        layout::{BlockKind, Permutation, block_of, constraint_blocks},
    };

    fn opaque(bytes: &[u8]) -> OpaqueField {
        OpaqueField::new(bytes).expect("within the bound")
    }

    fn context() -> RegistrationContext {
        RegistrationContext {
            network_id: opaque(b"net"),
            authority: opaque(b"authority"),
            assignment_id: opaque(b"assignment"),
            governance_attempt_id: opaque(b"g-7"),
            election_attempt_id: opaque(b"e-3"),
            body_role: opaque(b"member"),
        }
    }

    fn statement(profile: &Profile, secret: &CredentialSecret) -> RegistrationStatement {
        RegistrationStatement::for_secret(
            profile,
            secret,
            BodyContext::new(b"body").expect("within the bound"),
            context(),
        )
        .expect("statement")
    }

    #[test]
    fn the_relation_has_the_frozen_dimensions() {
        assert_eq!(RegistrationRelation.witness_bits(), 35_840);
        assert_eq!(
            Relation::<Gf256>::constraints(&RegistrationRelation),
            36_736
        );
        assert_eq!(
            total_constraints::<Gf256, _>(&RegistrationRelation),
            Ok(72_576)
        );
        for row in Row::ALL {
            let profile = Profile::new(row).expect("tables");
            let context = profile.context(Role::Registration).expect("context");
            assert_eq!(
                context.proof_bytes::<Gf256, _>(&RegistrationRelation),
                Ok(row.proof_bytes(Role::Registration))
            );
        }
    }

    #[test]
    fn the_statement_derives_b_c_d_reg_and_auth_as_the_record_defines_them() {
        let profile = Profile::new(Row::Candidate).expect("tables");
        let secret = CredentialSecret::from_bytes(&[0x61; 48]);
        let made = statement(&profile, &secret);
        let body = body_digest(made.body_context()).expect("frame");
        assert_eq!(made.body_digest(), &body);
        assert_eq!(made.commitment(), &secret.commitment(&body));
        let digest = made.registration_digest(&profile).expect("frame");
        assert_eq!(
            digest,
            registration_digest(
                profile.descriptor_digest(),
                made.body_context(),
                made.context(),
                &body,
                made.commitment()
            )
            .expect("frame")
        );
        assert_eq!(made.auth(), &secret.authorization(&digest));
        // The same fields through the plain constructor give the same statement.
        let rebuilt = RegistrationStatement::new(
            made.body_context().clone(),
            made.context().clone(),
            *made.commitment(),
            *made.auth(),
        )
        .expect("statement");
        assert_eq!(rebuilt, made);
        // The comparator row has another descriptor, hence another D_reg and auth.
        let other = statement(&Profile::new(Row::Comparator).expect("tables"), &secret);
        assert_eq!(other.commitment(), made.commitment());
        assert_ne!(other.auth(), made.auth());
        // F_REG: ten fields in the stated order.
        let frame = made.frame().expect("frame");
        assert!(
            frame.starts_with(
                b"\x0e\x00PARL/MU/REG/v1\x0a\x00\x04\x00\x00\x00body\x03\x00\x00\x00net"
            )
        );
        assert!(frame.ends_with(made.auth().as_bytes()));
        let instance = made.instance(&profile).expect("instance");
        assert_eq!(
            instance.mu(),
            &message_digest(&profile, Role::Registration, &frame).expect("mu")
        );
        assert_eq!(instance.public().commitment, *made.commitment());
        assert_eq!(
            &instance.public().commitment_block[68..132],
            body.as_bytes()
        );
        assert_eq!(
            &instance.public().authorization_block[68..132],
            digest.as_bytes()
        );
        assert_eq!(&instance.public().authorization_block[..4], b"PAU1");
    }

    #[test]
    fn the_honest_witness_satisfies_the_relation_and_others_do_not() {
        let profile = Profile::new(Row::Candidate).expect("tables");
        let secret = CredentialSecret::from_bytes(&[0x61; 48]);
        let instance = statement(&profile, &secret)
            .instance(&profile)
            .expect("instance");
        let honest = witness(instance.public(), &secret, &[0x9e; 32]);
        assert_eq!(honest.len(), 4480);
        assert_eq!(
            is_satisfied::<Gf256, _>(&RegistrationRelation, instance.public(), &honest),
            Ok(true)
        );
        // Another secret fails exactly the two outputs.
        let other = CredentialSecret::from_bytes(&[0x62; 48]);
        let wrong = witness(instance.public(), &other, &[0x9e; 32]);
        let blocks = constraint_blocks(Role::Registration);
        let mut kinds: Vec<BlockKind> =
            violated_constraints::<Gf256, _>(&RegistrationRelation, instance.public(), &wrong)
                .expect("well-formed")
                .into_iter()
                .filter_map(|index| block_of(&blocks, index))
                .collect();
        kinds.dedup();
        assert_eq!(
            kinds,
            [
                BlockKind::Output {
                    permutation: Permutation::Commitment
                },
                BlockKind::Output {
                    permutation: Permutation::Authorization
                }
            ]
        );
    }
}
