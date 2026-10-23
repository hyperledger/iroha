//! Exact native algebra and transcript framing for ZK-AMS Phases II and III.
//!
//! The helpers here implement the field-level Equations (6), (8)--(11) that
//! both the encrypted path and the final cleartext checker must share.  They do
//! not treat the implemented encrypted and terminal mechanics as evidence for
//! the still-missing hidden-mask opening relation.  The equation certificate
//! binds both the implemented mechanics and the exact fail-closed mask-proof
//! audit, so the release gate cannot be opened by stale coarse booleans.
#[cfg(test)]
use super::shake256;
#[cfg(test)]
use super::{Scalar, ZkAmsMkheErrorV1};
use super::{
    manifest::release_profile_v1, phase23_encrypted::zk_ams_phase23_encrypted_implementation_v1,
    phase23_mask_proof::zk_ams_phase23_mask_proof_audit_v1,
    terminal::zk_ams_phase3_terminal_implementation_v1,
};
#[cfg(test)]
const MAX_PHASE23_VECTOR_ELEMENTS_V1: usize = 1_048_576;
const PHASE23_MAX_BATCH_SIZE_V1: u8 = 8;
const PHASE23_ASSIGNMENT_COLUMNS_V1: u32 = 524_378;
const PHASE23_CONSTRAINT_ROWS_V1: u32 = 1_048_576;
const EQUATION_6_SCHEMA_V1: &[u8] =
    b"T=(AZ_acc)*(BZ_i)+(AZ_i)*(BZ_acc)-u_acc*(CZ_i)-u_i*(CZ_acc):componentwise:t256";
const EQUATION_7_SCHEMA_V1: &[u8] = b"Tbar=G_T*r_T+H_T*T:additive-module-commitment:t256";
const EQUATIONS_9_10_SCHEMA_V1: &[u8] =
    b"x,u,W,rW:=acc+v*incoming|E:=acc+v*T+v^2*incoming|rE:=acc+v*rT+v^2*incoming:t256";
const EQUATION_11_SCHEMA_V1: &[u8] =
    b"Ebar:=Ebar_acc+v*Tbar+v^2*Ebar_i|Wbar:=Wbar_acc+v*Wbar_i:t256";
const PHASE3_CHECKER_SCHEMA_V1: &[u8] = b"padding-fold:fixed-governed-instance|C1:commitment-openings+(AZ)*(BZ)=u*(CZ)+E|C2:transcript+padding+terminal-proof";
/// Fixed public material from which one folding challenge is derived.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsPhase23ChallengeContextV1 {
    /// Nonzero governed batch identifier.
    pub batch_id: [u8; 32],
    /// Digest of the exact NIFS verifier profile.
    pub nifs_verifier_digest: [u8; 32],
    /// Digest of the exact ordered settlement input list.
    pub ordered_batch_input_digest: [u8; 32],
    /// Accumulated public error commitment.
    pub accumulated_error_commitment_digest: [u8; 32],
    /// Accumulated public witness commitment.
    pub accumulated_witness_commitment_digest: [u8; 32],
    /// Incoming public error commitment.
    pub incoming_error_commitment_digest: [u8; 32],
    /// Incoming public witness commitment.
    pub incoming_witness_commitment_digest: [u8; 32],
    /// Public commitment to the hidden cross term.
    pub cross_term_commitment_digest: [u8; 32],
    /// One-based fold index in the canonical ordered batch.
    pub fold_index: u8,
}
/// Digestible closure state for the Phase-II/III algebraic obligations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsPhase23EquationCertificateV1 {
    /// Certificate schema version.
    pub version: u8,
    /// Maximum admitted batch size.
    pub max_batch_size: u8,
    /// Exact `Z=(W,x,u)` column count of the compiled admission relation.
    pub assignment_columns: u32,
    /// Exact padded row count of the compiled admission relation.
    pub constraint_rows: u32,
    /// Digest of the exact Equation (6) cross-term algebra.
    pub equation_6_digest: [u8; 32],
    /// Digest of the exact Equation (7) commitment algebra.
    pub equation_7_digest: [u8; 32],
    /// Digest of the exact Equations (9)--(10) private-state folds.
    pub equations_9_10_digest: [u8; 32],
    /// Digest of the exact Equation (11) public commitment folds.
    pub equation_11_digest: [u8; 32],
    /// Digest of the required padding/C1/C2 finalization relation.
    pub phase3_checker_digest: [u8; 32],
    /// Digest of the native encrypted Phase-II/III implementation identity.
    pub encrypted_implementation_digest: [u8; 32],
    /// Digest of the native Phase-III terminal implementation identity.
    pub terminal_implementation_digest: [u8; 32],
    /// Packed encrypted A/B/C linear maps have a native checked implementation.
    pub encrypted_sparse_maps_complete: bool,
    /// Compact collective multiplication/relinearization has a native checked implementation.
    pub encrypted_cross_term_complete: bool,
    /// Equation (7) module commitment is parameterized and implemented.
    pub encrypted_commitment_complete: bool,
    /// All six final accumulator families have canonical checked materialization.
    pub accumulator_materialization_complete: bool,
    /// Fixed padding, C1, and transcript-bound C2 finalization are implemented.
    pub padding_and_final_proof_complete: bool,
    /// The encrypted hidden masks have a complete release-sound opening proof.
    pub hidden_mask_proof_complete: bool,
    /// Exact blocker mask reported by the hidden-mask proof audit.
    pub hidden_mask_proof_blocker_mask: u8,
    /// Digest of the complete hidden-mask proof audit and its blockers.
    pub hidden_mask_proof_audit_digest: [u8; 32],
}
impl ZkAmsPhase23EquationCertificateV1 {
    /// Return true only when every encrypted and finalization obligation is
    /// implemented in addition to the shared native algebra.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.encrypted_sparse_maps_complete
            && digest_is_nonzero(self.encrypted_implementation_digest)
            && digest_is_nonzero(self.terminal_implementation_digest)
            && self.encrypted_cross_term_complete
            && self.encrypted_commitment_complete
            && self.accumulator_materialization_complete
            && self.padding_and_final_proof_complete
            && self.hidden_mask_proof_complete
            && self.hidden_mask_proof_blocker_mask == 0
            && digest_is_nonzero(self.hidden_mask_proof_audit_digest)
    }
}
const fn digest_is_nonzero(digest: [u8; 32]) -> bool {
    let mut index = 0;
    while index < digest.len() {
        if digest[index] != 0 {
            return true;
        }
        index += 1;
    }
    false
}
/// Return a digestible description of the exact shared algebra, implemented
/// mechanics, and fail-closed hidden-mask proof gate.
#[must_use]
pub fn zk_ams_phase23_equation_certificate_v1() -> ZkAmsPhase23EquationCertificateV1 {
    let encrypted_implementation = zk_ams_phase23_encrypted_implementation_v1();
    let terminal_implementation = zk_ams_phase3_terminal_implementation_v1();
    let encrypted_mechanics_complete = encrypted_implementation.version == 1
        && encrypted_implementation.algebra_digest != [0; 32]
        && encrypted_implementation.digest != [0; 32];
    let terminal_mechanics_complete = terminal_implementation.version == 1
        && terminal_implementation.c1_schema_digest != [0; 32]
        && terminal_implementation.c2_schema_digest != [0; 32]
        && terminal_implementation.digest != [0; 32];
    let (
        hidden_mask_proof_complete,
        hidden_mask_proof_blocker_mask,
        hidden_mask_proof_audit_digest,
    ) = match zk_ams_phase23_mask_proof_audit_v1(&release_profile_v1()) {
        Ok(audit) => (audit.release_available, audit.blocker_mask, audit.digest),
        // A future malformed profile or audit failure must remain visibly
        // distinct from a complete proof and can never open this gate.
        Err(_) => (false, u8::MAX, [0; 32]),
    };
    ZkAmsPhase23EquationCertificateV1 {
        version: 1,
        max_batch_size: PHASE23_MAX_BATCH_SIZE_V1,
        assignment_columns: PHASE23_ASSIGNMENT_COLUMNS_V1,
        constraint_rows: PHASE23_CONSTRAINT_ROWS_V1,
        equation_6_digest: super::native_outer_schema_v1(
            b"iroha.zk-ams.v1.phase23.equation-6-schema",
            EQUATION_6_SCHEMA_V1,
        ),
        equation_7_digest: super::native_outer_schema_v1(
            b"iroha.zk-ams.v1.phase23.equation-7-schema",
            EQUATION_7_SCHEMA_V1,
        ),
        equations_9_10_digest: super::native_outer_schema_v1(
            b"iroha.zk-ams.v1.phase23.equations-9-10-schema",
            EQUATIONS_9_10_SCHEMA_V1,
        ),
        equation_11_digest: super::native_outer_schema_v1(
            b"iroha.zk-ams.v1.phase23.equation-11-schema",
            EQUATION_11_SCHEMA_V1,
        ),
        phase3_checker_digest: super::native_outer_schema_v1(
            b"iroha.zk-ams.v1.phase23.phase3-checker-schema",
            PHASE3_CHECKER_SCHEMA_V1,
        ),
        encrypted_implementation_digest: encrypted_implementation.digest,
        terminal_implementation_digest: terminal_implementation.digest,
        encrypted_sparse_maps_complete: encrypted_mechanics_complete,
        encrypted_cross_term_complete: encrypted_mechanics_complete,
        encrypted_commitment_complete: encrypted_mechanics_complete,
        accumulator_materialization_complete: encrypted_mechanics_complete,
        padding_and_final_proof_complete: terminal_mechanics_complete,
        hidden_mask_proof_complete,
        hidden_mask_proof_blocker_mask,
        hidden_mask_proof_audit_digest,
    }
}
/// Return the consensus digest of the shared algebra and every open closure bit.
#[must_use]
pub fn zk_ams_phase23_equation_certificate_digest_v1() -> [u8; 32] {
    let certificate = zk_ams_phase23_equation_certificate_v1();
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        b"iroha.zk-ams.v1.phase23.equation-certificate",
        13,
    );
    hash.push_field(&[certificate.version])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[certificate.max_batch_size])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.assignment_columns.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.constraint_rows.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.equation_6_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.equation_7_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.equations_9_10_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.equation_11_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.phase3_checker_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.encrypted_implementation_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.terminal_implementation_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[
        certificate.encrypted_sparse_maps_complete.into(),
        certificate.encrypted_cross_term_complete.into(),
        certificate.encrypted_commitment_complete.into(),
        certificate.accumulator_materialization_complete.into(),
        certificate.padding_and_final_proof_complete.into(),
        certificate.hidden_mask_proof_complete.into(),
        certificate.hidden_mask_proof_blocker_mask,
    ])
    .expect("fixed bounded MKHE identity field");
    hash.push_field(&certificate.hidden_mask_proof_audit_digest)
        .expect("fixed bounded MKHE identity field");
    *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes()
}
/// Evaluate the exact Equation (6) cross term component-wise.
#[cfg(test)]
#[allow(
    clippy::too_many_arguments,
    reason = "Equation (6) has four explicit accumulated and incoming operands"
)]
pub fn zk_ams_phase23_cross_term_v1(
    az_accumulated: &[Scalar],
    bz_accumulated: &[Scalar],
    cz_accumulated: &[Scalar],
    u_accumulated: Scalar,
    az_incoming: &[Scalar],
    bz_incoming: &[Scalar],
    cz_incoming: &[Scalar],
    u_incoming: Scalar,
) -> Result<Vec<Scalar>, ZkAmsMkheErrorV1> {
    let length = require_same_nonzero_length(&[
        az_accumulated,
        bz_accumulated,
        cz_accumulated,
        az_incoming,
        bz_incoming,
        cz_incoming,
    ])?;
    let mut cross_term = Vec::with_capacity(length);
    for index in 0..length {
        cross_term.push(
            az_accumulated[index] * bz_incoming[index] + az_incoming[index] * bz_accumulated[index]
                - u_accumulated * cz_incoming[index]
                - u_incoming * cz_accumulated[index],
        );
    }
    Ok(cross_term)
}
/// Fold a level-zero vector as `accumulated + challenge * incoming`.
#[cfg(test)]
pub fn zk_ams_phase23_fold_linear_v1(
    accumulated: &[Scalar],
    incoming: &[Scalar],
    challenge: Scalar,
) -> Result<Vec<Scalar>, ZkAmsMkheErrorV1> {
    require_nondegenerate_challenge(challenge)?;
    require_same_nonzero_length(&[accumulated, incoming])?;
    Ok(accumulated
        .iter()
        .copied()
        .zip(incoming.iter().copied())
        .map(|(left, right)| left + challenge * right)
        .collect())
}
/// Fold a level-one vector as
/// `accumulated + challenge * cross_term + challenge^2 * incoming`.
#[cfg(test)]
pub fn zk_ams_phase23_fold_quadratic_v1(
    accumulated: &[Scalar],
    cross_term: &[Scalar],
    incoming: &[Scalar],
    challenge: Scalar,
) -> Result<Vec<Scalar>, ZkAmsMkheErrorV1> {
    require_nondegenerate_challenge(challenge)?;
    require_same_nonzero_length(&[accumulated, cross_term, incoming])?;
    let challenge_squared = challenge.square();
    Ok(accumulated
        .iter()
        .copied()
        .zip(cross_term.iter().copied())
        .zip(incoming.iter().copied())
        .map(|((accumulator, cross), fresh)| {
            accumulator + challenge * cross + challenge_squared * fresh
        })
        .collect())
}
/// Derive the full-field Equation (8) challenge from a fixed-width frame.
#[cfg(test)]
pub fn zk_ams_phase23_challenge_v1(
    context: ZkAmsPhase23ChallengeContextV1,
) -> Result<Scalar, ZkAmsMkheErrorV1> {
    if context.fold_index == 0
        || context.fold_index > PHASE23_MAX_BATCH_SIZE_V1
        || [
            context.batch_id,
            context.nifs_verifier_digest,
            context.ordered_batch_input_digest,
            context.accumulated_error_commitment_digest,
            context.accumulated_witness_commitment_digest,
            context.incoming_error_commitment_digest,
            context.incoming_witness_commitment_digest,
            context.cross_term_commitment_digest,
        ]
        .contains(&[0; 32])
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    let mut frame = Vec::with_capacity(320);
    frame.extend_from_slice(b"iroha.zk-ams.v1.phase23.equation-8");
    frame.extend_from_slice(&context.batch_id);
    frame.extend_from_slice(&context.nifs_verifier_digest);
    frame.extend_from_slice(&context.ordered_batch_input_digest);
    frame.extend_from_slice(&context.accumulated_error_commitment_digest);
    frame.extend_from_slice(&context.accumulated_witness_commitment_digest);
    frame.extend_from_slice(&context.incoming_error_commitment_digest);
    frame.extend_from_slice(&context.incoming_witness_commitment_digest);
    frame.extend_from_slice(&context.cross_term_commitment_digest);
    frame.push(context.fold_index);
    let uniform: [u8; 64] = shake256(&frame, 64)
        .try_into()
        .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
    let challenge = Scalar::from_uniform_le_bytes(uniform);
    require_nondegenerate_challenge(challenge)?;
    Ok(challenge)
}
#[cfg(test)]
fn require_same_nonzero_length(vectors: &[&[Scalar]]) -> Result<usize, ZkAmsMkheErrorV1> {
    let Some(first) = vectors.first() else {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    };
    let length = first.len();
    if length == 0
        || length > MAX_PHASE23_VECTOR_ELEMENTS_V1
        || vectors.iter().any(|vector| vector.len() != length)
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    Ok(length)
}
#[cfg(test)]
fn require_nondegenerate_challenge(challenge: Scalar) -> Result<(), ZkAmsMkheErrorV1> {
    if challenge.is_zero() {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn s(value: u64) -> Scalar {
        Scalar::from_u64(value)
    }
    fn challenge_context() -> ZkAmsPhase23ChallengeContextV1 {
        ZkAmsPhase23ChallengeContextV1 {
            batch_id: [1; 32],
            nifs_verifier_digest: [2; 32],
            ordered_batch_input_digest: [3; 32],
            accumulated_error_commitment_digest: [4; 32],
            accumulated_witness_commitment_digest: [5; 32],
            incoming_error_commitment_digest: [6; 32],
            incoming_witness_commitment_digest: [7; 32],
            cross_term_commitment_digest: [8; 32],
            fold_index: 2,
        }
    }
    #[test]
    fn equations_6_9_10_and_11_match_independent_scalar_expansion() {
        let az_acc = [s(2), s(3), s(5)];
        let bz_acc = [s(7), s(11), s(13)];
        let cz_acc = [s(17), s(19), s(23)];
        let az_in = [s(29), s(31), s(37)];
        let bz_in = [s(41), s(43), s(47)];
        let cz_in = [s(53), s(59), s(61)];
        let cross = zk_ams_phase23_cross_term_v1(
            &az_acc,
            &bz_acc,
            &cz_acc,
            s(67),
            &az_in,
            &bz_in,
            &cz_in,
            s(71),
        )
        .expect("Equation 6");
        for index in 0..cross.len() {
            assert_eq!(
                cross[index],
                az_acc[index] * bz_in[index] + az_in[index] * bz_acc[index]
                    - s(67) * cz_in[index]
                    - s(71) * cz_acc[index]
            );
        }
        let challenge = s(73);
        assert_eq!(
            zk_ams_phase23_fold_linear_v1(&az_acc, &az_in, challenge).unwrap(),
            (0..3)
                .map(|index| az_acc[index] + challenge * az_in[index])
                .collect::<Vec<_>>()
        );
        assert_eq!(
            zk_ams_phase23_fold_quadratic_v1(&cz_acc, &cross, &cz_in, challenge).unwrap(),
            (0..3)
                .map(|index| {
                    cz_acc[index] + challenge * cross[index] + challenge.square() * cz_in[index]
                })
                .collect::<Vec<_>>()
        );
    }
    #[test]
    fn every_challenge_binding_changes_equation_8_and_invalid_frames_fail_closed() {
        let baseline = challenge_context();
        let expected = zk_ams_phase23_challenge_v1(baseline).expect("challenge");
        for field in 0..9 {
            let mut changed = baseline;
            match field {
                0 => changed.batch_id[0] ^= 1,
                1 => changed.nifs_verifier_digest[0] ^= 1,
                2 => changed.ordered_batch_input_digest[0] ^= 1,
                3 => changed.accumulated_error_commitment_digest[0] ^= 1,
                4 => changed.accumulated_witness_commitment_digest[0] ^= 1,
                5 => changed.incoming_error_commitment_digest[0] ^= 1,
                6 => changed.incoming_witness_commitment_digest[0] ^= 1,
                7 => changed.cross_term_commitment_digest[0] ^= 1,
                8 => changed.fold_index += 1,
                _ => unreachable!(),
            }
            assert_ne!(zk_ams_phase23_challenge_v1(changed).unwrap(), expected);
        }
        for invalid in [
            ZkAmsPhase23ChallengeContextV1 {
                batch_id: [0; 32],
                ..baseline
            },
            ZkAmsPhase23ChallengeContextV1 {
                fold_index: 0,
                ..baseline
            },
            ZkAmsPhase23ChallengeContextV1 {
                fold_index: 9,
                ..baseline
            },
        ] {
            assert_eq!(
                zk_ams_phase23_challenge_v1(invalid),
                Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
            );
        }
    }
    #[test]
    fn malformed_vector_shapes_and_zero_challenges_fail_before_arithmetic() {
        assert_eq!(
            zk_ams_phase23_cross_term_v1(&[], &[], &[], s(1), &[], &[], &[], s(1)),
            Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
        );
        assert_eq!(
            zk_ams_phase23_cross_term_v1(
                &[s(1)],
                &[s(1), s(2)],
                &[s(1)],
                s(1),
                &[s(1)],
                &[s(1)],
                &[s(1)],
                s(1),
            ),
            Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
        );
        assert_eq!(
            zk_ams_phase23_fold_linear_v1(&[s(1)], &[s(2)], Scalar::zero()),
            Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
        );
        assert_eq!(
            zk_ams_phase23_fold_quadratic_v1(&[s(1)], &[s(2)], &[s(3)], Scalar::zero(),),
            Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
        );
    }
    #[test]
    fn equation_certificate_binds_implemented_mechanics_and_exact_mask_blockers() {
        let certificate = zk_ams_phase23_equation_certificate_v1();
        assert_eq!(certificate.assignment_columns, 524_378);
        assert_eq!(certificate.constraint_rows, 1_048_576);
        for digest in [
            certificate.equation_6_digest,
            certificate.equation_7_digest,
            certificate.equations_9_10_digest,
            certificate.equation_11_digest,
            certificate.phase3_checker_digest,
        ] {
            assert_ne!(digest, [0; 32]);
        }
        assert!(certificate.encrypted_sparse_maps_complete);
        assert!(certificate.encrypted_cross_term_complete);
        assert!(certificate.encrypted_commitment_complete);
        assert!(certificate.accumulator_materialization_complete);
        assert!(certificate.padding_and_final_proof_complete);
        assert_eq!(
            certificate.encrypted_implementation_digest,
            zk_ams_phase23_encrypted_implementation_v1().digest
        );
        assert_eq!(
            certificate.terminal_implementation_digest,
            zk_ams_phase3_terminal_implementation_v1().digest
        );
        assert!(!certificate.hidden_mask_proof_complete);
        assert_eq!(certificate.hidden_mask_proof_blocker_mask, 0b1111);
        assert_ne!(certificate.hidden_mask_proof_audit_digest, [0; 32]);
        let mask_audit = zk_ams_phase23_mask_proof_audit_v1(&release_profile_v1()).unwrap();
        assert_eq!(
            certificate.hidden_mask_proof_blocker_mask,
            mask_audit.blocker_mask
        );
        assert_eq!(
            certificate.hidden_mask_proof_audit_digest,
            mask_audit.digest
        );
        assert_ne!(zk_ams_phase23_equation_certificate_digest_v1(), [0; 32]);
        assert!(!certificate.is_complete());
    }
}
