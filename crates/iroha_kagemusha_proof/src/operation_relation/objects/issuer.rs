//! Direct scheme-root authorization of issuer-owned signed objects.

use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, UintChip, Word};

use super::{
    ObjectKind, SignedObjectCells,
    predicates::{all, equal, is_constant},
};
use crate::{a_relation::SignatureProofCells, q_signature::SignatureKey};

/// Exact opaque Q slots and the scheme identity being authorized.
pub struct IssuerAuthorization<'a> {
    /// Direct root certificate with the operation's required role.
    pub certificate: &'a SignedObjectCells,
    /// Certificate signature slot with a circuit-fixed scheme-root key.
    pub certificate_proof: &'a SignatureProofCells,
    /// Object signature slot under the delegated certificate key.
    pub object_proof: &'a SignatureProofCells,
    /// Root coordinates constrained against the fixed signature slot.
    pub root_key: &'a [Word<Fp>; 4],
    /// Scheme carried by the authenticated state and lineage.
    pub scheme: &'a [Word<Fp>; 2],
}

/// Authenticate the exact object, signer certificate, scope and required role.
///
/// The fixed object class determines the role and certificate-digest field;
/// neither can be witness-selected. This includes structural validity of both
/// tapes. The operation must additionally require object-specific semantics.
///
/// # Errors
/// A non-issuer object, a non-certificate/root-fixed slot, or layout failure.
pub fn authenticate(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    object: &SignedObjectCells,
    auth: &IssuerAuthorization<'_>,
) -> Result<Bit<Fp>, Error> {
    let (role, index) = match object.kind() {
        ObjectKind::Credential => (1, 28),
        ObjectKind::SchemePolicy | ObjectKind::Blacklist => (3, 6),
        ObjectKind::FeeSchedule | ObjectKind::ChargeQuote => (3, 10),
        ObjectKind::QuotaShare => (3, 9),
        ObjectKind::TimeAnchor => (4, 5),
        _ => return Err(Error::Synthesis),
    };
    let certificate = auth.certificate;
    if certificate.kind() != ObjectKind::Certificate
        || !matches!(auth.certificate_proof.key_policy(), SignatureKey::Fixed(_))
    {
        return Err(Error::Synthesis);
    }
    let checks = [
        object.structural_valid().clone(),
        certificate.structural_valid().clone(),
        is_constant(uint.glue(), region, certificate.word(2)?, role)?,
        equal(uint.glue(), region, certificate.identifier(1)?, auth.scheme)?,
        equal(uint.glue(), region, object.identifier(1)?, auth.scheme)?,
        uint.glue()
            .is_equal(region, object.word(index)?, certificate.digest())?,
        certificate.bind_signature(region, auth.certificate_proof, auth.root_key)?,
        object.bind_signature(region, auth.object_proof, certificate.key(3)?)?,
    ];
    all(uint.glue(), region, &checks)
}
