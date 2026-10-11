//! Credential evidence, scope, certificate authorization and renewal continuity.
//!
//! The issuer attests identity derivation and original platform evidence. Per
//! the construction's OQ-1 scope rule, A carries wallet/enrollment/account
//! identities without recomputing their SHA-256 preimages. A proves the exact
//! signed evidence fields, allowed facts, policy and payment-key continuity.

use ff::Field;
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, UintChip, Word};

use super::{
    ObjectKind, SignedObjectCells,
    predicates::{all, bits32, equal, implies, is_constant, le64, nonzero},
};
use crate::{
    a_relation::{LineagePublicCells, SignatureProofCells},
    operation_relation::state::{StateCells, rest_index},
    witness::core_index,
};

/// Credential cells with a total structural and semantic verdict.
/// The constructor alone does not authenticate the issuer or payment key.
#[derive(Clone, Debug)]
pub struct CredentialCells {
    object: SignedObjectCells,
    valid: Bit<Fp>,
}

/// Certificate-chain inputs from the fixed Q signature plan and scheme scope.
pub struct CredentialAuthorization<'a> {
    /// Direct scheme-root certificate naming the Enrollment signer.
    pub certificate: &'a SignedObjectCells,
    /// Verified certificate signature slot, with the scheme root pinned in Q.
    pub certificate_proof: &'a SignatureProofCells,
    /// Verified credential signature slot under the certificate's delegated key.
    pub credential_proof: &'a SignatureProofCells,
    /// Exact scheme-root coordinates, constrained to the fixed Q root key.
    pub root_key: &'a [Word<Fp>; 4],
    /// Scheme identity carried by the state/lineage relation.
    pub scheme: &'a [Word<Fp>; 2],
    /// Scheme's fixed provider contract identity.
    pub provider: &'a [Word<Fp>; 2],
}

impl CredentialCells {
    /// Check the credential's non-cryptographic fields with a total verdict.
    ///
    /// Invalid evidence kinds, fact masks, policy and renewal fields export
    /// false without making an incoming invalid-payment branch impossible.
    /// P-256 key validity is enforced by the linked signature verifier; identity
    /// SHA derivations are issuer responsibilities in the accepted construction.
    ///
    /// # Errors
    /// Wrong fixed object class or layout failure.
    pub fn check(
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        object: &SignedObjectCells,
    ) -> Result<Self, Error> {
        if object.kind() != ObjectKind::Credential {
            return Err(Error::Synthesis);
        }
        let mut checks = vec![object.structural_valid().clone()];
        for index in [1, 2, 3, 4, 8, 14, 20, 24] {
            checks.push(nonzero(uint.glue(), region, object.identifier(index)?)?);
        }
        checks.push(nonzero(
            uint.glue(),
            region,
            core::slice::from_ref(object.word(28)?),
        )?);
        let kinds = [1, 2, 3]
            .map(|kind| is_constant(uint.glue(), region, object.word(7)?, kind))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        let kind_sum = uint.glue().linear(
            region,
            &kinds
                .iter()
                .map(|bit| (Fp::ONE, bit.word()))
                .collect::<Vec<_>>(),
            Fp::ZERO,
        )?;
        checks.push(is_constant(uint.glue(), region, &kind_sum, 1)?);
        let android_word = uint.glue().add(region, kinds[0].word(), kinds[1].word())?;
        let android = uint.glue().assert_bool(region, &android_word)?;
        for (index, enrollment) in [(10, true), (16, false)] {
            let facts = bits32(uint, region, object.word(index)?)?;
            let undefined = facts[12..]
                .iter()
                .map(|bit| uint.glue().not(region, bit))
                .collect::<Result<Vec<_>, _>>()?;
            checks.push(all(uint.glue(), region, &undefined)?);
            for (kind, forbidden) in [
                (&android, &[6_usize, 7, 8][..]),
                (&kinds[2], &[0_usize, 1, 2, 3, 4, 5, 9][..]),
            ] {
                for index in forbidden {
                    let absent = uint.glue().not(region, &facts[*index])?;
                    checks.push(implies(uint.glue(), region, kind, &absent)?);
                }
            }
            for index in index + 1..index + 4 {
                let zero = is_constant(uint.glue(), region, object.word(index)?, 0)?;
                checks.push(implies(uint.glue(), region, &kinds[2], &zero)?);
            }
            if enrollment {
                for (kind, required) in [
                    (&android, &[0_usize, 2, 3, 5][..]),
                    (&kinds[1], &[1_usize][..]),
                    (&kinds[2], &[6_usize, 7][..]),
                ] {
                    for index in required {
                        checks.push(implies(uint.glue(), region, kind, &facts[*index])?);
                    }
                }
                let no_strongbox = uint.glue().not(region, &facts[1])?;
                checks.push(implies(uint.glue(), region, &kinds[0], &no_strongbox)?);
            }
        }
        let first = is_constant(uint.glue(), region, object.word(26)?, 0)?;
        for index in 8..14 {
            let unchanged = equal(
                uint.glue(),
                region,
                &object.fields()[index],
                &object.fields()[index + 6],
            )?;
            checks.push(implies(uint.glue(), region, &first, &unchanged)?);
        }
        checks.push(le64(uint, region, object.word(9)?, object.word(15)?)?);
        let controls = bits32(uint, region, object.word(21)?)?;
        let undefined = controls[3..]
            .iter()
            .map(|bit| uint.glue().not(region, bit))
            .collect::<Result<Vec<_>, _>>()?;
        checks.push(all(uint.glue(), region, &undefined)?);
        let has_age = nonzero(uint.glue(), region, core::slice::from_ref(object.word(22)?))?;
        checks.push(implies(uint.glue(), region, &has_age, &controls[0])?);
        let time_rules = [
            controls[1].word().clone(),
            controls[2].word().clone(),
            has_age.word().clone(),
        ];
        let time_required = nonzero(uint.glue(), region, &time_rules)?;
        let response = nonzero(uint.glue(), region, core::slice::from_ref(object.word(23)?))?;
        checks.push(
            uint.glue()
                .is_equal(region, time_required.word(), response.word())?,
        );
        let lease = nonzero(uint.glue(), region, core::slice::from_ref(object.word(27)?))?;
        checks.push(
            uint.glue()
                .is_equal(region, controls[2].word(), lease.word())?,
        );
        let valid = all(uint.glue(), region, &checks)?;
        Ok(Self {
            object: object.clone(),
            valid,
        })
    }

    /// Same-tape signed credential cells.
    pub const fn object(&self) -> &SignedObjectCells {
        &self.object
    }
    /// Total self-contained verdict; not issuer authentication by itself.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }
    /// Exact payment-key coordinates for receipt and Request signature slots.
    ///
    /// # Errors
    /// A fixed-schema inconsistency (never selected by private bytes).
    pub fn payment_key(&self) -> Result<&[Word<Fp>; 4], Error> {
        self.object.key(5)
    }
    /// Canonical account digest carried under the issuer signature.
    ///
    /// # Errors
    /// A fixed-schema inconsistency.
    pub fn account(&self) -> Result<&[Word<Fp>; 2], Error> {
        self.object.identifier(4)
    }

    /// Authenticate this credential under the direct Enrollment certificate.
    ///
    /// Includes structure, evidence rules, exact issuer digest, certificate role
    /// and scheme/provider scopes. Both proof inputs are tied to their original
    /// object bytes. The returned bit must be required by the owning relation.
    ///
    /// # Errors
    /// Wrong fixed certificate class or layout failure.
    pub fn authenticate(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        authorization: &CredentialAuthorization<'_>,
    ) -> Result<Bit<Fp>, Error> {
        let issuer = super::issuer::authenticate(
            uint,
            region,
            &self.object,
            &super::issuer::IssuerAuthorization {
                certificate: authorization.certificate,
                certificate_proof: authorization.certificate_proof,
                object_proof: authorization.credential_proof,
                root_key: authorization.root_key,
                scheme: authorization.scheme,
            },
        )?;
        let provider = equal(
            uint.glue(),
            region,
            self.object.identifier(6)?,
            authorization.provider,
        )?;
        all(uint.glue(), region, &[self.valid.clone(), issuer, provider])
    }

    /// Bind the authenticated current credential to the state and lineage.
    ///
    /// Return value includes this credential's total semantic verdict. This
    /// does not replace `authenticate` or the state's head/lineage binding.
    ///
    /// # Errors
    /// Layout failure.
    pub fn bind_current(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        state: &StateCells,
        lineage: &LineagePublicCells,
    ) -> Result<Bit<Fp>, Error> {
        let core = state.core();
        let mut checks = vec![self.valid.clone()];
        for (field, offset) in [
            (1, core_index::SCHEME),
            (2, core_index::ASSET),
            (3, core_index::WALLET),
        ] {
            checks.push(equal(
                uint.glue(),
                region,
                self.object.identifier(field)?,
                &core[offset..offset + 2],
            )?);
        }
        for (field, expected) in [
            (21, &state.rest()[rest_index::PERMITTED]),
            (22, &core[core_index::BLACKLIST_MAX_AGE]),
            (23, &core[core_index::TIME_ANCHOR_MAX_RESPONSE]),
            (27, &core[core_index::LEASE_EXPIRY]),
        ] {
            checks.push(
                uint.glue()
                    .is_equal(region, self.object.word(field)?, expected)?,
            );
        }
        checks.push(uint.glue().is_equal(
            region,
            self.object.digest(),
            &core[core_index::CREDENTIAL],
        )?);
        checks.push(equal(
            uint.glue(),
            region,
            self.payment_key()?,
            &lineage.fields()[9..13],
        )?);
        all(uint.glue(), region, &checks)
    }

    /// Enforce the native renewal continuity as a total predicate.
    ///
    /// Only fresh evidence, issue time, lease and issuer certificate may change;
    /// the u32 renewal counter advances exactly once without wraparound.
    /// Both credentials must also be authenticated by the operation.
    ///
    /// # Errors
    /// Layout failure.
    pub fn replacement_of(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        previous: &Self,
    ) -> Result<Bit<Fp>, Error> {
        let mut checks = vec![self.valid.clone(), previous.valid.clone()];
        for index in 0..29 {
            if (14..20).contains(&index) || [25, 26, 27, 28].contains(&index) {
                continue;
            }
            checks.push(equal(
                uint.glue(),
                region,
                &self.object.fields()[index],
                &previous.object.fields()[index],
            )?);
        }
        // u32 source and destination came from the same fixed byte tapes; the
        // unbounded field sum cannot wrap Fp, so max-u32 has no successor.
        let successor = uint
            .glue()
            .add_constant(region, previous.object.word(26)?, Fp::ONE)?;
        checks.push(
            uint.glue()
                .is_equal(region, self.object.word(26)?, &successor)?,
        );
        all(uint.glue(), region, &checks)
    }
}
