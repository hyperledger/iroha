//! Request credit identity, account ownership and receiver-key continuity.

use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, UintChip, Word, WordHasher};
use iroha_plonk_recursion::obligation::ledger::Variant;

use super::{
    ObjectKind, SignedObjectCells,
    credential::CredentialCells,
    predicates::{all, equal, implies, nonzero, sum_fits128},
};
use crate::{
    a_relation::{LineagePublicCells, SignatureProofCells},
    operation_relation::{incoming_statement::StatementView, statement::StatementCells},
};

/// A Request parsed from one exact signed byte tape and its total verdict.
#[derive(Clone, Debug)]
pub struct RequestCells {
    object: SignedObjectCells,
    fields: [Word<Fp>; 26],
    credit: Word<Fp>,
    valid: Bit<Fp>,
}
impl RequestCells {
    /// Check self-contained Request rules and compute its 26-element credit ID.
    ///
    /// This includes overflow, canonical field/identity rules, policy and recorded
    /// blacklist pairs. Certificate, fee, signature and operation bindings are
    /// separate. In particular this never substitutes the current blacklist.
    ///
    /// # Errors
    /// Wrong fixed object class or layout failure.
    pub fn check(
        uint: &mut UintChip<'_, Fp>,
        hash: &mut impl WordHasher<Fp>,
        region: &mut Region<'_, Fp>,
        object: &SignedObjectCells,
    ) -> Result<Self, Error> {
        if object.kind() != ObjectKind::Request {
            return Err(Error::Synthesis);
        }
        let fields: [Word<Fp>; 26] = object
            .fields()
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let credit = hash.hash_words(region, u64::from_le_bytes(*b"kgwcrdt1"), &fields)?;
        let mut checks = vec![object.structural_valid().clone()];
        for index in [1, 2, 3, 4, 5, 6, 18] {
            checks.push(nonzero(uint.glue(), region, object.identifier(index)?)?);
        }
        for index in [8, 9, 17] {
            checks.push(nonzero(
                uint.glue(),
                region,
                core::slice::from_ref(object.word(index)?),
            )?);
        }
        let same = equal(
            uint.glue(),
            region,
            object.identifier(3)?,
            object.identifier(5)?,
        )?;
        checks.push(uint.glue().not(region, &same)?);
        checks.push(sum_fits128(
            uint,
            region,
            object.word(9)?,
            object.word(11)?,
        )?);
        for (a, b) in [(12, 13), (15, 16)] {
            let a = uint.glue().is_zero(region, object.word(a)?)?;
            let b = uint.glue().is_zero(region, object.word(b)?)?;
            checks.push(uint.glue().is_equal(region, a.word(), b.word())?);
        }
        let fee = nonzero(uint.glue(), region, core::slice::from_ref(object.word(11)?))?;
        let schedule = nonzero(uint.glue(), region, core::slice::from_ref(object.word(10)?))?;
        checks.push(implies(uint.glue(), region, &fee, &schedule)?);
        let valid = all(uint.glue(), region, &checks)?;
        Ok(Self {
            object: object.clone(),
            fields,
            credit,
            valid,
        })
    }
    /// The exact decoded signed body, including its signature digest.
    pub const fn object(&self) -> &SignedObjectCells {
        &self.object
    }
    /// Fields in the canonical G1 26-element order.
    pub const fn fields(&self) -> &[Word<Fp>; 26] {
        &self.fields
    }
    /// Poseidon credit identity of these exact fields.
    pub const fn credit_id(&self) -> &Word<Fp> {
        &self.credit
    }
    /// Total body validity; signature and ownership remain separate.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }

    /// Bind Send's credit descriptor and the payer's own signed account identity.
    ///
    /// A Send does not own the receiver's Request signature obligation. It must
    /// separately check its head-committed fee terms; Q sigma owns time/control
    /// and arithmetic checks against this same credit identity.
    ///
    /// # Errors
    /// Non-Send statement or layout failure.
    pub fn bind_send<S: StatementView>(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        statement: &S,
        payer: &CredentialCells,
    ) -> Result<Bit<Fp>, Error> {
        if statement.variant() != Variant::Send {
            return Err(Error::Synthesis);
        }
        let f = statement.fields();
        let mut checks = vec![
            self.valid.clone(),
            payer.valid().clone(),
            statement.validity(uint, region)?,
        ];
        for (request, credential) in [(1, 1), (2, 2), (3, 3), (4, 4)] {
            checks.push(equal(
                uint.glue(),
                region,
                self.object.identifier(request)?,
                payer.object().identifier(credential)?,
            )?);
        }
        for (request, expected) in [(1, &f[3..5]), (2, &f[5..7]), (5, &f[18..20])] {
            checks.push(equal(
                uint.glue(),
                region,
                self.object.identifier(request)?,
                expected,
            )?);
        }
        for (actual, expected) in [
            (&self.credit, &f[17]),
            (self.object.word(7)?, &f[20]),
            (self.object.word(9)?, &f[21]),
            (self.object.word(11)?, &f[22]),
            (self.object.digest(), &f[23]),
        ] {
            checks.push(uint.glue().is_equal(region, actual, expected)?);
        }
        checks.push(
            uint.glue()
                .is_equal(region, payer.object().digest(), &f[7])?,
        );
        all(uint.glue(), region, &checks)
    }

    /// Bind the receiver's original Request credential and Receive statement.
    ///
    /// The quoted credential's digest binds the Request; its wallet and payment
    /// key match the current lineage. Its digest need not equal the current
    /// credential, so renewal does not invalidate an earlier Request. Its own
    /// Enrollment certificate must be authenticated (or exactly deduplicated).
    /// Recorded blacklist history and the incoming payer checks are separate.
    ///
    /// # Errors
    /// Non-Receive statement or layout failure.
    pub fn bind_receive(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        statement: &StatementCells,
        receiver: &CredentialCells,
        current: &LineagePublicCells,
        signature: &SignatureProofCells,
    ) -> Result<Bit<Fp>, Error> {
        if !matches!(
            statement.variant(),
            Variant::Receive | Variant::ReceiveRenewed
        ) {
            return Err(Error::Synthesis);
        }
        let f = statement.fields();
        let mut checks = vec![self.valid.clone(), receiver.valid().clone()];
        for (request, credential) in [(1, 1), (2, 2), (5, 3), (6, 4)] {
            checks.push(equal(
                uint.glue(),
                region,
                self.object.identifier(request)?,
                receiver.object().identifier(credential)?,
            )?);
        }
        for (request, expected) in [
            (1, &f[3..5]),
            (2, &f[5..7]),
            (3, &f[18..20]),
            (5, &current.fields()[6..8]),
        ] {
            checks.push(equal(
                uint.glue(),
                region,
                self.object.identifier(request)?,
                expected,
            )?);
        }
        for (actual, expected) in [
            (&self.credit, &f[17]),
            (self.object.word(9)?, &f[20]),
            (self.object.word(8)?, receiver.object().digest()),
        ] {
            checks.push(uint.glue().is_equal(region, actual, expected)?);
        }
        checks.push(equal(
            uint.glue(),
            region,
            receiver.payment_key()?,
            &current.fields()[9..13],
        )?);
        checks.push(
            self.object
                .bind_signature(region, signature, receiver.payment_key()?)?,
        );
        all(uint.glue(), region, &checks)
    }
}
