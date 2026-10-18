//! Bootstrap's fixed trust roots and witness-bound scheme authorization.
//!
//! The caller hard-verifies the single Q signature proof, retaining its opening
//! obligation. This component joins its typed outputs to the same state,
//! statement and object bytes; it does not provide native acceptance. A proves
//! the Bootstrap transition directly (lean lineage): `administrative::bootstrap`
//! constrains the statement cells themselves, so no sigma proof is verified.

use ff::Field;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{GlueChip, UintChip, bytes::tape::BytesChip, p256::native::Affine};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::{LineagePublicCells, SignatureProofCells, context::ContextObjectSpec};
use crate::{
    operation_relation::{
        administrative,
        objects::{
            ObjectKind, SignedObjectCells,
            credential::{CredentialAuthorization, CredentialCells},
            receipt::{self, ReceiptContext},
        },
        state::StateCells,
        statement::StatementCells,
    },
    q_signature::SignatureKey,
};

/// Trust-root and provider constants fixed into the Bootstrap relation key.
/// The scheme ID is carried by the constrained state/statement/lineage; fixing
/// it here would make the A keys depend cyclically on their own Ω catalog.
#[derive(Clone, Copy, Debug)]
pub struct BootstrapPolicy {
    provider: [u128; 2],
    root: Affine,
}
impl BootstrapPolicy {
    /// Validate fixed identities and the finite canonical P-256 root key.
    ///
    /// # Errors
    /// Zero provider identity or invalid root point.
    pub fn new(provider: [u128; 2], root: Affine) -> Result<Self, Error> {
        if provider == [0; 2] || !root.is_valid() {
            return Err(Error::Synthesis);
        }
        Ok(Self { provider, root })
    }
}

/// Same-tape certificate, current credential and receipt, in that order.
#[derive(Clone, Debug)]
pub struct BootstrapObjects {
    objects: [SignedObjectCells; 3],
}

/// Typed state and proof outputs consumed by Bootstrap object authentication.
#[derive(Clone, Copy)]
pub struct BootstrapInputs<'a> {
    /// Canonically opened initial state.
    pub state: &'a StateCells,
    /// Exact successor public lineage prefix.
    pub lineage: &'a LineagePublicCells,
    /// Own exact Bootstrap statement, constrained by the same A.
    pub statement: &'a StatementCells,
    /// Hard Q signature outputs ordered receipt, credential, certificate.
    pub signatures: &'a [SignatureProofCells],
}
impl BootstrapObjects {
    /// The fixed ordered object schema of the Bootstrap plan, including raw signatures.
    ///
    /// # Errors
    /// An impossible size conversion for a fixed object schema.
    pub fn context_specs() -> Result<[ContextObjectSpec; 3], Error> {
        let mut specs = Vec::new();
        for (tag, kind) in [
            (1, ObjectKind::Certificate),
            (2, ObjectKind::Credential),
            (3, ObjectKind::Receipt),
        ] {
            specs.push(ContextObjectSpec {
                tag,
                capacity: u32::try_from(kind.body_len() + 64).map_err(|_| Error::BoundsFailure)?,
            });
        }
        specs.try_into().map_err(|_| Error::Synthesis)
    }

    /// Parse exact canonical own objects from their original tapes.
    /// No signature verdict is asserted until `authenticate` consumes Q slots.
    ///
    /// # Errors
    /// Fixed framing or layout errors; malformed own objects are unsatisfiable.
    pub fn decode(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        source: [&[Value<u8>]; 3],
    ) -> Result<Self, Error> {
        let kinds = [
            ObjectKind::Certificate,
            ObjectKind::Credential,
            ObjectKind::Receipt,
        ];
        let mut objects = Vec::new();
        for (kind, source) in kinds.into_iter().zip(source) {
            let run = bytes.run(
                region,
                source,
                &kind.primary_segments(),
                &kind.secondary_segments(),
            )?;
            let lanes = chip.operation_lanes()?;
            objects.push(SignedObjectCells::from_run(
                &mut UintChip::new(lanes.glue, lanes.range),
                lanes.hash,
                region,
                kind,
                &run,
            )?);
        }
        Ok(Self {
            objects: objects.try_into().map_err(|_| Error::Synthesis)?,
        })
    }

    /// Authenticate the exact Bootstrap objects against hard-verified Q slots.
    /// Slots are `[receipt, credential, certificate]`; certificate must use the
    /// fixed root policy. Every returned credential/receipt predicate is required
    /// true here, including state/key/scheme/provider and enrollment bindings.
    /// The provider's enrollment-marker identity stays under the adopted issuer
    /// scope; this relation does not recompute its SHA-256 preimage.
    ///
    /// A proves the Bootstrap transition directly, so the receipt's sigma-only
    /// `proof_digest` names a proof A does not consume: it is taken from the
    /// signed receipt body itself, which the signature authenticates, and must
    /// still be nonzero.
    ///
    /// # Errors
    /// Wrong fixed variant, slot count/root policy or layout.
    /// Bad own evidence, authorization or object bindings are unsatisfiable.
    pub fn authenticate(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        policy: BootstrapPolicy,
        input: BootstrapInputs<'_>,
    ) -> Result<(), Error> {
        let BootstrapInputs {
            state,
            lineage,
            statement,
            signatures: slots,
        } = input;
        if statement.variant() != Variant::Bootstrap
            || slots.len() != 3
            || slots[2].key_policy() != SignatureKey::Fixed(policy.root)
        {
            return Err(Error::Synthesis);
        }
        let mut uint = chip.uint();
        // bootstrap below hard-joins state, statement and lineage scheme limbs.
        // Certificate/credential scope must bind to those same carried cells.
        let scheme = [lineage.fields()[1].clone(), lineage.fields()[2].clone()];
        let provider = policy
            .provider
            .map(|v| uint.constant::<128>(region, v).map(|v| v.word().clone()))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        administrative::bootstrap(&mut uint, region, statement, state, lineage)?;
        let credential = CredentialCells::check(&mut uint, region, &self.objects[1])?;
        let valid = credential.authenticate(
            &mut uint,
            region,
            &CredentialAuthorization {
                certificate: &self.objects[0],
                certificate_proof: &slots[2],
                credential_proof: &slots[1],
                root_key: slots[2].key(),
                scheme: &scheme,
                provider: &provider,
            },
        )?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        let current = credential.bind_current(&mut uint, region, state, lineage)?;
        GlueChip::assert_constant(region, current.word(), Fp::ONE)?;
        for (actual, expected) in credential
            .object()
            .identifier(23)?
            .iter()
            .zip(&statement.fields()[17..19])
        {
            GlueChip::assert_equal(region, actual, expected)?;
        }
        let receipt_signature =
            self.objects[2].bind_signature(region, &slots[0], credential.payment_key()?)?;
        GlueChip::assert_constant(region, receipt_signature.word(), Fp::ONE)?;
        let zero = uint.glue().constant(region, Fp::ZERO)?;
        let wallet = [lineage.fields()[6].clone(), lineage.fields()[7].clone()];
        let lanes = chip.operation_lanes()?;
        let valid = receipt::bind(
            &mut UintChip::new(lanes.glue, lanes.range),
            lanes.hash,
            region,
            &self.objects[2],
            &ReceiptContext {
                wallet: &wallet,
                provider: &provider,
                statement,
                proof_digest: self.objects[2].word(9)?,
                payment_digest: &zero,
            },
        )?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)
    }
}
