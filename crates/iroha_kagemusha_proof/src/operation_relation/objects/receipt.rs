//! Exact derived provider-receipt body bindings, including soft incoming checks.

use ff::Field;
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, UintChip, Word, WordHasher};
use iroha_plonk_recursion::obligation::ledger::Variant;

use super::{
    ObjectKind, SignedObjectCells,
    predicates::{all, equal, is_constant, nonzero},
};
use crate::operation_relation::{
    incoming_statement::{DynamicStatementCells, StatementView},
    statement::StatementCells,
};

/// Inputs already bound by the operation's state and proof verifiers.
/// `proof_digest` must come from the exact verified proof tape; Receive's
/// `payment_digest` must come from the full canonical Payment, not its Request.
pub struct ReceiptContext<'a, S = StatementCells> {
    /// Wallet incarnation whose payment key signs this receipt.
    pub wallet: &'a [Word<Fp>; 2],
    /// Scheme's pinned Advance contract identity.
    pub provider: &'a [Word<Fp>; 2],
    /// Validated operation statement, tied to its Q sigma input.
    pub statement: &'a S,
    /// Digest of the linked sigma-only or Omega/sigma proof bytes.
    pub proof_digest: &'a Word<Fp>,
    /// Full Payment digest for Receive; zero for every other operation.
    pub payment_digest: &'a Word<Fp>,
}

/// Bind a decoded receipt to all derived fields and return a total verdict.
///
/// Includes byte-structure validity, nonzero proof/capsule requirements and
/// the Receive-only Payment digest rule. Signature authentication is supplied
/// by `SignedObjectCells::bind_signature` under the credential's payment key.
/// A hard own receipt requires both verdicts true; incoming receipts include
/// both verdicts in the incoming predicate so invalid receipts take its branch.
///
/// # Errors
/// Wrong fixed object kind or layout failure. Mismatched witness fields produce false.
pub fn bind<S: StatementView>(
    uint: &mut UintChip<'_, Fp>,
    hash: &mut impl WordHasher<Fp>,
    region: &mut Region<'_, Fp>,
    receipt: &SignedObjectCells,
    context: &ReceiptContext<'_, S>,
) -> Result<Bit<Fp>, Error> {
    if receipt.kind() != ObjectKind::Receipt {
        return Err(Error::Synthesis);
    }
    let f = context.statement.fields();
    let mut inputs = context.wallet.to_vec();
    inputs.push(f[16].clone());
    match context.statement.variant() {
        Variant::Bootstrap => inputs.extend_from_slice(&f[17..19]),
        Variant::ArchiveReceive
        | Variant::ArchiveStatus
        | Variant::RefreshCredential
        | Variant::RefreshSchemePolicy
        | Variant::RefreshBlacklist
        | Variant::RefreshQuotaShare
        | Variant::RefreshTimeAnchor => inputs.push(f[18].clone()),
        Variant::Retiring => inputs.push(uint.glue().constant(region, Fp::ZERO)?),
        _ => inputs.push(f[17].clone()),
    }
    let operation = hash.hash_words(region, u64::from_le_bytes(*b"kgwopid1"), &inputs)?;
    let valid = context.statement.validity(uint, region)?;
    let receive = is_constant(uint.glue(), region, &f[16], 4)?;
    bind_context(
        uint,
        region,
        receipt,
        &BindingContext {
            wallet: context.wallet,
            provider: context.provider,
            fields: f,
            digest: context.statement.digest(),
            proof_digest: context.proof_digest,
            payment_digest: context.payment_digest,
            valid: &valid,
            operation: &operation,
            receive: &receive,
        },
    )
}

/// Bind a `CreditStatus` receipt whose folded head may have any operation tag.
/// Both possible operation-ID lengths and every input projection are fixed
/// constraints; a witness tag never changes circuit layout.
///
/// # Errors
/// Wrong receipt class or layout failure. Invalid statements/mismatches are false.
pub fn bind_dynamic(
    uint: &mut UintChip<'_, Fp>,
    hash: &mut impl WordHasher<Fp>,
    region: &mut Region<'_, Fp>,
    receipt: &SignedObjectCells,
    context: &ReceiptContext<'_, DynamicStatementCells>,
) -> Result<Bit<Fp>, Error> {
    if receipt.kind() != ObjectKind::Receipt {
        return Err(Error::Synthesis);
    }
    let f = context.statement.fields();
    let bootstrap = is_constant(uint.glue(), region, &f[16], 1)?;
    let archive = is_constant(uint.glue(), region, &f[16], 5)?;
    let refresh = is_constant(uint.glue(), region, &f[16], 7)?;
    let retiring = is_constant(uint.glue(), region, &f[16], 8)?;
    let alternate = uint.glue().add(region, archive.word(), refresh.word())?;
    let alternate = uint.glue().assert_bool(region, &alternate)?;
    let input = uint.glue().select(region, &alternate, &f[18], &f[17])?;
    let zero = uint.glue().constant(region, Fp::ZERO)?;
    let input = uint.glue().select(region, &retiring, &zero, &input)?;
    let mut words = context.wallet.to_vec();
    words.push(f[16].clone());
    let mut boot_words = words.clone();
    boot_words.extend_from_slice(&f[17..19]);
    words.push(input);
    let ordinary = hash.hash_words(region, u64::from_le_bytes(*b"kgwopid1"), &words)?;
    let boot = hash.hash_words(region, u64::from_le_bytes(*b"kgwopid1"), &boot_words)?;
    let operation = uint.glue().select(region, &bootstrap, &boot, &ordinary)?;
    let receive = is_constant(uint.glue(), region, &f[16], 4)?;
    bind_context(
        uint,
        region,
        receipt,
        &BindingContext {
            wallet: context.wallet,
            provider: context.provider,
            fields: f,
            digest: context.statement.digest(),
            proof_digest: context.proof_digest,
            payment_digest: context.payment_digest,
            valid: context.statement.valid(),
            operation: &operation,
            receive: &receive,
        },
    )
}

struct BindingContext<'a> {
    wallet: &'a [Word<Fp>; 2],
    provider: &'a [Word<Fp>; 2],
    fields: &'a [Word<Fp>; 26],
    digest: &'a Word<Fp>,
    proof_digest: &'a Word<Fp>,
    payment_digest: &'a Word<Fp>,
    valid: &'a Bit<Fp>,
    operation: &'a Word<Fp>,
    receive: &'a Bit<Fp>,
}
fn bind_context(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    receipt: &SignedObjectCells,
    context: &BindingContext<'_>,
) -> Result<Bit<Fp>, Error> {
    let f = context.fields;
    let mut bits = vec![receipt.structural_valid().clone(), context.valid.clone()];
    for (index, expected) in [
        (1, &f[3..5]),
        (2, context.wallet.as_slice()),
        (3, context.provider.as_slice()),
    ] {
        bits.push(equal(
            uint.glue(),
            region,
            receipt.identifier(index)?,
            expected,
        )?);
    }
    for (index, expected) in [
        (4, &f[9]),
        (5, context.operation),
        (6, &f[14]),
        (7, &f[15]),
        (8, context.digest),
        (9, context.proof_digest),
        (11, context.payment_digest),
    ] {
        bits.push(
            uint.glue()
                .is_equal(region, receipt.word(index)?, expected)?,
        );
    }
    bits.push(nonzero(
        uint.glue(),
        region,
        core::slice::from_ref(context.proof_digest),
    )?);
    bits.push(nonzero(uint.glue(), region, receipt.identifier(10)?)?);
    let has_payment = nonzero(
        uint.glue(),
        region,
        core::slice::from_ref(context.payment_digest),
    )?;
    bits.push(
        uint.glue()
            .is_equal(region, has_payment.word(), context.receive.word())?,
    );
    all(uint.glue(), region, &bits)
}
