//! Exact Archive pending removals and signed evidence fixture construction.
//!
//! These helpers create witnesses only. The caller must authenticate the Send
//! predecessor, retained Payment, incoming evidence, and complete Q/A/W chain.

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    admin_sigma::{ArchiveWitness, BootstrapWitness, StateWitness},
    operation_relation::{map_effects::PENDING_DOMAIN, objects::ObjectKind},
    tree::{IndexedRemove, IndexedTree},
    witness::core_index as core,
};
use iroha_pasta::{Fp, poseidon::hash_with_domain};
use iroha_plonk_gadgets::{bytes::p_bytes_native, statement::STATEMENT_DOMAIN};

use super::{
    bootstrap,
    bootstrap_objects::{self, Signed},
};

/// Exact state transition plus the two ordered pending-removal witnesses.
#[derive(Clone)]
pub struct ArchiveFixture {
    /// Both committed state openings and the tag5 statement.
    pub witness: ArchiveWitness,
    /// Original seven-word Send descriptor.
    pub descriptor: [Fp; 7],
    /// Core first, adjusted lineage second; both removal paths always exist.
    pub removals: [IndexedRemove<Fp>; 2],
}

/// Remove an original descriptor from the core and, iff valid, adjusted state.
/// No helper assertion treats the supplied verdict as proof of evidence.
pub fn from_pending(
    before: &StateWitness,
    descriptor: [Fp; 7],
    credited: Fp,
    valid: bool,
    core_pending: &IndexedTree<Fp>,
    adjusted_pending: &IndexedTree<Fp>,
) -> ArchiveFixture {
    assert_eq!(
        core_pending.root(),
        before.core[core::PENDING_OUTGOING_ROOT]
    );
    assert_eq!(adjusted_pending.root(), before.lineage[15]);
    let expected = hash_with_domain(PENDING_DOMAIN, &descriptor);
    assert_eq!(core_pending.get(&descriptor[0]), Some(expected));
    assert_eq!(adjusted_pending.get(&descriptor[0]), Some(expected));
    let mut pending = core_pending.clone();
    let mut adjusted = adjusted_pending.clone();
    let core_path = pending.remove(&descriptor[0]).unwrap();
    let lineage_path = adjusted.remove(&descriptor[0]).unwrap();
    let mut after = BootstrapWitness {
        core: before.core,
        rest: before.rest,
        lineage: before.lineage,
        statement: [Fp::ZERO; 26],
    };
    after.core[core::SEQUENCE] += Fp::ONE;
    after.core[core::STATE_NONCE] += Fp::ONE;
    after.core[core::PENDING_OUTGOING_ROOT] = pending.root();
    if valid {
        after.lineage[15] = adjusted.root();
    }
    after.statement[0] = Fp::ONE;
    after.statement[14] = before.lineage[5];
    after.statement[16] = Fp::from(5);
    after.statement[17] = descriptor[0];
    after.statement[18] = credited;
    bootstrap::rebind(&mut after);
    ArchiveFixture {
        witness: ArchiveWitness {
            predecessor: *before,
            successor: StateWitness::from(&after),
            statement: after.statement,
        },
        descriptor,
        removals: [core_path, lineage_path],
    }
}

/// Build the one-entry pending map of the controls-off Send fixture.
pub fn pending(descriptor: [Fp; 7]) -> IndexedTree<Fp> {
    let mut tree = IndexedTree::new();
    tree.insert(descriptor[0], hash_with_domain(PENDING_DOMAIN, &descriptor))
        .unwrap();
    tree
}

/// Exact native signed-object digest, including original big-endian signature.
pub fn object_digest(kind: ObjectKind, raw: &[u8]) -> Fp {
    assert_eq!(raw.len(), kind.body_len() + 64);
    let end = kind.body_len();
    let mut words = vec![p_bytes_native(kind.signing_domain(), &raw[..end])];
    for offset in [16, 0, 48, 32] {
        words.push(Fp::from_u128(u128::from_be_bytes(
            raw[end + offset..end + offset + 16].try_into().unwrap(),
        )));
    }
    hash_with_domain(kind.object_domain(), &words)
}

/// Exact sigma-only step digest used by Receive and Archive receipts.
pub fn step_digest(sigma: &[u8]) -> Fp {
    let mut tape = u32::try_from(sigma.len()).unwrap().to_le_bytes().to_vec();
    tape.extend_from_slice(sigma);
    p_bytes_native(u64::from_le_bytes(*b"kgwstep1"), &tape)
}

/// Sign the canonical sigma-only receipt with the test wallet's payment key.
/// Archive's operation identity uses its evidence digest; Receive uses credit.
pub fn step_receipt(
    before: &StateWitness,
    statement: &[Fp; 26],
    sigma: &[u8],
    payment: Fp,
    secret: u64,
    nonce: u64,
) -> Signed {
    let effect = if statement[16] == Fp::from(5) {
        statement[18]
    } else {
        statement[17]
    };
    let operation = hash_with_domain(
        u64::from_le_bytes(*b"kgwopid1"),
        &[
            before.core[core::WALLET],
            before.core[core::WALLET + 1],
            statement[16],
            effect,
        ],
    );
    let mut body = 1u16.to_le_bytes().to_vec();
    body.extend(bootstrap_objects::id(
        before.core[core::SCHEME],
        before.core[core::SCHEME + 1],
    ));
    body.extend(bootstrap_objects::id(
        before.core[core::WALLET],
        before.core[core::WALLET + 1],
    ));
    body.extend(bootstrap_objects::small_id(31, 32));
    body.extend(&statement[9].to_repr()[..16]);
    for word in [
        operation,
        statement[14],
        statement[15],
        hash_with_domain(STATEMENT_DOMAIN, statement),
        step_digest(sigma),
    ] {
        body.extend(word.to_repr());
    }
    body.extend(bootstrap_objects::small_id(551, 552));
    body.extend(payment.to_repr());
    bootstrap_objects::sign(ObjectKind::Receipt, body, secret, nonce)
}

/// Payment's fixed163-byte semantic transcript from the retained original Send.
/// Its proof digest is retained in the original receipt and checked separately.
pub fn payment(
    request: &[u8],
    credential: &[u8],
    statement: &[Fp; 26],
    receipt: &Signed,
) -> Vec<u8> {
    let proof = Fp::from_repr(receipt.bytes[242..274].try_into().unwrap()).unwrap();
    let package = hash_with_domain(
        u64::from_le_bytes(*b"kgwpkg_1"),
        &[
            hash_with_domain(STATEMENT_DOMAIN, statement),
            proof,
            receipt.digest(),
        ],
    );
    let mut bytes = 1u16.to_le_bytes().to_vec();
    bytes.extend(object_digest(ObjectKind::Request, request).to_repr());
    bytes.extend(&credential[130..195]);
    bytes.extend(object_digest(ObjectKind::Credential, credential).to_repr());
    bytes.extend(package.to_repr());
    assert_eq!(bytes.len(), 163);
    bytes
}

/// Credited's exact99-byte Receive form and its original component addresses.
pub fn credited_receive(
    credit: Fp,
    payment: Fp,
    statement: &[Fp; 26],
    receipt: &Signed,
    sigma: &[u8],
) -> Vec<u8> {
    let package = hash_with_domain(
        u64::from_le_bytes(*b"kgwpkg_1"),
        &[
            hash_with_domain(STATEMENT_DOMAIN, statement),
            step_digest(sigma),
            receipt.digest(),
        ],
    );
    let mut bytes = vec![1, 0, 1];
    for word in [credit, payment, package] {
        bytes.extend(word.to_repr());
    }
    assert_eq!(bytes.len(), 99);
    bytes
}
