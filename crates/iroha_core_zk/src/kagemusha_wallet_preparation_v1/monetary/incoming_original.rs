//! Original Payment projection within the native Receive carrier's custody grammar.
//!
//! The domain is one bounded canonical Norito `PaymentV1`, a V1 Send package,
//! present lineage, canonical P-256 key/low-S signature encodings, and statement
//! atoms representable in Fp. Bad framing, unsupported outer carriers, malformed
//! SEC1/scalar encodings and noncanonical field atoms are custody errors. This is
//! not a total decoder over arbitrary byte strings; it never fabricates a tape
//! for an input the fixed carrier cannot represent.
//!
//! Within that domain, represented versions, signed values, mismatched identities,
//! incorrect signatures and arbitrary sigma/lineage proof bytes are preserved.
//! Computing their commitments grants no incoming acceptance. The native A owners
//! derive the object, signature and proof predicates from the original tapes.

use super::*;

pub(super) struct IncomingOriginalV1 {
    pub(super) payment: KagemushaWalletPaymentV1,
    pub(super) receipt: Vec<u8>,
    pub(super) compact: Vec<u8>,
    pub(super) payment_digest: [u8; 32],
    pub(super) incoming_statement: [Fp; 26],
    pub(super) omega: Vec<u8>,
}

pub(super) fn payment(bytes: &[u8]) -> Result<IncomingOriginalV1, Error> {
    if bytes.is_empty() || bytes.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
        return Err(Error::Authority);
    }
    let payment: KagemushaWalletPaymentV1 =
        norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
            .map_err(|_| Error::Authority)?;
    // The fixed Send carrier has no package-version or absent-lineage tape.
    // Reject an unrepresentable outer shape instead of silently normalizing it.
    if payment.send.version != KAGEMUSHA_WALLET_VERSION_V1
        || payment.send.statement.effect.kind() != KagemushaWalletOperationKindV1::Send
    {
        return Err(Error::Authority);
    }
    let lineage = payment.send.lineage.lineage().ok_or(Error::Authority)?;
    let omega = lineage.bytes();
    let incoming_statement = incoming_statement::fields(&payment.send.statement)?;
    let statement_digest = authority(kagemusha_wallet_poseidon_v1(
        KAGEMUSHA_WALLET_STATEMENT_DOMAIN_V1,
        &incoming_statement.map(|value| value.to_repr()),
    ))?;
    let mut proof_body = Vec::with_capacity(omega.len() + payment.send.step_proof.bytes.len() + 8);
    proof_body.extend_from_slice(
        &u32::try_from(omega.len())
            .map_err(|_| Error::Authority)?
            .to_le_bytes(),
    );
    proof_body.extend_from_slice(&omega);
    proof_body.extend_from_slice(
        &u32::try_from(payment.send.step_proof.bytes.len())
            .map_err(|_| Error::Authority)?
            .to_le_bytes(),
    );
    proof_body.extend_from_slice(&payment.send.step_proof.bytes);
    let proof_digest =
        kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_PROOF_DOMAIN_V1, &proof_body);
    let original = &payment.send.receipt;
    let body = KagemushaWalletReceiptBodyV1 {
        version: original.version,
        scheme_id: lineage.public.scheme_id,
        wallet_id: lineage.public.wallet_id,
        provider_contract: kagemusha_wallet_provider_contract_v1(),
        sequence: payment.send.statement.sequence,
        operation_id: original.operation_id,
        predecessor: payment.send.statement.predecessor,
        successor: payment.send.statement.successor,
        statement_digest,
        proof_digest,
        capsule_digest: original.capsule_digest,
        payment_digest: original.payment_digest,
    };
    let receipt_digest = kagemusha_wallet_signed_object_digest_v1(
        KagemushaWalletObjectDigestDomainV1::Receipt,
        &body.signing_message(),
        &original.signature,
    );
    let package_digest = authority(kagemusha_wallet_package_digest_v1(
        &statement_digest,
        &proof_digest,
        &receipt_digest,
    ))?;
    let mut compact = kagemusha_wallet_payment_transcript_v1(
        &payment.request.request_digest(),
        &payment.payer_payment_key,
        &payment.payer_credential_digest,
        &package_digest,
    );
    // The model helper constructs a new V1 object. Here an invalid carried version
    // must remain visible to ReceiveObjects rather than being repaired to one.
    compact[..2].copy_from_slice(&payment.version.to_le_bytes());
    let payment_digest =
        kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1, &compact);
    Ok(IncomingOriginalV1 {
        receipt: signed_tape(body.transcript(), &original.signature),
        payment,
        compact,
        payment_digest,
        incoming_statement,
        omega,
    })
}

#[cfg(test)]
#[path = "incoming_original_tests.rs"]
mod tests;
