//! Authenticate immutable local Send custody without requiring its current credential digest.

use super::*;

pub(super) struct Retained {
    pub(super) native: native::RetainedPayment,
    pub(super) request: KagemushaWalletRequestV1,
    pub(super) pending: KagemushaWalletPendingOutgoingLeafV1,
    pub(super) payment_digest: [u8; 32],
}

pub(super) fn originals(
    scheme: &KagemushaWalletSchemeV1,
    current: &KagemushaWalletCredentialV1,
    inputs: &[KagemushaWalletRetainedInputV1],
) -> Result<Retained, Error> {
    use KagemushaWalletRetainedInputRoleV1 as Role;
    let request: KagemushaWalletRequestV1 = decode(retained_original(inputs, Role::Request)?)?;
    let payment = authority(KagemushaWalletPaymentV1::decode_canonical(
        retained_original(inputs, Role::Payment)?,
        &scheme.scheme_id(),
    ))?;
    let payer = authority(KagemushaWalletCredentialV1::decode_canonical(
        retained_original(inputs, Role::Credential)?,
        &scheme.scheme_id(),
    ))?;
    let certificates: KagemushaWalletCertificateSetV1 =
        decode(retained_original(inputs, Role::CertificateSet)?)?;
    let digests = authority(payment.verify(scheme, &payer, &certificates, &request))?;
    // Renewal changes credential identity, never this wallet's monetary identity.
    if payer.body.wallet_id != current.body.wallet_id
        || payer.body.payment_key != current.body.payment_key
        || payer.body.account_digest != current.body.account_digest
        || payer.body.asset_digest != current.body.asset_digest
        || payer.body.scheme_id != current.body.scheme_id
        || payer.body.provider_contract != current.body.provider_contract
    {
        return Err(Error::Authority);
    }
    let signer = authority(KagemushaWalletReceiptSignerV1::from_credential(&payer))?;
    let receipt = authority(payment.send.receipt.body(
        &signer,
        &payment.send.statement,
        &digests.package.proof,
    ))?;
    let pending = authority(payment.pending_outgoing_leaf())?;
    let native = native::RetainedPayment {
        signed: [
            signed_tape(request.body.transcript(), &request.signature),
            signed_tape(payer.body.transcript(), &payer.signature),
            signed_tape(receipt.transcript(), &payment.send.receipt.signature),
            signed_tape(
                request.receiver_credential.body.transcript(),
                &request.receiver_credential.signature,
            ),
        ],
        payment: kagemusha_wallet_payment_transcript_v1(
            &digests.request,
            &payment.payer_payment_key,
            &payment.payer_credential_digest,
            &digests.package.package,
        ),
        statement: fields(authority(payment.send.statement.field_items())?)?,
        omega: payment
            .send
            .lineage
            .lineage()
            .ok_or(Error::Authority)?
            .bytes(),
        sigma: payment.send.step_proof.bytes,
    };
    Ok(Retained {
        native,
        request,
        pending,
        payment_digest: digests.payment,
    })
}
