// Source-owned FI permissions enter the existing numeric movement kernel here.

pub(in crate::smartcontracts::isi) fn execute_verified_linked_fi_transfer(
    state_transaction: &mut StateTransaction<'_, '_>,
    verified: crate::smartcontracts::isi::asset_fi::VerifiedLinkedFiTransfer,
) -> Result<(), Error> {
    let (authority, source, destination, amount, binding) = verified.into_parts();
    // The private capability was constructed only after exact FI eligibility,
    // authenticated reference, owner consent, runtime frame and revision checks.
    // Its purpose changes UID spending classification, never source reserves,
    // availability, receiving limits or the separate gross outgoing ceiling.
    execute_numeric_asset_movement(
        state_transaction,
        source,
        destination,
        amount,
        NumericAssetMovementAuthorization {
            debit: NumericMovementDebitAuthorization::Protocol,
            transcript_authority: authority,
            transcript: NumericMovementTranscriptRequirement::TransactionOrTypedPurpose {
                tag: "owner-linked-fi-transfer-v1",
                binding,
            },
            source_policy: NumericAssetTransferSourcePolicy::LinkedFi,
            control_policy: NumericAssetTransferControlPolicy::Enforce,
            destination_admission: NumericAssetDestinationAdmissionPolicy::ExistingAccount,
        },
    )
}
