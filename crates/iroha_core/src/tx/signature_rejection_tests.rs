#[test]
fn malformed_multisig_bundle_shapes_have_stable_rejection_code() {
    for error in [
        TransactionSignatureError::UnexpectedMultisigSignatures,
        TransactionSignatureError::NonCanonicalMultisigSignatures,
    ] {
        assert_eq!(
            AcceptedTransaction::signature_rejection_code(&error),
            Ok(SignatureRejectionCode::MalformedSignature),
        );
    }
}
#[test]
fn malformed_domain_shape_errors_have_stable_rejection_code() {
    for error in [
        TransactionSignatureError::GenesisDomainNotAllowed,
        TransactionSignatureError::GenesisDomainRequired,
    ] {
        assert_eq!(
            AcceptedTransaction::signature_rejection_code(&error),
            Ok(SignatureRejectionCode::MalformedSignature),
        );
    }
}
