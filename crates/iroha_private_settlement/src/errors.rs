//! Redacted operational categories over surviving original failure owners.
use super::*;
use iroha::workflow::{WorkflowStorageError, WorkflowStorageErrorKind};
use iroha_core_privacy::privacy_engines::{
    atomic_private_settlement::{
        AtomicPrivateSettlementProofErrorV1 as ProofError,
        AtomicPrivateSettlementRelationErrorV1 as RelationError,
        AtomicPrivateSettlementWalletErrorV1 as WalletError,
        audit::PrivateSettlementAuditCryptoErrorV1 as AuditError,
    },
    proof_managed_accumulator::ProofManagedAccumulatorErrorV1 as FrontierError,
};
use iroha_data_model::sumeragi::finality::NativeFinalityDecodeError;
use iroha_data_model::sumeragi_finality::GenesisReadError;

impl OneCallPrivateSettlementError {
    /// Classify this original operational failure without granting a ledger outcome.
    ///
    /// This is the same category used by the preparation driver's transient failure.
    /// It does not mark a round failed or persist diagnostics. Reopening the same durable
    /// operation rechecks its original custody and evidence; it never synthesizes success
    /// or rejection from a previous local error. Unknown provider or erased codec origins
    /// remain `EvidenceUnavailable`, including errors whose display mentions capacity.
    #[must_use]
    pub fn workflow_code(&self) -> WorkflowErrorCode {
        use OneCallPrivateSettlementError as E;
        match self {
            E::Binding => WorkflowErrorCode::BindingMismatch,
            E::Capacity | E::Storage(_) => WorkflowErrorCode::LocalResourceUnavailable,
            E::Pending => WorkflowErrorCode::EvidenceUnavailable,
            E::Workflow(error) => error.code,
            E::Finality(_) => WorkflowErrorCode::ProofInvalid,
            E::FinalityRead(error) => finality_read_code(error),
            E::Preparation(error) => preparation_code(error),
            E::Provider(error) => provider_code(error),
            E::Encoding(error) => codec_code(error),
            E::Settlement(error) => settlement_code(error),
        }
    }
}

fn decode_code(error: &norito::core::DecodeAttemptError) -> WorkflowErrorCode {
    match error.kind() {
        norito::core::DecodeAttemptErrorKind::Invalid => WorkflowErrorCode::NonCanonicalEncoding,
        norito::core::DecodeAttemptErrorKind::Allocator
        | norito::core::DecodeAttemptErrorKind::EnclosingLimit => {
            WorkflowErrorCode::LocalResourceUnavailable
        }
    }
}
fn codec_code(error: &norito::Error) -> WorkflowErrorCode {
    // A raw codec resource label does not prove which original attempt/scope refused.
    // In particular, a deterministic input ceiling is not local allocation pressure.
    if error.is_decode_resource_limit()
        || matches!(error, norito::Error::Message(_) | norito::Error::Io(_))
    {
        // Generic codec I/O may be an invalid/truncated reader, not local capacity.
        WorkflowErrorCode::EvidenceUnavailable
    } else {
        WorkflowErrorCode::NonCanonicalEncoding
    }
}
fn native_decode_code(error: &NativeFinalityDecodeError) -> WorkflowErrorCode {
    match error {
        NativeFinalityDecodeError::Resource(error) => decode_code(error),
        NativeFinalityDecodeError::Invalid(_) | NativeFinalityDecodeError::Malformed(_) => {
            WorkflowErrorCode::ProofInvalid
        }
    }
}
fn finality_read_code(error: &FinalityReadError) -> WorkflowErrorCode {
    match error {
        FinalityReadError::Invalid(_)
        | FinalityReadError::Genesis(GenesisReadError::Invalid(_)) => {
            WorkflowErrorCode::ProofInvalid
        }
        FinalityReadError::DecodeResource(error) => decode_code(error),
        FinalityReadError::ScratchLimit(_) | FinalityReadError::Allocator(_) => {
            WorkflowErrorCode::LocalResourceUnavailable
        }
        FinalityReadError::Genesis(GenesisReadError::Json(error)) => {
            if error.is_decode_resource_limit() {
                // JSON currently preserves its bound, but not classified original scope.
                WorkflowErrorCode::EvidenceUnavailable
            } else {
                WorkflowErrorCode::ProofInvalid
            }
        }
    }
}
fn provider_code(error: &eyre::Report) -> WorkflowErrorCode {
    let http_code = |status| match status {
        401 | 403 => WorkflowErrorCode::AuthorizationDenied,
        404 | 405 | 501 => WorkflowErrorCode::UnsupportedOperation,
        _ => WorkflowErrorCode::EvidenceUnavailable,
    };
    if let Some(error) = error.downcast_ref::<iroha::Error>() {
        return match error {
            iroha::Error::Api { error, .. } => http_code(error.status()),
            iroha::Error::Http { status, .. } => http_code(*status),
            iroha::Error::RequestSigning { .. } | iroha::Error::TransactionSigning(_) => {
                WorkflowErrorCode::AuthorizationDenied
            }
            iroha::Error::Context(_) | iroha::Error::ResponseBinding { .. } => {
                WorkflowErrorCode::BindingMismatch
            }
            iroha::Error::InvalidRequest { .. } => WorkflowErrorCode::InvalidInput,
            iroha::Error::Decode { .. } => WorkflowErrorCode::ProofInvalid,
            iroha::Error::ResponseTooLarge { .. } => WorkflowErrorCode::ResourceLimitExceeded,
            iroha::Error::CanonicalDecode(error) => decode_code(&error.source),
            iroha::Error::NativeFinalityDecode(error) => native_decode_code(&error.source),
            _ => WorkflowErrorCode::EvidenceUnavailable,
        };
    }
    if let Some(error) = error.downcast_ref::<FinalityReadError>() {
        return finality_read_code(error);
    }
    if error.downcast_ref::<FinalityError>().is_some() {
        return WorkflowErrorCode::ProofInvalid;
    }
    if let Some(error) = error.downcast_ref::<NativeFinalityDecodeError>() {
        return native_decode_code(error);
    }
    if let Some(error) = error.downcast_ref::<norito::Error>() {
        return codec_code(error);
    }
    if let Some(error) = error.downcast_ref::<WorkflowStorageError>() {
        return match error.kind {
            WorkflowStorageErrorKind::Conflict => WorkflowErrorCode::JournalConflict,
            WorkflowStorageErrorKind::Oversized => WorkflowErrorCode::StorageCorrupted,
            WorkflowStorageErrorKind::Busy
            | WorkflowStorageErrorKind::Unavailable
            | WorkflowStorageErrorKind::WriteUncertain => {
                WorkflowErrorCode::LocalResourceUnavailable
            }
        };
    }
    WorkflowErrorCode::EvidenceUnavailable
}
fn proof_code(error: &ProofError) -> WorkflowErrorCode {
    match error {
        ProofError::Relation(error) => relation_code(error),
        ProofError::ResourceLimit => WorkflowErrorCode::ResourceLimitExceeded,
        ProofError::RandomnessUnavailable | ProofError::UnhealthyRandomness => {
            WorkflowErrorCode::LocalResourceUnavailable
        }
        ProofError::InvalidProof | ProofError::SelfVerification | ProofError::ProverInvariant => {
            WorkflowErrorCode::ProofInvalid
        }
    }
}
fn relation_code(error: &RelationError) -> WorkflowErrorCode {
    match error {
        RelationError::CanonicalEncoding => WorkflowErrorCode::EvidenceUnavailable,
        RelationError::InvalidNetworkBinding => WorkflowErrorCode::BindingMismatch,
        _ => WorkflowErrorCode::ProofInvalid,
    }
}
fn preparation_code(error: &AtomicPrivateSettlementPreparationErrorV1) -> WorkflowErrorCode {
    use AtomicPrivateSettlementPreparationErrorV1 as E;
    match error {
        E::Binding => WorkflowErrorCode::BindingMismatch,
        // These producer variants erase the original codec cause; do not guess its origin.
        E::Encoding => WorkflowErrorCode::EvidenceUnavailable,
        E::Wallet(error) => match error {
            WalletError::InvalidBundle => WorkflowErrorCode::NonCanonicalEncoding,
            WalletError::WalletBinding | WalletError::PublicBinding => {
                WorkflowErrorCode::BindingMismatch
            }
            WalletError::SecretMaterial => WorkflowErrorCode::AuthorizationDenied,
            WalletError::Proof(error) => proof_code(error),
        },
        E::Frontier(error) => match error {
            FrontierError::NamespaceEncoding => WorkflowErrorCode::EvidenceUnavailable,
            FrontierError::TreeFull => WorkflowErrorCode::ResourceLimitExceeded,
            _ => WorkflowErrorCode::ProofInvalid,
        },
        E::Relation(error) => relation_code(error),
        E::Audit(error) => match error {
            AuditError::CanonicalEncoding => WorkflowErrorCode::EvidenceUnavailable,
            AuditError::InvalidPlaintextFrame => WorkflowErrorCode::NonCanonicalEncoding,
            AuditError::InvalidPlaintextSize => WorkflowErrorCode::ResourceLimitExceeded,
            AuditError::PlaintextCommitmentMismatch | AuditError::RecipientKeyMismatch => {
                WorkflowErrorCode::BindingMismatch
            }
            AuditError::UnknownAuditor => WorkflowErrorCode::AuthorizationDenied,
            AuditError::InvalidWire(_) => WorkflowErrorCode::ProofInvalid,
            AuditError::RandomnessUnavailable => WorkflowErrorCode::LocalResourceUnavailable,
            AuditError::CryptographicFailure => WorkflowErrorCode::EvidenceUnavailable,
        },
        E::Randomness(_) => WorkflowErrorCode::LocalResourceUnavailable,
        E::Proof(error) => proof_code(error),
    }
}
fn settlement_code(error: &PrivateSettlementError) -> WorkflowErrorCode {
    match error {
        PrivateSettlementError::Binding => WorkflowErrorCode::BindingMismatch,
        PrivateSettlementError::Workflow(error) => error.code,
        PrivateSettlementError::Protocol(error) => provider_code(error),
        PrivateSettlementError::Codec(error) => codec_code(error),
        PrivateSettlementError::Finality(error) => finality_read_code(error),
        PrivateSettlementError::Execution(_) | PrivateSettlementError::Receipt(_) => {
            WorkflowErrorCode::ProofInvalid
        }
        PrivateSettlementError::ReadBudget | PrivateSettlementError::Worker => {
            WorkflowErrorCode::LocalResourceUnavailable
        }
        PrivateSettlementError::Unresolved => WorkflowErrorCode::EvidenceUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_operational_categories_do_not_infer_capacity_from_text_or_codec_labels() {
        use WorkflowErrorCode as C;
        let cases = [
            (
                OneCallPrivateSettlementError::Preparation(
                    AtomicPrivateSettlementPreparationErrorV1::Relation(
                        RelationError::CanonicalEncoding,
                    ),
                ),
                C::EvidenceUnavailable,
            ),
            (
                OneCallPrivateSettlementError::Preparation(
                    AtomicPrivateSettlementPreparationErrorV1::Relation(
                        RelationError::InvalidNetworkBinding,
                    ),
                ),
                C::BindingMismatch,
            ),
            (
                OneCallPrivateSettlementError::Preparation(
                    AtomicPrivateSettlementPreparationErrorV1::Audit(
                        AuditError::CryptographicFailure,
                    ),
                ),
                C::EvidenceUnavailable,
            ),
            (
                OneCallPrivateSettlementError::Preparation(
                    AtomicPrivateSettlementPreparationErrorV1::Audit(
                        AuditError::RecipientKeyMismatch,
                    ),
                ),
                C::BindingMismatch,
            ),
            (
                OneCallPrivateSettlementError::Preparation(
                    AtomicPrivateSettlementPreparationErrorV1::Audit(
                        AuditError::InvalidPlaintextFrame,
                    ),
                ),
                C::NonCanonicalEncoding,
            ),
            (
                OneCallPrivateSettlementError::Preparation(
                    AtomicPrivateSettlementPreparationErrorV1::Frontier(FrontierError::TreeFull),
                ),
                C::ResourceLimitExceeded,
            ),
            (
                OneCallPrivateSettlementError::Preparation(
                    AtomicPrivateSettlementPreparationErrorV1::Wallet(WalletError::SecretMaterial),
                ),
                C::AuthorizationDenied,
            ),
            (
                OneCallPrivateSettlementError::Preparation(
                    AtomicPrivateSettlementPreparationErrorV1::Proof(ProofError::SelfVerification),
                ),
                C::ProofInvalid,
            ),
            (
                OneCallPrivateSettlementError::Preparation(
                    AtomicPrivateSettlementPreparationErrorV1::Proof(
                        ProofError::RandomnessUnavailable,
                    ),
                ),
                C::LocalResourceUnavailable,
            ),
            (
                OneCallPrivateSettlementError::Encoding(norito::Error::Message(
                    "allocation limit or permission denied".into(),
                )),
                C::EvidenceUnavailable,
            ),
            (
                OneCallPrivateSettlementError::Encoding(norito::Error::ArchiveLengthExceeded {
                    length: 2,
                    limit: 1,
                }),
                C::EvidenceUnavailable,
            ),
            (
                OneCallPrivateSettlementError::Settlement(PrivateSettlementError::Codec(
                    norito::Error::InvalidMagic,
                )),
                C::NonCanonicalEncoding,
            ),
            (
                OneCallPrivateSettlementError::Settlement(PrivateSettlementError::Execution(
                    FinalityError("completed check failed".into()),
                )),
                C::ProofInvalid,
            ),
            (
                OneCallPrivateSettlementError::Provider(eyre::Report::new(
                    WorkflowStorageError::new(
                        WorkflowStorageErrorKind::Oversized,
                        "original oversized journal",
                    ),
                )),
                C::StorageCorrupted,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.workflow_code(), expected, "{error:?}");
        }
        for kind in [
            std::io::ErrorKind::InvalidData,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let error = OneCallPrivateSettlementError::Encoding(norito::Error::Io(
                std::io::Error::new(kind, "erased reader or writer owner"),
            ));
            assert_eq!(error.workflow_code(), C::EvidenceUnavailable);
        }
    }

    #[test]
    fn original_finality_scratch_refusal_stays_local_through_direct_and_provider_errors() {
        for provider in [false, true] {
            // Obtain a typed demand refusal without attempting a physical allocation.
            let refusal = iroha_data_model::block::BlockSignatures::backing_layouts(usize::MAX)
                .expect_err("an unrepresentable signature count must refuse its layout");
            let original = FinalityReadError::ScratchLimit(refusal);
            let error = if provider {
                OneCallPrivateSettlementError::Provider(eyre::Report::new(original))
            } else {
                OneCallPrivateSettlementError::FinalityRead(original)
            };
            assert_eq!(
                error.workflow_code(),
                WorkflowErrorCode::LocalResourceUnavailable
            );
        }
    }

    #[test]
    fn typed_native_decode_and_json_refusals_preserve_their_surviving_origin() {
        let malformed = norito::core::classify_decode_attempt(|| {
            norito::decode_canonical::<Vec<u8>>(b"not a canonical frame")
        })
        .unwrap_err();
        let error = OneCallPrivateSettlementError::Provider(eyre::Report::new(
            NativeFinalityDecodeError::Malformed(malformed),
        ));
        assert_eq!(error.workflow_code(), WorkflowErrorCode::ProofInvalid);
        let json = norito::json::from_str::<Vec<u8>>("not json").unwrap_err();
        let error = OneCallPrivateSettlementError::FinalityRead(FinalityReadError::Genesis(
            GenesisReadError::Json(json),
        ));
        assert_eq!(error.workflow_code(), WorkflowErrorCode::ProofInvalid);
        let error = OneCallPrivateSettlementError::FinalityRead(FinalityReadError::Genesis(
            GenesisReadError::Json(norito::json::Error::DecodeResourceLimit),
        ));
        assert_eq!(
            error.workflow_code(),
            WorkflowErrorCode::EvidenceUnavailable,
            "a JSON resource label is not an original classified attempt"
        );
    }
}
