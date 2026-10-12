//! Native SCCP message proof preflight against independently observed destination state.
//!
//! Offered committees and certificates are data, never pins. The shared destination verifier
//! checks the exact native quorum, signature, current generation/checkpoint eligibility,
//! payload, deadline, pause and Merkle paths. It does not query consumed bits, supply, fees
//! or TON bucket state. A caller must check those and refresh its coherent destination
//! observation before paying; a successful result is immutable proof evidence only.

use iroha_sccp::{
    api::{ApiShapeError, SccpCertificateV1, SccpMessageProofBundleV1},
    v1::destination::{
        CertificateSourceV1, CheckpointRefV1, DestinationObservationV1, MessagePreflightV1,
        MessageProofV1, MessagePurposeV1, PreflightError, TairaCertificateV1,
    },
};

/// Explicitly selected native call form; unavailable checkpoints never cause a fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleSourceV1 {
    /// Verify an inline certificate of the current generation.
    Inline,
    /// Use the exact header of an independently observed, eligible stored checkpoint.
    Checkpoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VerifiedSourceV1 {
    Inline(TairaCertificateV1),
    Checkpoint(CheckpointRefV1),
}
impl VerifiedSourceV1 {
    pub(crate) fn borrow(&self) -> CertificateSourceV1<'_> {
        match self {
            Self::Inline(certificate) => CertificateSourceV1::Inline(certificate),
            Self::Checkpoint(reference) => CertificateSourceV1::Checkpoint(reference),
        }
    }
    pub(crate) fn from_bundle(
        certificate: &SccpCertificateV1,
        source: BundleSourceV1,
    ) -> Result<Self, ApiShapeError> {
        certificate.check_shape()?;
        match source {
            BundleSourceV1::Inline => certificate.to_destination_certificate().map(Self::Inline),
            BundleSourceV1::Checkpoint => Ok(Self::Checkpoint(CheckpointRefV1 {
                header: certificate.header.to_vec(),
            })),
        }
    }
}

/// Why a native bundle cannot be admitted for the selected request and destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleError {
    /// A bounded wire field or request/deployment label is inconsistent.
    Shape(ApiShapeError),
    /// Missing observations or a refusal by the shared native destination verifier.
    Preflight(PreflightError),
}
impl core::fmt::Display for BundleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Shape(error) => write!(f, "bundle shape: {error}"),
            Self::Preflight(error) => write!(f, "bundle preflight: {error}"),
        }
    }
}
impl std::error::Error for BundleError {}
impl From<ApiShapeError> for BundleError {
    fn from(error: ApiShapeError) -> Self {
        Self::Shape(error)
    }
}
impl From<PreflightError> for BundleError {
    fn from(error: PreflightError) -> Self {
        Self::Preflight(error)
    }
}

/// Immutable message bytes and native proof evidence for one selected call form and purpose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMessageBundleV1 {
    network: iroha_data_model::bridge::SccpNetworkV1,
    source: VerifiedSourceV1,
    proof: MessageProofV1,
    transfer: MessagePreflightV1,
    purpose: MessagePurposeV1,
    historical: bool,
}
impl VerifiedMessageBundleV1 {
    /// Destination profile actually authenticated by the proof preflight.
    #[must_use]
    pub const fn network(&self) -> iroha_data_model::bridge::SccpNetworkV1 {
        self.network
    }

    /// Exact verified certificate or checkpoint reference for the calldata/message encoder.
    #[must_use]
    pub fn source(&self) -> CertificateSourceV1<'_> {
        self.source.borrow()
    }
    /// Exact verified transfer proof. The block reference includes any history path.
    #[must_use]
    pub const fn proof(&self) -> &MessageProofV1 {
        &self.proof
    }
    /// Deadline branch actually checked.
    #[must_use]
    pub const fn purpose(&self) -> MessagePurposeV1 {
        self.purpose
    }
    /// Whether the leaf's block precedes the certified header.
    #[must_use]
    pub const fn is_historical(&self) -> bool {
        self.historical
    }
    /// Authenticated message identity.
    #[must_use]
    pub fn message_id(&self) -> [u8; 32] {
        self.transfer.message_id()
    }
    /// Authenticated payload nonce; consumed state still needs a destination query.
    #[must_use]
    pub fn nonce(&self) -> u64 {
        self.transfer.nonce()
    }
    /// Authenticated destination-time deadline.
    #[must_use]
    pub fn deadline_ms(&self) -> u64 {
        self.transfer.deadline_ms()
    }
    /// Authenticated payload amount.
    #[must_use]
    pub fn amount(&self) -> u128 {
        self.transfer.amount()
    }
    /// Authenticated recipient bytes.
    #[must_use]
    pub fn recipient(&self) -> &[u8] {
        self.transfer.recipient()
    }
}

/// Check a response against the independently selected message id and destination state.
/// A supplied committee never changes the observation. Exactly one native quorum is required;
/// signer supersets are refused, not trimmed. Checkpoint mode requires an actual stored id.
///
/// # Errors
/// Returns a shape/request-label error, an unavailable checkpoint observation, or the first
/// native destination proof refusal. No state is changed on any path.
pub fn verify_message_bundle(
    bundle: &SccpMessageProofBundleV1,
    expected_message_id: &[u8; 32],
    observation: &DestinationObservationV1,
    source: BundleSourceV1,
    purpose: MessagePurposeV1,
) -> Result<VerifiedMessageBundleV1, BundleError> {
    let proof = bundle.message_proof(
        &observation.deployment().taira_network_id,
        expected_message_id,
    )?;
    let source = VerifiedSourceV1::from_bundle(&bundle.certificate, source)?;
    let transfer = observation.preflight_message(source.borrow(), &proof, purpose)?;
    Ok(VerifiedMessageBundleV1 {
        network: observation.deployment().network,
        source,
        proof,
        transfer,
        purpose,
        historical: bundle.is_historical(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{DAY, Fixture, NOW, T0, reads};
    use super::*;
    use iroha_sccp::v1::destination::{DestinationError, DestinationFlavor, MessagePurposeV1};
    use std::collections::BTreeMap;
    fn run(
        bundle: &SccpMessageProofBundleV1,
        observation: &DestinationObservationV1,
    ) -> Result<VerifiedMessageBundleV1, BundleError> {
        verify_message_bundle(
            bundle,
            &bundle.message_id,
            observation,
            BundleSourceV1::Inline,
            MessagePurposeV1::Finalize,
        )
    }

    #[test]
    fn exact_quorum_rejects_supersets_instead_of_trimming() {
        let f = Fixture::new(DestinationFlavor::Evm);
        let good = f.message(false);
        let observation = f.observation(NOW, reads(&good.certificate, false));
        assert!(run(&good, &observation).is_ok());
        for signers in [0b11_u32, 0b1111, 0b1_0111] {
            let mut bad = good.clone();
            bad.certificate.qc[112..].copy_from_slice(&signers.to_be_bytes());
            assert!(matches!(
                run(&bad, &observation),
                Err(BundleError::Shape(ApiShapeError::BadCertificate))
            ));
        }
        assert_eq!(&good.certificate.qc[112..], &0b111_u32.to_be_bytes());
    }
    #[test]
    fn native_verification_binds_digest_committee_and_instance() {
        let f = Fixture::new(DestinationFlavor::Evm);
        let good = f.message(false);
        let observation = f.observation(NOW, reads(&good.certificate, false));
        assert!(run(&good, &observation).is_ok());
        let mut foreign = Fixture::new(DestinationFlavor::Evm);
        foreign.deployment.consensus_instance[0] ^= 1;
        assert_eq!(
            run(
                &good,
                &foreign.observation(NOW, reads(&good.certificate, false))
            ),
            Err(BundleError::Preflight(PreflightError::Destination(
                DestinationError::BadSignature
            )))
        );
        let mut bad = good.clone();
        bad.certificate.qc[80] ^= 1;
        assert_eq!(
            run(&bad, &observation),
            Err(BundleError::Preflight(PreflightError::Destination(
                DestinationError::BadSignature
            )))
        );
        let mut bad = good.clone();
        bad.certificate.committee.swap(0, 1);
        assert!(run(&bad, &observation).is_err());
        let mut bad = good.clone();
        bad.certificate.committee.pop();
        assert!(run(&bad, &observation).is_err());
        let mut foreign = Fixture::new(DestinationFlavor::Evm);
        foreign.deployment.taira_network_id[0] ^= 1;
        assert!(matches!(
            run(
                &good,
                &foreign.observation(NOW, reads(&good.certificate, false))
            ),
            Err(BundleError::Shape(ApiShapeError::MetadataMismatch))
        ));
    }
    #[test]
    fn checkpoint_acceptance_uses_observed_storage_not_previous_roster_grace() {
        let f = Fixture::new(DestinationFlavor::Evm);
        let good = f.message(false);
        let unavailable = f.observation(NOW, BTreeMap::new());
        assert_eq!(
            run(&good, &unavailable),
            Err(BundleError::Preflight(
                PreflightError::CheckpointUnavailable(100)
            ))
        );
        let absent = f.observation(NOW, reads(&good.certificate, false));
        assert_eq!(
            verify_message_bundle(
                &good,
                &good.message_id,
                &absent,
                BundleSourceV1::Checkpoint,
                MessagePurposeV1::Finalize
            ),
            Err(BundleError::Preflight(PreflightError::Destination(
                DestinationError::UnknownCheckpoint
            )))
        );
        let present = f.observation(NOW, reads(&good.certificate, true));
        assert!(
            verify_message_bundle(
                &good,
                &good.message_id,
                &present,
                BundleSourceV1::Checkpoint,
                MessagePurposeV1::Finalize
            )
            .is_ok()
        );
        let mut state = *present.committee();
        state.generation += 1;
        state.start = 151;
        state.high = 150;
        let retired =
            f.observation_with(NOW, state, reads(&good.certificate, true), present.pause());
        assert_eq!(
            verify_message_bundle(
                &good,
                &good.message_id,
                &retired,
                BundleSourceV1::Checkpoint,
                MessagePurposeV1::Finalize
            ),
            Err(BundleError::Preflight(PreflightError::Destination(
                DestinationError::CommitteeNotAccepted
            )))
        );
    }
    #[test]
    fn native_deadline_splits_finalize_and_void() {
        let f = Fixture::new(DestinationFlavor::Evm);
        let good = f.message(false);
        for (now, mint, void) in [(T0 + DAY, true, false), (T0 + DAY + 1, false, true)] {
            let view = f.observation(now, reads(&good.certificate, false));
            assert_eq!(
                verify_message_bundle(
                    &good,
                    &good.message_id,
                    &view,
                    BundleSourceV1::Inline,
                    MessagePurposeV1::Finalize
                )
                .is_ok(),
                mint
            );
            assert_eq!(
                verify_message_bundle(
                    &good,
                    &good.message_id,
                    &view,
                    BundleSourceV1::Inline,
                    MessagePurposeV1::VoidExpired
                )
                .is_ok(),
                void
            );
        }
    }
    #[test]
    fn verify_message_bundle_accepts_originals_and_rejects_tampering() {
        let f = Fixture::new(DestinationFlavor::Evm);
        let good = f.message(false);
        let observation = f.observation(NOW, reads(&good.certificate, false));
        let accepted = run(&good, &observation).unwrap();
        assert!(!accepted.is_historical());
        assert_eq!(accepted.nonce(), 5);
        assert_eq!(accepted.deadline_ms(), T0 + DAY);
        assert_eq!(accepted.proof().payload, good.payload);
        assert_eq!(accepted.message_id(), good.message_id);
        let mut wrong = good.clone();
        wrong.message_id[0] ^= 1;
        assert!(run(&wrong, &observation).is_err());
        assert!(
            verify_message_bundle(
                &good,
                &[0; 32],
                &observation,
                BundleSourceV1::Inline,
                MessagePurposeV1::Finalize
            )
            .is_err()
        );
        let mut wrong = good.clone();
        wrong.deadline_ms += 1;
        assert!(run(&wrong, &observation).is_err());
        let mut wrong = good.clone();
        wrong.block.message_count += 1;
        assert!(run(&wrong, &observation).is_err());
        let mut wrong = good.clone();
        wrong.path[0][0] ^= 1;
        assert_eq!(
            run(&wrong, &observation),
            Err(BundleError::Preflight(PreflightError::Destination(
                DestinationError::BadProof
            )))
        );
        let expired = f.observation(T0 + 14 * DAY + 1, reads(&good.certificate, false));
        assert!(
            verify_message_bundle(
                &good,
                &good.message_id,
                &expired,
                BundleSourceV1::Inline,
                MessagePurposeV1::VoidExpired
            )
            .is_err()
        );
    }
    #[test]
    fn bundle_errors_display_native_refusals_and_preserve_sources() {
        let shape = BundleError::from(ApiShapeError::PayloadTooLong);
        assert_eq!(shape, BundleError::Shape(ApiShapeError::PayloadTooLong));
        assert!(shape.to_string().starts_with("bundle shape"));
        let unavailable = BundleError::from(PreflightError::CheckpointUnavailable(8));
        assert!(unavailable.to_string().contains("8"));
        let error: Box<dyn std::error::Error> = Box::new(BundleError::from(
            PreflightError::Destination(DestinationError::BadSignature),
        ));
        assert!(error.to_string().contains("destination"));
    }
}
