//! Native intent binding for user operations and private authenticated Archive work.

use super::*;

/// Sealed coordinator intent retained across preparation, Advance and folding.
/// Foreign APIs accept `OperationRequestV1`; only the native coordinator can construct
/// Archive work from a retained Send and its exact historical originals.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::NativeIntentV1")]
pub struct NativeIntentV1 {
    value: Intent,
}

#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::NativeIntentKindV1")]
enum Intent {
    User(OperationRequestV1),
    Archive(ArchiveIntentV1),
}

#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::ArchiveIntentV1")]
pub(crate) struct ArchiveIntentV1 {
    request_id: [u8; 32],
    pub(crate) send_capsule: [u8; 32],
    pub(crate) request: Vec<u8>,
    pub(crate) payment: Vec<u8>,
    pub(crate) credential: Vec<u8>,
    pub(crate) certificates: Vec<u8>,
    pub(crate) credited: Vec<u8>,
}

impl NativeIntentV1 {
    pub(in crate::kagemusha_wallet_state_v1) fn user(request: OperationRequestV1) -> Self {
        Self {
            value: Intent::User(request),
        }
    }

    /// Stable request identity in this wallet's authenticated preparation index.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 32] {
        match &self.value {
            Intent::User(request) => request.request_id,
            Intent::Archive(request) => request.request_id,
        }
    }

    /// Fixed operation kind; this never selects a caller-supplied proof profile.
    #[must_use]
    pub const fn kind(&self) -> KagemushaWalletOperationKindV1 {
        match &self.value {
            Intent::User(request) => request.kind(),
            Intent::Archive(_) => KagemushaWalletOperationKindV1::ArchiveSent,
        }
    }

    pub(crate) fn user_request(&self) -> Option<&OperationRequestV1> {
        match &self.value {
            Intent::User(request) => Some(request),
            Intent::Archive(_) => None,
        }
    }
    pub(crate) fn archive_request(&self) -> Option<&ArchiveIntentV1> {
        match &self.value {
            Intent::Archive(request) => Some(request),
            Intent::User(_) => None,
        }
    }
    pub(crate) fn refresh(&self) -> Option<KagemushaWalletPolicyUpdateKindV1> {
        match self.user_request().map(|request| &request.action) {
            Some(OperationActionV1::Refresh { kind, .. }) => Some(*kind),
            _ => None,
        }
    }

    pub(crate) fn validate(&self, scheme: &KagemushaWalletSchemeV1) -> Result<(), Error> {
        match &self.value {
            Intent::User(request) => request.validate(scheme),
            Intent::Archive(request) => {
                if request.request_id == [0; 32] || request.send_capsule == [0; 32] {
                    return Err(Error::Invalid("Archive intent identity"));
                }
                let originals: KagemushaWalletRequestV1 = archive::decode(&request.request)?;
                valid(originals.verify(scheme))?;
                let payment = valid(KagemushaWalletPaymentV1::decode_canonical(
                    &request.payment,
                    &scheme.scheme_id(),
                ))?;
                let payer = valid(KagemushaWalletCredentialV1::decode_canonical(
                    &request.credential,
                    &scheme.scheme_id(),
                ))?;
                let certificates: KagemushaWalletCertificateSetV1 =
                    archive::decode(&request.certificates)?;
                valid(payment.verify(scheme, &payer, &certificates, &originals))?;
                if payment.send.receipt.capsule_digest != request.send_capsule {
                    return Err(Error::Invalid("Archive retained Send identity"));
                }
                // Incoming receipt signatures, proof validity and membership stay soft
                // obligations of Archive. Intake bounds and canonical structure grant no verdict.
                if request.credited.is_empty()
                    || request.credited.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
                {
                    return Err(Error::Invalid("Archive evidence size"));
                }
                let credited: KagemushaWalletCreditedV1 = archive::decode(&request.credited)?;
                if credited.version != 1
                    || credited.scheme_id != scheme.scheme_id()
                    || credited.evidence.statement().scheme_id != scheme.scheme_id()
                {
                    return Err(Error::Invalid("Archive evidence scheme"));
                }
                Ok(())
            }
        }
    }

    pub(in crate::kagemusha_wallet_state_v1) fn decode(
        bytes: &[u8],
        _scheme: &KagemushaWalletSchemeV1,
    ) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > REQUEST_MAX_BYTES {
            return Err(Error::WitnessLost("native intent size"));
        }
        let intent: Self = archive::decode(bytes)?;
        if intent.request_id() == [0; 32] {
            return Err(Error::WitnessLost("native intent identity"));
        }
        Ok(intent)
    }

    pub(super) fn archive(
        send: &ReleasedStep,
        certificates: Vec<u8>,
        credited: Vec<u8>,
    ) -> Result<Self, Error> {
        if send.frozen.capsule.kind != KagemushaWalletOperationKindV1::Send {
            return Err(Error::Invalid("Archive requires retained Send"));
        }
        let mut requests = send
            .frozen
            .capsule
            .retained_inputs
            .iter()
            .filter(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request);
        let request = requests
            .next()
            .ok_or(Error::WitnessLost("Archive Send Request"))?
            .bytes
            .clone();
        if requests.next().is_some() {
            return Err(Error::WitnessLost("Archive duplicate Send Request"));
        }
        let send_capsule = valid(send.frozen.capsule.capsule_digest())?;
        Ok(Self {
            value: Intent::Archive(ArchiveIntentV1 {
                request_id: Self::archive_identity(
                    &send_capsule,
                    &send.frozen.capsule.wallet_id,
                    &credited,
                ),
                send_capsule,
                request,
                payment: send.retained.record.output.clone(),
                credential: valid(send.frozen.credential.to_canonical_bytes())?,
                certificates,
                credited,
            }),
        })
    }

    pub(super) fn archive_identity(
        capsule: &[u8; 32],
        wallet: &[u8; 32],
        credited: &[u8],
    ) -> [u8; 32] {
        use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_provider_digest_v1 as digest;
        let mut identity = capsule.to_vec();
        identity.extend_from_slice(wallet);
        identity.extend_from_slice(credited);
        digest("wallet-private-archive-intent", &identity)
    }

    #[cfg(test)]
    pub(in crate::kagemusha_wallet_state_v1) fn retained_delivery_test_originals(
        payment: &KagemushaWalletPaymentV1,
        request: Vec<u8>,
        credited: Vec<u8>,
        credential: Vec<u8>,
        certificates: Vec<u8>,
    ) -> Self {
        let capsule = payment.send.receipt.capsule_digest;
        Self {
            value: Intent::Archive(ArchiveIntentV1 {
                request_id: Self::archive_identity(
                    &capsule,
                    &payment.request.body.payer_wallet_id,
                    &credited,
                ),
                send_capsule: capsule,
                request,
                payment: payment.to_canonical_bytes().unwrap(),
                credential,
                certificates,
                credited,
            }),
        }
    }
}
