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
    pub(crate) send_commitment: [u8; 32],
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
                let payment = read_model_original(
                    || {
                        KagemushaWalletPaymentV1::decode_canonical(
                            &request.payment,
                            &scheme.scheme_id(),
                        )
                    },
                    Error::Invalid("G1 validation"),
                )?;
                let payer = read_model_original(
                    || {
                        KagemushaWalletCredentialV1::decode_canonical(
                            &request.credential,
                            &scheme.scheme_id(),
                        )
                    },
                    Error::Invalid("G1 validation"),
                )?;
                let certificates: KagemushaWalletCertificateSetV1 =
                    archive::decode(&request.certificates)?;
                valid(payment.verify(scheme, &payer, &certificates, &originals))?;
                if payment.send.receipt.capsule_commitment != request.send_commitment
                    || request.send_commitment == [0; 32]
                {
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
        if send.frozen.capsule.body().kind != KagemushaWalletOperationKindV1::Send {
            return Err(Error::Invalid("Archive requires retained Send"));
        }
        let mut requests = send
            .frozen
            .capsule
            .body()
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
        valid(
            send.retained
                .record
                .verify(&send.frozen.credential, &send.frozen.capsule),
        )?;
        let send_capsule = send.frozen.capsule.custody_digest();
        if send.retained.capsule_digest != send_capsule {
            return Err(Error::WitnessLost("Archive selected Send custody"));
        }
        Ok(Self {
            value: Intent::Archive(ArchiveIntentV1 {
                request_id: Self::archive_identity(
                    &send_capsule,
                    &send.frozen.capsule.body().wallet_id,
                    &credited,
                ),
                send_capsule,
                send_commitment: send.frozen.capsule.receipt_commitment(),
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
        capsule: [u8; 32],
        request: Vec<u8>,
        credited: Vec<u8>,
        credential: Vec<u8>,
        certificates: Vec<u8>,
    ) -> Self {
        let payer = payment
            .signed_request()
            .expect("fixture Request")
            .body
            .payer_wallet_id;
        Self::archive_test_originals(
            &payer,
            payment,
            capsule,
            request,
            credited,
            credential,
            certificates,
        )
    }

    /// The same exact retained Archive originals, bound to `wallet`'s private identity.
    #[cfg(test)]
    pub(in crate::kagemusha_wallet_state_v1) fn archive_test_originals(
        wallet: &[u8; 32],
        payment: &KagemushaWalletPaymentV1,
        capsule: [u8; 32],
        request: Vec<u8>,
        credited: Vec<u8>,
        credential: Vec<u8>,
        certificates: Vec<u8>,
    ) -> Self {
        Self {
            value: Intent::Archive(ArchiveIntentV1 {
                request_id: Self::archive_identity(&capsule, wallet, &credited),
                send_capsule: capsule,
                send_commitment: payment.send.receipt.capsule_commitment,
                request,
                payment: payment.to_canonical_bytes().unwrap(),
                credential,
                certificates,
                credited,
            }),
        }
    }
}

// Own decoded originals through their last use, including failed intake/recovery.
// This clears these allocations, not caller aliases or lower-level codec scratch.
impl Drop for NativeIntentV1 {
    fn drop(&mut self) {
        self.clear_originals();
    }
}
impl NativeIntentV1 {
    fn clear_originals(&mut self) {
        use zeroize::Zeroize;
        match &mut self.value {
            Intent::User(request) => {
                request.request_id.zeroize();
                match &mut request.action {
                    OperationActionV1::Load { receipt, finality } => {
                        receipt.zeroize();
                        finality.zeroize();
                    }
                    OperationActionV1::Send { request } => request.zeroize(),
                    OperationActionV1::Receive {
                        payment,
                        payer_credential,
                        certificates,
                    } => {
                        payment.zeroize();
                        payer_credential.zeroize();
                        certificates.zeroize();
                    }
                    OperationActionV1::Refresh {
                        update,
                        certificates,
                        ..
                    } => {
                        update.zeroize();
                        certificates.zeroize();
                    }
                    OperationActionV1::Unload { amount, charge } => {
                        amount.zeroize();
                        if let Some(charge) = charge {
                            charge.quote.zeroize();
                            charge.certificates.zeroize();
                        }
                    }
                    OperationActionV1::Retire => {}
                }
            }
            Intent::Archive(request) => {
                request.request_id.zeroize();
                request.send_capsule.zeroize();
                request.send_commitment.zeroize();
                request.request.zeroize();
                request.payment.zeroize();
                request.credential.zeroize();
                request.certificates.zeroize();
                request.credited.zeroize();
            }
        }
    }
}

#[cfg(test)]
mod clearing_tests {
    use super::*;

    #[test]
    fn all_owned_intake_original_roles_clear_before_release() {
        let actions = [
            OperationActionV1::Load {
                receipt: vec![1],
                finality: vec![2],
            },
            OperationActionV1::Send { request: vec![3] },
            OperationActionV1::Receive {
                payment: vec![4],
                payer_credential: vec![5],
                certificates: vec![6],
            },
            OperationActionV1::Refresh {
                kind: KagemushaWalletPolicyUpdateKindV1::Credential,
                update: vec![7],
                certificates: vec![8],
            },
            OperationActionV1::Unload {
                amount: 9,
                charge: Some(ChargeOriginalsV1 {
                    quote: vec![10],
                    certificates: vec![11],
                }),
            },
            OperationActionV1::Retire,
        ];
        for action in actions {
            let mut intent = NativeIntentV1::user(OperationRequestV1 {
                request_id: [99; 32],
                action,
            });
            intent.clear_originals();
            let request = intent.user_request().unwrap();
            assert_eq!(request.request_id, [0; 32]);
            match &request.action {
                OperationActionV1::Load { receipt, finality } => {
                    assert!(receipt.is_empty() && finality.is_empty())
                }
                OperationActionV1::Send { request } => assert!(request.is_empty()),
                OperationActionV1::Receive {
                    payment,
                    payer_credential,
                    certificates,
                } => assert!(
                    payment.is_empty() && payer_credential.is_empty() && certificates.is_empty()
                ),
                OperationActionV1::Refresh {
                    update,
                    certificates,
                    ..
                } => assert!(update.is_empty() && certificates.is_empty()),
                OperationActionV1::Unload { amount, charge } => {
                    assert_eq!(*amount, 0);
                    let charge = charge.as_ref().unwrap();
                    assert!(charge.quote.is_empty() && charge.certificates.is_empty());
                }
                OperationActionV1::Retire => {}
            }
        }
        let mut intent = NativeIntentV1 {
            value: Intent::Archive(ArchiveIntentV1 {
                request_id: [1; 32],
                send_capsule: [2; 32],
                send_commitment: [3; 32],
                request: vec![4],
                payment: vec![5],
                credential: vec![6],
                certificates: vec![7],
                credited: vec![8],
            }),
        };
        intent.clear_originals();
        let request = intent.archive_request().unwrap();
        assert_eq!(request.request_id, [0; 32]);
        assert_eq!(request.send_capsule, [0; 32]);
        assert_eq!(request.send_commitment, [0; 32]);
        assert!(
            [
                &request.request,
                &request.payment,
                &request.credential,
                &request.certificates,
                &request.credited
            ]
            .iter()
            .all(|bytes| bytes.is_empty())
        );
    }
}
