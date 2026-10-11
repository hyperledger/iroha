//! Bounded lifecycle inputs; only native preparation may derive state or witnesses.

use iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLoadReceiptV1;

use super::*;

/// Largest online finality or administrative original plus companion and request metadata.
/// This local intake bound leaves the 10,000-byte peer Payment limit unchanged.
pub const REQUEST_MAX_BYTES: usize = {
    let original =
        if KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1 > KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1 {
            KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1
        } else {
            KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1
        };
    original + KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 + 1024
};

/// Exact signed online-charge originals; the caller cannot supply an accepted charge value.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::ChargeOriginalsV1")]
pub struct ChargeOriginalsV1 {
    /// Canonical signed charge quote.
    pub quote: Vec<u8>,
    /// Canonical certificate set authenticating that quote.
    pub certificates: Vec<u8>,
}

/// First-release transition requests. State, proof selectors, roots, map openings, quota
/// usage, timestamps and fresh nonces are deliberately absent from this foreign boundary.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::OperationActionV1")]
pub enum OperationActionV1 {
    /// Exact ordinary-ledger receipt and its compact finality proof.
    Load {
        /// Original canonical receipt.
        receipt: Vec<u8>,
        /// Original canonical finality evidence; still requires the installed verifier.
        finality: Vec<u8>,
    },
    /// Irreversible Send to the exact receiver-signed Request.
    Send {
        /// Original canonical Request, including its credential and certificates.
        request: Vec<u8>,
    },
    /// Receive the exact Payment; Native selects its durably issued Request by digest.
    Receive {
        /// Original canonical Payment, at most10,000 bytes.
        payment: Vec<u8>,
        /// Original payer credential.
        payer_credential: Vec<u8>,
        /// Original payer certificate set.
        certificates: Vec<u8>,
    },
    /// Apply one of the five existing signed update classes.
    Refresh {
        /// Exact existing fixed update class; no new proof profile is selected here.
        kind: KagemushaWalletPolicyUpdateKindV1,
        /// Original signed update.
        update: Vec<u8>,
        /// Original certificate set.
        certificates: Vec<u8>,
    },
    /// Consume folded value to the credential's canonical account.
    Unload {
        /// Requested positive gross amount; Native derives the charge and recovery map.
        amount: u128,
        /// Optional exact signed quote; absence means the existing zero-charge policy.
        charge: Option<ChargeOriginalsV1>,
    },
    /// Irreversibly enter the existing Retiring lifecycle from a folded head.
    Retire,
}

/// Stable caller request identity, retained with exact canonical input bytes before proving.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::OperationRequestV1")]
pub struct OperationRequestV1 {
    /// Nonzero local request identity; reusing it with different bytes is always a conflict.
    pub request_id: [u8; 32],
    /// User intent and exact original objects.
    pub action: OperationActionV1,
}

fn bounded(bytes: &[u8], limit: usize) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(Error::Invalid("lifecycle original size"));
    }
    Ok(())
}

fn certificates(bytes: &[u8], scheme: &[u8; 32]) -> Result<(), Error> {
    bounded(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?;
    let set: KagemushaWalletCertificateSetV1 = archive::decode(bytes)?;
    valid(set.validate())?;
    if set
        .certificates
        .iter()
        .any(|certificate| certificate.body.scheme_id != *scheme)
    {
        return Err(Error::Invalid("lifecycle certificate scheme"));
    }
    Ok(())
}

impl OperationRequestV1 {
    /// Fixed protocol operation requested by this typed action.
    #[must_use]
    pub const fn kind(&self) -> KagemushaWalletOperationKindV1 {
        match self.action {
            OperationActionV1::Load { .. } => KagemushaWalletOperationKindV1::Load,
            OperationActionV1::Send { .. } => KagemushaWalletOperationKindV1::Send,
            OperationActionV1::Receive { .. } => KagemushaWalletOperationKindV1::Receive,
            OperationActionV1::Refresh { .. } => KagemushaWalletOperationKindV1::RefreshPolicy,
            OperationActionV1::Unload { .. } => KagemushaWalletOperationKindV1::Unload,
            OperationActionV1::Retire => KagemushaWalletOperationKindV1::Retiring,
        }
    }

    /// Bound and decode canonical originals under the installed scheme. This is intake
    /// validation, not sigma/Omega acceptance, source selection or issuer admission.
    ///
    /// # Errors
    /// Zero identity, malformed/noncanonical/oversized original, foreign scheme or zero amount.
    pub fn validate(&self, scheme: &KagemushaWalletSchemeV1) -> Result<(), Error> {
        if self.request_id == [0; 32] {
            return Err(Error::Invalid("lifecycle request identity"));
        }
        let id = scheme.scheme_id();
        match &self.action {
            OperationActionV1::Load { receipt, finality } => {
                let receipt = valid(KagemushaWalletLoadReceiptV1::decode_canonical(receipt))?;
                if receipt.scheme_id != id {
                    return Err(Error::Invalid("load request scheme"));
                }
                valid(KagemushaWalletLoadFinalityV1::decode_canonical(finality))?;
            }
            OperationActionV1::Send { request } => {
                bounded(request, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?;
                let request: KagemushaWalletRequestV1 = archive::decode(request)?;
                valid(request.verify(scheme))?;
            }
            OperationActionV1::Receive {
                payment,
                payer_credential,
                certificates: set,
            } => {
                valid(KagemushaWalletPaymentV1::decode_canonical(payment, &id))?;
                valid(KagemushaWalletCredentialV1::decode_canonical(
                    payer_credential,
                    &id,
                ))?;
                certificates(set, &id)?;
            }
            OperationActionV1::Refresh {
                kind,
                update,
                certificates: set,
            } => {
                use KagemushaWalletPolicyUpdateKindV1 as K;
                match kind {
                    K::Credential => {
                        valid(KagemushaWalletCredentialV1::decode_canonical(update, &id))?;
                    }
                    K::SchemePolicy => {
                        valid(KagemushaWalletSchemePolicyV1::decode_canonical(update, &id))?;
                    }
                    K::Blacklist => {
                        valid(KagemushaWalletBlacklistV1::decode_canonical(update, &id))?;
                    }
                    K::TimeAnchor => {
                        valid(KagemushaWalletTimeAnchorV1::decode_canonical(update, &id))?;
                    }
                    K::QuotaShare => {
                        valid(KagemushaWalletQuotaShareV1::decode_canonical(update, &id))?;
                    }
                }
                certificates(set, &id)?;
            }
            OperationActionV1::Unload { amount, charge } => {
                if *amount == 0 {
                    return Err(Error::Invalid("unload request amount"));
                }
                if let Some(charge) = charge {
                    valid(KagemushaWalletChargeQuoteV1::decode_canonical(
                        &charge.quote,
                        &id,
                    ))?;
                    certificates(&charge.certificates, &id)?;
                }
            }
            OperationActionV1::Retire => {}
        }
        Ok(())
    }

    /// Decode only the current canonical request layout after enforcing its allocation bound.
    ///
    /// # Errors
    /// Oversized, malformed or noncanonical bytes, or invalid current original inputs.
    pub fn decode(bytes: &[u8], scheme: &KagemushaWalletSchemeV1) -> Result<Self, Error> {
        bounded(bytes, REQUEST_MAX_BYTES)?;
        let request: Self = archive::decode(bytes)?;
        request.validate(scheme)?;
        Ok(request)
    }
}
