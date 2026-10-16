//! Account-authenticated transport of direct BLS Load and ledger finality evidence.

use super::{ActivationEvidenceReadAuth, Client, Kagemusha, ensure_deadline};
use crate::{Error, Result, client::dispatch, http::StatusCode};
use iroha_crypto::HashOf;
use iroha_data_model::{
    isi::kagemusha_wallet::KagemushaWalletLoadReceiptV1,
    kagemusha::{
        KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1, KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
        KagemushaWalletLedgerFinalityV1, KagemushaWalletLoadFinalityV1,
    },
    sumeragi_finality::{MAX_COMMIT_CERTIFICATE_BYTES_V1, SumeragiCommitCertificateV1},
    transaction::TransactionEntrypoint,
};

const OP: &str = "kagemusha.wallet.load_finality.read";
const EPOCH_OP: &str = "kagemusha.wallet.load_epoch.read";
const LEDGER_OP: &str = "kagemusha.wallet.ledger_finality.read";
const LEDGER_EPOCH_OP: &str = "kagemusha.wallet.ledger_epoch.read";

impl Kagemusha<'_> {
    /// Retrieve the native BLS certificate and event inclusion for the exact retained receipt.
    ///
    /// This account-authenticated bounded read returns transport data. Call the evidence's
    /// `verify_with` method with independently authenticated genesis-rooted epoch authority
    /// before authorizing a Load. Synchronize missing epochs with [`Self::load_epoch`].
    /// No finality prover, asynchronous proof job or polling is required.
    ///
    /// # Errors
    /// Invalid receipt or payer, signing/HTTP failures, expired deadline, malformed evidence,
    /// or a response bound to a different receipt.
    pub async fn load_finality(
        &self,
        receipt: &KagemushaWalletLoadReceiptV1,
    ) -> Result<KagemushaWalletLoadFinalityV1> {
        let path = receipt_path(
            iroha_torii_shared::route_catalog::contracts_and_verification_keys::KAGEMUSHA_LOAD_FINALITY_GET.path(),
            receipt,
        );
        let evidence: KagemushaWalletLoadFinalityV1 = self
            .read_finality_original(
                receipt,
                &path,
                KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
                OP,
            )
            .await?;
        evidence.validate().map_err(|error| Error::Decode {
            operation: OP,
            details: error.to_string(),
        })?;
        if evidence.receipt_digest
            != receipt.receipt_digest().map_err(|error| Error::Decode {
                operation: OP,
                details: error.to_string(),
            })?
        {
            return Err(Error::ResponseBinding {
                operation: OP,
                field: "receipt_digest",
            });
        }
        ensure_deadline(&self.account.context, OP)?;
        Ok(evidence)
    }

    /// Retrieve one bounded epoch-boundary certificate before the receipt's height.
    ///
    /// Select `boundary_height` from the last independently authenticated epoch authority.
    /// The response is DATA: verify its incumbent `CommitQC` before accepting its successor
    /// committee or selecting another boundary. Never import a peer-supplied checkpoint.
    ///
    /// # Errors
    /// Invalid receipt, payer or height, signing/HTTP failures, expired deadline, malformed
    /// certificate, or a response naming a different height.
    pub async fn load_epoch(
        &self,
        receipt: &KagemushaWalletLoadReceiptV1,
        boundary_height: u64,
    ) -> Result<SumeragiCommitCertificateV1> {
        if boundary_height < 2 || boundary_height >= receipt.block_height {
            return Err(Error::InvalidRequest {
                operation: EPOCH_OP,
                details: "epoch boundary must precede the receipt and follow genesis".into(),
            });
        }
        let path = receipt_path(
            iroha_torii_shared::route_catalog::contracts_and_verification_keys::KAGEMUSHA_LOAD_EPOCH_GET.path(),
            receipt,
        )
        .replace("{boundary}", &boundary_height.to_string());
        let certificate: SumeragiCommitCertificateV1 = self
            .read_finality_original(receipt, &path, MAX_COMMIT_CERTIFICATE_BYTES_V1, EPOCH_OP)
            .await?;
        bind_boundary(&certificate, boundary_height, EPOCH_OP)?;
        ensure_deadline(&self.account.context, EPOCH_OP)?;
        Ok(certificate)
    }

    /// Retrieve direct ledger finality for one committed Activate or Unload attempt of this
    /// account: the inclusion block's original certificate and the selective membership of
    /// the exact entrypoint and its joined Network output.
    ///
    /// An attempt of this account is one it signed, or an Unload whose claim pays it, which
    /// another account may have relayed. `entrypoint` is the hash of the signed attempt the
    /// wallet retains. The response is transport DATA: verify it with
    /// `KagemushaWalletLedgerFinalityV1::verify` on the wallet's selected epoch reader before
    /// using any outcome, and synchronize a missing epoch with [`Self::ledger_epoch`]. This read
    /// does not compare the transaction's signer with this account; the wallet's retained
    /// exact claim and signed wire bind a relayed Unload. Torii answers one 404
    /// (`kagemusha_ledger_entry_not_committed`) for an uncommitted attempt and for every
    /// input that is not this account's Activate or Unload naming this wallet.
    ///
    /// # Errors
    /// Zero identities, a non-direct signer, signing/HTTP failures, expired deadline,
    /// malformed or oversized evidence, or evidence naming another entrypoint.
    pub async fn ledger_finality(
        &self,
        scheme: &[u8; 32],
        wallet: &[u8; 32],
        entrypoint: &HashOf<TransactionEntrypoint>,
    ) -> Result<KagemushaWalletLedgerFinalityV1> {
        let path = ledger_path(
            iroha_torii_shared::route_catalog::contracts_and_verification_keys::KAGEMUSHA_LEDGER_FINALITY_GET.path(),
            scheme,
            wallet,
            entrypoint,
            LEDGER_OP,
        )?;
        let evidence: KagemushaWalletLedgerFinalityV1 = self
            .read_account_original(
                &path,
                KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1,
                LEDGER_OP,
            )
            .await?;
        evidence.validate().map_err(|error| Error::Decode {
            operation: LEDGER_OP,
            details: error.to_string(),
        })?;
        if evidence.entrypoint_hash != *entrypoint {
            return Err(Error::ResponseBinding {
                operation: LEDGER_OP,
                field: "entrypoint",
            });
        }
        ensure_deadline(&self.account.context, LEDGER_OP)?;
        Ok(evidence)
    }

    /// Retrieve one bounded epoch-boundary certificate before a committed Activate or Unload
    /// attempt of this account, as [`Self::ledger_finality`] defines it.
    ///
    /// Select `boundary_height` from the wallet's own authenticated epoch progress; Torii
    /// serves only a boundary before the attempt's inclusion height. The response is DATA:
    /// verify its incumbent `CommitQC` before accepting its successor committee.
    ///
    /// # Errors
    /// Zero identities or a genesis boundary, a non-direct signer, signing/HTTP failures,
    /// expired deadline, malformed certificate, or a response naming a different height.
    pub async fn ledger_epoch(
        &self,
        scheme: &[u8; 32],
        wallet: &[u8; 32],
        entrypoint: &HashOf<TransactionEntrypoint>,
        boundary_height: u64,
    ) -> Result<SumeragiCommitCertificateV1> {
        if boundary_height < 2 {
            return Err(Error::InvalidRequest {
                operation: LEDGER_EPOCH_OP,
                details: "epoch boundary must follow genesis".into(),
            });
        }
        let path = ledger_path(
            iroha_torii_shared::route_catalog::contracts_and_verification_keys::KAGEMUSHA_LEDGER_EPOCH_GET.path(),
            scheme,
            wallet,
            entrypoint,
            LEDGER_EPOCH_OP,
        )?
        .replace("{boundary}", &boundary_height.to_string());
        let certificate: SumeragiCommitCertificateV1 = self
            .read_account_original(&path, MAX_COMMIT_CERTIFICATE_BYTES_V1, LEDGER_EPOCH_OP)
            .await?;
        bind_boundary(&certificate, boundary_height, LEDGER_EPOCH_OP)?;
        ensure_deadline(&self.account.context, LEDGER_EPOCH_OP)?;
        Ok(certificate)
    }

    async fn read_finality_original<T>(
        &self,
        receipt: &KagemushaWalletLoadReceiptV1,
        path: &str,
        maximum: usize,
        operation: &'static str,
    ) -> Result<T>
    where
        T: norito::core::NoritoSerialize,
        for<'de> T: norito::core::NoritoDeserialize<'de>,
    {
        receipt.validate().map_err(|error| Error::InvalidRequest {
            operation,
            details: error.to_string(),
        })?;
        let payer = iroha_data_model::kagemusha::kagemusha_wallet_account_digest_v1(
            self.account.authority(),
        )
        .map_err(|error| Error::InvalidRequest {
            operation,
            details: error.to_string(),
        })?;
        if receipt.payer_account_digest != payer {
            return Err(Error::ResponseBinding {
                operation,
                field: "payer",
            });
        }
        self.read_account_original(path, maximum, operation).await
    }

    /// One bounded canonical Norito GET signed by this account's direct signer.
    async fn read_account_original<T>(
        &self,
        path: &str,
        maximum: usize,
        operation: &'static str,
    ) -> Result<T>
    where
        T: norito::core::NoritoSerialize,
        for<'de> T: norito::core::NoritoDeserialize<'de>,
    {
        let client = &self.account.context;
        if client.account.controller.single_signatory() != Some(client.key_pair.public_key())
            || client
                .headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("X-Iroha-Witness"))
        {
            return Err(Error::InvalidRequest {
                operation,
                details: "wallet finality reads require the direct account signer".into(),
            });
        }
        ensure_deadline(client, operation)?;
        let builder = client
            .canonical_norito_get_request(path, maximum, ActivationEvidenceReadAuth::Account)
            .map_err(|error| Error::RequestSigning {
                operation,
                details: error.to_string(),
            })?;
        let response = dispatch::send(client, operation, builder, "application/x-norito").await?;
        if response.status() != StatusCode::OK {
            return Err(Error::Http {
                operation,
                status: response.status().as_u16(),
                retry_after: crate::error::retry_after(response.headers()),
                body: response.into_body(),
            });
        }
        let original = Client::decode_canonical_norito_response(&response, maximum, operation)?;
        ensure_deadline(client, operation)?;
        Ok(original)
    }
}

/// Bind one boundary certificate's finite shape and header height to the requested height.
fn bind_boundary(
    certificate: &SumeragiCommitCertificateV1,
    boundary_height: u64,
    operation: &'static str,
) -> Result<()> {
    certificate
        .validate_shape()
        .map_err(|error| Error::Decode {
            operation,
            details: error.to_string(),
        })?;
    let height = certificate.height().map_err(|error| Error::Decode {
        operation,
        details: error.to_string(),
    })?;
    if height != boundary_height {
        return Err(Error::ResponseBinding {
            operation,
            field: "boundary_height",
        });
    }
    Ok(())
}

fn receipt_path(template: &str, receipt: &KagemushaWalletLoadReceiptV1) -> String {
    template
        .replace("{scheme}", &hex::encode(receipt.scheme_id))
        .replace("{wallet}", &hex::encode(receipt.wallet_id))
        .replace("{request}", &hex::encode(receipt.request_id))
}

/// Canonical lowercase route for one attempt; Torii refuses zero identities.
fn ledger_path(
    template: &str,
    scheme: &[u8; 32],
    wallet: &[u8; 32],
    entrypoint: &HashOf<TransactionEntrypoint>,
    operation: &'static str,
) -> Result<String> {
    if scheme == &[0; 32] || wallet == &[0; 32] {
        return Err(Error::InvalidRequest {
            operation,
            details: "ledger identities must be nonzero".into(),
        });
    }
    let entrypoint: &[u8; 32] = entrypoint.as_ref();
    Ok(template
        .replace("{scheme}", &hex::encode(scheme))
        .replace("{wallet}", &hex::encode(wallet))
        .replace("{entrypoint}", &hex::encode(entrypoint)))
}
