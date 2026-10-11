//! Account-authenticated wallet enrollment and canonical load issuance originals.

mod enrollment;
mod finality;
pub use iroha_torii_shared::kagemusha_enrollment::{
    EnrollmentServiceActionV1, EnrollmentServiceRequestV1, EnrollmentServiceResponseV1,
};

use super::{AccountClient, ActivationEvidenceReadAuth, Client, dispatch};
use crate::{Error, Result, http::StatusCode};
use iroha_data_model::isi::kagemusha_wallet::load_finality::{
    KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1, KagemushaWalletLoadReceiptV1,
};

// The receipt contains a fixed payer digest and one bounded canonical frame.
pub(super) const MAX_RESPONSE_BYTES: usize = KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1;
const READ: &str = "kagemusha.wallet.load_issuance.read";

/// Wallet service operations using one immutable account and network context.
///
/// These records are transport data. Monetary authorization requires independently verified
/// ordinary block finality and the successful transaction with these exact load terms.
///
/// ```compile_fail
/// fn read_load(client: &iroha::client::Client) {
///     let _ = client.kagemusha();
/// }
/// ```
///
/// ```compile_fail
/// fn read_load(operator: &iroha::client::OperatorClient) {
///     let _ = operator.kagemusha();
/// }
#[derive(Clone, Copy, Debug)]
pub struct Kagemusha<'a> {
    account: &'a AccountClient,
}

impl AccountClient {
    /// Access wallet enrollment and load records using this account's exact network signature.
    #[must_use]
    pub const fn kagemusha(&self) -> Kagemusha<'_> {
        Kagemusha { account: self }
    }
}

impl Kagemusha<'_> {
    /// Retrieve the original receipt of one finalized ordinary load transaction.
    ///
    /// All three identities must be nonzero. The request signs the canonical lowercase
    /// route for this context's payer and network. It performs one bounded asynchronous
    /// GET, without a compatibility probe, alternate codec or automatic retry. An unavailable
    /// source remains an error. This read alone grants no offline balance authority.
    ///
    /// # Errors
    /// Rejects invalid identities or a non-direct signer, signing/transport/deadline/HTTP
    /// failures, noncanonical binary responses, foreign payer/scope or invalid receipt fields.
    pub async fn load_issuance(
        &self,
        scheme: &[u8; 32],
        wallet: &[u8; 32],
        request: &[u8; 32],
    ) -> Result<KagemushaWalletLoadReceiptV1> {
        let client = &self.account.context;
        for identity in [scheme, wallet, request] {
            if identity == &[0; 32] {
                return Err(Error::InvalidRequest {
                    operation: READ,
                    details: "load identities must be nonzero".to_owned(),
                });
            }
        }
        if client.account.controller.single_signatory() != Some(client.key_pair.public_key())
            || client
                .headers
                .keys()
                .any(|name| name.eq_ignore_ascii_case("X-Iroha-Witness"))
        {
            return Err(Error::InvalidRequest {
                operation: READ,
                details: "load reads require the direct payer signer without witness headers"
                    .to_owned(),
            });
        }
        ensure_deadline(client, READ)?;
        let path = iroha_torii_shared::route_catalog::contracts_and_verification_keys::KAGEMUSHA_LOAD_ISSUANCE_GET
            .path()
            .replace("{scheme}", &hex::encode(scheme))
            .replace("{wallet}", &hex::encode(wallet))
            .replace("{request}", &hex::encode(request));
        let builder = client
            .canonical_norito_get_request(
                &path,
                MAX_RESPONSE_BYTES,
                ActivationEvidenceReadAuth::Account,
            )
            .map_err(|error| Error::RequestSigning {
                operation: READ,
                details: error.to_string(),
            })?;
        let response = dispatch::send(client, READ, builder, "application/x-norito").await?;
        if response.status() != StatusCode::OK {
            return Err(Error::Http {
                operation: READ,
                status: response.status().as_u16(),
                retry_after: crate::error::retry_after(response.headers()),
                body: response.into_body(),
            });
        }
        let issuance =
            Client::decode_canonical_norito_response(&response, MAX_RESPONSE_BYTES, READ)?;
        validate_response(&issuance, self.account.authority(), scheme, wallet, request)?;
        ensure_deadline(client, READ)?;
        Ok(issuance)
    }
}

fn ensure_deadline(client: &Client, operation: &'static str) -> Result<()> {
    if client
        .http_transport
        .deadline()
        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    {
        return Err(Error::Timeout { operation });
    }
    Ok(())
}

fn validate_response(
    issuance: &KagemushaWalletLoadReceiptV1,
    payer: &iroha_data_model::account::AccountId,
    scheme: &[u8; 32],
    wallet: &[u8; 32],
    request: &[u8; 32],
) -> Result<()> {
    let mismatch = |field| Error::ResponseBinding {
        operation: READ,
        field,
    };
    if issuance.request_id != *request {
        return Err(mismatch("request_id"));
    }
    if issuance.payer_account_digest
        != iroha_data_model::kagemusha::kagemusha_wallet_account_digest_v1(payer)
            .map_err(|_| mismatch("payer"))?
    {
        return Err(mismatch("payer"));
    }
    if issuance.scheme_id != *scheme || issuance.wallet_id != *wallet {
        return Err(mismatch("wallet scope"));
    }
    issuance.validate().map_err(|_| mismatch("issuance body"))?;
    Ok(())
}
