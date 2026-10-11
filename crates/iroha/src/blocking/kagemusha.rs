//! Wallet enrollment and load reads on the account facade's reusable asynchronous runtime.

use super::{AccountClient, RuntimeOwner};
use crate::Result;
use iroha_data_model::isi::kagemusha_wallet::load_finality::KagemushaWalletLoadReceiptV1;

/// Blocking access to canonical account-authenticated wallet services.
#[derive(Clone, Copy, Debug)]
pub struct Kagemusha<'a> {
    inner: crate::client::kagemusha::Kagemusha<'a>,
    runtime: &'a RuntimeOwner,
}

impl AccountClient {
    /// Access wallet services through this account's immutable authority and owned runtime.
    #[must_use]
    pub fn kagemusha(&self) -> Kagemusha<'_> {
        Kagemusha {
            inner: self.inner.kagemusha(),
            runtime: &self.runtime,
        }
    }
}

impl Kagemusha<'_> {
    /// Retrieve direct BLS evidence for an exact receipt, without granting balance authority.
    ///
    /// Verify against independently authenticated genesis-rooted epoch authority.
    /// # Errors
    /// Returns the asynchronous read failure or a blocking-runtime rejection.
    pub fn load_finality(
        &self,
        receipt: &KagemushaWalletLoadReceiptV1,
    ) -> Result<iroha_data_model::kagemusha::KagemushaWalletLoadFinalityV1> {
        self.runtime.block_on(self.inner.load_finality(receipt))?
    }

    /// Retrieve one boundary certificate without granting epoch authority.
    ///
    /// Select the boundary from authenticated native progress and verify its CommitQC
    /// before accepting the successor committee.
    /// # Errors
    /// Returns the asynchronous read failure or a blocking-runtime rejection.
    pub fn load_epoch(
        &self,
        receipt: &KagemushaWalletLoadReceiptV1,
        boundary_height: u64,
    ) -> Result<iroha_data_model::sumeragi_finality::SumeragiCommitCertificateV1> {
        self.runtime
            .block_on(self.inner.load_epoch(receipt, boundary_height))?
    }

    /// Send one exact enrollment operation, preserving native originals for durable recovery.
    ///
    /// Returned originals require the native wallet owner's verification and durable admission.
    /// # Errors
    /// Returns the asynchronous enrollment failure or a typed blocking-runtime rejection.
    pub fn enrollment(
        &self,
        request: &crate::client::kagemusha::EnrollmentServiceRequestV1,
    ) -> Result<crate::client::kagemusha::EnrollmentServiceResponseV1> {
        self.runtime.block_on(self.inner.enrollment(request))?
    }

    /// Retrieve one original load transaction receipt without granting balance authority.
    ///
    /// # Errors
    /// Returns the canonical asynchronous failure or a typed blocking-runtime rejection.
    pub fn load_issuance(
        &self,
        scheme: &[u8; 32],
        wallet: &[u8; 32],
        request: &[u8; 32],
    ) -> Result<KagemushaWalletLoadReceiptV1> {
        self.runtime
            .block_on(self.inner.load_issuance(scheme, wallet, request))?
    }
}
