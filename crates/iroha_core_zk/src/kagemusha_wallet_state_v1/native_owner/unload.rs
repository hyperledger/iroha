//! Native Unload transport projection; ledger finality remains a separate operation.
use super::*;

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    /// Construct the bounded canonical ledger claim for an exact completed Unload request.
    /// The account comes from native admission, and optional charge-beneficiary DATA must match
    /// the exact retained quote. No proof/signature is regenerated and no settlement is claimed.
    /// Retries remain available after fold-witness collection from permanent selected originals.
    ///
    /// # Errors
    /// Pending/unknown/wrong-kind requests, lost selected originals, unavailable custody,
    /// foreign beneficiary/quote/account, or an encoded claim exceeding its fixed bound.
    pub fn unload_claim_bytes(
        &mut self,
        request_id: &[u8; 32],
        beneficiary_original: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let account = self.proofs.account.clone();
        self.retained_unload_claim(request_id, &account, beneficiary_original)
    }
}
