//! Mandatory deployment-owned authority boundaries; no DATA-to-session adapter is supplied.

use super::*;

/// Trusted daemon integration. Every method is mandatory; none accepts a caller's verdict.
///
/// Implementations own the actual authenticated Torii envelope, current configured policy,
/// provider-owned current account/actor eligibility, bounded authenticated transport and exclusive worker/signer custody. They
/// must fail closed on missing/replaced runtime handles, revoked policy and unknown outcomes.
/// A test implementation proves orchestration only, never real provider/platform qualification.
pub trait EnrollmentIssuerRuntimeV1 {
    /// Actual transport original consumed by this deployment verifier, never an account verdict.
    type Call: ?Sized;
    /// Fresh authenticated operator selection, including explicit revocation/removal.
    ///
    /// # Errors
    ///
    /// Returns an error if the current authenticated operator configuration
    /// cannot be obtained.
    fn current_configuration(&mut self) -> Result<Arc<KagemushaEnrollmentIssuer>>;
    /// Admit the actual current transport, prepared worker and rooted signer owners.
    /// Checking strings or hashes alone does not satisfy this requirement.
    ///
    /// # Errors
    ///
    /// Returns an error if configured selection changed or the transport,
    /// worker, or rooted signer owners are unavailable or fail revalidation.
    fn require_dependencies(&mut self, config: &KagemushaEnrollmentIssuer) -> Result<()>;
    /// Verify the actual Torii signature/witness, exact network/method/path/body, freshness and
    /// replay. The signature must cover the entire operation envelope and its exact `expected_dispatch`;
    /// a bare account header or unsigned extracted dispatch is insufficient.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or unavailable call authentication,
    /// including mismatched dispatch, freshness, or replay evidence.
    fn authenticate_call(
        &mut self,
        call: &Self::Call,
        expected_dispatch: &[u8],
    ) -> Result<AccountId>;
    /// Actual UTC clock observation; failures and rollback abort the operation.
    ///
    /// # Errors
    ///
    /// Returns an error if a valid UTC millisecond observation is unavailable.
    fn now_ms(&mut self) -> Result<u64>;
    /// Derive the exact asset policy from the selected template, then exchange one canonical eligibility request through this configured HTTPS
    /// endpoint and private credential. Disable redirects and cap the response before allocation.
    /// The selected provider independently verifies the account/actor/customer relationship and
    /// current eligibility. Configured routing and request DATA alone must never grant approval.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected provider or authenticated transport is
    /// unavailable, the bounded request/response is invalid, or the exchange times out.
    fn observe_eligibility(
        &mut self,
        provider: &KagemushaEnrollmentProvider,
        asset: &KagemushaWalletAssetScopeV1,
        request: &[u8],
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>>;
    /// Bind actual authenticated worker custody to the exact selected app/policy/root/runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if provider selection changed or the authenticated
    /// worker cannot bind the selected application, policy, asset, and root.
    fn worker_configuration(
        &mut self,
        provider: &KagemushaEnrollmentProvider,
        asset: &KagemushaWalletAssetScopeV1,
    ) -> Result<VerifierConfigurationV1>;
    /// Exchange an exact framed packet on that configuration's admitted private worker channel.
    /// Missing worker custody is unavailable; fabricated protocol-shaped replies are forbidden.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or changed worker custody, invalid framing
    /// or configuration, or an unavailable or uncertain worker exchange.
    fn worker_exchange(
        &mut self,
        provider: &KagemushaEnrollmentProvider,
        configuration: &VerifierConfigurationV1,
        exchange: &VerifierExchangeV1,
    ) -> Result<Vec<u8>>;
    /// Invoke the exact rooted Enrollment signer on the supplied protocol message; return the
    /// actual bounded DER original. The owner verifies its role and public key again natively.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected rooted signer is unavailable or fails
    /// custody/signing checks; an uncertain outcome must not be reported as success.
    fn sign_enrollment(
        &mut self,
        provider: &KagemushaEnrollmentProvider,
        message: &[u8; 32],
    ) -> Result<Vec<u8>>;
}
