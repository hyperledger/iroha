//! Native account-authorized enrollment over one exclusive hardware custody provider.
//!
//! Trusted native deployment selects the exact scheme, policies and, on Apple, the root
//! original; an Android `KeyMint` chain carries its own root, matched by SPKI. Foreign
//! calls provide retry identity and original account/asset/permit/evidence frames only. Native retains
//! a client nonce before issuer E1 and checks the rooted permit and process-bound,
//! suspend-inclusive elapsed budget immediately before hardware generation. This live clock
//! is never restored: restarting the process requires a fresh dispatch and permit. It grants
//! no boot identity or persisted time-anchor authority. The issuer independently
//! authenticates its live challenge, current account eligibility and platform evidence before
//! signing. Retained E5 and E6 bytes survive retries; this module grants no Bootstrap proof
//! capability and never replaces the complete source-qualified wallet-open boundary.

mod carrier;
mod credential;
pub mod issuer_worker;
mod owner;
mod prekey;
pub use carrier::{
    ANDROID_CERTIFICATE_MAX_BYTES, ANDROID_CHAIN_MAX, ANDROID_CHAIN_MAX_BYTES, ANDROID_CHAIN_MIN,
    EVIDENCE_MAX_BYTES, IssuerEvidenceV1, PlatformEvidenceV1, REQUEST_MAX_BYTES, RESULT_MAX_BYTES,
    RequestBodyV1, RequestV1, ResultV1,
};
pub use owner::{
    EnrollmentAbandonmentV1, EnrollmentConfigV1, EnrollmentOwnerV1, EnrollmentProgressV1, Error,
    RequestPreparationV1,
};
pub(crate) use prekey::GenerationAuthorizationV1;
pub use prekey::{PREKEY_DISPATCH_MAX_BYTES, PreKeyDispatchV1};
