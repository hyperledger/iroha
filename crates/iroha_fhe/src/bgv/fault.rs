//! Named points at which a test can make a secret-handling operation unwind.
//!
//! Erasure on unwind cannot be observed unless an operation panics while its
//! secret buffers are live. Each secret-handling operation therefore names
//! one point in its middle. In a production build [`reached`] compiles to
//! nothing. Under `cfg(any(test, feature = "bgv-test-fixtures"))` a test arms
//! one point on its own thread and the next operation that reaches it
//! panics once.
#[cfg(any(test, feature = "bgv-test-fixtures"))]
use std::cell::Cell;

/// A point in the middle of a secret-handling operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    /// Secret-key generation, after the secret was sampled and transformed.
    SecretKeyAfterSampling,
    /// Public-key generation, after the error was sampled.
    PublicKeyAfterSampling,
    /// Switching-key generation, after the first digit was built.
    SwitchingKeyAfterFirstDigit,
    /// Encryption, after the mask and both errors were sampled.
    EncryptionAfterSampling,
    /// Decryption, after `c0 + c1*s` was formed.
    DecryptionAfterInnerProduct,
    /// Offline dealer, after the first secret sharing polynomial was sampled.
    ThresholdAfterFirstPolynomial,
    /// Offline dealer, after calculating a share but before marking it issued.
    ThresholdBeforeShareRelease,
}

#[cfg(any(test, feature = "bgv-test-fixtures"))]
thread_local! {
    static ARMED: Cell<Option<FaultPoint>> = const { Cell::new(None) };
}

/// Arm `point` on this thread: the next operation that reaches it panics once.
#[cfg(any(test, feature = "bgv-test-fixtures"))]
pub fn arm(point: FaultPoint) {
    ARMED.with(|armed| armed.set(Some(point)));
}

/// Disarm this thread.
#[cfg(any(test, feature = "bgv-test-fixtures"))]
pub fn disarm() {
    ARMED.with(|armed| armed.set(None));
}

/// Called by an operation when it reaches `point`.
pub(super) fn reached(point: FaultPoint) {
    #[cfg(any(test, feature = "bgv-test-fixtures"))]
    {
        let fire = ARMED.with(|armed| {
            let fire = armed.get() == Some(point);
            if fire {
                armed.set(None);
            }
            fire
        });
        assert!(!fire, "injected fault at {point:?}");
    }
    #[cfg(not(any(test, feature = "bgv-test-fixtures")))]
    {
        let _ = point;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::catch_unwind;

    #[test]
    fn an_armed_point_fires_once_and_only_for_its_own_point() {
        reached(FaultPoint::EncryptionAfterSampling);
        arm(FaultPoint::EncryptionAfterSampling);
        reached(FaultPoint::DecryptionAfterInnerProduct);
        assert!(catch_unwind(|| reached(FaultPoint::EncryptionAfterSampling)).is_err());
        reached(FaultPoint::EncryptionAfterSampling);
        arm(FaultPoint::SecretKeyAfterSampling);
        disarm();
        reached(FaultPoint::SecretKeyAfterSampling);
    }
}
