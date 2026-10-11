//! Generic proof-resource bounds do not select or authorize a proof engine.
use ivm::host::{DefaultHost, ZkVerifyLimits};

#[test]
fn host_limits_default_and_replacement_are_exact() {
    let mut host = DefaultHost::new();
    assert_eq!(host.zk_verify_limits(), ZkVerifyLimits::default());
    let limits = ZkVerifyLimits {
        max_verify_batch: 3,
        max_envelope_bytes: 4096,
        max_proof_bytes: 1024,
    };
    host.set_zk_verify_limits(limits);
    assert_eq!(host.zk_verify_limits(), limits);
    assert_eq!(
        DefaultHost::new()
            .with_zk_verify_limits(limits)
            .zk_verify_limits(),
        limits
    );
}
