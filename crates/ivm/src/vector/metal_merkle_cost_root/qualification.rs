//! Required real whole-root work and original physical-owner cost receipts.

use super::*;
use crate::vector::{MetalKernel, metal_merkle, metal_owner::HealthLease, metal_runtime};

fn counts(health: &HealthLease, synthetic: bool) -> [u64; 2] {
    [MetalKernel::Sha256Leaves, MetalKernel::Sha256Pairs].map(|kernel| {
        if synthetic {
            health.synthetic_completions(kernel as usize)
        } else {
            health.completions(kernel as usize)
        }
    })
}

#[test]
fn required_metal_root_exact_geometry_uses_whole_operation_and_synthetic_receipts() {
    const CHILD: &str = "IVM_METAL_ROOT_EXACT_GEOMETRY";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let module = module_path!().split_once("::").unwrap().1;
        let test = format!(
            "{module}::required_metal_root_exact_geometry_uses_whole_operation_and_synthetic_receipts"
        );
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        print!("{stdout}{stderr}");
        assert!(
            output.status.success(),
            "physical whole-root qualification failed"
        );
        assert!(stdout.contains("1 passed; 0 failed; 0 ignored"));
        return;
    }
    crate::set_acceleration_config(crate::AccelerationConfig {
        enable_metal: true,
        enable_cuda: false,
        merkle_min_leaves_gpu: Some(0),
        merkle_min_leaves_metal: Some(0),
        ..Default::default()
    });
    let slots = metal_runtime::device_slots().expect("complete physical Metal inventory");
    assert!(slots > 0, "physical Metal device is required");
    for slot in 0..slots {
        metal_runtime::with_device_for_qualification(slot, || {
            let health = metal_runtime::current_health().expect("original physical owner");
            for (bytes, chunk) in [(8_193 * 17 - 7, 17), (8_193 * 32 - 1, 32)] {
                let geometry = Geometry::new(bytes, chunk).unwrap();
                let levels = u64::from(usize::BITS - (geometry.leaves - 1).leading_zeros());
                let production = counts(&health, false);
                let synthetic = counts(&health, true);
                let profile = calibrate(geometry, Instant::now()).expect("bounded actual root calibration on required physical runner");
                assert_eq!(profile.geometry, geometry);
                assert_eq!(counts(&health, false), production);
                let trials = 2 * TRIALS as u64;
                assert_eq!(counts(&health, true), [synthetic[0] + trials, synthetic[1] + trials * levels]);
                sample::with_inputs(geometry, Instant::now(), |_, input| {
                    input.fill(0x63);
                    let canonical = iroha_crypto::MerkleTree::<[u8; 32]>::from_byte_chunks(input, chunk).unwrap();
                    let expected = *canonical.root().unwrap().as_ref();
                    assert_eq!(metal_merkle::root_from_bytes(input, chunk), Some(expected));
                    assert_eq!(counts(&health, false), [production[0] + 1, production[1] + levels]);
                    // Publish only the first genuinely measured shape. Subsequent
                    // qualification samples do not reset the original owner/cache.
                    if chunk == 17 {
                        super::super::with_metal_state_try(|state| {
                            let mut cache = state.merkle_root_cost.try_lock().ok()?;
                            assert!(cache.profile.is_none());
                            let now = Instant::now();
                            assert_eq!(cache.qualified_cost(now, geometry, || Some(now), |_| Ok(profile)), profile.cost());
                            Some(())
                        }).expect("profile belongs to original physical owner");
                        let before = counts(&health, false);
                        let probes = counts(&health, true);
                        assert_eq!((crate::byte_merkle_tree::ByteMerkleTree::root_from_bytes_accel(input, chunk)).expect("expected successful fixture result"), expected);
                        let native = u64::from(profile.cost().is_some());
                        assert_eq!(counts(&health, false), [before[0] + native, before[1] + native * levels]);
                        assert_eq!(counts(&health, true), probes);
                    }
                    let enabled = crate::acceleration_config();
                    let mut refused = enabled;
                    refused.resource_limits.work.host_bytes = 0;
                    crate::set_acceleration_config(refused);
                    let before = counts(&health, false);
                    assert_eq!(metal_merkle::root_from_bytes(input, chunk), None);
                    assert_eq!((crate::byte_merkle_tree::ByteMerkleTree::root_from_bytes_accel(input, chunk)).expect("expected successful fixture result"), expected);
                    assert_eq!(counts(&health, false), before, "unfunded native attempt earns no dispatch credit");
                    crate::set_acceleration_config(enabled);
                    assert!(input.iter().all(|&byte| byte == 0x63));
                    Ok(())
                }).unwrap();
                println!("IVM_METAL_ROOT_EXACT_RECEIPT device={} bytes={} chunk={} production_leaf={} production_pair={} synthetic_leaf={} synthetic_pair={}", health.identity(), bytes, chunk, counts(&health, false)[0] - production[0], counts(&health, false)[1] - production[1], counts(&health, true)[0] - synthetic[0], counts(&health, true)[1] - synthetic[1]);
            }
        }).expect("every original physical device must execute");
    }
}
