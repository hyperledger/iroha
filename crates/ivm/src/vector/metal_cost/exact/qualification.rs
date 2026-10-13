//! Required exact AES geometry and actual synthetic/ordinary physical receipts.

use super::*;
use crate::vector::{MetalKernel, metal_aes, metal_runtime};
use iroha_accel::ProcessResources;

#[test]
fn required_metal_aes_exact_geometry_keeps_original_samples_and_receipts() {
    const CHILD: &str = "IVM_METAL_AES_EXACT_GEOMETRY";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let module = module_path!().split_once("::").unwrap().1;
        let test = format!(
            "{module}::required_metal_aes_exact_geometry_keeps_original_samples_and_receipts"
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
            "physical exact AES qualification failed"
        );
        assert!(stdout.contains("1 passed; 0 failed; 0 ignored"));
        return;
    }
    crate::set_acceleration_config(crate::AccelerationConfig {
        enable_simd: true,
        enable_metal: true,
        enable_cuda: false,
        ..Default::default()
    });
    let slots = metal_runtime::device_slots().expect("complete physical Metal inventory");
    assert!(slots > 0, "physical Metal device required");
    let owner = ProcessResources::get().unwrap();
    for slot in 0..slots {
        metal_runtime::with_device_for_qualification(slot, || {
            let health = metal_runtime::current_health().unwrap();
            for (work, blocks, kernel) in [
                (MetalBatchWork::Encrypt, 33, MetalKernel::AesEncBatch),
                (MetalBatchWork::Decrypt, 129, MetalKernel::AesDecBatch),
                (MetalBatchWork::EncryptRounds(9), 513, MetalKernel::AesEncRounds),
                (MetalBatchWork::DecryptRounds(64), 2_047, MetalKernel::AesDecRounds),
            ] {
                let geometry = Geometry::new(work, blocks).unwrap();
                let baseline = AesCpuBaseline::capture(work);
                let production = health.completions(kernel as usize);
                let synthetic = health.synthetic_completions(kernel as usize);
                let original_usage = owner.usage();
                let measured = calibrate(geometry, baseline, Instant::now())
                    .expect("bounded complete exact calibration on required runner");
                assert_eq!(measured.geometry, geometry);
                assert_eq!(measured.baseline, baseline);
                assert_eq!(health.completions(kernel as usize), production);
                assert_eq!(health.synthetic_completions(kernel as usize), synthetic + (PATTERNS * TRIALS) as u64);
                let after_sample = owner.usage();
                assert_eq!(after_sample.host_bytes[0], original_usage.host_bytes[0], "sample final owners refund exact host credit");
                assert!(after_sample.host_bytes[1] >= original_usage.host_bytes[1], "peak reservation history remains monotonic");

                let mut keys = owner.try_host_output::<[u8; 16]>(work.rounds()).unwrap();
                let mut original = owner.try_host_output::<[u8; 16]>(blocks).unwrap();
                let mut expected = owner.try_host_output::<[u8; 16]>(blocks).unwrap();
                let mut output = owner.try_host_output::<[u8; 16]>(blocks).unwrap();
                for (round, key) in keys.iter_mut().enumerate() {
                    *key = std::array::from_fn(|lane| (round * 17 + lane * 7) as u8);
                }
                for (block, value) in original.iter_mut().enumerate() {
                    *value = std::array::from_fn(|lane| (block * 11 + lane * 13) as u8);
                }
                for (source, target) in original.iter().zip(expected.iter_mut()) {
                    *target = keys.iter().fold(*source, |state, key| work.direction().scalar(state, *key));
                }
                output.copy_from_slice(&original);
                assert!(metal_aes::measured_in_place(&mut output, &keys, baseline));
                assert_eq!(output.as_slice(), expected.as_slice());
                assert_eq!(health.completions(kernel as usize), production + 1);

                // Only the actual six-dispatch comparison enters this original
                // owner's slot. A losing GPU comparison never forces selection.
                crate::vector::with_metal_state_try(|state| {
                    let mut cache = state.batch_cost[work.family_index()].try_lock().ok()?;
                    let now = Instant::now();
                    assert_eq!(cache.qualified_cost(now, geometry, baseline, || Some(now), |_| Ok(measured)), measured.cost());
                    Some(())
                }).expect("exact measured comparison installs on original physical owner");
                let before = health.completions(kernel as usize);
                let probes = health.synthetic_completions(kernel as usize);
                output.copy_from_slice(&original);
                let accepted = crate::vector::select_metal_batch(work, blocks)
                    .is_some_and(|selected| selected.run(&mut output, &keys));
                assert_eq!(accepted, measured.cost().is_some());
                if !accepted {
                    crate::aes::rounds_cpu_in_place(&mut output, &keys, work.decrypt());
                }
                assert_eq!(output.as_slice(), expected.as_slice());
                assert_eq!(health.completions(kernel as usize), before + u64::from(accepted));
                assert_eq!(health.synthetic_completions(kernel as usize), probes);
                assert!(crate::vector::select_metal_batch(work, blocks + 1).is_none(), "neighboring geometry cannot consume an exact cached comparison during cooldown");
                assert_eq!(health.synthetic_completions(kernel as usize), probes);

                let enabled = crate::acceleration_config();
                let mut refused = enabled;
                refused.resource_limits.work.host_bytes = 0;
                crate::set_acceleration_config(refused);
                let before = health.completions(kernel as usize);
                output.copy_from_slice(&original);
                assert!(!metal_aes::measured_in_place(&mut output, &keys, baseline));
                assert_eq!(output.as_slice(), original.as_slice());
                assert_eq!(health.completions(kernel as usize), before);
                assert!(health.usable());
                crate::set_acceleration_config(enabled);
                crate::aes::rounds_cpu_in_place(&mut output, &keys, work.decrypt());
                assert_eq!(output.as_slice(), expected.as_slice());
                println!("IVM_METAL_AES_EXACT_RECEIPT device={} work={work:?} blocks={blocks} synthetic_dispatches={} automatic_accepted={accepted} source_preserved=true", health.identity(), PATTERNS * TRIALS);
            }
        }).expect("every original physical owner must execute");
    }
}
