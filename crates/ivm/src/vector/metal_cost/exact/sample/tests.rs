//! Exact sample allocation admission, both public patterns and final-owner refund.

use super::*;

fn assert_pattern(inputs: &Inputs, nonzero: bool) {
    for (round, key) in inputs.keys.iter().enumerate() {
        assert_eq!(
            *key,
            std::array::from_fn(|lane| if nonzero {
                (round as u8)
                    .wrapping_mul(19)
                    .wrapping_add(lane as u8)
                    .wrapping_add(11)
            } else {
                0
            })
        );
    }
    for (block, value) in inputs.blocks.iter().enumerate() {
        assert_eq!(
            *value,
            std::array::from_fn(|lane| if nonzero {
                (block as u8)
                    .wrapping_mul(37)
                    .wrapping_add((block >> 8) as u8)
                    .wrapping_add(lane as u8)
            } else {
                0
            })
        );
    }
}

#[test]
fn exact_samples_keep_all_four_original_owners_through_patterns_refusal_and_unwind() {
    const CHILD: &str = "IVM_AES_EXACT_SAMPLE_CUSTODY";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let module = module_path!().split_once("::").unwrap().1;
        let test = format!(
            "{module}::exact_samples_keep_all_four_original_owners_through_patterns_refusal_and_unwind"
        );
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(stdout.contains("1 passed; 0 failed; 0 ignored"));
        return;
    }
    let mut config = crate::AccelerationConfig {
        enable_simd: false,
        enable_cuda: false,
        enable_metal: false,
        ..Default::default()
    };
    config.resource_limits.work.host_bytes = 0;
    crate::set_acceleration_config(config);
    let owner = ProcessResources::get().unwrap();
    for (work, blocks) in [
        (MetalBatchWork::Encrypt, 33),
        (MetalBatchWork::Decrypt, 129),
        (MetalBatchWork::EncryptRounds(9), 513),
        (MetalBatchWork::DecryptRounds(64), 2_048),
    ] {
        let geometry = Geometry::new(work, blocks).unwrap();
        let keys = 16 * work.rounds();
        let block_bytes = 16 * blocks;
        let required = keys + 3 * block_bytes;
        for limit in [
            0,
            keys,
            keys + block_bytes,
            keys + 2 * block_bytes,
            required - 1,
        ] {
            config.resource_limits.work.host_bytes = limit;
            crate::set_acceleration_config(config);
            assert!(matches!(
                Inputs::prepare(geometry, Instant::now()),
                Err(CalibrationFailure::Allocation)
            ));
            assert_eq!(
                owner.usage().host_bytes[0],
                0,
                "partial refusal refunds every earlier owner"
            );
        }
        config.resource_limits.work.host_bytes = required;
        crate::set_acceleration_config(config);
        let mut inputs = Inputs::prepare(geometry, Instant::now()).unwrap();
        assert_eq!(owner.usage().host_bytes[0], required);
        assert_eq!(inputs.keys.len(), work.rounds());
        assert_eq!(inputs.blocks.len(), blocks);
        assert_eq!(inputs.expected.len(), blocks);
        assert_eq!(inputs.actual.len(), blocks);
        assert!(inputs.expected.iter().all(|block| *block == [0; 16]));
        assert!(inputs.actual.iter().all(|block| *block == [0; 16]));
        let pointers = [
            inputs.keys.as_ptr(),
            inputs.blocks.as_ptr(),
            inputs.expected.as_ptr(),
            inputs.actual.as_ptr(),
        ];
        for nonzero in [false, true, false] {
            inputs.fill_pattern(nonzero);
            assert_pattern(&inputs, nonzero);
            inputs.expected.fill([0x31; 16]);
            inputs.actual.fill([0x73; 16]);
            assert_pattern(&inputs, nonzero);
            assert!(inputs.expected.iter().all(|block| *block == [0x31; 16]));
            assert!(inputs.actual.iter().all(|block| *block == [0x73; 16]));
            assert_eq!(
                pointers,
                [
                    inputs.keys.as_ptr(),
                    inputs.blocks.as_ptr(),
                    inputs.expected.as_ptr(),
                    inputs.actual.as_ptr()
                ]
            );
            assert_eq!(owner.usage().host_bytes[0], required);
        }
        config.resource_limits.work.host_bytes = 0;
        crate::set_acceleration_config(config);
        assert!(std::ptr::eq(owner, ProcessResources::get().unwrap()));
        assert_eq!(owner.usage().host_bytes[0], required);
        assert!(owner.try_host_output::<u8>(1).is_err());
        drop(inputs);
        assert_eq!(owner.usage().host_bytes[0], 0);
        let baseline = AesCpuBaseline::capture(work);
        assert!(matches!(
            calibrate(geometry, baseline, Instant::now()),
            Err(CalibrationFailure::Allocation)
        ));
        assert_eq!(owner.usage().host_bytes[0], 0);
        config.resource_limits.work.host_bytes = required;
        crate::set_acceleration_config(config);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut inputs = Inputs::prepare(geometry, Instant::now()).unwrap();
                inputs.fill_pattern(true);
                assert_pattern(&inputs, true);
                assert_eq!(owner.usage().host_bytes[0], required);
                panic!("sample unwind drops all four original backings");
            }))
            .is_err()
        );
        assert_eq!(owner.usage().host_bytes[0], 0);
        assert!(matches!(
            calibrate(geometry, baseline, Instant::now()),
            Err(CalibrationFailure::BackendUnavailable)
        ));
        assert_eq!(
            owner.usage().host_bytes[0],
            0,
            "GPU refusal releases complete sample storage"
        );
    }
    assert_eq!(16 * MAX_ROUNDS + 3 * 16 * MAX_BLOCKS, 99_328);
}

#[test]
fn deadline_and_cpu_identity_refuse_before_any_sample_allocation() {
    let geometry = Geometry::new(MetalBatchWork::Encrypt, 33).unwrap();
    let expired = Instant::now() - MAX_CALIBRATION;
    assert!(matches!(
        Inputs::prepare(geometry, expired),
        Err(CalibrationFailure::Deadline)
    ));
    let baseline = AesCpuBaseline::capture(MetalBatchWork::Decrypt);
    assert!(matches!(
        calibrate(geometry, baseline, expired),
        Err(CalibrationFailure::Deadline)
    ));
    assert!(matches!(
        calibrate(geometry, baseline, Instant::now()),
        Err(CalibrationFailure::CpuChanged)
    ));
    assert!(elapsed(Instant::now() - Duration::from_nanos(1)).unwrap() > 0);
}
