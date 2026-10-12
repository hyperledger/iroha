//! AES acceptance binds the measured CPU identity and the original native owner.

use super::*;
use crate::vector::{SimdChoice, metal_cost::MetalBatchWork};

struct SimdRestore(Option<SimdChoice>);
impl SimdRestore {
    fn set(choice: Option<SimdChoice>) -> Self {
        Self(crate::vector::set_thread_forced_simd(choice))
    }
}
impl Drop for SimdRestore {
    fn drop(&mut self) {
        crate::vector::set_thread_forced_simd(self.0);
    }
}

#[test]
fn measured_adapter_rejects_unsupported_or_mismatched_geometry_without_mutation() {
    let _scalar = SimdRestore::set(Some(SimdChoice::Scalar));
    let keys = [[0x39; 16]; 9];
    let mut states = [[0x17; 16]; 128];
    for work in [
        MetalBatchWork::Encrypt,
        MetalBatchWork::Decrypt,
        MetalBatchWork::EncryptRounds(9),
        MetalBatchWork::DecryptRounds(9),
    ] {
        let baseline = AesCpuBaseline::capture(work);
        let wrong_keys = if work.fused() { &keys[..8] } else { &keys[..2] };
        assert!(!measured_in_place(&mut states, wrong_keys, baseline));
        assert_eq!(states, [[0x17; 16]; 128]);
        assert!(!measured_in_place(
            &mut states[..31],
            &keys[..work.rounds()],
            baseline
        ));
        assert_eq!(states, [[0x17; 16]; 128]);
    }
}

#[cfg(feature = "metal-hardware-tests")]
#[test]
fn required_metal_aes_rechecks_measured_cpu_after_native_completion() {
    const CHILD: &str = "IVM_METAL_AES_CPU_ACCEPTANCE";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let module = module_path!().split_once("::").unwrap().1;
        let test =
            format!("{module}::required_metal_aes_rechecks_measured_cpu_after_native_completion");
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
            "required native AES acceptance control failed"
        );
        assert!(stdout.contains("1 passed; 0 failed; 0 ignored"));
        return;
    }
    let _restore = SimdRestore::set(None);
    crate::set_acceleration_config(crate::AccelerationConfig {
        enable_metal: true,
        enable_simd: true,
        enable_cuda: false,
        ..Default::default()
    });
    let slots = crate::vector::metal_runtime::device_slots().expect("complete physical inventory");
    assert!(slots > 0, "physical Metal device required");
    let states: [[u8; 16]; 128] =
        std::array::from_fn(|block| std::array::from_fn(|lane| (block * 13 + lane) as u8));
    let keys: [[u8; 16]; 9] =
        std::array::from_fn(|round| std::array::from_fn(|lane| (round * 17 + lane * 7) as u8));
    for slot in 0..slots {
        for work in [
            MetalBatchWork::Encrypt,
            MetalBatchWork::Decrypt,
            MetalBatchWork::EncryptRounds(9),
            MetalBatchWork::DecryptRounds(9),
        ] {
            let keys = &keys[..work.rounds()];
            let expected = states.map(|block| {
                keys.iter()
                    .fold(block, |value, key| work.direction().scalar(value, *key))
            });
            let kernel = kernel(work.decrypt(), work.fused());
            for scalar_before in [false, true] {
                crate::vector::set_thread_forced_simd(scalar_before.then_some(SimdChoice::Scalar));
                let baseline = AesCpuBaseline::capture(work);
                assert_eq!(
                    crate::aes::cpu::backend(work.direction()),
                    if scalar_before {
                        crate::aes::cpu::Backend::Scalar
                    } else {
                        crate::aes::cpu::Backend::Native
                    },
                    "physical native CPU AES is required"
                );
                // This is an explicit qualification control, not a fabricated
                // fastest-path profile. It uses ordinary selected publication.
                let (health, output, completed) =
                    crate::vector::metal_runtime::with_device_for_qualification(slot, || {
                        let health = crate::vector::metal_runtime::current_health().unwrap();
                        let before = health.completions(kernel as usize);
                        let output = attempt(
                            &states,
                            keys,
                            work.decrypt(),
                            work.fused(),
                            Some(kernel),
                            Comparison::Measured(baseline),
                        )
                        .expect("actual native output required before changing the CPU identity");
                        assert_eq!(health.completions(kernel as usize), before + 1);
                        (health, output, before + 1)
                    })
                    .expect("every physical owner must execute");
                assert!(crate::vector::metal_runtime::current_health().is_none());
                crate::vector::set_thread_forced_simd(
                    (!scalar_before).then_some(SimdChoice::Scalar),
                );
                assert!(
                    !baseline.is_current(),
                    "the measured CPU identity must actually change"
                );
                let mut destination = [[0xa7; 16]; 128];
                assert!(!output.copy_into(&mut destination));
                assert_eq!(destination, [[0xa7; 16]; 128]);
                assert_eq!(health.completions(kernel as usize), completed);
                assert!(
                    health.usable(),
                    "a CPU policy change cannot quarantine a healthy GPU"
                );

                crate::vector::set_thread_forced_simd(scalar_before.then_some(SimdChoice::Scalar));
                crate::vector::metal_runtime::with_device_for_qualification(slot, || {
                    for (wrong_blocks, wrong_keys) in [(true, false), (false, true)] {
                        let selected = MetalAesSelection::new(
                            crate::vector::metal_runtime::current_selection().unwrap(),
                            baseline,
                            states.len(),
                        )
                        .unwrap();
                        let mut original = states;
                        let destination = if wrong_blocks {
                            &mut original[..32]
                        } else {
                            original.as_mut_slice()
                        };
                        let keys = if wrong_keys {
                            &keys[..keys.len() - 1]
                        } else {
                            keys
                        };
                        assert!(!selected.run(destination, keys));
                        assert_eq!(original, states);
                        assert_eq!(health.completions(kernel as usize), completed);
                    }
                    let selected = MetalAesSelection::new(
                        crate::vector::metal_runtime::current_selection().unwrap(),
                        baseline,
                        states.len(),
                    )
                    .unwrap();
                    let mut original = states;
                    assert!(selected.run(&mut original, keys));
                    assert_eq!(original, expected);
                })
                .expect("healthy original owner remains eligible");
                assert_eq!(health.completions(kernel as usize), completed + 1);
                assert!(health.usable());
                println!(
                    "IVM_METAL_AES_CPU_ACCEPTANCE device={} work={work:?} scalar_before={scalar_before} rejected_after_native=true unchanged=true healthy_retry=true",
                    health.identity()
                );
            }
        }
    }
}
