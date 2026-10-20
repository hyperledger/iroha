//! Poseidon CUDA publication from one complete charged state owner.

use super::policy::{Kernel, public_workload_task_id};
use iroha_accel::cuda::CudaFailure;
#[path = "poseidon_cost.rs"]
mod cost;
#[path = "poseidon_launch.rs"]
mod launch;

#[derive(Clone, Copy)]
enum Input<'a> {
    Two(&'a [(u64, u64)]),
    Six(&'a [[u64; 6]]),
}
impl Input<'_> {
    fn width(self) -> usize {
        match self {
            Self::Two(_) => 3,
            Self::Six(_) => 6,
        }
    }
    fn len(self) -> usize {
        match self {
            Self::Two(values) => values.len(),
            Self::Six(values) => values.len(),
        }
    }
    fn kernel(self) -> Kernel {
        match self {
            Self::Two(_) => Kernel::Poseidon2,
            Self::Six(_) => Kernel::Poseidon6,
        }
    }
    fn word(self, index: usize) -> u64 {
        if !index.is_multiple_of(4) {
            return 0;
        }
        let lane = index / 4;
        match self {
            Self::Two(values) => match lane % 3 {
                0 => values[lane / 3].0,
                1 => values[lane / 3].1,
                _ => 0,
            },
            Self::Six(values) => values[lane / 6][lane % 6],
        }
    }
}

fn stage(input: Input<'_>, geometry: launch::Geometry) -> Result<launch::Output, CudaFailure> {
    let artifact = crate::cuda_artifact::artifact(input.kernel())?;
    let result = crate::cuda_dispatch::with_selected(input.kernel(), artifact, |device| {
        match input {
            Input::Two(_) => {
                let (constants, matrix) = crate::poseidon::poseidon2_params();
                // SAFETY: exact fixed-width representation, complete initialized
                // state, and the canonical CPU parameters for the admitted artifact.
                unsafe {
                    launch::output(
                        device,
                        artifact,
                        geometry,
                        |i| input.word(i),
                        |i| constants[i / 12][(i / 4) % 3].0[i % 4],
                        |i| matrix[i / 12][(i / 4) % 3].0[i % 4],
                    )
                }
            }
            Input::Six(_) => {
                let (constants, matrix) = crate::poseidon::poseidon6_params();
                // SAFETY: same contract as the width-three branch with width six.
                unsafe {
                    launch::output(
                        device,
                        artifact,
                        geometry,
                        |i| input.word(i),
                        |i| constants[i / 24][(i / 4) % 6].0[i % 4],
                        |i| matrix[i / 24][(i / 4) % 6].0[i % 4],
                    )
                }
            }
        }
    });
    match result {
        // Completion credit belongs to validated caller publication, after the
        // original selected policy and CPU identity have been rechecked.
        Ok(output) => Ok(output),
        Err(error) => {
            if !matches!(
                error,
                CudaFailure::Capacity | CudaFailure::Busy | CudaFailure::Unavailable
            ) {
                crate::cuda_dispatch::quarantine_current_kernel();
            }
            Err(error)
        }
    }
}

fn valid_output(output: &launch::Output, input: Input<'_>) -> bool {
    super::output_validation::poseidon(
        output.status,
        output.state.as_deref(),
        input.width(),
        input.len(),
        || {},
    )
}

pub(super) fn admit(kernel: Kernel) -> bool {
    let Ok(artifact) = crate::cuda_artifact::artifact(kernel) else {
        return false;
    };
    crate::cuda_dispatch::admit_kernel(kernel, artifact, || {
        let Some(_guard) = super::imp::SelftestRunningGuard::enter() else {
            return Err(CudaFailure::Busy);
        };
        let two = [(0, 0), (7, 11), (u64::MAX, 1), (u64::MAX, u64::MAX)];
        let six = [
            [0; 6],
            [1, 2, 3, 4, 5, 6],
            [u64::MAX, 0, 1, 2, 3, 4],
            [u64::MAX; 6],
        ];
        let input = match kernel {
            Kernel::Poseidon2 => Input::Two(&two),
            Kernel::Poseidon6 => Input::Six(&six),
            _ => return Ok(false),
        };
        let output = stage(
            input,
            launch::Geometry::canonical(input.width(), input.len()),
        )?;
        if !valid_output(&output, input) {
            return Ok(false);
        }
        let state = output.state.as_ref().expect("valid output contains state");
        Ok(matches_cpu_output(state, input))
    })
}

// The complete-state canonicality check precedes this CPU parity comparison.
// Both admission and publication use the fixed-arity rate coordinate one.
fn matches_cpu_output(state: &[u64], input: Input<'_>) -> bool {
    if input.len().checked_mul(input.width() * 4) != Some(state.len()) {
        return false;
    }
    state
        .chunks_exact(input.width() * 4)
        .enumerate()
        .all(|(index, words)| {
            words[4]
                == match input {
                    Input::Two(values) => {
                        crate::poseidon::poseidon2_simd(values[index].0, values[index].1)
                    }
                    Input::Six(values) => crate::poseidon::poseidon6_simd(values[index]),
                }
        })
}

fn valid_request(input: Input<'_>, destination_len: usize) -> bool {
    input.len() == destination_len
        && u32::try_from(input.len()).is_ok()
        && input.len().checked_mul(input.width() * 4).is_some()
}

// All state and policy checks finish before the first caller byte is written.
fn publish(
    status: [u32; 2],
    state: Option<&[u64]>,
    width: usize,
    destination: &mut [u64],
    still_selected: impl FnOnce() -> bool,
) -> Result<(), CudaFailure> {
    if !super::output_validation::poseidon(status, state, width, destination.len(), || {}) {
        return Err(CudaFailure::Quarantined);
    }
    if !still_selected() {
        return Err(CudaFailure::Unavailable);
    }
    let state = state.expect("validated complete state");
    for (result, words) in destination.iter_mut().zip(state.chunks_exact(width * 4)) {
        *result = words[4];
    }
    Ok(())
}

fn complete_current(
    input: Input<'_>,
    destination: &mut [u64],
    still_selected: impl FnOnce() -> bool,
) -> Result<(), CudaFailure> {
    if !valid_request(input, destination.len()) {
        return Err(CudaFailure::InvalidRequest);
    }
    let artifact = crate::cuda_artifact::artifact(input.kernel())?;
    if !super::imp::cuda_policy_allows_attempt()
        || !crate::cuda_dispatch::current_is_admitted(input.kernel(), artifact)
    {
        return Err(CudaFailure::Unavailable);
    }
    let output = stage(
        input,
        launch::Geometry::canonical(input.width(), input.len()),
    )?;
    let result = publish(
        output.status,
        output.state.as_deref(),
        input.width(),
        destination,
        || {
            super::imp::cuda_policy_allows_attempt()
                && crate::cuda_dispatch::current_is_admitted(input.kernel(), artifact)
                && still_selected()
        },
    );
    if result == Err(CudaFailure::Quarantined) {
        crate::cuda_dispatch::quarantine_current_kernel();
    }
    result?;
    super::imp::record_completed_cuda_dispatch(input.kernel(), artifact);
    Ok(())
}

fn automatic_into(input: Input<'_>, destination: &mut [u64]) -> bool {
    if !valid_request(input, destination.len()) || super::imp::cuda_disabled() {
        return false;
    }
    if input.len() == 0 {
        return true;
    }
    let cpu = crate::field_dispatch::field_impl();
    let kernel = input.kernel();
    let Ok(artifact) = crate::cuda_artifact::artifact(kernel) else {
        return false;
    };
    let Some(selected) = crate::cuda_dispatch::measured::select(
        kernel,
        artifact,
        input.len(),
        cpu,
        || super::imp::ensure_cuda_kernel(kernel),
        |deadline| cost::calibrate(kernel, cpu, deadline),
    ) else {
        return false;
    };
    selected
        .run(|token| {
            super::imp::record_cuda_attempt();
            complete_current(input, destination, || token.valid()).is_ok()
        })
        .unwrap_or(false)
}

pub(crate) fn poseidon2_auto_into(inputs: &[(u64, u64)], destination: &mut [u64]) -> bool {
    automatic_into(Input::Two(inputs), destination)
}
pub(crate) fn poseidon6_auto_into(inputs: &[[u64; 6]], destination: &mut [u64]) -> bool {
    automatic_into(Input::Six(inputs), destination)
}

fn into(input: Input<'_>, destination: &mut [u64]) -> bool {
    if !valid_request(input, destination.len()) {
        return false;
    }
    if input.len() == 0 {
        return true;
    }
    let task = public_workload_task_id(
        0x0f0f_0f0f_0000_0030,
        &[input.kernel() as u64, input.len() as u64],
    );
    crate::cuda_dispatch::with_task_scope(task, || {
        super::imp::record_cuda_attempt();
        if !super::imp::ensure_cuda_kernel(input.kernel()) {
            return false;
        }
        complete_current(input, destination, || true).is_ok()
    })
}

/// Attempt a Poseidon2 batch into caller storage; failure leaves it unchanged.
pub fn poseidon2_cuda_many_into(inputs: &[(u64, u64)], destination: &mut [u64]) -> bool {
    into(Input::Two(inputs), destination)
}
/// Attempt a Poseidon6 batch into caller storage; failure leaves it unchanged.
pub fn poseidon6_cuda_many_into(inputs: &[[u64; 6]], destination: &mut [u64]) -> bool {
    into(Input::Six(inputs), destination)
}
/// Attempt one Poseidon2 hash using stack-owned output.
pub fn poseidon2_cuda(a: u64, b: u64) -> Option<u64> {
    let mut output = [0];
    poseidon2_cuda_many_into(&[(a, b)], &mut output).then_some(output[0])
}
/// Attempt one Poseidon6 hash using stack-owned output.
pub fn poseidon6_cuda(inputs: [u64; 6]) -> Option<u64> {
    let mut output = [0];
    poseidon6_cuda_many_into(&[inputs], &mut output).then_some(output[0])
}

#[cfg(test)]
pub(super) fn fault_probe(short_stride: bool) -> Option<[u32; 2]> {
    crate::cuda_dispatch::with_task_scope(0, || {
        if !super::imp::ensure_cuda_kernel(Kernel::Poseidon2) {
            return None;
        }
        let input = Input::Two(&[(0, 1)]);
        let mut geometry = launch::Geometry::canonical(3, 1);
        if short_stride {
            geometry.stride = 1;
        } else {
            geometry.full_rounds = 0;
            geometry.partial_rounds = 0;
        }
        // These exact invalid parameters return before state/constant accesses.
        stage(input, geometry).ok().map(|output| output.status)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_parity_and_publication_use_rate_coordinate_one() {
        let pairs = [(1, 2), (u64::MAX, 7)];
        let sixes = [[1, 2, 3, 4, 5, 6], [u64::MAX; 6]];
        for input in [Input::Two(&pairs), Input::Six(&sixes)] {
            let width = input.width();
            let mut backing = [0u64; 48];
            let state = &mut backing[..input.len() * width * 4];
            let expected: [u64; 2] = std::array::from_fn(|index| match input {
                Input::Two(values) => {
                    crate::poseidon::poseidon2_simd(values[index].0, values[index].1)
                }
                Input::Six(values) => crate::poseidon::poseidon6_simd(values[index]),
            });
            for (words, value) in state.chunks_exact_mut(width * 4).zip(expected) {
                words[0] = value ^ 1;
                words[4] = value;
            }
            assert!(matches_cpu_output(state, input));
            let mut published = [0; 2];
            publish([0, 0], Some(state), width, &mut published, || true).unwrap();
            assert_eq!(published, expected);
            assert!(!matches_cpu_output(&state[..state.len() - 1], input));
            state[width * 4 + 4] ^= 1;
            assert!(
                !matches_cpu_output(state, input),
                "later item must be checked"
            );
            state[width * 4 + 4] ^= 1;
            for words in state.chunks_exact_mut(width * 4) {
                words.swap(0, 4);
            }
            assert!(
                !matches_cpu_output(state, input),
                "capacity output is not the fixed-arity result"
            );
        }
    }

    #[test]
    fn checked_requests_and_unadmitted_completion_preserve_caller_storage() {
        let two = [(1, 2), (3, 4)];
        let six = [[1; 6], [u64::MAX; 6]];
        assert!(valid_request(Input::Two(&two), 2));
        assert!(valid_request(Input::Six(&six), 2));
        assert!(!valid_request(Input::Two(&two), 1));
        let mut destination = [17, 19];
        assert_eq!(
            complete_current(Input::Two(&two), &mut destination, || panic!("unadmitted")),
            Err(CudaFailure::Unavailable)
        );
        assert_eq!(destination, [17, 19]);
        assert!(!poseidon2_auto_into(&two, &mut destination[..1]));
        assert!(!poseidon6_auto_into(&six, &mut destination[..1]));
        assert_eq!(destination, [17, 19]);
        assert!(!poseidon2_cuda_many_into(&two, &mut destination[..1]));
        assert!(!poseidon6_cuda_many_into(&six, &mut destination[..1]));
        assert!(poseidon2_cuda_many_into(&[], &mut []));
        assert!(poseidon6_cuda_many_into(&[], &mut []));
    }

    #[test]
    fn full_state_validation_and_late_policy_refusal_precede_every_write() {
        for width in [3, 6] {
            let mut state = [0u64; 48];
            state[4] = 7;
            state[width * 4 + 4] = 11;
            let complete = &state[..width * 8];
            let mut output = [91, 93];
            assert_eq!(
                publish([0, 0], Some(complete), width, &mut output, || false),
                Err(CudaFailure::Unavailable)
            );
            assert_eq!(output, [91, 93]);
            for (status, native) in [
                ([1, 0], Some(complete)),
                ([0, 0], None),
                ([0, 0], Some(&complete[..complete.len() - 1])),
            ] {
                assert_eq!(
                    publish(status, native, width, &mut output, || panic!(
                        "invalid complete state"
                    )),
                    Err(CudaFailure::Quarantined)
                );
                assert_eq!(output, [91, 93]);
            }
            let mut noncanonical = state;
            noncanonical[width * 4 + 4..width * 4 + 8].copy_from_slice(&crate::bn254_vec::MODULUS);
            assert_eq!(
                publish(
                    [0, 0],
                    Some(&noncanonical[..width * 8]),
                    width,
                    &mut output,
                    || panic!("noncanonical later field")
                ),
                Err(CudaFailure::Quarantined)
            );
            assert_eq!(output, [91, 93]);
            assert!(matches!(
                publish([0, 0], Some(complete), width, &mut output, || true),
                Ok(())
            ));
            assert_eq!(output, [7, 11]);
        }
    }

    #[test]
    fn generated_state_words_preserve_every_input_and_zero_upper_limbs() {
        let pairs = [(u64::MAX, 7), (11, 13)];
        let input = Input::Two(&pairs);
        let words: [u64; 24] = std::array::from_fn(|i| input.word(i));
        assert_eq!(
            [
                words[0], words[4], words[8], words[12], words[16], words[20]
            ],
            [u64::MAX, 7, 0, 11, 13, 0]
        );
        assert!(
            words
                .iter()
                .enumerate()
                .all(|(i, word)| i % 4 == 0 || *word == 0)
        );
        let lanes = [[1, 2, 3, 4, 5, u64::MAX]];
        let input = Input::Six(&lanes);
        assert_eq!(
            std::array::from_fn::<_, 6, _>(|i| input.word(i * 4)),
            lanes[0]
        );
    }

    #[test]
    fn every_fixed_parameter_upload_limb_matches_the_canonical_width_owner() {
        use iroha_zkp_halo2::poseidon::{
            bn254_poseidon_params_width3, bn254_poseidon_params_width6,
        };
        let (rc3, m3) = crate::poseidon::poseidon2_params();
        let (rc6, m6) = crate::poseidon::poseidon6_params();
        let fixed3 = bn254_poseidon_params_width3();
        let fixed6 = bn254_poseidon_params_width6();
        for (actual, expected) in rc3.iter().flatten().chain(m3.iter().flatten()).zip(
            fixed3
                .round_constants
                .iter()
                .flatten()
                .chain(fixed3.mds.iter().flatten()),
        ) {
            for limb in 0..4 {
                assert_eq!(
                    actual.0[limb],
                    u64::from_le_bytes(expected[limb * 8..(limb + 1) * 8].try_into().unwrap())
                );
            }
        }
        for (actual, expected) in rc6.iter().flatten().chain(m6.iter().flatten()).zip(
            fixed6
                .round_constants
                .iter()
                .flatten()
                .chain(fixed6.mds.iter().flatten()),
        ) {
            for limb in 0..4 {
                assert_eq!(
                    actual.0[limb],
                    u64::from_le_bytes(expected[limb * 8..(limb + 1) * 8].try_into().unwrap())
                );
            }
        }
        assert_eq!((rc3.len(), rc6.len()), (65, 68));
    }

    #[test]
    fn admitted_native_staged_complete_states_match_every_cpu_limb() {
        crate::cuda_dispatch::with_task_scope(0, || {
            let pairs = [(0, 0), (7, 11), (u64::MAX, u64::MAX)];
            let six = [[0; 6], [1, 2, 3, 4, 5, 6], [u64::MAX; 6]];
            for input in [Input::Two(&pairs), Input::Six(&six)] {
                if !super::super::imp::ensure_cuda_kernel(input.kernel()) {
                    #[cfg(feature = "cuda-hardware-tests")]
                    panic!("mandatory Poseidon native admission unavailable");
                    #[cfg(not(feature = "cuda-hardware-tests"))]
                    return;
                }
                let artifact = crate::cuda_artifact::artifact(input.kernel())
                    .expect("original admitted artifact");
                assert!(crate::cuda_dispatch::current_is_admitted(
                    input.kernel(),
                    artifact
                ));
                let result = stage(
                    input,
                    launch::Geometry::canonical(input.width(), input.len()),
                );
                let output = match result {
                    Ok(output) => output,
                    Err(error) => {
                        #[cfg(feature = "cuda-hardware-tests")]
                        panic!("mandatory complete Poseidon dispatch refused: {error:?}");
                        #[cfg(not(feature = "cuda-hardware-tests"))]
                        {
                            let _ = error;
                            return;
                        }
                    }
                };
                assert!(valid_output(&output, input));
                let states = output.state.as_ref().unwrap();
                for (index, words) in states.chunks_exact(input.width() * 4).enumerate() {
                    match input {
                        Input::Two(values) => {
                            let (a, b) = values[index];
                            let expected = crate::poseidon::parameter_tests::state2([
                                crate::bn254_vec::FieldElem([0, 2, 0, 0]),
                                crate::bn254_vec::FieldElem::from_u64(a),
                                crate::bn254_vec::FieldElem::from_u64(b),
                            ]);
                            for (actual, expected) in words.chunks_exact(4).zip(expected) {
                                assert_eq!(actual, expected.0);
                            }
                        }
                        Input::Six(values) => {
                            let input = values[index];
                            let mut expected = crate::poseidon::parameter_tests::state6([
                                crate::bn254_vec::FieldElem([0, 6, 0, 0]),
                                crate::bn254_vec::FieldElem::from_u64(input[0]),
                                crate::bn254_vec::FieldElem::from_u64(input[1]),
                                crate::bn254_vec::FieldElem::from_u64(input[2]),
                                crate::bn254_vec::FieldElem::from_u64(input[3]),
                                crate::bn254_vec::FieldElem::from_u64(input[4]),
                            ]);
                            expected[1] = crate::bn254_vec::add(
                                expected[1],
                                crate::bn254_vec::FieldElem::from_u64(input[5]),
                            );
                            let expected = crate::poseidon::parameter_tests::state6(expected);
                            for (actual, expected) in words.chunks_exact(4).zip(expected) {
                                assert_eq!(actual, expected.0);
                            }
                        }
                    }
                }
                // This is a validation probe, not production caller publication:
                // stage completes without awarding ordinary completion credit.
            }
        });
    }
}
