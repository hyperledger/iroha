use super::*;
use rand_core_06::{CryptoRng, Error as RngError, RngCore};
#[derive(Clone)]
struct TestRng(u64);
impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(out);
        Ok(())
    }
}
impl CryptoRng for TestRng {}
struct FailingRng;
impl RngCore for FailingRng {
    fn next_u32(&mut self) -> u32 {
        panic!("fallible interface required")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("fallible interface required")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("fallible interface required")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), RngError> {
        Err(RngError::new("injected"))
    }
}
impl CryptoRng for FailingRng {}
#[test]
fn uniform_samplers_are_bounded_and_fallible() {
    let mut rng = TestRng(9);
    for _ in 0..1024 {
        assert!(
            sample_bounded_u64_v1(JINDO_ENCODING_BASE_V1, &mut rng).unwrap()
                < JINDO_ENCODING_BASE_V1
        );
    }
    assert_eq!(
        sample_bounded_u64_v1(17, &mut FailingRng),
        Err(JindoSamplingErrorV1::RandomnessUnavailable)
    );
}
#[test]
fn aggregate_gaussian_is_inside_the_exact_tail() {
    let mut rng = TestRng(0x1234_5678_9abc_def0);
    let sample = sample_discrete_gaussian_v1(
        SignedQ128V1::ZERO,
        JindoGaussianWidthV1::AggregateMask,
        &mut rng,
    )
    .unwrap();
    assert!(sample.unsigned_abs() <= JindoGaussianWidthV1::AggregateMask.tail_radius());
}
#[test]
fn rejection_probability_is_integer_defined_and_rng_fallible() {
    let mut a = TestRng(77);
    let mut b = TestRng(77);
    assert_eq!(
        accept_aggregation_rejection_v1(-123_456_789, &mut a).unwrap(),
        accept_aggregation_rejection_v1(-123_456_789, &mut b).unwrap(),
    );
    assert_eq!(
        accept_aggregation_rejection_v1(0, &mut FailingRng),
        Err(JindoSamplingErrorV1::RandomnessUnavailable),
    );
}
#[test]
fn uniform_field_sampler_is_canonical() {
    let mut rng = TestRng(42);
    for _ in 0..32 {
        let value = sample_uniform_field_element_v1(&mut rng).unwrap();
        assert!(JindoFieldElementV1::from_canonical_bytes(value.to_canonical_bytes()).is_some());
    }
    assert_eq!(
        sample_uniform_field_element_v1(&mut FailingRng),
        Err(JindoSamplingErrorV1::RandomnessUnavailable),
    );
}

#[test]
fn fractional_decay_initializes_once_on_a_bounded_native_stack_with_exact_values() {
    use sha3::{Digest as _, Sha3_256};

    let digest = std::thread::Builder::new()
        .name("jindo-fraction-table-small-stack".to_owned())
        .stack_size(128 * 1024)
        .spawn(|| {
            // A fresh cell forces the actual initializer even when another
            // sampler test already warmed the production static table.
            let table = OnceLock::new();
            let values = table.get_or_init(build_fraction_decay_table_q256_v1);
            assert_eq!(values.len(), FRACTION_TABLE_LEN_V1);
            assert_eq!(values[0], U512::ONE.shl_vartime(Q256_FRACTION_BITS_V1));
            assert!(values.windows(2).all(|pair| pair[0] > pair[1]));
            assert!(core::ptr::eq(
                values,
                table.get_or_init(|| panic!("decay table must initialize exactly once")),
            ));
            assert_eq!(values.as_ref(), fraction_decay_table_q256_v1());
            let mut digest = Sha3_256::new();
            for value in values.iter() {
                digest.update(value.to_be_bytes());
            }
            <[u8; 32]>::from(digest.finalize())
        })
        .expect("bounded-stack test thread must spawn")
        .join()
        .expect("fresh fractional-decay initialization must not exhaust the native stack");
    // Independent integer replay of the original Q256 recurrence, covering
    // every one of the 4,096 public entries in canonical big-endian order.
    assert_eq!(
        hex::encode(digest),
        "a14479d5caab8b8d9bdfed56a41e9d39a76f6b6e034d4d1bea2de248b8d7cf7c",
    );
}
