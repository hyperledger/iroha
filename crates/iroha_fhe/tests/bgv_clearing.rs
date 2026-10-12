//! Observes that every secret-holding buffer of the BGV scheme is cleared before it is released.
//!
//! A statement about dropped memory cannot be checked through the public
//! interface, so this test binary installs an allocator that inspects every
//! heap block of at least a chosen size as it is freed on the current thread.
//! With a ring degree of 256, every polynomial-sized buffer (a secret key, a
//! sampled mask or error, a transform scratch, a decryption scratch, a
//! plaintext) is at least 2048 bytes and the 128 scalar slots of an encoding
//! are 1024 bytes, while the bookkeeping the scheme frees (vectors and map
//! nodes of key handles, the words of a public noise bound) stays below 800
//! bytes. Each scenario arms the probe at 1024 bytes, runs one
//! secret-handling operation and asserts that at least one such block was
//! released and that every released block was all zero:
//!
//! - after success, when the operation's scratch and then its results are dropped;
//! - after an error return in the middle of the operation, including entropy
//!   that fails or sticks at each draw of a key-set generation;
//! - after an unwind from a fault injected in the middle of the operation.
//!
//! The seed of an operation, the BLAKE3 state that absorbs it, the
//! extendable-output state, the buffered stream bytes and the bytes of the
//! word being sampled are key-equivalent: they regenerate everything the
//! operation samples. They live in one heap block of a size no other buffer
//! of the scheme has ([`fixtures::COIN_STATE_BYTES`]). The probe counts those
//! blocks separately, so each scenario also asserts how many of them the
//! operation released (one per seed drawn) and that every byte of each was
//! zero, padding included.
//!
//! The probe sees heap blocks only. What it cannot observe is stated in the
//! documentation of `iroha_fhe::bgv::coins`: the stack frames of the hash
//! function and values held in registers while a coefficient is computed.
#![allow(
    unsafe_code,
    reason = "the allocator probe reads a block that is still allocated"
)]

use iroha_fhe::bgv::{
    BgvError, BgvParameters, BgvProfile, EvaluationKeys, KeySet, Plaintext, PublicKey, SecretKey,
    SlotEncoding, SwitchingKey, SwitchingKeyKind,
    fixtures::{self, COIN_STATE_BYTES, FaultPoint, FixtureEntropy},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
};

thread_local! {
    /// Smallest block size under observation on this thread; zero disarms the probe.
    static WATCHED_MINIMUM: Cell<usize> = const { Cell::new(0) };
    /// Watched blocks freed since the probe was armed.
    static FREED: Cell<usize> = const { Cell::new(0) };
    /// Watched blocks that still held a non-zero byte when they were freed.
    static FREED_UNCLEARED: Cell<usize> = const { Cell::new(0) };
    /// Blocks of the coin-state size freed since the probe was armed.
    static COIN_BLOCKS: Cell<usize> = const { Cell::new(0) };
    /// Coin-state blocks that still held a non-zero byte when they were freed.
    static COIN_BLOCKS_UNCLEARED: Cell<usize> = const { Cell::new(0) };
}

struct FreedBlockProbe;

// SAFETY: every method forwards to `System` with the caller's unchanged arguments. `dealloc`
// additionally reads the block, which is still allocated at that point, and only for block
// sizes a test armed; those blocks are vector buffers that were written in full.
unsafe impl GlobalAlloc for FreedBlockProbe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded with the caller's layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // Thread-local access can fail while a thread is torn down; nothing is watched then.
        let minimum = WATCHED_MINIMUM.try_with(Cell::get).unwrap_or(0);
        let coin_state = layout.size() == COIN_STATE_BYTES;
        if minimum != 0 && (layout.size() >= minimum || coin_state) {
            // SAFETY: the block is allocated with this layout until `System.dealloc` below.
            let bytes = unsafe { core::slice::from_raw_parts(pointer, layout.size()) };
            let uncleared = bytes.iter().any(|&byte| byte != 0);
            if layout.size() >= minimum {
                let _ = FREED.try_with(|count| count.set(count.get() + 1));
                if uncleared {
                    let _ = FREED_UNCLEARED.try_with(|count| count.set(count.get() + 1));
                }
            }
            if coin_state {
                let _ = COIN_BLOCKS.try_with(|count| count.set(count.get() + 1));
                if uncleared {
                    let _ = COIN_BLOCKS_UNCLEARED.try_with(|count| count.set(count.get() + 1));
                }
            }
        }
        // SAFETY: forwarded with the caller's pointer and layout.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded with the caller's layout.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded with the caller's arguments. Growing buffers (the test harness's
        // captured output, for one) therefore never pass through the probe.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static PROBE: FreedBlockProbe = FreedBlockProbe;

/// Freed watched blocks and how many of them were not cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Observation {
    /// Blocks of at least the watched size.
    freed: usize,
    /// Those of them that held a non-zero byte.
    uncleared: usize,
    /// Blocks of exactly the coin-state size.
    coin_blocks: usize,
    /// Those of them that held a non-zero byte.
    coin_uncleared: usize,
}

const DEGREE: usize = 256;
/// The 128 scalar slots of the F257 encoding: the smallest buffer that holds secret data.
/// One polynomial limb is twice this size.
const POLYNOMIAL_BYTES: usize = DEGREE / 2 * size_of::<u64>();

/// Run `body` with the probe armed for blocks of at least `minimum` bytes on this thread.
fn observe<T>(minimum: usize, body: impl FnOnce() -> T) -> (T, Observation) {
    FREED.with(|count| count.set(0));
    FREED_UNCLEARED.with(|count| count.set(0));
    COIN_BLOCKS.with(|count| count.set(0));
    COIN_BLOCKS_UNCLEARED.with(|count| count.set(0));
    WATCHED_MINIMUM.with(|watched| watched.set(minimum));
    let result = body();
    WATCHED_MINIMUM.with(|watched| watched.set(0));
    let observation = Observation {
        freed: FREED.with(Cell::get),
        uncleared: FREED_UNCLEARED.with(Cell::get),
        coin_blocks: COIN_BLOCKS.with(Cell::get),
        coin_uncleared: COIN_BLOCKS_UNCLEARED.with(Cell::get),
    };
    (result, observation)
}

/// Assert that exactly `seeds` coin-state blocks were released and that all of them were clear.
fn assert_coins_cleared(label: &str, observation: Observation, seeds: usize) {
    assert_eq!(
        observation.coin_blocks, seeds,
        "{label}: coin-state blocks released"
    );
    assert_eq!(
        observation.coin_uncleared, 0,
        "{label}: {} of {} coin-state blocks were not cleared",
        observation.coin_uncleared, observation.coin_blocks
    );
}

/// Assert that large blocks were released and that all of them were clear.
fn assert_cleared(label: &str, observation: Observation) {
    assert!(
        observation.freed > 0,
        "{label}: no polynomial-sized block was released"
    );
    assert_eq!(
        observation.uncleared, 0,
        "{label}: {} of {} released blocks were not cleared",
        observation.uncleared, observation.freed
    );
}

fn profile() -> BgvProfile {
    BgvProfile::new(BgvParameters::derive(8, 257, (40, 3), (41, 2), 2).expect("parameters"))
        .expect("profile")
}

fn master(tag: u8) -> [u8; 64] {
    std::array::from_fn(|index| {
        tag.wrapping_add(
            u8::try_from(index)
                .expect("index below 64")
                .wrapping_mul(11),
        )
    })
}

fn message(profile: &BgvProfile) -> Plaintext {
    // Non-zero everywhere, so an uncleared copy cannot look cleared.
    Plaintext::new(
        profile,
        (0..DEGREE as u64).map(|index| 1 + index % 256).collect(),
    )
    .expect("plaintext")
}

/// A fault point, its label and the operation that reaches it.
type Scenario<'a> = (FaultPoint, &'static str, Box<dyn Fn() + 'a>);

/// Silence the panic output of the injected faults; every other panic keeps the default report.
fn quiet_injected_faults() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let message = info
                .payload()
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| info.payload().downcast_ref::<&str>().copied())
                .unwrap_or("");
            if !message.starts_with("injected fault") {
                default(info);
            }
        }));
    });
}

#[test]
fn the_probe_sees_cleared_and_uncleared_blocks() {
    let none = Observation {
        freed: 0,
        uncleared: 0,
        coin_blocks: 0,
        coin_uncleared: 0,
    };
    let plain = vec![7_u64; DEGREE / 2];
    let ((), observation) = observe(POLYNOMIAL_BYTES, move || drop(plain));
    assert_eq!(
        observation,
        Observation {
            freed: 1,
            uncleared: 1,
            ..none
        },
        "a plain vector is released with its contents"
    );
    let clearing = zeroize::Zeroizing::new(vec![7_u64; DEGREE / 2]);
    let ((), observation) = observe(POLYNOMIAL_BYTES, move || drop(clearing));
    assert_eq!(observation, Observation { freed: 1, ..none });
    // Blocks below the minimum are not counted.
    let small = vec![7_u64; DEGREE / 2 - 1];
    let ((), observation) = observe(POLYNOMIAL_BYTES, move || drop(small));
    assert_eq!(observation, none);
    // A block of the coin-state size is counted on its own, cleared or not. No polynomial
    // buffer of this ring (a multiple of 1024 bytes) has that size.
    const {
        assert!(COIN_STATE_BYTES > POLYNOMIAL_BYTES);
        assert!(!COIN_STATE_BYTES.is_multiple_of(POLYNOMIAL_BYTES));
    }
    let stale = vec![0x5A_u8; COIN_STATE_BYTES];
    let ((), observation) = observe(POLYNOMIAL_BYTES, move || drop(stale));
    assert_eq!(
        observation,
        Observation {
            freed: 1,
            uncleared: 1,
            coin_blocks: 1,
            coin_uncleared: 1
        },
        "a coin-state sized block that keeps its contents is seen"
    );
    let wiped = zeroize::Zeroizing::new(vec![0x5A_u8; COIN_STATE_BYTES]);
    let ((), observation) = observe(POLYNOMIAL_BYTES, move || drop(wiped));
    assert_eq!(
        observation,
        Observation {
            freed: 1,
            coin_blocks: 1,
            ..none
        }
    );
}

#[test]
fn key_generation_clears_every_buffer_on_success() {
    let profile = profile();
    let ((), observation) = observe(POLYNOMIAL_BYTES, || {
        let mut entropy = FixtureEntropy::new(master(1));
        let keys = fixtures::key_set(&profile, &[5, 511], &mut entropy).expect("keys");
        // Dropping the keys releases the secret key and the public material.
        drop(keys);
    });
    assert_cleared("key set", observation);
    // One seed each for the secret key, the public key, the relinearization key and two
    // Galois keys.
    assert_coins_cleared("key set", observation, 5);
    // The same holds for the generators that draw operating-system entropy.
    let ((), observation) = observe(POLYNOMIAL_BYTES, || {
        let keys = KeySet::generate(&profile, &[5]).expect("keys");
        drop(keys);
    });
    assert_cleared("key set from the operating system", observation);
    assert_coins_cleared("key set from the operating system", observation, 4);
    let ((), observation) = observe(POLYNOMIAL_BYTES, || {
        let secret = SecretKey::generate(&profile).expect("secret");
        let public = PublicKey::generate(&profile, &secret).expect("public");
        let relinearization =
            SwitchingKey::generate_relinearization(&profile, &secret).expect("key");
        let galois = SwitchingKey::generate_galois(&profile, &secret, 5).expect("key");
        let evaluation = EvaluationKeys::generate(&profile, &secret, &[5, 511]).expect("keys");
        drop((secret, public, relinearization, galois, evaluation));
    });
    assert_cleared("single generators from the operating system", observation);
    assert_coins_cleared(
        "single generators from the operating system",
        observation,
        7,
    );
    // Each generator on its own, keeping its result alive: only scratch is released.
    let mut entropy = FixtureEntropy::new(master(2));
    let (secret, observation) = observe(POLYNOMIAL_BYTES, || {
        fixtures::secret_key(&profile, &mut entropy)
    });
    let secret = secret.expect("secret");
    assert_eq!(observation.uncleared, 0, "secret key scratch");
    assert_coins_cleared("secret key", observation, 1);
    let (public, observation) = observe(POLYNOMIAL_BYTES, || {
        fixtures::public_key(&profile, &secret, &mut entropy)
    });
    assert!(public.is_ok());
    assert_cleared("public key scratch", observation);
    assert_coins_cleared("public key", observation, 1);
    for kind in [
        SwitchingKeyKind::Relinearization,
        SwitchingKeyKind::Galois(5),
    ] {
        let (key, observation) = observe(POLYNOMIAL_BYTES, || {
            fixtures::switching_key(&profile, &secret, kind, &mut entropy)
        });
        assert!(key.is_ok());
        assert_cleared("switching key scratch", observation);
        // One seed serves every digit of a switching key.
        assert_coins_cleared("switching key", observation, 1);
    }
    let ((), observation) = observe(POLYNOMIAL_BYTES, move || drop(secret));
    assert_cleared("secret key", observation);
}

#[test]
fn encryption_and_decryption_clear_every_buffer_on_success() {
    let profile = profile();
    let mut entropy = FixtureEntropy::new(master(3));
    let keys = fixtures::key_set(&profile, &[], &mut entropy).expect("keys");
    let plaintext = message(&profile);
    let (ciphertext, observation) = observe(POLYNOMIAL_BYTES, || {
        fixtures::encrypt(&profile, &keys.public, &plaintext, &mut entropy)
    });
    let ciphertext = ciphertext.expect("ciphertext");
    // The mask, both errors, the transformed mask and the lifted message are released, and
    // the seed that regenerates the mask and the errors with them.
    assert_cleared("encryption", observation);
    assert!(observation.freed >= 5, "{observation:?}");
    assert_coins_cleared("encryption", observation, 1);
    let (ciphertext_os, observation) = observe(POLYNOMIAL_BYTES, || {
        keys.public.encrypt(&profile, &plaintext)
    });
    assert!(ciphertext_os.is_ok());
    assert_cleared("encryption with operating-system entropy", observation);
    assert_coins_cleared("encryption with operating-system entropy", observation, 1);
    let (opened, observation) = observe(POLYNOMIAL_BYTES, || {
        keys.secret.decrypt(&profile, &ciphertext)
    });
    let opened = opened.expect("plaintext");
    assert_eq!(opened, plaintext);
    // The inner product `c0 + c1*s` and its transforms are released; the plaintext leaves.
    assert_cleared("decryption", observation);
    // Decryption draws no coins.
    assert_coins_cleared("decryption", observation, 0);
    let ((), observation) = observe(POLYNOMIAL_BYTES, move || drop(opened));
    assert_cleared("decrypted plaintext", observation);
    let ((), observation) = observe(POLYNOMIAL_BYTES, move || drop(plaintext));
    assert_cleared("plaintext", observation);
    // Slot encodings hold the scalars and their transform in clearing buffers too.
    let encoding = SlotEncoding::new(&profile).expect("encoding");
    let values: Vec<u64> = (0..128).map(|index| 1 + index).collect();
    let (decoded, observation) = observe(POLYNOMIAL_BYTES, || {
        let encoded = encoding.encode(&profile, &values).expect("encoded");
        let decoded = encoding.decode(&encoded).expect("decoded");
        decoded.to_vec()
    });
    assert_eq!(decoded, values);
    // `decoded.to_vec()` is the caller's own copy; nothing the encoding released was uncleared.
    assert_cleared("slot encoding", observation);
}

#[test]
fn every_error_exit_clears_the_secrets_built_so_far() {
    let profile = profile();
    // Entropy that fails at each draw of a key-set generation: the secret key (and whatever
    // else was built) is dropped inside the call.
    for available in 1..5_u32 {
        let (result, observation) = observe(POLYNOMIAL_BYTES, || {
            let mut entropy = FixtureEntropy::failing_after(master(4), available);
            fixtures::key_set(&profile, &[5, 511], &mut entropy)
        });
        assert_eq!(result.err(), Some(BgvError::EntropyUnavailable));
        assert_cleared("key set with failing entropy", observation);
        // The block of every completed draw and the block of the refused one.
        assert_coins_cleared(
            "key set with failing entropy",
            observation,
            available as usize + 1,
        );
    }
    // A stuck source writes its bytes into the coin block before the draw is refused: the
    // block that held them is released cleared, at every draw of a key-set generation.
    for available in 0..5_u32 {
        let (result, observation) = observe(POLYNOMIAL_BYTES, || {
            let mut entropy = FixtureEntropy::stuck_after(master(4), available, 0xC3);
            fixtures::key_set(&profile, &[5, 511], &mut entropy)
        });
        assert_eq!(result.err(), Some(BgvError::EntropyUnavailable));
        assert_eq!(observation.uncleared, 0, "key set with stuck entropy");
        assert_coins_cleared(
            "key set with stuck entropy",
            observation,
            available as usize + 1,
        );
    }
    let mut entropy = FixtureEntropy::new(master(5));
    let keys = fixtures::key_set(&profile, &[], &mut entropy).expect("keys");
    let secret_coefficients = fixtures::secret_coefficients(&keys.secret);
    drop(secret_coefficients);
    // A switching key whose second digit has a malformed error: the first digit, the source
    // `s^2` and the coins are released on the error return.
    let full_words = 5 * DEGREE;
    let coins = vec![
        (vec![3_u64; full_words], vec![1_i64; DEGREE]),
        (vec![3_u64; full_words], vec![1_i64; DEGREE - 1]),
    ];
    let (result, observation) = observe(POLYNOMIAL_BYTES, || {
        fixtures::switching_key_from_coins(
            &profile,
            &keys.secret,
            SwitchingKeyKind::Relinearization,
            &coins,
        )
    });
    assert_eq!(
        result.err(),
        Some(BgvError::LengthMismatch {
            expected: DEGREE,
            found: DEGREE - 1
        })
    );
    assert_cleared("switching key with a malformed digit", observation);
    // A public key with a malformed error: the mask is released.
    let caller_mask = vec![3_u64; 3 * DEGREE];
    let (result, observation) = observe(POLYNOMIAL_BYTES, || {
        fixtures::public_key_from_coins(&profile, &keys.secret, &caller_mask, &[1_i64; DEGREE - 1])
    });
    assert!(result.is_err());
    assert_cleared("public key with a malformed error", observation);
    // Secret coefficients outside {-1, 0, 1}: the rejected copy is released cleared.
    let (result, observation) = observe(POLYNOMIAL_BYTES, || {
        fixtures::secret_key_from_coefficients(&profile, &[2_i64; DEGREE])
    });
    assert_eq!(result.err(), Some(BgvError::NonCanonical { index: 0 }));
    assert_cleared("rejected secret coefficients", observation);
    // A plaintext with a non-canonical coefficient: the rejected buffer is cleared.
    let (result, observation) = observe(POLYNOMIAL_BYTES, || {
        Plaintext::new(&profile, vec![257_u64; DEGREE])
    });
    assert_eq!(result.err(), Some(BgvError::NonCanonical { index: 0 }));
    assert_cleared("rejected plaintext", observation);
    // Encryption with failing entropy and decryption under another profile fail before any
    // secret-dependent buffer exists, and release nothing uncleared.
    let plaintext = message(&profile);
    let (result, observation) = observe(POLYNOMIAL_BYTES, || {
        let mut entropy = FixtureEntropy::failing_after(master(6), 0);
        fixtures::encrypt(&profile, &keys.public, &plaintext, &mut entropy)
    });
    assert_eq!(result.err(), Some(BgvError::EntropyUnavailable));
    assert_eq!(observation.uncleared, 0);
    assert_coins_cleared("encryption with failing entropy", observation, 1);
    let (result, observation) = observe(POLYNOMIAL_BYTES, || {
        let mut entropy = FixtureEntropy::stuck_after(master(6), 0, 0x3C);
        fixtures::encrypt(&profile, &keys.public, &plaintext, &mut entropy)
    });
    assert_eq!(result.err(), Some(BgvError::EntropyUnavailable));
    assert_eq!(observation.uncleared, 0);
    assert_coins_cleared("encryption with stuck entropy", observation, 1);
    let other =
        BgvProfile::new(BgvParameters::derive(8, 257, (40, 2), (41, 2), 2).expect("parameters"))
            .expect("profile");
    let ciphertext = keys
        .public
        .encrypt(&profile, &plaintext)
        .expect("ciphertext");
    let (result, observation) = observe(POLYNOMIAL_BYTES, || {
        keys.secret.decrypt(&other, &ciphertext)
    });
    assert_eq!(result.err(), Some(BgvError::ProfileMismatch));
    assert_eq!(observation.uncleared, 0);
}

#[test]
fn every_unwind_clears_the_secrets_built_so_far() {
    quiet_injected_faults();
    let profile = profile();
    let mut entropy = FixtureEntropy::new(master(7));
    let keys = fixtures::key_set(&profile, &[], &mut entropy).expect("keys");
    let plaintext = message(&profile);
    let ciphertext = keys
        .public
        .encrypt(&profile, &plaintext)
        .expect("ciphertext");
    let scenarios: [Scenario<'_>; 5] = [
        (
            FaultPoint::SecretKeyAfterSampling,
            "secret key",
            Box::new(|| {
                let mut entropy = FixtureEntropy::new(master(8));
                let _ = fixtures::secret_key(&profile, &mut entropy);
            }),
        ),
        (
            FaultPoint::PublicKeyAfterSampling,
            "public key",
            Box::new(|| {
                let mut entropy = FixtureEntropy::new(master(9));
                let _ = fixtures::public_key(&profile, &keys.secret, &mut entropy);
            }),
        ),
        (
            FaultPoint::SwitchingKeyAfterFirstDigit,
            "switching key",
            Box::new(|| {
                let mut entropy = FixtureEntropy::new(master(10));
                let _ = fixtures::switching_key(
                    &profile,
                    &keys.secret,
                    SwitchingKeyKind::Relinearization,
                    &mut entropy,
                );
            }),
        ),
        (
            FaultPoint::EncryptionAfterSampling,
            "encryption",
            Box::new(|| {
                let mut entropy = FixtureEntropy::new(master(11));
                let _ = fixtures::encrypt(&profile, &keys.public, &plaintext, &mut entropy);
            }),
        ),
        (
            FaultPoint::DecryptionAfterInnerProduct,
            "decryption",
            Box::new(|| {
                let _ = keys.secret.decrypt(&profile, &ciphertext);
            }),
        ),
    ];
    for (point, label, operation) in &scenarios {
        // Without the fault the operation completes.
        assert!(catch_unwind(AssertUnwindSafe(operation)).is_ok(), "{label}");
        fixtures::arm_fault(*point);
        let (outcome, observation) = observe(POLYNOMIAL_BYTES, || {
            catch_unwind(AssertUnwindSafe(operation))
        });
        assert!(outcome.is_err(), "{label}: the injected fault did not fire");
        assert_cleared(label, observation);
        // Every sampling operation unwinds with its seed block live; decryption has none.
        let seeds = usize::from(*point != FaultPoint::DecryptionAfterInnerProduct);
        assert_coins_cleared(label, observation, seeds);
        // The fault fired once: the next call completes.
        assert!(catch_unwind(AssertUnwindSafe(operation)).is_ok(), "{label}");
    }
    // A whole key-set generation that unwinds while building its first switching key
    // releases the secret key and the public key it had already built.
    fixtures::arm_fault(FaultPoint::SwitchingKeyAfterFirstDigit);
    let (outcome, observation) = observe(POLYNOMIAL_BYTES, || {
        catch_unwind(AssertUnwindSafe(|| {
            let mut entropy = FixtureEntropy::new(master(12));
            let _ = fixtures::key_set(&profile, &[5], &mut entropy);
        }))
    });
    assert!(outcome.is_err());
    assert_cleared("key set", observation);
    // The seeds of the secret key, the public key and the interrupted switching key.
    assert_coins_cleared("key set", observation, 3);
    fixtures::disarm_fault();
}

/// A ring whose secret-key custody frame (32 + 4096 / 4 bytes) is a watched block.
fn custody_profile() -> BgvProfile {
    BgvProfile::new(BgvParameters::derive(12, 257, (40, 1), (41, 1), 1).expect("parameters"))
        .expect("profile")
}

#[test]
fn secret_key_custody_frames_are_cleared_on_success_error_and_unwind() {
    quiet_injected_faults();
    let profile = custody_profile();
    assert!(SecretKey::custody_len(&profile) >= POLYNOMIAL_BYTES);
    let mut entropy = FixtureEntropy::new(master(13));
    let secret = fixtures::secret_key(&profile, &mut entropy).expect("secret");
    let coefficients = fixtures::secret_coefficients(&secret);
    // Success: the exported frame and the imported key leave nothing behind when dropped.
    let (frame, observation) = observe(POLYNOMIAL_BYTES, || {
        secret.to_custody_bytes(&profile).expect("frame")
    });
    assert_eq!(observation.uncleared, 0, "export scratch");
    let (restored, observation) = observe(POLYNOMIAL_BYTES, || {
        SecretKey::from_custody_bytes(&profile, frame)
    });
    let restored = restored.expect("secret");
    assert_eq!(fixtures::secret_coefficients(&restored), coefficients);
    // The frame was consumed and released by the import.
    assert_cleared("import", observation);
    let ((), observation) = observe(POLYNOMIAL_BYTES, move || drop(restored));
    assert_cleared("imported secret key", observation);
    let ((), observation) = observe(POLYNOMIAL_BYTES, || {
        drop(secret.to_custody_bytes(&profile).expect("frame"));
    });
    assert_cleared("exported frame", observation);
    // Error: a malformed code, another identity and another length release the frame and
    // the coefficients decoded so far.
    let malformed = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut frame = secret.to_custody_bytes(&profile).expect("frame");
        edit(&mut frame);
        observe(POLYNOMIAL_BYTES, || {
            SecretKey::from_custody_bytes(&profile, frame).err()
        })
    };
    let (error, observation) = malformed(&|frame| frame[600] |= 0b11);
    assert_eq!(error, Some(BgvError::MalformedFrame));
    assert_cleared("malformed frame", observation);
    assert!(observation.freed >= 2, "{observation:?}");
    let (error, observation) = malformed(&|frame| frame[0] ^= 1);
    assert_eq!(error, Some(BgvError::ProfileMismatch));
    assert_cleared("frame of another profile", observation);
    let (error, observation) = malformed(&|frame| frame.truncate(1024));
    assert!(matches!(error, Some(BgvError::LengthMismatch { .. })));
    assert_cleared("short frame", observation);
    // Unwind: the import panics after the key was rebuilt; frame, coefficients and the
    // evaluation form are released cleared.
    let frame = secret.to_custody_bytes(&profile).expect("frame");
    fixtures::arm_fault(FaultPoint::SecretKeyAfterSampling);
    let (outcome, observation) = observe(POLYNOMIAL_BYTES, || {
        catch_unwind(AssertUnwindSafe(|| {
            let _ = SecretKey::from_custody_bytes(&profile, frame);
        }))
    });
    assert!(outcome.is_err(), "the injected fault did not fire");
    assert_cleared("import that unwinds", observation);
    assert!(observation.freed >= 3, "{observation:?}");
    fixtures::disarm_fault();
}
