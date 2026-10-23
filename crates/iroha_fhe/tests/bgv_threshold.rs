//! Offline threshold-custody controls and an independent integer interpolation oracle.
//!
//! No test here establishes verifiable threshold decryption, distributed key
//! generation, or qualified BGV parameters. Secret probes exist only in fixtures.
mod support;

use iroha_fhe::bgv::{
    BgvError, BgvParameters, BgvProfile, SecretKey,
    fixtures::{self, FixtureEntropy},
    threshold::{DealerKeyShares, SecretKeyShare, ThresholdContext, ThresholdError},
};
use num_bigint::BigInt;
use support::oracle;
use zeroize::Zeroizing;

fn profile() -> BgvProfile {
    BgvProfile::new(BgvParameters::derive(4, 257, (40, 2), (41, 1), 1).expect("parameters"))
        .expect("profile")
}

fn context(profile: &BgvProfile, threshold: u16) -> ThresholdContext {
    ThresholdContext::new(profile, [81; 32], 17, threshold, vec![1, 2, 7, 19, 211])
        .expect("context")
}

fn secret(profile: &BgvProfile) -> SecretKey {
    fixtures::secret_key(profile, &mut FixtureEntropy::new([33; 64])).expect("secret")
}

fn dealer(profile: &BgvProfile, context: ThresholdContext, tag: u8) -> DealerKeyShares<'_> {
    let limit = DealerKeyShares::required_secret_bytes(profile, &context).expect("budget");
    fixtures::threshold_dealer(
        profile,
        context,
        secret(profile),
        limit,
        &mut FixtureEntropy::new([tag; 64]),
    )
    .expect("dealer")
}

fn primes(profile: &BgvProfile) -> Vec<u64> {
    profile
        .parameters()
        .main_primes
        .iter()
        .chain(&profile.parameters().special_primes)
        .copied()
        .collect()
}

/// Lagrange interpolation at zero using arbitrary integers, not the production kernels.
fn interpolate(profile: &BgvProfile, points: &[(u16, Zeroizing<Vec<u64>>)]) -> Vec<u64> {
    let mut result = Vec::new();
    for (limb, prime) in primes(profile).into_iter().enumerate() {
        let modulus = oracle::big(prime);
        let weights: Vec<BigInt> = points
            .iter()
            .map(|(x, _)| {
                let mut numerator = BigInt::from(1);
                let mut denominator = BigInt::from(1);
                for (other, _) in points {
                    if other != x {
                        numerator *= -BigInt::from(*other);
                        denominator *= BigInt::from(*x) - BigInt::from(*other);
                    }
                }
                oracle::rem(
                    &(numerator * oracle::inverse(&denominator, &modulus)),
                    &modulus,
                )
            })
            .collect();
        for coefficient in 0..profile.degree() {
            let sum =
                points
                    .iter()
                    .zip(&weights)
                    .fold(BigInt::from(0), |sum, ((_, words), weight)| {
                        sum + BigInt::from(words[limb * profile.degree() + coefficient]) * weight
                    });
            result.push(oracle::word_mod(&sum, prime));
        }
    }
    result
}

fn expected_words(profile: &BgvProfile, key: &SecretKey) -> Vec<u64> {
    let coefficients = fixtures::secret_coefficients(key);
    primes(profile)
        .into_iter()
        .flat_map(|prime| {
            coefficients
                .iter()
                .map(move |&value| oracle::word_mod(&BigInt::from(value), prime))
        })
        .collect()
}

/// Independent coin expansion and power-sum evaluation, with no production sampler.
fn reference_share(
    profile: &BgvProfile,
    context: &ThresholdContext,
    key: &SecretKey,
    master: &[u8; 64],
    participant: u16,
) -> Vec<u64> {
    let mut output = expected_words(profile, key);
    for power in 1..context.threshold() {
        let mut hash = blake3::Hasher::new_derive_key("iroha_fhe bgv v1 coin stream");
        hash.update(context.identity());
        hash.update(&[10]);
        hash.update(&u32::from(power).to_le_bytes());
        hash.update(&0_u32.to_le_bytes());
        hash.update(&oracle::fixture_seed(master, 0));
        let mut reader = hash.finalize_xof();
        for (limb, prime) in primes(profile).into_iter().enumerate() {
            let mask = (1_u64 << (64 - prime.leading_zeros())) - 1;
            let weight = BigInt::from(participant).pow(u32::from(power));
            for coefficient in 0..profile.degree() {
                let random = loop {
                    let mut bytes = [0_u8; 8];
                    reader.fill(&mut bytes);
                    let candidate = u64::from_le_bytes(bytes) & mask;
                    if candidate < prime {
                        break candidate;
                    }
                };
                let index = limb * profile.degree() + coefficient;
                output[index] = oracle::word_mod(
                    &(BigInt::from(output[index]) + BigInt::from(random) * &weight),
                    prime,
                );
            }
        }
    }
    output
}

fn points(shares: &[&SecretKeyShare]) -> Vec<(u16, Zeroizing<Vec<u64>>)> {
    shares
        .iter()
        .map(|share| (share.participant(), fixtures::threshold_share_words(share)))
        .collect()
}

#[test]
fn every_declared_threshold_subset_reconstructs_all_main_and_special_limbs() {
    let profile = profile();
    let expected = expected_words(&profile, &secret(&profile));
    // A five-member roster with t=2/3/5 is not a Sumeragi committee or quorum.
    for threshold in [1, 2, 3, 5] {
        let context = context(&profile, threshold);
        let mut dealer = dealer(&profile, context.clone(), 51);
        let instance = *dealer.instance();
        assert_eq!(dealer.context(), &context);
        let shares: Vec<_> = context
            .participants()
            .iter()
            .map(|&id| dealer.take_share(id).expect("share"))
            .collect();
        assert_eq!(dealer.remaining(), 0);
        for mask in 0_u32..32 {
            if mask.count_ones() != u32::from(threshold) {
                continue;
            }
            let subset: Vec<_> = shares
                .iter()
                .enumerate()
                .filter_map(|(i, share)| ((mask >> i) & 1 == 1).then_some(share))
                .collect();
            context
                .validate_selection_metadata(&instance, &subset)
                .expect("declared threshold");
            assert_eq!(interpolate(&profile, &points(&subset)), expected);
        }
        let all: Vec<_> = shares.iter().collect();
        context
            .validate_selection_metadata(&instance, &all)
            .expect("superset");
        assert_eq!(interpolate(&profile, &points(&all)), expected);
        for share in &shares {
            assert_eq!(share.context(), &context);
            assert_eq!(share.instance(), &instance);
            assert_eq!(
                share.secret_buffer_bytes(),
                expected.len() * size_of::<u64>()
            );
        }
    }
}

#[test]
fn context_rejects_malformed_rosters_thresholds_and_field_coordinates() {
    let profile = profile();
    for roster in [vec![], vec![0], vec![1, 1], vec![2, 1]] {
        assert_eq!(
            ThresholdContext::new(&profile, [0; 32], 0, 1, roster),
            Err(ThresholdError::InvalidRoster)
        );
    }
    for threshold in [0, 3] {
        assert_eq!(
            ThresholdContext::new(&profile, [0; 32], 0, threshold, vec![1, 2]),
            Err(ThresholdError::InvalidThreshold)
        );
    }
    // Real small prime fields: participant IDs cannot wrap or alias modulo a prime.
    let small =
        BgvProfile::new(BgvParameters::derive(2, 3, (7, 1), (8, 1), 1).expect("small parameters"))
            .expect("small profile");
    let smallest = *primes(&small).iter().min().expect("prime");
    let outside = u16::try_from(smallest).expect("small field");
    assert_eq!(
        ThresholdContext::new(&small, [0; 32], 0, 1, vec![outside]),
        Err(ThresholdError::CoordinateOutOfField)
    );
    ThresholdContext::new(&small, [0; 32], 0, 1, vec![outside - 1]).expect("last field coordinate");
}

#[test]
fn context_identity_binds_every_declared_dimension() {
    let profile = profile();
    let base = context(&profile, 3);
    assert_eq!(base.key_context(), &[81; 32]);
    assert_eq!(base.epoch(), 17);
    assert_eq!(base.threshold(), 3);
    assert_eq!(base.participants(), [1, 2, 7, 19, 211]);
    assert_eq!(base.identity(), context(&profile, 3).identity());
    for other in [
        ThresholdContext::new(&profile, [82; 32], 17, 3, base.participants().to_vec())
            .expect("key context"),
        ThresholdContext::new(&profile, [81; 32], 18, 3, base.participants().to_vec())
            .expect("epoch"),
        context(&profile, 2),
        ThresholdContext::new(&profile, [81; 32], 17, 3, vec![1, 2, 7, 19, 212]).expect("roster"),
    ] {
        assert_ne!(base.identity(), other.identity());
    }
    let other_profile =
        BgvProfile::new(BgvParameters::derive(5, 257, (40, 2), (41, 1), 1).expect("parameters"))
            .expect("profile");
    assert_ne!(base.identity(), context(&other_profile, 3).identity());
}

#[test]
fn selection_refuses_insufficient_duplicate_excessive_wrong_epoch_and_wrong_instance() {
    let profile = profile();
    let context = context(&profile, 3);
    let mut first = dealer(&profile, context.clone(), 1);
    let instance = *first.instance();
    let a = first.take_share(1).expect("a");
    let b = first.take_share(2).expect("b");
    let c = first.take_share(7).expect("c");
    assert_eq!(
        context.validate_selection_metadata(&instance, &[&a, &b]),
        Err(ThresholdError::InsufficientShares)
    );
    assert_eq!(
        context.validate_selection_metadata(&instance, &[&a, &a, &b]),
        Err(ThresholdError::DuplicateParticipant)
    );
    assert_eq!(
        context.validate_selection_metadata(&instance, &[&a, &b, &c, &a, &b, &c]),
        Err(ThresholdError::TooManyShares)
    );
    let mut second = dealer(&profile, context.clone(), 2);
    assert_ne!(instance, *second.instance());
    let foreign = second.take_share(7).expect("foreign instance");
    assert_eq!(
        context.validate_selection_metadata(&instance, &[&a, &b, &foreign]),
        Err(ThresholdError::InstanceMismatch)
    );
    assert_eq!(
        context.validate_selection_metadata(&[0; 32], &[&a, &b, &c]),
        Err(ThresholdError::InstanceMismatch)
    );
    for other in [
        ThresholdContext::new(&profile, [81; 32], 18, 3, context.participants().to_vec())
            .expect("next epoch"),
        ThresholdContext::new(&profile, [82; 32], 17, 3, context.participants().to_vec())
            .expect("other key context"),
        ThresholdContext::new(&profile, [81; 32], 17, 2, context.participants().to_vec())
            .expect("other threshold"),
        ThresholdContext::new(&profile, [81; 32], 17, 3, vec![1, 2, 7, 19, 212])
            .expect("other roster"),
    ] {
        let mut other = dealer(&profile, other, 1);
        let foreign = other.take_share(7).expect("other context");
        assert_eq!(
            context.validate_selection_metadata(&instance, &[&a, &b, &foreign]),
            Err(ThresholdError::ContextMismatch)
        );
    }
    context
        .validate_selection_metadata(&instance, &[&c, &a, &b])
        .expect("order independent");
}

#[test]
fn each_participant_is_issued_once_and_unknown_requests_do_not_consume_custody() {
    let profile = profile();
    let mut dealer = dealer(&profile, context(&profile, 2), 9);
    assert_eq!(dealer.remaining(), 5);
    assert_eq!(
        dealer.take_share(0).err(),
        Some(ThresholdError::UnknownParticipant)
    );
    assert_eq!(dealer.remaining(), 5);
    let share = dealer.take_share(7).expect("share");
    assert_eq!(dealer.remaining(), 4);
    assert_eq!(
        dealer.take_share(7).err(),
        Some(ThresholdError::AlreadyIssued)
    );
    drop(share);
    assert_eq!(
        dealer.take_share(7).err(),
        Some(ThresholdError::AlreadyIssued)
    );
    for id in [1, 2, 19, 211] {
        drop(dealer.take_share(id).expect("share"));
    }
    assert_eq!(dealer.remaining(), 0);
    assert_eq!(
        dealer.take_share(1).err(),
        Some(ThresholdError::AlreadyIssued)
    );
}

#[test]
fn secret_buffer_budget_and_profile_are_checked_before_entropy_is_drawn() {
    let profile = profile();
    let context = context(&profile, 3);
    let poly = profile.degree() * primes(&profile).len() * size_of::<u64>();
    let expected =
        3 * poly + profile.degree() * size_of::<i64>() + poly.max(fixtures::COIN_STATE_BYTES);
    assert_eq!(
        DealerKeyShares::required_secret_bytes(&profile, &context),
        Ok(expected)
    );
    let mut entropy = FixtureEntropy::new([61; 64]);
    assert_eq!(
        fixtures::threshold_dealer(
            &profile,
            context.clone(),
            secret(&profile),
            expected - 1,
            &mut entropy
        )
        .err(),
        Some(ThresholdError::SecretBufferLimit {
            required: expected,
            limit: expected - 1
        })
    );
    assert_eq!(entropy.draws(), 0);
    let other =
        BgvProfile::new(BgvParameters::derive(5, 257, (40, 2), (41, 1), 1).expect("parameters"))
            .expect("profile");
    assert_eq!(
        DealerKeyShares::required_secret_bytes(&other, &context),
        Err(ThresholdError::ProfileMismatch)
    );
    assert_eq!(
        fixtures::threshold_dealer(
            &other,
            context.clone(),
            secret(&other),
            expected,
            &mut entropy
        )
        .err(),
        Some(ThresholdError::ProfileMismatch)
    );
    assert_eq!(
        fixtures::threshold_dealer(
            &profile,
            context.clone(),
            secret(&other),
            expected,
            &mut entropy
        )
        .err(),
        Some(ThresholdError::ProfileMismatch)
    );
    assert_eq!(entropy.draws(), 0);
    drop(
        fixtures::threshold_dealer(&profile, context, secret(&profile), expected, &mut entropy)
            .expect("exact limit"),
    );
    assert_eq!(entropy.draws(), 1);
}

#[test]
fn real_entropy_failures_and_stuck_sources_do_not_produce_a_dealer() {
    let profile = profile();
    let context = context(&profile, 2);
    let limit = DealerKeyShares::required_secret_bytes(&profile, &context).expect("limit");
    for mut entropy in [
        FixtureEntropy::failing_after([1; 64], 0),
        FixtureEntropy::stuck_after([1; 64], 0, 11),
    ] {
        assert_eq!(
            fixtures::threshold_dealer(
                &profile,
                context.clone(),
                secret(&profile),
                limit,
                &mut entropy
            )
            .err(),
            Some(ThresholdError::Bgv(BgvError::EntropyUnavailable))
        );
        assert_eq!(entropy.draws(), 1);
    }
}

#[test]
fn os_seeded_dealers_have_distinct_instances_and_masks() {
    let profile = profile();
    let context = context(&profile, 2);
    let limit = DealerKeyShares::required_secret_bytes(&profile, &context).expect("limit");
    let mut first = DealerKeyShares::split(&profile, context.clone(), secret(&profile), limit)
        .expect("OS dealer");
    let mut second =
        DealerKeyShares::split(&profile, context, secret(&profile), limit).expect("OS dealer");
    assert_ne!(first.instance(), second.instance());
    let a = first.take_share(1).expect("a");
    let b = second.take_share(1).expect("b");
    assert_ne!(
        *fixtures::threshold_share_words(&a),
        *fixtures::threshold_share_words(&b)
    );
}

#[test]
fn fixed_coins_are_reproducible_and_instance_bytes_are_domain_separated() {
    let profile = profile();
    let context = context(&profile, 3);
    let mut first = dealer(&profile, context.clone(), 7);
    let mut replay = dealer(&profile, context.clone(), 7);
    assert_eq!(first.instance(), replay.instance());
    let a = first.take_share(1).expect("a");
    let b = replay.take_share(1).expect("b");
    assert_eq!(
        *fixtures::threshold_share_words(&a),
        *fixtures::threshold_share_words(&b)
    );
    // Independent stream derivation pins the new domain and purpose tag.
    let mut hash = blake3::Hasher::new_derive_key("iroha_fhe bgv v1 coin stream");
    hash.update(context.identity());
    hash.update(&[9]);
    hash.update(&0_u32.to_le_bytes());
    hash.update(&0_u32.to_le_bytes());
    hash.update(&FixtureEntropy::new([7; 64]).seed(0));
    let mut expected = [0_u8; 32];
    hash.finalize_xof().fill(&mut expected);
    assert_eq!(first.instance(), &expected);
    assert_eq!(
        *fixtures::threshold_share_words(&a),
        reference_share(&profile, &context, &secret(&profile), &[7; 64], 1)
    );
    let high_coordinate = first.take_share(211).expect("large coordinate");
    assert_eq!(
        *fixtures::threshold_share_words(&high_coordinate),
        reference_share(&profile, &context, &secret(&profile), &[7; 64], 211)
    );

    let changed = ThresholdContext::new(&profile, [81; 32], 18, 3, context.participants().to_vec())
        .expect("epoch");
    let mut changed = dealer(&profile, changed, 7);
    assert_ne!(first.instance(), changed.instance());
    let c = changed.take_share(1).expect("c");
    assert_ne!(
        *fixtures::threshold_share_words(&a),
        *fixtures::threshold_share_words(&c)
    );
}

#[test]
fn a_canonical_malicious_share_fails_the_independent_key_oracle() {
    let profile = profile();
    let context = context(&profile, 3);
    let expected = expected_words(&profile, &secret(&profile));
    let mut dealer = dealer(&profile, context.clone(), 7);
    let a = dealer.take_share(1).expect("a");
    let b = dealer.take_share(2).expect("b");
    let c = dealer.take_share(7).expect("c");
    let mut points = points(&[&a, &b, &c]);
    assert_eq!(interpolate(&profile, &points), expected);
    // Canonical residues alone do not establish an honest sharing polynomial.
    // This explicit fixture mutation cannot enter the opaque production owner.
    points[2].1[0] = (points[2].1[0] + 1) % primes(&profile)[0];
    assert_ne!(interpolate(&profile, &points), expected);
}
