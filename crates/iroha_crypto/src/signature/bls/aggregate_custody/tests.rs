//! Independent original-relation parity and exact scratch custody regressions.

use std::cell::Cell;

use super::*;
use crate::{
    Algorithm, Error, KeyPair, Signature, bls_normal_aggregate_signatures, bls_normal_pop_prove,
    signature::bls,
    test_allocations::{
        allocations_during, observed_deallocations, with_allocation_failure,
        with_deallocation_observation, without_allocations,
    },
};

struct Fixture {
    pairs: Vec<KeyPair>,
    keys: Vec<BlsNormalPopVerifiedKey>,
}

fn fixture() -> Fixture {
    let pairs: Vec<_> = (141..=144)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect();
    let keys = pairs
        .iter()
        .map(|pair| {
            let pop = bls_normal_pop_prove(pair.private_key()).unwrap();
            BlsNormalPopVerifiedKey::from_owned_uncached(pair.public_key().clone(), &pop).unwrap()
        })
        .collect();
    Fixture { pairs, keys }
}

fn aggregate(fixture: &Fixture, groups: &[(&[usize], &[u8])]) -> Vec<u8> {
    let signatures: Vec<_> = groups
        .iter()
        .flat_map(|(keys, message)| {
            keys.iter()
                .map(|&index| Signature::new(fixture.pairs[index].private_key(), message))
        })
        .collect();
    bls_normal_aggregate_signatures(
        &signatures
            .iter()
            .map(Signature::payload)
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

// Independent original owned adapter and w3f prepared-pairing implementation.
fn original(
    groups: &[(&[&BlsNormalPopVerifiedKey], &[u8])],
    aggregate: &[u8],
) -> Result<(), Error> {
    use std::collections::BTreeSet;
    if groups.is_empty() {
        return Err(Error::BadSignature);
    }
    let mut messages = BTreeSet::new();
    let mut points = Vec::with_capacity(groups.len());
    for (keys, message) in groups {
        if keys.is_empty() || !messages.insert(*message) {
            return Err(Error::BadSignature);
        }
        let mut seen = BTreeSet::new();
        let mut group = Vec::with_capacity(keys.len());
        for key in *keys {
            if !seen.insert(key.payload()) {
                return Err(Error::BadSignature);
            }
            group.push(bls::BlsNormal::parse_public_key(key.payload())?);
        }
        points.push(group);
    }
    let refs: Vec<Vec<_>> = points.iter().map(|group| group.iter().collect()).collect();
    let parsed: Vec<_> = refs
        .iter()
        .zip(groups)
        .map(|(keys, (_, msg))| (keys.as_slice(), *msg))
        .collect();
    bls::verify_preaggregated_multi_message_normal(&parsed, aggregate)
}

fn compare<O>(
    scratch: &mut BlsNormalAggregateScratch<O>,
    groups: &[(&[&BlsNormalPopVerifiedKey], &[u8])],
    aggregate: &[u8],
) -> bool {
    let expected = original(groups, aggregate).map_err(|error| error.to_string());
    let actual = without_allocations(|| {
        scratch.verify(
            groups
                .iter()
                .map(|(keys, message)| (keys.iter().copied(), *message)),
            aggregate,
        )
    })
    .map_err(|error| error.into_error().to_string());
    assert_eq!(actual, expected);
    actual.is_ok()
}

#[test]
fn aggregate_scratch_matches_original_grouped_relation_without_verifier_allocations() {
    let fixture = fixture();
    let refs: Vec<_> = fixture.keys.iter().collect();
    let mut scratch = BlsNormalAggregateScratch::new(|_| Ok::<_, ()>(())).unwrap();
    let first = b"native aggregate first".as_slice();
    let second = b"native aggregate second".as_slice();
    let signed = aggregate(&fixture, &[(&[0, 1], first), (&[2, 3], second)]);
    let groups = [(&refs[..2], first), (&refs[2..], second)];
    assert!(compare(&mut scratch, &groups, &signed));
    // Signature parser and group preflight retain original exact diagnostics.
    assert!(!compare(&mut scratch, &[], &signed));
    assert!(!compare(&mut scratch, &[(&[], first)], &signed));
    assert!(!compare(
        &mut scratch,
        &[(&refs[..2], first), (&refs[2..], first)],
        &signed
    ));
    let duplicate = [refs[0], refs[0]];
    assert!(!compare(&mut scratch, &[(&duplicate, first)], &signed));
    assert!(!compare(
        &mut scratch,
        &[(&refs[..1], first), (&refs[2..], second)],
        &signed
    ));
    assert!(!compare(
        &mut scratch,
        &[(&refs[..2], second), (&refs[2..], first)],
        &signed
    ));
    for len in 0..signed.len() {
        assert!(!compare(&mut scratch, &groups, &signed[..len]));
    }
    for fill in [0, 0xff] {
        assert!(!compare(&mut scratch, &groups, &[fill; 96]));
    }
    let mut identity = [0; 96];
    identity[0] = 0xc0;
    assert!(!compare(&mut scratch, &groups, &identity));
    let mut extended = signed.clone();
    extended.push(0);
    assert!(!compare(&mut scratch, &groups, &extended));
    let mut changed = signed.clone();
    changed[39] ^= 1;
    assert!(!compare(&mut scratch, &groups, &changed));
    // A rejected proof may not poison the next valid verification.
    assert!(compare(&mut scratch, &groups, &signed));
    let distinct = aggregate(&fixture, &[(&[0, 2, 3], b"")]);
    let selected = [refs[0], refs[2], refs[3]];
    assert!(compare(&mut scratch, &[(&selected, b"")], &distinct));
    assert!(!compare(&mut scratch, &groups, &distinct));
    assert!(compare(&mut scratch, &groups, &signed));
    // The same credential in distinct message groups is permitted.
    let reuse = aggregate(&fixture, &[(&[0], first), (&[0], second)]);
    assert!(compare(
        &mut scratch,
        &[(&refs[..1], first), (&refs[..1], second)],
        &reuse
    ));
}

#[test]
fn aggregate_scratch_rejects_identity_key_sum_before_pairing() {
    use w3f_bls::SerializableToBytes as _;
    let secret =
        w3f_bls::SecretKeyVT::<w3f_bls::ZBLS>::from_seed(b"aggregate-scratch-cancellation");
    let opposite = w3f_bls::SecretKeyVT::<w3f_bls::ZBLS>(-secret.0);
    let positive_secret =
        crate::PrivateKey::from_bytes(Algorithm::BlsNormal, &secret.to_bytes()).unwrap();
    let negative_secret =
        crate::PrivateKey::from_bytes(Algorithm::BlsNormal, &opposite.to_bytes()).unwrap();
    let positive = BlsNormalPopVerifiedKey::from_owned_uncached(
        crate::PublicKey::from(positive_secret.clone()),
        &bls_normal_pop_prove(&positive_secret).unwrap(),
    )
    .unwrap();
    let negative = BlsNormalPopVerifiedKey::from_owned_uncached(
        crate::PublicKey::from(negative_secret.clone()),
        &bls_normal_pop_prove(&negative_secret).unwrap(),
    )
    .unwrap();
    assert_eq!(positive.point, -negative.point);
    let refs = [&positive, &negative];
    let signed = Signature::new(&positive_secret, b"sum");
    let signed = signed.payload();
    let mut scratch = BlsNormalAggregateScratch::new(|_| Ok::<_, ()>(())).unwrap();
    assert!(!compare(&mut scratch, &[(&refs, b"sum")], signed));
    assert!(compare(&mut scratch, &[(&refs[..1], b"sum")], signed));
}

#[test]
fn aggregate_scratch_exact_admission_refuses_before_backing_and_drops_backing_before_funding() {
    struct Token<'a> {
        bytes: usize,
        used: &'a Cell<usize>,
    }
    impl Drop for Token<'_> {
        fn drop(&mut self) {
            assert_eq!(
                observed_deallocations(),
                1,
                "backing must be freed before refund"
            );
            self.used.set(self.used.get() - self.bytes);
        }
    }
    let bytes = BlsNormalAggregateScratch::<()>::backing_bytes();
    assert!(bytes > 0);
    let layout = BlsNormalAggregateScratch::<()>::backing_layout();
    assert_eq!(layout, FalliblePairing::layout());
    assert_eq!(layout.size(), bytes);
    assert_eq!(layout.align(), core::mem::align_of::<u64>());
    let used = Cell::new(0);
    let limit = Cell::new(bytes - 1);
    let admit = |requested| {
        assert_eq!(requested, bytes);
        if used.get() + requested > limit.get() {
            return Err((requested, limit.get()));
        }
        used.set(used.get() + requested);
        Ok(Token {
            bytes: requested,
            used: &used,
        })
    };
    let refusal = without_allocations(|| BlsNormalAggregateScratch::new(admit));
    assert!(
        matches!(refusal, Err(AggregateScratchError::Admission((requested, ceiling))) if requested == bytes && ceiling == bytes - 1)
    );
    assert_eq!(used.get(), 0);
    limit.set(bytes);
    let scratch = BlsNormalAggregateScratch::new(admit)
        .unwrap_or_else(|error| panic!("same owner retry: {error:?}"));
    assert_eq!(used.get(), bytes);
    let ((), frees) = with_deallocation_observation(bytes, || drop(scratch));
    assert_eq!(frees, 1);
    assert_eq!(used.get(), 0);
}

#[test]
fn aggregate_scratch_physical_failure_and_move_preserve_original_custody() {
    struct Owner<'a>(&'a Cell<usize>);
    impl Drop for Owner<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Cell::new(0);
    let bytes = BlsNormalAggregateScratch::<()>::backing_bytes();
    let (result, attempts) = allocations_during(|| {
        with_allocation_failure(bytes, || {
            BlsNormalAggregateScratch::new(|requested| {
                assert_eq!(requested, bytes);
                Ok::<_, ()>(Owner(&drops))
            })
        })
    });
    assert!(
        matches!(result, Err(AggregateScratchError::Allocator { layout, .. })
        if layout.size() == bytes && layout.align() == core::mem::align_of::<u64>())
    );
    assert_eq!(attempts, 1);
    assert_eq!(drops.get(), 1);
    let scratch = BlsNormalAggregateScratch::new(|_| Ok::<_, ()>(Owner(&drops))).unwrap();
    let pointer = scratch.pairing.backing_pointer();
    let moved = without_allocations(|| scratch);
    assert_eq!(moved.pairing.backing_pointer(), pointer);
    drop(moved);
    assert_eq!(drops.get(), 2);
}

#[test]
fn aggregate_public_adapter_uses_stack_and_same_relation() {
    let fixture = fixture();
    let references: Vec<_> = fixture.keys.iter().collect();
    let message = b"stack aggregate".as_slice();
    let signature = aggregate(&fixture, &[(&[0, 1, 2, 3], message)]);
    let groups = [(&references[..], message)];
    let wrong_message = [(&references[..], b"other message".as_slice())];
    without_allocations(|| {
        assert!(crate::bls_normal_verify_preaggregated_multi_message(&groups, &signature).is_ok());
        assert!(
            crate::bls_normal_verify_preaggregated_multi_message(&wrong_message, &signature)
                .is_err()
        );
    });
}

#[test]
fn aggregate_scratch_and_stack_adapter_cross_the_eight_term_pairing_flush() {
    // blst folds each full buffer of eight Miller-loop terms into its accumulator; a
    // ninth term starts a second batch that commit folds in.
    let fixture = fixture();
    let refs: Vec<_> = fixture.keys.iter().collect();
    let messages: Vec<[u8; 2]> = (0..10_u8).map(|group| [b'g', group]).collect();
    let signers: Vec<[usize; 1]> = (0..10).map(|group| [group % refs.len()]).collect();
    let members: Vec<[&BlsNormalPopVerifiedKey; 1]> =
        signers.iter().map(|[index]| [refs[*index]]).collect();
    let mut scratch = BlsNormalAggregateScratch::new(|_| Ok::<_, ()>(())).unwrap();
    for count in [8, 9, 10] {
        let signing: Vec<(&[usize], &[u8])> = (0..count)
            .map(|group| (&signers[group][..], &messages[group][..]))
            .collect();
        let signed = aggregate(&fixture, &signing);
        let groups: Vec<(&[&BlsNormalPopVerifiedKey], &[u8])> = (0..count)
            .map(|group| (&members[group][..], &messages[group][..]))
            .collect();
        // The admitted heap context matches the independent w3f relation, as does the
        // stack adapter, before and after the flushed terms change.
        assert!(compare(&mut scratch, &groups, &signed), "{count} groups");
        assert!(
            without_allocations(|| crate::bls_normal_verify_preaggregated_multi_message(
                &groups, &signed
            ))
            .is_ok()
        );
        for changed in [0, count - 1] {
            let mut altered = groups.clone();
            altered[changed].1 = b"altered".as_slice();
            assert!(
                !compare(&mut scratch, &altered, &signed),
                "{count} groups, term {changed}"
            );
            assert!(
                crate::bls_normal_verify_preaggregated_multi_message(&altered, &signed).is_err()
            );
        }
    }
}
