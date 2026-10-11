//! Canonical golden blacklist custody and storage faults; these confer no issuer authority.

use super::*;
use crate::kagemusha_wallet_state_v1::{
    ArchiveKey, ArchiveStore,
    tests::{MemoryArchive, fixture},
};

fn original() -> Vec<u8> {
    fixture::<KagemushaWalletBlacklistV1>("KagemushaWalletBlacklistV1")
        .to_canonical_bytes()
        .unwrap()
}

fn scheme() -> [u8; 32] {
    fixture::<KagemushaWalletBlacklistV1>("KagemushaWalletBlacklistV1")
        .body
        .scheme_id
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    Missing,
    Corrupt,
    Unavailable,
    Protected,
    WriteBefore,
    WriteAfter,
}

struct StorageProbe {
    inner: MemoryArchive,
    fault: Fault,
    reads: usize,
    writes: usize,
}

impl StorageProbe {
    fn new() -> Self {
        Self {
            inner: MemoryArchive::new(),
            fault: Fault::None,
            reads: 0,
            writes: 0,
        }
    }
}

impl ArchiveStore for StorageProbe {
    fn binding(&self) -> ([u8; 32], [u8; 32]) {
        self.inner.binding()
    }
    fn get(&mut self, key: ArchiveKey, maximum: usize) -> Result<Option<Vec<u8>>, Error> {
        self.reads += 1;
        match self.fault {
            Fault::Missing => Ok(None),
            Fault::Corrupt => {
                let mut original = self.inner.get(key, maximum)?.unwrap();
                let last = original.len() - 1;
                original[last] ^= 1;
                Ok(Some(original))
            }
            Fault::Unavailable => Err(Error::Storage(std::io::Error::from(
                std::io::ErrorKind::WouldBlock,
            ))),
            Fault::Protected => Err(Error::Provider(
                crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderErrorV1::Unavailable(
                    crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Locked,
                ),
            )),
            _ => self.inner.get(key, maximum),
        }
    }
    fn put(&mut self, key: ArchiveKey, original: &[u8]) -> Result<(), Error> {
        self.writes += 1;
        if matches!(self.fault, Fault::WriteBefore) {
            return Err(Error::Storage(std::io::Error::from(
                std::io::ErrorKind::WouldBlock,
            )));
        }
        self.inner.put(key, original)?;
        if matches!(self.fault, Fault::WriteAfter) {
            return Err(Error::Storage(std::io::Error::from(
                std::io::ErrorKind::WouldBlock,
            )));
        }
        Ok(())
    }
    fn remove(&mut self, _: ArchiveKey) -> Result<(), Error> {
        panic!("retaining or restoring policy never authorizes erase")
    }
}

#[test]
fn exact_complete_golden_list_uses_one_bounded_reference_codec_never_an_inline_fallback() {
    let original = original();
    let scheme = scheme();
    let reference = BlacklistOriginalReferenceV1::for_original(&scheme, &original).unwrap();
    let frame = reference.to_canonical_bytes().unwrap();
    assert!(frame.len() <= REFERENCE_MAX_BYTES);
    assert_eq!(reference.original_bytes as usize, original.len());
    assert_eq!(reference.original_digest, object_digest(&original));
    assert_eq!(
        BlacklistOriginalReferenceV1::decode_canonical(&frame, &scheme).unwrap(),
        reference
    );
    reference.verify_original(&scheme, &original).unwrap();
    assert!(
        BlacklistOriginalReferenceV1::decode_canonical(&original, &scheme).is_err(),
        "Blacklist PolicyUpdate accepts the current reference schema only"
    );
    let header =
        archive::encode(&fixture::<KagemushaWalletBlacklistV1>("KagemushaWalletBlacklistV1").body)
            .unwrap();
    assert!(
        BlacklistOriginalReferenceV1::for_original(&scheme, &header).is_err(),
        "the signed body is never the complete list"
    );
    let mut trailer = frame.clone();
    trailer.push(0);
    assert!(BlacklistOriginalReferenceV1::decode_canonical(&trailer, &scheme).is_err());
    assert!(
        BlacklistOriginalReferenceV1::decode_canonical(&frame[..frame.len() - 1], &scheme).is_err()
    );
    assert!(
        BlacklistOriginalReferenceV1::decode_canonical(&vec![0; REFERENCE_MAX_BYTES + 1], &scheme)
            .is_err()
    );
    let mut changed = original.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(
        reference.verify_original(&scheme, &changed).is_err(),
        "every final entry byte is bound"
    );
    assert!(reference.verify_original(&[0x99; 32], &original).is_err());
}

#[test]
fn successful_reference_publication_requires_complete_original_readback() {
    let original = original();
    let scheme = scheme();
    for fault in [
        Fault::Missing,
        Fault::Corrupt,
        Fault::Unavailable,
        Fault::Protected,
    ] {
        let mut objects = StorageProbe::new();
        objects.fault = fault;
        let error = publish_blacklist_original(&mut objects, &scheme, &original).unwrap_err();
        match fault {
            Fault::Missing | Fault::Corrupt => assert!(matches!(error, Error::WitnessLost(_))),
            Fault::Unavailable => assert!(matches!(error, Error::Storage(_))),
            Fault::Protected => assert!(matches!(error, Error::Provider(_))),
            _ => unreachable!(),
        }
        assert_eq!(objects.writes, 1);
        assert_eq!(objects.reads, 1);
        objects.fault = Fault::None;
        let reference = publish_blacklist_original(&mut objects, &scheme, &original).unwrap();
        assert_eq!(
            read_blacklist_original(&mut objects, &reference, &scheme).unwrap(),
            original
        );
    }
}

#[test]
fn uncertain_write_retries_only_the_same_complete_original_and_does_not_claim_a_reference() {
    let original = original();
    let scheme = scheme();
    for fault in [Fault::WriteBefore, Fault::WriteAfter] {
        let mut objects = StorageProbe::new();
        objects.fault = fault;
        assert!(matches!(
            publish_blacklist_original(&mut objects, &scheme, &original),
            Err(Error::Storage(_))
        ));
        assert_eq!(
            objects.reads, 0,
            "failed publication returned no completed reference"
        );
        objects.fault = Fault::None;
        let reference = publish_blacklist_original(&mut objects, &scheme, &original).unwrap();
        assert_eq!(
            read_blacklist_original(&mut objects, &reference, &scheme).unwrap(),
            original
        );
        assert_eq!(
            publish_blacklist_original(&mut objects, &scheme, &original).unwrap(),
            reference
        );
    }
}

#[test]
fn missing_corrupt_unavailable_and_locked_selected_originals_remain_distinct() {
    let original = original();
    let scheme = scheme();
    let mut objects = StorageProbe::new();
    let reference = publish_blacklist_original(&mut objects, &scheme, &original).unwrap();
    for fault in [
        Fault::Missing,
        Fault::Corrupt,
        Fault::Unavailable,
        Fault::Protected,
    ] {
        objects.fault = fault;
        let error = read_blacklist_original(&mut objects, &reference, &scheme).unwrap_err();
        match fault {
            Fault::Missing | Fault::Corrupt => assert!(matches!(error, Error::WitnessLost(_))),
            Fault::Unavailable => match error {
                Error::Storage(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
                other => panic!("retryable unavailable storage was reclassified: {other:?}"),
            },
            Fault::Protected => assert!(matches!(error, Error::Provider(_))),
            _ => unreachable!(),
        }
    }
    objects.fault = Fault::None;
    let reads = objects.reads;
    assert!(read_blacklist_original(&mut objects, &reference, &[0x99; 32]).is_err());
    assert_eq!(
        objects.reads, reads,
        "foreign scheme rejected before object access"
    );
    assert_eq!(
        read_blacklist_original(&mut objects, &reference, &scheme).unwrap(),
        original
    );
}

#[test]
fn reference_preserves_full_standalone_cap_and_refuses_changed_version_hash_or_length() {
    assert_eq!(KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1, 2_228_736);
    let original = original();
    let scheme = scheme();
    let reference = BlacklistOriginalReferenceV1::for_original(&scheme, &original).unwrap();
    for n in [
        0,
        reference.original_bytes - 1,
        reference.original_bytes + 1,
        KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1 as u32 + 1,
    ] {
        let mut changed = reference.clone();
        changed.original_bytes = n;
        assert!(changed.verify_original(&scheme, &original).is_err());
    }
    let mut changed = reference.clone();
    changed.version = 2;
    assert!(
        BlacklistOriginalReferenceV1::decode_canonical(
            &archive::encode(&changed).unwrap(),
            &scheme
        )
        .is_err()
    );
    let mut changed = reference;
    changed.original_digest = [0; 32];
    assert!(changed.to_canonical_bytes().is_err());
    // Full allocation guard, not an accepted list or issuer proof.
    assert!(
        BlacklistOriginalReferenceV1::for_original(
            &scheme,
            &vec![0; KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1 + 1]
        )
        .is_err()
    );
}

#[test]
fn fixed_update_kind_binds_the_complete_original_without_heuristics_or_fallbacks() {
    let original = original();
    let scheme = scheme();
    let reference = BlacklistOriginalReferenceV1::for_original(&scheme, &original)
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    verify_policy_update_original(
        KagemushaWalletPolicyUpdateKindV1::Blacklist,
        &scheme,
        &reference,
        &original,
    )
    .unwrap();
    assert!(
        verify_policy_update_original(
            KagemushaWalletPolicyUpdateKindV1::Blacklist,
            &scheme,
            &original,
            &original
        )
        .is_err()
    );
    let mut changed = original.clone();
    changed.push(0);
    assert!(
        verify_policy_update_original(
            KagemushaWalletPolicyUpdateKindV1::Blacklist,
            &scheme,
            &reference,
            &changed
        )
        .is_err()
    );
    for kind in [
        KagemushaWalletPolicyUpdateKindV1::Credential,
        KagemushaWalletPolicyUpdateKindV1::SchemePolicy,
        KagemushaWalletPolicyUpdateKindV1::TimeAnchor,
        KagemushaWalletPolicyUpdateKindV1::QuotaShare,
    ] {
        // Exact-original equality only; these buffers are not issuer/update admission.
        verify_policy_update_original(kind, &scheme, &[1, 2, 3], &[1, 2, 3]).unwrap();
        assert!(verify_policy_update_original(kind, &scheme, &[1, 2, 3], &[1, 2, 4]).is_err());
        assert!(verify_policy_update_original(kind, &scheme, &[], &[]).is_err());
    }
}
