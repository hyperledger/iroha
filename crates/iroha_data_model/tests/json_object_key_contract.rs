//! Canonical JSON object-key contracts across data-model identifier owners.
#![allow(unsafe_code)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    collections::BTreeMap,
    fmt::Debug,
};

use iroha_crypto::PublicKey;
use iroha_data_model::{
    account::AccountId,
    asset::{AssetBalanceScope, AssetDefinitionId, AssetId},
    compute::ComputePriceRiskClass,
    isi::settlement::SettlementId,
    nft::NftId,
    oracle::FeedId,
    parameter::custom::CustomParameterId,
    proof::ProofId,
    role::RoleId,
    trigger::TriggerId,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::peer::PeerId;
use iroha_model_base::{name::Name, state_path::StatePath};
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use norito::json::{self, JsonDeserialize, JsonObjectKey, JsonObjectKeyOwned};

const KEY: &str = "ed01201C61FAF8FE94E253B93114240394F79A607B7FA55F9E5A41EBEC74B88055768B";

struct TrackingAllocator;

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation(bytes: usize) {
    if TRACKING.with(Cell::get) {
        ALLOCATIONS.with(|count| count.set(count.get().saturating_add(1)));
        ALLOCATED_BYTES.with(|count| count.set(count.get().saturating_add(bytes)));
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: forward the allocation request unchanged to System.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: forward the zeroed allocation request unchanged to System.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: pointer and layout belong to the matching System allocation.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation(size);
        // SAFETY: forward the existing allocation and new size unchanged to System.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

fn measured<T>(operation: impl FnOnce() -> T) -> (T, usize, usize) {
    struct StopTracking;
    impl Drop for StopTracking {
        fn drop(&mut self) {
            TRACKING.with(|tracking| tracking.set(false));
        }
    }
    ALLOCATIONS.with(|count| count.set(0));
    ALLOCATED_BYTES.with(|count| count.set(0));
    TRACKING.with(|tracking| tracking.set(true));
    let tracking = StopTracking;
    let result = operation();
    drop(tracking);
    (
        result,
        ALLOCATIONS.with(Cell::get),
        ALLOCATED_BYTES.with(Cell::get),
    )
}

fn assert_key<T>(value: T, canonical: &str)
where
    T: JsonObjectKey + JsonObjectKeyOwned + Ord + Debug,
{
    let expected = format!(
        "{{{}:7}}",
        json::to_json(canonical).expect("quote fixture key")
    );
    let map = BTreeMap::from([(value, 7_u8)]);
    assert_eq!(json::to_json(&map).expect("serialize key map"), expected);
    assert_eq!(
        json::to_json_bounded(&map, expected.len()).expect("exact output bound"),
        expected
    );
    assert!(matches!(
        json::to_json_bounded(&map, expected.len() - 1),
        Err(json::BoundedJsonError::BodyTooLarge)
    ));
    assert_eq!(
        json::from_json::<BTreeMap<T, u8>>(&expected).expect("decode key map"),
        map
    );
    let semantic = json::from_json::<json::Value>(&expected).expect("semantic key map");
    assert_eq!(
        BTreeMap::<T, u8>::json_from_value(&semantic).expect("decode semantic map"),
        map
    );
}

fn asset_fixture(scope: AssetBalanceScope) -> AssetId {
    let key: PublicKey = KEY.parse().expect("public key fixture");
    let mut uuid = [0x11_u8; 16];
    uuid[6] = 0x41;
    uuid[8] = 0x81;
    let definition = AssetDefinitionId::from_uuid_bytes(uuid).expect("UUIDv4 fixture");
    AssetId::with_scope(definition, AccountId::new(key), scope)
}

#[test]
fn named_and_numeric_identifiers_roundtrip_as_quoted_keys() {
    let name: Name = "transfer".parse().expect("name fixture");
    assert_key(name.clone(), "transfer");
    assert_key(RoleId::new(name.clone()), "transfer");
    assert_key(TriggerId::new(name.clone()), "transfer");
    assert_key(SettlementId::new(name.clone()), "transfer");
    assert_key(FeedId(name.clone()), "transfer");
    assert_key(CustomParameterId::new(name.clone()), "transfer");
    let domain = DomainId::try_new("wonderland", "universal").expect("domain fixture");
    assert_key(domain.clone(), "wonderland.universal");
    assert_key(NftId::new(domain, name), "transfer$wonderland.universal");
    assert_key(LaneId::new(u32::MAX), "4294967295");
    assert_key(DataSpaceId::new(u64::MAX), "18446744073709551615");
    assert_key(PeerId::new(KEY.parse().expect("peer fixture")), KEY);
}

#[test]
fn compute_risk_class_keys_have_one_spelling_per_variant() {
    for (class, key) in [
        (ComputePriceRiskClass::Low, "Low"),
        (ComputePriceRiskClass::Balanced, "Balanced"),
        (ComputePriceRiskClass::High, "High"),
    ] {
        assert_key(class, key);
    }
    for invalid in ["low", "balanced", "HIGH", " High", "unknown"] {
        assert!(ComputePriceRiskClass::from_json_key_text(invalid).is_err());
    }
}

#[test]
fn composite_asset_keys_preserve_scope_and_account_identity() {
    for scope in [
        AssetBalanceScope::Global,
        AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
    ] {
        let asset = asset_fixture(scope);
        let canonical = asset.canonical_literal();
        assert_key(asset.definition().clone(), &asset.definition().to_string());
        assert_key(asset.account().clone(), &asset.account().to_string());
        assert_key(asset, &canonical);
    }
}

#[test]
fn asset_keys_preserve_account_decode_budget_and_resource_errors() {
    let unlimited =
        norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    for scope in [
        AssetBalanceScope::Global,
        AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
    ] {
        let asset = asset_fixture(scope);
        let key = asset.canonical_literal();
        let account_key = asset.account().to_string();
        let (account, usage) = norito::core::with_decode_limits_measured(unlimited, || {
            AccountId::from_json_key_text(&account_key)
        });
        assert_eq!(&account.expect("account key"), asset.account());
        let exact = usage.total_allocated_bytes();
        assert!(exact > 0);
        let limits = |bytes| {
            norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
        };
        let (decoded, usage) = norito::core::with_decode_limits_measured(limits(exact), || {
            AssetId::from_json_key_text(&key)
        });
        assert_eq!(decoded.expect("asset key at exact account budget"), asset);
        assert_eq!(usage.total_allocated_bytes(), exact);
        let (rejected, _) = norito::core::with_decode_limits_measured(limits(exact - 1), || {
            AssetId::from_json_key_text(&key)
        });
        assert!(matches!(
            rejected,
            Err(json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ));
    }
}

#[test]
fn proof_backend_escapes_roundtrip_without_changing_identity() {
    for backend in ["halo2/ipa", "quote\"newline\nbackslash\\", "証明"] {
        let canonical = format!("{backend}:{}", "AB".repeat(32));
        let proof = canonical.parse::<ProofId>().expect("proof fixture");
        assert_key(proof, &canonical);
    }
}

#[test]
fn identifier_decode_charges_cover_observed_normalization_allocations() {
    fn check<T: JsonObjectKeyOwned + Debug>(key: &str) {
        let limits = norito::core::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
        );
        // Initialize shared normalization tables outside per-input heap tracking.
        T::from_json_key_text(key).expect("warm valid identifier");
        // Decode-budget bookkeeping is outside allocator tracking; measure only
        // allocations requested while constructing this identifier.
        let ((decoded, _, requested), usage) =
            norito::core::with_decode_limits_measured(limits, || {
                measured(|| T::from_json_key_text(key))
            });
        decoded.expect("measured identifier decode");
        assert!(
            usage.total_allocated_bytes() >= requested,
            "key {key:?} requested {requested} heap bytes but charged {}",
            usage.total_allocated_bytes()
        );
    }

    for key in [
        "treasury.centralbank",
        "xn--bcher-kva.centralbank",
        "xn--r8jz45g.xn--zckzah",
    ] {
        check::<DomainId>(key);
    }
    let long_label =
        DomainId::try_new("é".repeat(40), "centralbank").expect("long A-label fixture");
    check::<DomainId>(&long_label.to_string());
    for key in [
        "root/a".to_owned(),
        "root/é".repeat(4),
        format!("root/q{}", "\u{301}".repeat(96)),
    ] {
        check::<StatePath>(&key);
    }
}
