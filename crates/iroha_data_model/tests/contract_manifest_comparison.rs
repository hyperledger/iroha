//! Canonical manifest comparisons borrow their original graph without allocating.
// This isolated test observes the production comparison through System's native allocator.
#![allow(unsafe_code)]

use iroha_crypto::{Hash, KeyPair};
use iroha_data_model::smart_contract::manifest::{
    AccessSetHints, ContractErrorMessage, ContractErrorTypeDescriptor,
    ContractErrorVariantDescriptor, ContractManifest, EntryPointKind, EntrypointDescriptor,
    EntrypointParamDescriptor, KotobaTranslation, KotobaTranslationEntry, StateDescriptor,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

struct ObservedAllocator;
thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
    static FAIL_SIZE: Cell<Option<usize>> = const { Cell::new(None) };
}
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

#[path = "contract_manifest_projection_tests.rs"]
mod projection_tests;

#[path = "contract_manifest_id_box_projection_tests.rs"]
mod id_box_projection_tests;

fn owned_context(
    allocated_bytes: usize,
) -> (
    iroha_allocation::AllocationBudget,
    iroha_allocation::AllocationReservation,
    norito::core::DecodeBudgetContext,
) {
    let owner = iroha_allocation::AllocationBudget::new(
        allocated_bytes + norito::core::DecodeBudgetContext::allocation_layout().size(),
    );
    let grant = owner
        .try_reserve_bytes(allocated_bytes)
        .expect("original physical fixture grant");
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        norito::core::DecodeLimits::new(65_536, 1024 * 1024, 65_536, allocated_bytes, 256),
        &owner,
    )
    .expect("original physical counter owner");
    (owner, grant, context)
}

fn canonical_signing_frame(manifest: &ContractManifest) -> Vec<u8> {
    let (_owner, _grant, context) = owned_context(1024 * 1024);
    manifest
        .signature_payload_bytes(&context, 1024 * 1024)
        .expect("bounded fixture frame")
}

fn record() {
    let _ = ENABLED.try_with(|enabled| {
        if enabled.get() {
            let _ = COUNT.try_with(|count| count.set(count.get().saturating_add(1)));
        }
    });
}

fn refuse(layout: Layout) -> bool {
    ENABLED.try_with(|enabled| enabled.get()).unwrap_or(false)
        && FAIL_SIZE
            .try_with(|size| {
                if size.get() == Some(layout.size()) {
                    size.set(None);
                    true
                } else {
                    false
                }
            })
            .unwrap_or(false)
}

unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record();
        if refuse(layout) {
            return std::ptr::null_mut();
        }
        // SAFETY: forward the original allocator request unchanged.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record();
        if refuse(layout) {
            return std::ptr::null_mut();
        }
        // SAFETY: forward the original allocator request unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record();
        // SAFETY: forward the caller's original allocation and resized request unchanged.
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forward the caller's matching allocation unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }
}

fn measured<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ENABLED.with(|enabled| enabled.set(false));
            FAIL_SIZE.with(|size| size.set(None));
        }
    }
    ENABLED.with(|enabled| assert!(!enabled.get(), "nested measurement"));
    COUNT.with(|count| count.set(0));
    ENABLED.with(|enabled| enabled.set(true));
    let reset = Reset;
    let value = operation();
    drop(reset);
    (value, COUNT.with(Cell::get))
}

fn empty_manifest() -> ContractManifest {
    ContractManifest {
        seiyaku_name: None,
        code_hash: None,
        abi_hash: None,
        compiler_fingerprint: None,
        features_bitmap: None,
        access_set_hints: None,
        entrypoints: None,
        states: None,
        error_types: None,
        error_messages: None,
        kotoba: None,
        provenance: None,
    }
}

fn populated_manifest() -> ContractManifest {
    let mut manifest = empty_manifest();
    manifest.seiyaku_name = Some("Payment".into());
    manifest.code_hash = Some(Hash::new(b"compiled-artifact"));
    manifest.abi_hash = Some(Hash::new(b"canonical-abi"));
    manifest.compiler_fingerprint = Some("native-compiler".into());
    manifest.features_bitmap = Some(1);
    manifest.access_set_hints = Some(AccessSetHints {
        read_keys: vec!["state:first".into(), "state:second".into()],
        write_keys: vec!["state:balance".into()],
        dynamic_reads: Vec::new(),
        dynamic_writes: Vec::new(),
    });
    manifest.entrypoints = Some(vec![EntrypointDescriptor {
        name: "pay".into(),
        kind: EntryPointKind::Kotoage,
        params: vec![EntrypointParamDescriptor {
            name: "amount".into(),
            type_name: "quantity".into(),
        }],
        argument_schema: None,
        return_type: Some("()".into()),
        return_schema: None,
        permission: Some("CanPay".into()),
        read_keys: vec!["state:balance".into()],
        write_keys: vec!["state:balance".into()],
        access_hints_complete: Some(true),
        access_hints_skipped: Vec::new(),
        triggers: Vec::new(),
    }]);
    manifest.states = Some(vec![StateDescriptor {
        name: "balance".into(),
        type_name: "quantity".into(),
    }]);
    manifest.error_types = Some(vec![ContractErrorTypeDescriptor {
        identity: "PaymentError".into(),
        variants: vec![ContractErrorVariantDescriptor {
            name: "Insufficient".into(),
            code: 1,
        }],
    }]);
    manifest.error_messages = Some(vec![ContractErrorMessage {
        error_type: "PaymentError".into(),
        code: 1,
        message: "Insufficient funds".into(),
    }]);
    manifest.kotoba = Some(vec![KotobaTranslationEntry {
        msg_id: "insufficient".into(),
        translations: vec![KotobaTranslation {
            lang: "en".into(),
            text: "Insufficient funds".into(),
        }],
    }]);
    manifest
}

#[test]
fn borrowed_comparison_observes_every_signed_field_and_optional_presence() {
    let original = empty_manifest();
    let changes: [fn(&mut ContractManifest); 11] = [
        |m| m.seiyaku_name = Some(String::new()),
        |m| m.code_hash = Some(Hash::new(b"code")),
        |m| m.abi_hash = Some(Hash::new(b"abi")),
        |m| m.compiler_fingerprint = Some(String::new()),
        |m| m.features_bitmap = Some(0),
        |m| m.access_set_hints = populated_manifest().access_set_hints,
        |m| m.entrypoints = Some(Vec::new()),
        |m| m.states = Some(Vec::new()),
        |m| m.error_types = Some(Vec::new()),
        |m| m.error_messages = Some(Vec::new()),
        |m| m.kotoba = Some(Vec::new()),
    ];
    for (field, change) in changes.into_iter().enumerate() {
        let mut different = original.clone();
        change(&mut different);
        assert_ne!(
            canonical_signing_frame(&original),
            canonical_signing_frame(&different)
        );
        let (same, allocations) = measured(|| original.same_signed_content(&different));
        assert!(!same, "signed field {field} was excluded");
        assert_eq!(allocations, 0);
    }
}

#[test]
fn borrowed_comparison_preserves_nested_values_order_and_provenance_exclusion() {
    let original = populated_manifest();
    let key_pair = KeyPair::try_random().expect("test signing key");
    let (_owner, _grant, context) = owned_context(1024 * 1024);
    let signed = original
        .clone()
        .try_signed(&context, 1024 * 1024, &key_pair)
        .expect("sign fixture");
    let (same, allocations) = measured(|| original.same_signed_content(&signed));
    assert!(same);
    assert_eq!(allocations, 0);
    assert_eq!(
        canonical_signing_frame(&original),
        canonical_signing_frame(&signed)
    );

    let changes: [fn(&mut ContractManifest); 5] = [
        |m| m.access_set_hints.as_mut().unwrap().read_keys.swap(0, 1),
        |m| m.entrypoints.as_mut().unwrap()[0].params[0].type_name = "int".into(),
        |m| m.states.as_mut().unwrap()[0].type_name = "int".into(),
        |m| m.error_types.as_mut().unwrap()[0].variants[0].code = 2,
        |m| m.kotoba.as_mut().unwrap()[0].translations[0].text = "Revised".into(),
    ];
    for change in changes {
        let mut different = signed.clone();
        change(&mut different);
        assert_ne!(
            canonical_signing_frame(&original),
            canonical_signing_frame(&different)
        );
        let (same, allocations) = measured(|| original.same_signed_content(&different));
        assert!(!same);
        assert_eq!(allocations, 0);
    }
}

#[test]
fn native_observer_distinguishes_owned_graph_copies_from_borrowed_payload_views() {
    let original = populated_manifest();
    let other = original.clone();
    let (copy, allocations) = measured(|| std::hint::black_box(&original).clone());
    assert!(copy.same_signed_content(&original));
    assert!(allocations > 0, "observer must see a real owned graph copy");
    let (view, allocations) = measured(|| std::hint::black_box(&original).signature_payload());
    assert_eq!(allocations, 0);
    assert!(std::ptr::eq(
        view.seiyaku_name.unwrap().as_ptr(),
        original.seiyaku_name.as_ref().unwrap().as_ptr()
    ));
    let (same, allocations) = measured(|| {
        std::hint::black_box(&original).same_signed_content(std::hint::black_box(&other))
    });
    assert!(same);
    assert_eq!(allocations, 0);
}
