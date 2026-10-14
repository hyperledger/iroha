//! Pipeline cache policy acceptance tests

//!
//! Covers:
//! - Insert/hit/eviction behavior under bounded capacity
//! - Capacity clamp when configured to zero (must behave as capacity = 1)
use ivm::{encoding, instruction, ivm_cache};
use std::sync::{LazyLock, Mutex};
static CACHE_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
fn halt32_code() -> Vec<u8> {
    encoding::wide::encode_halt().to_le_bytes().to_vec()
}
fn second_code() -> Vec<u8> {
    encoding::wide::encode_rr(instruction::wide::arithmetic::SUB, 2, 3, 4)
        .to_le_bytes()
        .to_vec()
}
fn alt_two_c_ops_code() -> Vec<u8> {
    // Use two wide RR instructions with distinct registers to guarantee a unique byte stream.
    let add = encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 5, 6, 7).to_le_bytes();
    let xor = encoding::wide::encode_rr(instruction::wide::arithmetic::XOR, 8, 9, 10).to_le_bytes();
    [add.to_vec(), xor.to_vec()].concat()
}
#[test]
fn cache_insert_hit_and_eviction_under_capacity() {
    let _lock = CACHE_TEST_LOCK.lock().unwrap();
    // Ensure a small deterministic capacity and record initial counters.
    ivm_cache::set_global_capacity(2);
    let (h0, m0, e0) = ivm_cache::global_counters();
    let code1 = halt32_code();
    let code2 = second_code();
    // third distinct stream: use unique wide ops to ensure distinct cache key
    let code3 = alt_two_c_ops_code();
    // Insert two distinct entries (misses)
    let _a1 = ivm_cache::global_get(&code1).expect("decode code1");
    let a2_first = ivm_cache::global_get(&code2).expect("decode code2");
    // Re-access code1 to mark it most-recently used (hit)
    let _a1_hit = ivm_cache::global_get(&code1).expect("hit code1");
    // Insert third distinct entry; capacity=2 so LRU (code2) should be evicted
    let _a3 = ivm_cache::global_get(&code3).expect("decode code3");
    // Access code2 again; should be a miss and produce a new allocation (re-decoded)
    let a2_second = ivm_cache::global_get(&code2).expect("re-decode code2");
    assert!(
        !ivm::cache_memory::SharedAllocation::ptr_eq(&a2_first, &a2_second),
        "expected code2 to be evicted and re-decoded",
    );
    let (h1, m1, e1) = ivm_cache::global_counters();
    assert!(h1 > h0, "expected at least one cache hit");
    assert!(
        m1 >= m0 + 3,
        "expected at least three misses (first inserts + re-decode)"
    );
    assert!(e1 > e0, "expected at least one eviction due to capacity");
}
#[test]
fn zero_capacity_is_clamped_to_one() {
    let _lock = CACHE_TEST_LOCK.lock().unwrap();
    // Capacity set to zero must behave as capacity = 1 (no panics; single entry kept)
    ivm_cache::set_global_capacity(0);
    let code1 = halt32_code();
    let code2 = second_code();
    let a1_first = ivm_cache::global_get(&code1).expect("decode code1");
    let _a2 = ivm_cache::global_get(&code2).expect("decode code2 (evict code1)");
    let a1_second = ivm_cache::global_get(&code1).expect("re-decode code1");
    // With effective capacity=1, code1 should have been evicted by code2 and re-decoded now
    assert!(
        !ivm::cache_memory::SharedAllocation::ptr_eq(&a1_first, &a1_second),
        "expected code1 to be evicted under capacity=1 and re-decoded",
    );
}
