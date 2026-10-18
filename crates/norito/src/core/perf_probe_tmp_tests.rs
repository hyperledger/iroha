//! Temporary per-operation timing probe (removed before hand-off).
use super::*;
use std::time::Instant;

fn best<F: FnMut()>(iterations: usize, mut f: F) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..7 {
        let start = Instant::now();
        for _ in 0..iterations {
            f();
        }
        best = best.min(start.elapsed().as_secs_f64() * 1e9 / iterations as f64);
    }
    best
}

#[test]
#[ignore]
fn perf_probe_field_overheads() {
    let payload = vec![7_u8; 64];
    let limits = crate::canonical_decode_limits(4096);
    let outer = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32);
    with_decode_limits_scope(outer, || {
        with_decode_limits_scope(limits, || {
            let _flags = DecodeFlagsGuard::enter(default_encode_flags());
            let _ctx = PayloadCtxGuard::enter(&payload);
            let n = 200_000;
            let check = best(n, || {
                std::hint::black_box(check_decode_field_length(std::hint::black_box(16))).ok();
            });
            let depth = best(n, || {
                std::hint::black_box(DecodeDepthGuard::enter()).ok();
            });
            let reserve = best(n, || {
                std::hint::black_box(reserve_decode_allocation(0)).ok();
            });
            let ctx_state = best(n, || {
                std::hint::black_box(payload_ctx_state());
            });
            let ctx_guard = best(n, || {
                let guard = PayloadCtxGuard::enter(std::hint::black_box(&payload[1..9]));
                std::hint::black_box(&guard);
            });
            let flags = best(n, || {
                std::hint::black_box(effective_layout_flags());
            });
            let catch = best(n, || {
                std::hint::black_box(crate::guarded_try_deserialize(|| Ok::<_, Error>(1_u8))).ok();
            });
            let mut field = Vec::new();
            serialize_to_buffer(&0x1234_5678_u32, &mut field).unwrap();
            let canonical_u32 = best(n, || {
                std::hint::black_box(decode_field_canonical::<u32>(std::hint::black_box(&field)))
                    .ok();
            });
            let inspect = best(n, || {
                std::hint::black_box(inspect_len_from_slice(std::hint::black_box(&[4_u8, 0]))).ok();
            });
            eprintln!(
                "check {check:.1} ns, depth {depth:.1} ns, reserve {reserve:.1} ns, ctx_state {ctx_state:.1} ns, ctx_guard {ctx_guard:.1} ns, flags {flags:.1} ns, catch_unwind {catch:.1} ns, inspect_len {inspect:.1} ns, decode_field_canonical<u32> {canonical_u32:.1} ns"
            );
        })
    });
}
