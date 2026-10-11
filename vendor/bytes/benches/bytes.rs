//! Stable Criterion workloads for immutable Bytes storage and sharing.
#![warn(rust_2018_idioms)]

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

fn deref_unique(c: &mut Criterion) {
    let buf = Bytes::from(vec![0; 1024]);

    let mut group = c.benchmark_group("bytes");
    group.bench_function("deref_unique", |b| {
        b.iter(|| {
            for _ in 0..1024 {
                black_box(&buf[..]);
            }
        })
    });
    group.finish();
}

fn deref_shared(c: &mut Criterion) {
    let buf = Bytes::from(vec![0; 1024]);
    let _b2 = buf.clone();

    let mut group = c.benchmark_group("bytes");
    group.bench_function("deref_shared", |b| {
        b.iter(|| {
            for _ in 0..1024 {
                black_box(&buf[..]);
            }
        })
    });
    group.finish();
}

fn deref_static(c: &mut Criterion) {
    let buf = Bytes::from_static(b"hello world");

    let mut group = c.benchmark_group("bytes");
    group.bench_function("deref_static", |b| {
        b.iter(|| {
            for _ in 0..1024 {
                black_box(&buf[..]);
            }
        })
    });
    group.finish();
}

fn clone_static(c: &mut Criterion) {
    let bytes =
        Bytes::from_static("hello world 1234567890 and have a good byte 0987654321".as_bytes());

    let mut group = c.benchmark_group("bytes");
    group.bench_function("clone_static", |b| {
        b.iter(|| {
            for _ in 0..1024 {
                black_box(black_box(&bytes).clone());
            }
        })
    });
    group.finish();
}

fn clone_shared(c: &mut Criterion) {
    let bytes = Bytes::from(b"hello world 1234567890 and have a good byte 0987654321".to_vec());

    let mut group = c.benchmark_group("bytes");
    group.bench_function("clone_shared", |b| {
        b.iter(|| {
            for _ in 0..1024 {
                black_box(black_box(&bytes).clone());
            }
        })
    });
    group.finish();
}

fn clone_arc_vec(c: &mut Criterion) {
    use std::sync::Arc;
    let bytes = Arc::new(b"hello world 1234567890 and have a good byte 0987654321".to_vec());

    let mut group = c.benchmark_group("bytes");
    group.bench_function("clone_arc_vec", |b| {
        b.iter(|| {
            for _ in 0..1024 {
                black_box(black_box(&bytes).clone());
            }
        })
    });
    group.finish();
}

fn from_long_slice(c: &mut Criterion) {
    let data = [0u8; 128];
    let mut group = c.benchmark_group("bytes");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("from_long_slice", |b| {
        b.iter(|| {
            let buf = Bytes::copy_from_slice(&data[..]);
            black_box(buf);
        })
    });
    group.finish();
}

fn slice_empty(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes");
    group.bench_function("slice_empty", |b| {
        b.iter(|| {
            // `clone` is to convert to ARC
            let b = Bytes::from(vec![17; 1024]).clone();
            for i in 0..1000 {
                black_box(b.slice(i % 100..i % 100));
            }
        })
    });
    group.finish();
}

fn slice_short_from_arc(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes");
    group.bench_function("slice_short_from_arc", |b| {
        b.iter(|| {
            // `clone` is to convert to ARC
            let b = Bytes::from(vec![17; 1024]).clone();
            for i in 0..1000 {
                black_box(b.slice(1..2 + i % 10));
            }
        })
    });
    group.finish();
}

fn split_off_and_drop(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes");
    group.bench_function("split_off_and_drop", |b| {
        b.iter(|| {
            for _ in 0..1024 {
                let v = vec![10; 200];
                let mut b = Bytes::from(v);
                black_box(b.split_off(100));
                black_box(b);
            }
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    deref_unique,
    deref_shared,
    deref_static,
    clone_static,
    clone_shared,
    clone_arc_vec,
    from_long_slice,
    slice_empty,
    slice_short_from_arc,
    split_off_and_drop
);
criterion_main!(benches);
