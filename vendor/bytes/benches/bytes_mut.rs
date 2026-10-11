//! Stable Criterion workloads for mutable buffer allocation, access and writes.
#![warn(rust_2018_idioms)]

use bytes::{BufMut, BytesMut};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

fn alloc_small(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes_mut");
    group.bench_function("alloc_small", |b| {
        b.iter(|| {
            for _ in 0..1024 {
                black_box(BytesMut::with_capacity(12));
            }
        })
    });
    group.finish();
}

fn alloc_mid(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes_mut");
    group.bench_function("alloc_mid", |b| {
        b.iter(|| {
            black_box(BytesMut::with_capacity(128));
        })
    });
    group.finish();
}

fn alloc_big(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes_mut");
    group.bench_function("alloc_big", |b| {
        b.iter(|| {
            black_box(BytesMut::with_capacity(4096));
        })
    });
    group.finish();
}

fn deref_unique(c: &mut Criterion) {
    let mut buf = BytesMut::with_capacity(4096);
    buf.put(&[0u8; 1024][..]);

    let mut group = c.benchmark_group("bytes_mut");
    group.bench_function("deref_unique", |b| {
        b.iter(|| {
            for _ in 0..1024 {
                black_box(&buf[..]);
            }
        })
    });
    group.finish();
}

fn deref_unique_unroll(c: &mut Criterion) {
    let mut buf = BytesMut::with_capacity(4096);
    buf.put(&[0u8; 1024][..]);

    let mut group = c.benchmark_group("bytes_mut");
    group.bench_function("deref_unique_unroll", |b| {
        b.iter(|| {
            for _ in 0..128 {
                black_box(&buf[..]);
                black_box(&buf[..]);
                black_box(&buf[..]);
                black_box(&buf[..]);
                black_box(&buf[..]);
                black_box(&buf[..]);
                black_box(&buf[..]);
                black_box(&buf[..]);
            }
        })
    });
    group.finish();
}

fn deref_shared(c: &mut Criterion) {
    let mut buf = BytesMut::with_capacity(4096);
    buf.put(&[0u8; 1024][..]);
    let _b2 = buf.split_off(1024);

    let mut group = c.benchmark_group("bytes_mut");
    group.bench_function("deref_shared", |b| {
        b.iter(|| {
            for _ in 0..1024 {
                black_box(&buf[..]);
            }
        })
    });
    group.finish();
}

fn deref_two(c: &mut Criterion) {
    let mut buf1 = BytesMut::with_capacity(8);
    buf1.put(&[0u8; 8][..]);

    let mut buf2 = BytesMut::with_capacity(4096);
    buf2.put(&[0u8; 1024][..]);

    let mut group = c.benchmark_group("bytes_mut");
    group.bench_function("deref_two", |b| {
        b.iter(|| {
            for _ in 0..512 {
                black_box(&buf1[..]);
                black_box(&buf2[..]);
            }
        })
    });
    group.finish();
}

fn clone_frozen(c: &mut Criterion) {
    let bytes = BytesMut::from(&b"hello world 1234567890 and have a good byte 0987654321"[..])
        .split()
        .freeze();

    let mut group = c.benchmark_group("bytes_mut");
    group.bench_function("clone_frozen", |b| {
        b.iter(|| {
            for _ in 0..1024 {
                black_box(&bytes.clone());
            }
        })
    });
    group.finish();
}

fn alloc_write_split_to_mid(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes_mut");
    group.bench_function("alloc_write_split_to_mid", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(128);
            buf.put_slice(&[0u8; 64]);
            black_box(buf.split_to(64));
        })
    });
    group.finish();
}

fn drain_write_drain(c: &mut Criterion) {
    let data = [0u8; 128];

    let mut group = c.benchmark_group("bytes_mut");
    group.bench_function("drain_write_drain", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(1024);
            let mut parts = Vec::with_capacity(8);

            for _ in 0..8 {
                buf.put(&data[..]);
                parts.push(buf.split_to(128));
            }

            black_box(parts);
        })
    });
    group.finish();
}

fn fmt_write(c: &mut Criterion) {
    use std::fmt::Write;
    let mut buf = BytesMut::with_capacity(128);
    let s = "foo bar baz quux lorem ipsum dolor et";

    let mut group = c.benchmark_group("bytes_mut");
    group.throughput(Throughput::Bytes(s.len() as u64));
    group.bench_function("fmt_write", |b| {
        b.iter(|| {
            let _ = write!(buf, "{}", s);
            black_box(&buf);
            unsafe {
                buf.set_len(0);
            }
        })
    });
    group.finish();
}

fn bytes_mut_extend(c: &mut Criterion) {
    let mut buf = BytesMut::with_capacity(256);
    let data = [33u8; 32];

    let mut group = c.benchmark_group("bytes_mut");
    group.throughput(Throughput::Bytes(data.len() as u64 * 4));
    group.bench_function("bytes_mut_extend", |b| {
        b.iter(|| {
            for _ in 0..4 {
                buf.extend(&data);
            }
            black_box(&buf);
            unsafe {
                buf.set_len(0);
            }
        });
    });
    group.finish();
}

// BufMut for BytesMut vs Vec<u8>

fn put_slice_bytes_mut(c: &mut Criterion) {
    let mut buf = BytesMut::with_capacity(256);
    let data = [33u8; 32];

    let mut group = c.benchmark_group("bytes_mut");
    group.throughput(Throughput::Bytes(data.len() as u64 * 4));
    group.bench_function("put_slice_bytes_mut", |b| {
        b.iter(|| {
            for _ in 0..4 {
                buf.put_slice(&data);
            }
            black_box(&buf);
            unsafe {
                buf.set_len(0);
            }
        });
    });
    group.finish();
}

fn put_u8_bytes_mut(c: &mut Criterion) {
    let mut buf = BytesMut::with_capacity(256);
    let cnt = 128;

    let mut group = c.benchmark_group("bytes_mut");
    group.throughput(Throughput::Bytes(cnt as u64));
    group.bench_function("put_u8_bytes_mut", |b| {
        b.iter(|| {
            for _ in 0..cnt {
                buf.put_u8(b'x');
            }
            black_box(&buf);
            unsafe {
                buf.set_len(0);
            }
        });
    });
    group.finish();
}

fn put_slice_vec(c: &mut Criterion) {
    let mut buf = Vec::<u8>::with_capacity(256);
    let data = [33u8; 32];

    let mut group = c.benchmark_group("bytes_mut");
    group.throughput(Throughput::Bytes(data.len() as u64 * 4));
    group.bench_function("put_slice_vec", |b| {
        b.iter(|| {
            for _ in 0..4 {
                buf.put_slice(&data);
            }
            black_box(&buf);
            unsafe {
                buf.set_len(0);
            }
        });
    });
    group.finish();
}

fn put_u8_vec(c: &mut Criterion) {
    let mut buf = Vec::<u8>::with_capacity(256);
    let cnt = 128;

    let mut group = c.benchmark_group("bytes_mut");
    group.throughput(Throughput::Bytes(cnt as u64));
    group.bench_function("put_u8_vec", |b| {
        b.iter(|| {
            for _ in 0..cnt {
                buf.put_u8(b'x');
            }
            black_box(&buf);
            unsafe {
                buf.set_len(0);
            }
        });
    });
    group.finish();
}

fn put_slice_vec_extend(c: &mut Criterion) {
    let mut buf = Vec::<u8>::with_capacity(256);
    let data = [33u8; 32];

    let mut group = c.benchmark_group("bytes_mut");
    group.throughput(Throughput::Bytes(data.len() as u64 * 4));
    group.bench_function("put_slice_vec_extend", |b| {
        b.iter(|| {
            for _ in 0..4 {
                buf.extend_from_slice(&data);
            }
            black_box(&buf);
            unsafe {
                buf.set_len(0);
            }
        });
    });
    group.finish();
}

fn put_u8_vec_push(c: &mut Criterion) {
    let mut buf = Vec::<u8>::with_capacity(256);
    let cnt = 128;

    let mut group = c.benchmark_group("bytes_mut");
    group.throughput(Throughput::Bytes(cnt as u64));
    group.bench_function("put_u8_vec_push", |b| {
        b.iter(|| {
            for _ in 0..cnt {
                buf.push(b'x');
            }
            black_box(&buf);
            unsafe {
                buf.set_len(0);
            }
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    alloc_small,
    alloc_mid,
    alloc_big,
    deref_unique,
    deref_unique_unroll,
    deref_shared,
    deref_two,
    clone_frozen,
    alloc_write_split_to_mid,
    drain_write_drain,
    fmt_write,
    bytes_mut_extend,
    put_slice_bytes_mut,
    put_u8_bytes_mut,
    put_slice_vec,
    put_u8_vec,
    put_slice_vec_extend,
    put_u8_vec_push
);
criterion_main!(benches);
