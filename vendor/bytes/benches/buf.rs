//! Stable Criterion scalar reads across original slice and segmented Buf fixtures.
#![warn(rust_2018_idioms)]

use bytes::Buf;
use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use std::hint::black_box;

/// Dummy Buf implementation
struct TestBuf {
    buf: &'static [u8],
    readlens: &'static [usize],
    init_pos: usize,
    pos: usize,
    readlen_pos: usize,
    readlen: usize,
}
impl TestBuf {
    fn new(buf: &'static [u8], readlens: &'static [usize], init_pos: usize) -> TestBuf {
        let mut buf = TestBuf {
            buf,
            readlens,
            init_pos,
            pos: 0,
            readlen_pos: 0,
            readlen: 0,
        };
        buf.reset();
        buf
    }
    fn reset(&mut self) {
        self.pos = self.init_pos;
        self.readlen_pos = 0;
        self.next_readlen();
    }
    /// Compute the length of the next read :
    /// - use the next value specified in readlens (capped by remaining) if any
    /// - else the remaining
    fn next_readlen(&mut self) {
        self.readlen = self.buf.len() - self.pos;
        if let Some(readlen) = self.readlens.get(self.readlen_pos) {
            self.readlen = std::cmp::min(self.readlen, *readlen);
            self.readlen_pos += 1;
        }
    }
}
impl Buf for TestBuf {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn advance(&mut self, cnt: usize) {
        self.pos += cnt;
        assert!(self.pos <= self.buf.len());
        self.next_readlen();
    }
    fn chunk(&self) -> &[u8] {
        if self.readlen == 0 {
            Default::default()
        } else {
            &self.buf[self.pos..self.pos + self.readlen]
        }
    }
}

/// Dummy Buf implementation
///  version with methods forced to not be inlined (to simulate costly calls)
struct TestBufC {
    inner: TestBuf,
}
impl TestBufC {
    fn new(buf: &'static [u8], readlens: &'static [usize], init_pos: usize) -> TestBufC {
        TestBufC {
            inner: TestBuf::new(buf, readlens, init_pos),
        }
    }
    fn reset(&mut self) {
        self.inner.reset()
    }
}
impl Buf for TestBufC {
    #[inline(never)]
    fn remaining(&self) -> usize {
        self.inner.remaining()
    }
    #[inline(never)]
    fn advance(&mut self, cnt: usize) {
        self.inner.advance(cnt)
    }
    #[inline(never)]
    fn chunk(&self) -> &[u8] {
        self.inner.chunk()
    }
}

macro_rules! bench {
    ($fname:ident, testbuf $testbuf:ident $readlens:expr, $method:ident $(,$arg:expr)*) => (
        fn $fname(b: &mut Bencher<'_>) {
            let mut bufs = [
                $testbuf::new(&[1u8; 8+0], $readlens, 0),
                $testbuf::new(&[1u8; 8+1], $readlens, 1),
                $testbuf::new(&[1u8; 8+2], $readlens, 2),
                $testbuf::new(&[1u8; 8+3], $readlens, 3),
                $testbuf::new(&[1u8; 8+4], $readlens, 4),
                $testbuf::new(&[1u8; 8+5], $readlens, 5),
                $testbuf::new(&[1u8; 8+6], $readlens, 6),
                $testbuf::new(&[1u8; 8+7], $readlens, 7),
            ];
            b.iter(|| {
                for i in 0..8 {
                    bufs[i].reset();
                    let buf: &mut dyn Buf =  &mut bufs[i]; // type erasure
                    black_box(buf.$method($($arg,)*));
                }
            })
        }
    );
    ($fname:ident, slice, $method:ident $(,$arg:expr)*) => (
        fn $fname(b: &mut Bencher<'_>) {
            // buf must be long enough for one read of 8 bytes starting at pos 7
            let arr = [1u8; 8+7];
            b.iter(|| {
                for i in 0..8 {
                    let mut buf = &arr[i..];
                    let buf = &mut buf as &mut dyn Buf; // type erasure
                    black_box(buf.$method($($arg,)*));
                }
            })
        }
    );
    ($fname:ident, option) => (
        fn $fname(b: &mut Bencher<'_>) {
            let data = [1u8; 1];
            b.iter(|| {
                for _ in 0..8 {
                    let mut buf = Some(data);
                    let buf = &mut buf as &mut dyn Buf; // type erasure
                    black_box(buf.get_u8());
                }
            })
        }
    );
}

macro_rules! bench_group {
    ($group:literal, $method:ident $(,$arg:expr)*) => (
        bench!(slice, slice, $method $(,$arg)*);
        bench!(tbuf_1,        testbuf TestBuf  &[],  $method $(,$arg)*);
        bench!(tbuf_1_costly, testbuf TestBufC &[],  $method $(,$arg)*);
        bench!(tbuf_2,        testbuf TestBuf  &[1], $method $(,$arg)*);
        bench!(tbuf_2_costly, testbuf TestBufC &[1], $method $(,$arg)*);
        // bench!(tbuf_onebyone,        testbuf TestBuf  &[1,1,1,1,1,1,1,1], $method $(,$arg)*);
        // bench!(tbuf_onebyone_costly, testbuf TestBufC &[1,1,1,1,1,1,1,1], $method $(,$arg)*);
        /// Register the original five fixtures for this scalar read.
        pub(super) fn register(c: &mut Criterion) {
            let mut group = c.benchmark_group($group);
            group.bench_function("slice", slice);
            group.bench_function("tbuf_1", tbuf_1);
            group.bench_function("tbuf_1_costly", tbuf_1_costly);
            group.bench_function("tbuf_2", tbuf_2);
            group.bench_function("tbuf_2_costly", tbuf_2_costly);
            group.finish();
        }
    );
}

mod get_u8 {
    use super::*;
    bench_group!("get_u8", get_u8);
}
mod get_u16 {
    use super::*;
    bench_group!("get_u16", get_u16);
}
mod get_u32 {
    use super::*;
    bench_group!("get_u32", get_u32);
}
mod get_u64 {
    use super::*;
    bench_group!("get_u64", get_u64);
}
mod get_f32 {
    use super::*;
    bench_group!("get_f32", get_f32);
}
mod get_f64 {
    use super::*;
    bench_group!("get_f64", get_f64);
}
mod get_uint24 {
    use super::*;
    bench_group!("get_uint24", get_uint, 3);
}

fn benchmarks(c: &mut Criterion) {
    get_u8::register(c);
    get_u16::register(c);
    get_u32::register(c);
    get_u64::register(c);
    get_f32::register(c);
    get_f64::register(c);
    get_uint24::register(c);
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
