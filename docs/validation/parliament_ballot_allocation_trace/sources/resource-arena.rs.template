//! Fixed buddy allocator for the standalone worker. All block rounding and the
//! complete availability tree are inside the reserved workspace mapping.

use std::{
    alloc::Layout,
    cell::UnsafeCell,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

pub const HEAP_BYTES: usize = 32 * 1024 * 1024;
pub const MIN_BLOCK: usize = 64;
pub const TREE_BYTES: usize = 2 * (HEAP_BYTES / MIN_BLOCK) - 1;

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub live_blocks: usize,
    pub live_requested: usize,
    pub peak_blocks: usize,
    pub peak_requested: usize,
    pub allocations: usize,
}

struct Inner {
    heap: *mut u8,
    tree: *mut u8,
    bytes: usize,
    alignment: usize,
    limit: usize,
    stats: Stats,
}

pub struct Arena {
    locked: AtomicBool,
    inner: UnsafeCell<Inner>,
}

// SAFETY: the spin lock serializes all accesses to Inner. The backing mapping
// outlives every allocation and every operation on this arena.
unsafe impl Sync for Arena {}

// Tree orders are at most log2(usize::MAX), hence at most 63 on supported
// targets. Truncating those orders to a byte is exact and cannot unwind.
#[allow(clippy::cast_possible_truncation)]
impl Arena {
    /// The caller supplies disjoint writable heap/tree storage for this arena's
    /// entire lifetime. `bytes/MIN_BLOCK` is a power of two; tree has twice that
    /// many bytes minus one; heap is aligned to `alignment` (a power of two).
    pub unsafe fn new(
        heap: *mut u8,
        tree: *mut u8,
        bytes: usize,
        alignment: usize,
        limit: usize,
    ) -> Self {
        assert!(bytes >= MIN_BLOCK && bytes.is_power_of_two());
        assert!(alignment.is_power_of_two());
        let leaves = bytes / MIN_BLOCK;
        let height = leaves.ilog2();
        for depth in 0..=height {
            let start = (1usize << depth) - 1;
            // SAFETY: each tree level lies within the supplied tree storage.
            unsafe {
                tree.add(start)
                    .write_bytes((height - depth + 1) as u8, 1 << depth)
            };
        }
        Self {
            locked: AtomicBool::new(false),
            inner: UnsafeCell::new(Inner {
                heap,
                tree,
                bytes,
                alignment,
                limit: limit.min(bytes),
                stats: Stats::default(),
            }),
        }
    }

    fn with_inner<T>(&self, operation: impl FnOnce(&mut Inner) -> T) -> T {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
        }
        // SAFETY: this lock grants exclusive access; operations below neither
        // allocate, invoke user callbacks, nor panic for valid allocator input.
        let result = operation(unsafe { &mut *self.inner.get() });
        self.locked.store(false, Ordering::Release);
        result
    }

    pub fn stats(&self) -> Stats {
        self.with_inner(|inner| inner.stats)
    }

    pub fn contains(&self, pointer: *mut u8) -> bool {
        self.with_inner(|inner| {
            let address = pointer as usize;
            let start = inner.heap as usize;
            address >= start && address - start < inner.bytes
        })
    }

    pub fn allocate(&self, layout: Layout) -> *mut u8 {
        self.with_inner(|inner| {
            let Some(block) = layout
                .size()
                .max(layout.align())
                .max(MIN_BLOCK)
                .checked_next_power_of_two()
            else {
                return ptr::null_mut();
            };
            if layout.align() > inner.alignment
                || block > inner.bytes
                || block > inner.limit.saturating_sub(inner.stats.live_blocks)
            {
                return ptr::null_mut();
            }
            let wanted = (block / MIN_BLOCK).ilog2() as u8 + 1;
            // SAFETY: root is present in every admitted arena.
            if unsafe { *inner.tree } < wanted {
                return ptr::null_mut();
            }
            let mut index = 0;
            let mut width = inner.bytes;
            let mut offset = 0;
            while width > block {
                width /= 2;
                let left = index * 2 + 1;
                // SAFETY: a non-leaf has both children within the tree.
                if unsafe { *inner.tree.add(left) } >= wanted {
                    index = left;
                } else {
                    index = left + 1;
                    offset += width;
                }
            }
            // SAFETY: the selected node is a free block; ancestors exist.
            unsafe {
                *inner.tree.add(index) = 0;
                while index > 0 {
                    index = (index - 1) / 2;
                    *inner.tree.add(index) =
                        (*inner.tree.add(index * 2 + 1)).max(*inner.tree.add(index * 2 + 2));
                }
            }
            inner.stats.live_blocks += block;
            inner.stats.live_requested += layout.size();
            inner.stats.peak_blocks = inner.stats.peak_blocks.max(inner.stats.live_blocks);
            inner.stats.peak_requested = inner.stats.peak_requested.max(inner.stats.live_requested);
            inner.stats.allocations += 1;
            // SAFETY: offset identifies the exclusive allocated block.
            unsafe { inner.heap.add(offset) }
        })
    }

    /// `pointer` and `layout` must describe a currently live allocation here.
    pub unsafe fn release(&self, pointer: *mut u8, layout: Layout) {
        self.with_inner(|inner| {
            let block = layout
                .size()
                .max(layout.align())
                .max(MIN_BLOCK)
                .next_power_of_two();
            let offset = pointer as usize - inner.heap as usize;
            let mut index = (inner.bytes + offset) / block - 1;
            let mut available = (block / MIN_BLOCK).ilog2() as u8 + 1;
            // SAFETY: GlobalAlloc's caller contract establishes pointer/layout
            // provenance and liveness; this identifies its allocated node.
            unsafe {
                *inner.tree.add(index) = available;
                while index > 0 {
                    index = (index - 1) / 2;
                    let left = *inner.tree.add(index * 2 + 1);
                    let right = *inner.tree.add(index * 2 + 2);
                    *inner.tree.add(index) = if left == available && right == available {
                        available + 1
                    } else {
                        left.max(right)
                    };
                    available += 1;
                }
            }
            inner.stats.live_blocks -= block;
            inner.stats.live_requested -= layout.size();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::GlobalAlloc;

    struct Local<'a>(&'a Arena);

    // SAFETY: this test wrapper forwards the allocation contract to its arena.
    unsafe impl GlobalAlloc for Local<'_> {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            self.0.allocate(layout)
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { self.0.release(pointer, layout) };
        }
    }

    fn arena(heap: &mut [u64], tree: &mut [u8], limit: usize) -> Arena {
        // SAFETY: test backing buffers remain alive and disjoint for the arena.
        unsafe {
            Arena::new(
                heap.as_mut_ptr().cast(),
                tree.as_mut_ptr(),
                std::mem::size_of_val(heap),
                8,
                limit,
            )
        }
    }

    #[test]
    fn exact_budget_alignment_and_coalescing() {
        let mut heap = [0u64; 512];
        let mut tree = [0u8; 127];
        let arena = arena(&mut heap, &mut tree, 256);
        let layout = Layout::from_size_align(65, 8).unwrap();
        let a = arena.allocate(layout);
        let b = arena.allocate(layout);
        assert!(!a.is_null() && !b.is_null() && a != b);
        assert_eq!(a as usize % 8, 0);
        assert!(arena.allocate(layout).is_null());
        assert!(
            arena
                .allocate(Layout::from_size_align(1, 16).unwrap())
                .is_null()
        );
        assert_eq!(arena.stats().live_blocks, 256);
        // SAFETY: both allocations are live and use their original layouts.
        unsafe {
            arena.release(a, layout);
            arena.release(b, layout);
        }
        let large = Layout::from_size_align(256, 8).unwrap();
        let p = arena.allocate(large);
        assert!(!p.is_null());
        unsafe { arena.release(p, large) };
        assert_eq!(arena.stats().live_requested, 0);
        assert_eq!(arena.stats().live_blocks, 0);
    }

    #[test]
    fn deterministic_fragmentation_campaign_preserves_live_bytes() {
        let mut heap = [0u64; 8192];
        let mut tree = [0u8; 2047];
        let arena = arena(&mut heap, &mut tree, 65536);
        let mut live: Vec<(*mut u8, Layout, u8)> = Vec::new();
        let mut rng = 0x7328_b912_a614_88f3u64;
        for step in 0..20_000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            if !live.is_empty() && rng & 3 == 0 {
                let index = (rng as usize) % live.len();
                let (p, layout, byte) = live.swap_remove(index);
                // SAFETY: the tracked allocation remains live until released.
                unsafe {
                    assert!(
                        std::slice::from_raw_parts(p, layout.size())
                            .iter()
                            .all(|b| *b == byte)
                    );
                    arena.release(p, layout);
                }
            } else {
                let layout =
                    Layout::from_size_align((rng as usize % 3000) + 1, 1 << (rng % 4)).unwrap();
                let p = arena.allocate(layout);
                if !p.is_null() {
                    let byte = step as u8;
                    unsafe { p.write_bytes(byte, layout.size()) };
                    live.push((p, layout, byte));
                }
            }
            assert!(arena.stats().live_blocks <= 65536);
        }
        for (p, layout, byte) in live {
            unsafe {
                assert!(
                    std::slice::from_raw_parts(p, layout.size())
                        .iter()
                        .all(|b| *b == byte)
                );
                arena.release(p, layout);
            }
        }
        let layout = Layout::from_size_align(65536, 8).unwrap();
        let p = arena.allocate(layout);
        assert!(
            !p.is_null(),
            "all buddies must coalesce after arbitrary frees"
        );
        unsafe { arena.release(p, layout) };
        assert_eq!(arena.stats().live_blocks, 0);
    }

    #[test]
    fn zeroed_reallocation_copy_and_failed_growth_follow_allocator_contract() {
        let mut heap = [0u64; 512];
        let mut tree = [0u8; 127];
        let arena = arena(&mut heap, &mut tree, 4096);
        let allocator = Local(&arena);
        let original = Layout::from_size_align(100, 8).unwrap();
        // SAFETY: every access stays within a tracked live allocation; default
        // GlobalAlloc growth retains the old pointer when allocation fails.
        unsafe {
            let a = allocator.alloc_zeroed(original);
            assert!(!a.is_null());
            assert!(std::slice::from_raw_parts(a, 100).iter().all(|b| *b == 0));
            a.write_bytes(0xa7, 100);
            let b = allocator.realloc(a, original, 1025);
            assert!(!b.is_null());
            assert!(
                std::slice::from_raw_parts(b, 100)
                    .iter()
                    .all(|b| *b == 0xa7)
            );
            let grown = Layout::from_size_align(1025, 8).unwrap();
            assert!(allocator.realloc(b, grown, 4096).is_null());
            assert!(
                std::slice::from_raw_parts(b, 100)
                    .iter()
                    .all(|b| *b == 0xa7)
            );
            allocator.dealloc(b, grown);
        }
        assert_eq!(arena.stats().live_blocks, 0);
        assert_eq!(arena.stats().peak_blocks, 2176);
    }
}
