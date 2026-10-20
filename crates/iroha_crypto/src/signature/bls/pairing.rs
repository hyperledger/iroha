//! Fallible exact-layout ownership for the upstream `blst` pairing context.
//!
//! This is the allocation boundary used by both aggregate suites. The raw calls
//! below are the same calls made by `blst::Pairing`, but allocation is fallible and
//! cannot abort between logical admission and creation of the caller's owner.
//! Both owners refuse an unsupported linked context size before entering C;
//! [`check_pairing_geometry`] lets node startup refuse such a build outright.

use core::alloc::Layout;

use blst::{blst_fp12, blst_p1_affine, blst_p2_affine};

/// Failure to acquire an explicitly owned aggregate verification context.
#[derive(Debug)]
pub enum AggregateScratchError<E> {
    /// The caller's original admission refusal, without replacement or projection.
    Admission(E),
    /// The physical allocator refused the exact, already-admitted context layout.
    ///
    /// This is independent of pool capacity and carries no capacity-release wait.
    Allocator {
        /// Original refusal returned by the physical backing reservation.
        error: std::collections::TryReserveError,
        /// Exact checked backing layout requested from the physical allocator.
        layout: Layout,
    },
    /// The linked `blst` reports a context size this owner cannot initialize: zero
    /// bytes, which would hand C a dangling pointer, or a size with no native layout.
    ///
    /// Refused before any backing reservation or C call; the admitted owner is
    /// retired. Node startup refuses such a build ([`check_pairing_geometry`]).
    UnsupportedGeometry {
        /// `blst_pairing_sizeof()` reported by the linked implementation.
        context_bytes: usize,
    },
}

/// The linked `blst` pairing context does not fit the bounded stack storage of the
/// verdict-only aggregate adapters.
///
/// Those adapters (including dynamic QC/TC verification) would reject every valid
/// aggregate as a bad signature, so a node must not run on this build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedPairingGeometry {
    /// `blst_pairing_sizeof()` reported by the linked implementation.
    pub context_bytes: usize,
    /// Fixed stack storage available to verdict-only aggregate verification.
    pub stack_bytes: usize,
}

impl core::fmt::Display for UnsupportedPairingGeometry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the linked blst pairing context reports {} bytes; aggregate verification \
             supports 1..={} bytes",
            self.context_bytes, self.stack_bytes
        )
    }
}

impl std::error::Error for UnsupportedPairingGeometry {}

/// Check that the linked `blst` pairing context fits the bounded stack storage of
/// every verdict-only aggregate adapter.
///
/// This is one pointer-free size query; it allocates nothing and enters no context.
/// The heap scratch owners accept any nonzero size, so passing this check also
/// covers them. Node startup must refuse to run when it fails.
///
/// # Errors
/// Returns the linked context size and the stack bound when the context is empty
/// or larger than that bound.
pub fn check_pairing_geometry() -> Result<(), UnsupportedPairingGeometry> {
    let context_bytes = FalliblePairing::context_bytes();
    if StackPairing::fits_context(context_bytes) {
        Ok(())
    } else {
        Err(UnsupportedPairingGeometry {
            context_bytes,
            stack_bytes: StackPairing::BYTES,
        })
    }
}

/// Sole owner of one exact upstream context allocation. Moving it never moves storage.
#[derive(Debug)]
pub(super) struct FalliblePairing {
    words: Vec<u64>,
}

/// Fixed stack storage for adapters that return only a cryptographic verdict.
///
/// blst 0.3.16's `aggregate.c` uses `N_MAX = 8`: 24 scalar/pointer bytes,
/// 576 target-group bytes, 288 aggregate-point bytes and 8 * (192 + 96)
/// affine-point bytes, totalling 3192 bytes on 64-bit hosts. The 4096-byte
/// ceiling also covers its supported 32-bit pointer layout. Check the linked
/// implementation before entering C so an upstream layout change cannot overflow.
pub(super) struct StackPairing {
    words: [u64; 512],
}

impl StackPairing {
    /// Bytes of fixed stack storage available to one context.
    const BYTES: usize = core::mem::size_of::<[u64; 512]>();

    /// `None` exactly when [`check_pairing_geometry`] fails, before entering C.
    pub(super) fn new(dst: &'static [u8]) -> Option<Self> {
        if !Self::fits_context(FalliblePairing::context_bytes()) {
            return None;
        }
        let mut pairing = Self { words: [0; 512] };
        pairing.context().init(true, dst);
        Some(pairing)
    }

    fn fits_context(bytes: usize) -> bool {
        bytes > 0 && bytes <= Self::BYTES
    }

    pub(super) fn context(&mut self) -> PairingContext<'_> {
        PairingContext {
            words: &mut self.words,
        }
    }
}

/// Unique borrow of initialized, suitably sized and aligned heap or stack words.
pub(super) struct PairingContext<'a> {
    words: &'a mut [u64],
}

#[allow(
    unsafe_code,
    reason = "exact-layout ownership around the same synchronous C context calls as blst::Pairing"
)]
impl FalliblePairing {
    fn context_bytes() -> usize {
        // SAFETY: pointer-free upstream query. Upstream backs this context with
        // u64 words, so u64 alignment is sufficient on every supported target.
        unsafe { blst::blst_pairing_sizeof() }
    }

    pub(super) fn layout() -> Layout {
        Layout::array::<u64>(Self::context_bytes().div_ceil(core::mem::size_of::<u64>()))
            .expect("the linked blst context has a valid native allocation layout")
    }

    /// The exact backing layout of a nonzero, representable context size.
    ///
    /// `None` for zero bytes (an empty `Vec` would hand C a dangling pointer) or a
    /// size with no native array layout. Pure and allocation-free.
    fn initializable_layout(context_bytes: usize) -> Option<Layout> {
        if context_bytes == 0 {
            return None;
        }
        Layout::array::<u64>(context_bytes.div_ceil(core::mem::size_of::<u64>())).ok()
    }

    pub(super) fn new<E>(dst: &'static [u8]) -> Result<Self, AggregateScratchError<E>> {
        let context_bytes = Self::context_bytes();
        let layout = Self::initializable_layout(context_bytes)
            .ok_or(AggregateScratchError::UnsupportedGeometry { context_bytes })?;
        let count = layout.size() / core::mem::size_of::<u64>();
        let mut words = Vec::new();
        words
            .try_reserve_exact(count)
            .map_err(|error| AggregateScratchError::Allocator { error, layout })?;
        // Reserving from an empty Vec requests the checked array layout once.
        // Retain that original Vec: boxing/shrinking it could allocate again.
        words.resize(count, 0);
        let mut pairing = Self { words };
        pairing.context().init(true, dst);
        Ok(pairing)
    }

    pub(super) fn context(&mut self) -> PairingContext<'_> {
        PairingContext {
            words: &mut self.words,
        }
    }

    #[cfg(test)]
    pub(super) fn backing_pointer(&self) -> *const blst::blst_pairing {
        self.words.as_ptr().cast()
    }
}

#[allow(
    unsafe_code,
    reason = "the only constructors borrow checked u64-aligned, initialized blst storage"
)]
impl PairingContext<'_> {
    pub(super) fn init(&mut self, hash_or_encode: bool, dst: &'static [u8]) {
        // SAFETY: the unique context has at least blst_pairing_sizeof() writable
        // bytes at upstream's required alignment. blst retains the DST pointer;
        // requiring a static slice keeps it alive across every reset and move.
        unsafe {
            blst::blst_pairing_init(
                self.words.as_mut_ptr().cast(),
                hash_or_encode,
                dst.as_ptr(),
                dst.len(),
            );
        }
    }

    pub(super) fn raw_aggregate(&mut self, q: &blst_p2_affine, p: &blst_p1_affine) {
        // SAFETY: context is initialized and uniquely borrowed; fixed point
        // inputs live through this synchronous call and are not retained.
        unsafe { blst::blst_pairing_raw_aggregate(self.words.as_mut_ptr().cast(), q, p) }
    }

    pub(super) fn commit(&mut self) {
        // SAFETY: initialized, uniquely borrowed upstream context.
        unsafe { blst::blst_pairing_commit(self.words.as_mut_ptr().cast()) }
    }

    pub(super) fn finalverify(&self, signature: Option<&blst_fp12>) -> bool {
        // SAFETY: initialized context is shared immutably and the optional fixed
        // target-group value remains alive for the synchronous read-only call.
        unsafe {
            blst::blst_pairing_finalverify(
                self.words.as_ptr().cast(),
                signature.map_or(core::ptr::null(), core::ptr::from_ref),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn checked_layout_matches_linked_context_and_stack_alignment() {
        let layout = FalliblePairing::layout();
        // SAFETY: pointer-free upstream layout query.
        assert_eq!(layout.size(), unsafe { blst::blst_pairing_sizeof() });
        assert_eq!(layout.align(), core::mem::align_of::<u64>());
        assert!(layout.size() <= core::mem::size_of::<StackPairing>());
        assert_eq!(core::mem::align_of::<StackPairing>(), layout.align());
        let pairing = FalliblePairing::new::<()>(super::super::consensus::DST_SIG).unwrap();
        assert_eq!(
            pairing.words.capacity() * core::mem::size_of::<u64>(),
            layout.size()
        );
        assert_eq!(pairing.words.len(), pairing.words.capacity());
    }

    #[test]
    fn stack_bound_rejects_unsupported_geometry_before_entering_c() {
        crate::test_allocations::without_allocations(|| {
            let limit = core::mem::size_of::<[u64; 512]>();
            assert_eq!(StackPairing::BYTES, limit);
            assert!(StackPairing::fits_context(FalliblePairing::context_bytes()));
            assert!(StackPairing::fits_context(limit));
            assert!(!StackPairing::fits_context(0));
            assert!(!StackPairing::fits_context(limit + 1));
            assert!(!StackPairing::fits_context(usize::MAX));
            assert!(StackPairing::new(super::super::consensus::DST_SIG).is_some());
        });
    }

    #[test]
    fn heap_owner_refuses_empty_or_unrepresentable_context_before_reserving() {
        let linked = FalliblePairing::context_bytes();
        crate::test_allocations::without_allocations(|| {
            assert_eq!(FalliblePairing::initializable_layout(0), None);
            assert_eq!(FalliblePairing::initializable_layout(usize::MAX), None);
            assert_eq!(
                FalliblePairing::initializable_layout(linked),
                Some(FalliblePairing::layout())
            );
            // One byte still needs one whole aligned word, never an empty backing.
            assert_eq!(
                FalliblePairing::initializable_layout(1),
                Some(Layout::new::<u64>())
            );
        });
        let (pairing, allocations) = crate::test_allocations::allocations_during(|| {
            FalliblePairing::new::<()>(super::super::consensus::DST_SIG)
        });
        assert!(pairing.is_ok());
        assert_eq!(
            allocations, 1,
            "the linked geometry reserves its one backing"
        );
    }

    #[test]
    fn linked_geometry_check_is_allocation_free_and_admits_both_owners() {
        let checked = crate::test_allocations::without_allocations(check_pairing_geometry);
        assert_eq!(checked, Ok(()));
        assert!(StackPairing::new(super::super::consensus::DST_SIG).is_some());
        assert!(FalliblePairing::new::<()>(super::super::consensus::DST_SIG).is_ok());
        let refusal = UnsupportedPairingGeometry {
            context_bytes: StackPairing::BYTES + 8,
            stack_bytes: StackPairing::BYTES,
        };
        assert_eq!(
            refusal.to_string(),
            "the linked blst pairing context reports 4104 bytes; aggregate verification \
             supports 1..=4096 bytes"
        );
    }
}
