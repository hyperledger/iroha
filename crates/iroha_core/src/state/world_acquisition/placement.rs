//! Exact placement into the original admitted World backing, with joint cleanup.

use super::OriginalWorldFields;
use crate::state::WorldBlockFields;
use mv::BlockRetirement;

pub(in crate::state) trait ReleaseWorldAcquisition {
    fn release_all(&mut self);
}

/// A borrowed guard, never another heap shell or publication owner.
/// On any refusal/unwind it releases both sides of the field-transfer frontier
/// before either side can drop payloads, original charges or release notices.
pub(in crate::state) struct WorldPlacement<'a, 'world, P: ReleaseWorldAcquisition> {
    fields: &'a mut OriginalWorldFields<'world>,
    pending: &'a mut P,
    complete: bool,
}
impl<'a, 'world, P: ReleaseWorldAcquisition> WorldPlacement<'a, 'world, P> {
    pub(in crate::state) fn new(
        fields: &'a mut OriginalWorldFields<'world>,
        pending: &'a mut P,
    ) -> Self {
        assert!(
            fields.values.as_slice().is_empty() && fields.initialized == 0,
            "original World placement is one-shot"
        );
        Self {
            fields,
            pending,
            complete: false,
        }
    }
    pub(in crate::state) fn parts(&mut self) -> (&mut OriginalWorldFields<'world>, &mut P) {
        (self.fields, self.pending)
    }
    pub(in crate::state) fn finish(mut self) {
        self.fields.finish_initialization();
        self.complete = true;
    }
}
impl<P: ReleaseWorldAcquisition> Drop for WorldPlacement<'_, '_, P> {
    fn drop(&mut self) {
        if !self.complete {
            self.pending.release_all();
            self.fields.release_initialized();
        }
    }
}

impl<'world> OriginalWorldFields<'world> {
    /// Transfer one exact original field directly to its prepaid heap projection.
    /// Keeping the conversion in this borrowed call avoids a full census of
    /// per-field by-value temporaries in the enclosing World stack frame.
    ///
    /// # Safety
    /// `target` must satisfy `write_next`'s exact same-allocation field/frontier
    /// contract. The enclosing WorldPlacement retains this source and all sibling
    /// acquisitions until the initialized marker has been recorded.
    #[allow(unsafe_code)]
    #[inline(never)]
    pub(in crate::state) unsafe fn take_next<A>(
        &mut self,
        target: *mut <A::Block as super::super::IntoWorldField>::Field,
        source: &mut A,
    ) where
        A: super::super::WorldFieldAcquisition,
        A::Block: super::super::IntoWorldField,
    {
        use super::super::IntoWorldField as _;
        // Original take_block validates before extraction; conversion is an
        // inert move, without callbacks, allocation or payload destruction.
        let field = source.take_block().into_world_field();
        // SAFETY: the caller retains the same placement guard and passes only
        // the next distinct field in the exhaustive original heap inventory.
        unsafe { self.write_next(target, field) };
    }

    pub(in crate::state) fn uninitialized_pointer(&mut self) -> *mut WorldBlockFields<'world> {
        assert!(
            self.values.as_slice().is_empty(),
            "original World is already initialized"
        );
        self.values
            .spare_capacity_mut()
            .first_mut()
            .expect("original one-slot backing")
            .as_mut_ptr()
    }

    /// Write exactly the next field from the exhaustive placement census.
    ///
    /// # Safety
    /// `target` must be that next field's aligned projection into this owner's
    /// original backing. It must not overlap a previously initialized field.
    /// No reference to the incomplete whole World may be created. Caller must
    /// retain WorldPlacement until every field and its initialized marker is set.
    #[allow(unsafe_code)]
    #[inline(never)]
    pub(in crate::state) unsafe fn write_next<T>(&mut self, target: *mut T, value: T) {
        // SAFETY: exact private caller projection and order are required above;
        // pointer write cannot run a destructor, callback or allocate.
        unsafe { target.write(value) };
        self.initialized += 1;
        #[cfg(test)]
        after_field_placement(self.initialized);
    }
}

macro_rules! original_placement_inventory {
    (; [$($prefix:ident,)*] [$($privacy:ident,)*] [$($suffix:ident,)*]) => {
        impl OriginalWorldFields<'_> {
            fn finish_initialization(&mut self) {
                const FIELD_COUNT: usize = 2 $(+ { let _ = stringify!($prefix); 1 })* $(+ { let _ = stringify!($privacy); 1 })* $(+ { let _ = stringify!($suffix); 1 })*;
                assert_eq!(self.initialized, FIELD_COUNT, "complete original World placement");
                // SAFETY: the exact exhaustive inventory initialized all fields
                // once in this same one-slot backing. No whole-value move occurs.
                #[allow(unsafe_code)]
                unsafe { self.values.set_initialized_len(1) };
                self.initialized = 0;
            }

            fn release_initialized(&mut self) {
                if self.initialized == 0 { return; }
                let target = self.uninitialized_pointer();
                let mut index = 1; // dataspace_catalog owns no physical writer
                // SAFETY: only a fully written field at or before the recorded
                // frontier is borrowed. No reference to the partial World exists.
                #[allow(unsafe_code)]
                unsafe {
                    $(index += 1; if self.initialized >= index { (&mut *std::ptr::addr_of_mut!((*target).$prefix)).release_writers(); })*
                    $(index += 1; if self.initialized >= index { (&mut *std::ptr::addr_of_mut!((*target).$privacy)).release_writers(); })*
                    $(index += 1; if self.initialized >= index { (&mut *std::ptr::addr_of_mut!((*target).$suffix)).release_writers(); })*
                }
                let _ = index;
            }

            fn drop_initialized(&mut self) {
                if self.initialized == 0 { return; }
                let target = self.uninitialized_pointer();
                let initialized = std::mem::take(&mut self.initialized);
                let mut index = 0;
                // SAFETY: each projection is a distinct initialized field. All
                // writers were already released jointly by WorldPlacement. The
                // prefix is disarmed first, so destructor unwind never retries a
                // partially dropped field. Remaining nested owners conservatively
                // leak on destructor panic; none is read as an initialized World.
                #[allow(unsafe_code)]
                unsafe {
                    index += 1; if initialized >= index { std::ptr::drop_in_place(std::ptr::addr_of_mut!((*target).dataspace_catalog)); }
                    $(index += 1; if initialized >= index { std::ptr::drop_in_place(std::ptr::addr_of_mut!((*target).$prefix)); })*
                    $(index += 1; if initialized >= index { std::ptr::drop_in_place(std::ptr::addr_of_mut!((*target).$privacy)); })*
                    $(index += 1; if initialized >= index { std::ptr::drop_in_place(std::ptr::addr_of_mut!((*target).$suffix)); })*
                    index += 1; if initialized >= index { std::ptr::drop_in_place(std::ptr::addr_of_mut!((*target).external_event_buf)); }
                }
                let _ = index;
            }
        }

        // Compile-time exhaustive census check: a new field cannot silently be
        // omitted from placement/drop even if Rust changes physical field order.
        #[expect(dead_code, reason = "type-checked exhaustive placement census")]
        fn exhaustive_fields(fields: &WorldBlockFields<'_>) {
            let WorldBlockFields { dataspace_catalog: _, $($prefix: _,)* $($privacy: _,)* $($suffix: _,)* external_event_buf: _ } = fields;
        }
    };
}
with_world_overlay_fields!(original_placement_inventory);

impl Drop for OriginalWorldFields<'_> {
    fn drop(&mut self) {
        self.release_initialized();
        self.drop_initialized();
        // The same original backing now frees before its charge, at Vec length 0
        // for incomplete/emptied shells and length 1 for a complete original World.
    }
}

#[cfg(test)]
std::thread_local! {
    static FAIL_AFTER_FIELD: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn after_field_placement(initialized: usize) {
    if FAIL_AFTER_FIELD.with(|value| value.get()) == Some(initialized) {
        panic!("injected original field placement failure");
    }
}
#[cfg(test)]
pub(in crate::state) fn with_placement_failure<R>(field: usize, action: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAIL_AFTER_FIELD.with(|value| value.set(None));
        }
    }
    assert!(
        FAIL_AFTER_FIELD
            .with(|value| value.replace(Some(field)))
            .is_none()
    );
    let _reset = Reset;
    action()
}
