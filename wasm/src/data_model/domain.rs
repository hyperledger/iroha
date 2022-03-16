use iroha_data_model::prelude::*;
use parity_scale_codec::Encode;

use crate::host::iroha_fn;

#[repr(transparent)]
pub struct Domain {
    // Required for FFI-safe 0-sized type.
    ptr: [u8; 0],

    // Required for !Send & !Sync & !Unpin.
    //
    // - `*mut u8` is !Send & !Sync. It must be in `PhantomData` to not
    //   affect alignment.
    //
    // - `PhantomPinned` is !Unpin. It must be in `PhantomData` because
    //   its memory representation is not considered FFI-safe.
    marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

impl Identifiable for Domain {
    type Id = DomainId;
}

impl Domain {
    fn new(id: <Self as Identifiable>::Id) -> Self {
        let bytes = id.encode();

        Self {
            ptr: iroha_fn(0, bytes, bytes.len),
            marker: core::marker::PhantomData,
        }
    }
}

impl Drop for Domain {
    fn drop(&mut self) {
        iroha_fn(0, self.ptr, 0)
    }
}
