#![allow(unsafe_code, clippy::restriction, clippy::pedantic)]

use std::mem::MaybeUninit;

use iroha_ffi::{ffi_export, FfiConvert, FfiReturn, FfiType};

#[derive(Debug, Clone, Copy, PartialEq, Eq, FfiType)]
#[repr(u8)]
pub enum Ambiguous {
    Inherent,
    AmbiguousX,
    AmbiguousY,
    None,
}

/// FfiStruct
#[derive(Clone, Copy, FfiType)]
pub struct FfiStruct;

#[ffi_export]
impl FfiStruct {
    /// Ambiguous method
    pub fn ambiguous() -> Ambiguous {
        Ambiguous::Inherent
    }
}

pub trait AmbiguousX {
    fn ambiguous() -> Ambiguous;
}

pub trait AmbiguousY {
    fn ambiguous() -> Ambiguous;
}

#[ffi_export]
impl AmbiguousX for FfiStruct {
    fn ambiguous() -> Ambiguous {
        Ambiguous::AmbiguousX
    }
}

#[ffi_export]
impl AmbiguousY for FfiStruct {
    fn ambiguous() -> Ambiguous {
        Ambiguous::AmbiguousY
    }
}

#[test]
fn unambiguous_method_call() {
    let mut output = MaybeUninit::new(Ambiguous::None as _);

    unsafe {
        assert_eq!(FfiReturn::Ok, FfiStruct__ambiguous(output.as_mut_ptr()));
        let inherent = Ambiguous::try_from_ffi(output.assume_init(), &mut ()).unwrap();
        assert_eq!(Ambiguous::Inherent, inherent);

        assert_eq!(
            FfiReturn::Ok,
            FfiStruct__AmbiguousX__ambiguous(output.as_mut_ptr())
        );
        let ambiguous_x = Ambiguous::try_from_ffi(output.assume_init(), &mut ()).unwrap();
        assert_eq!(Ambiguous::AmbiguousX, ambiguous_x);

        assert_eq!(
            FfiReturn::Ok,
            FfiStruct__AmbiguousY__ambiguous(output.as_mut_ptr())
        );
        let ambiguous_y = Ambiguous::try_from_ffi(output.assume_init(), &mut ()).unwrap();
        assert_eq!(Ambiguous::AmbiguousY, ambiguous_y);
    }
}
