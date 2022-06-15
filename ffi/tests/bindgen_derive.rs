#![allow(unsafe_code, clippy::restriction, clippy::pedantic)]

use std::mem::MaybeUninit;

use getset::{Getters, MutGetters, Setters};
use iroha_ffi::{ffi_export, FfiResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name(String);

#[ffi_export]
#[derive(Setters, Getters, MutGetters)]
#[getset(get = "pub")]
pub struct FfiStruct {
    #[getset(set = "pub", get_mut = "pub")]
    id: u32,
    name: Name,
}

#[test]
fn getset_get() {
    let init_name = Name("Name".to_owned());
    let ffi_struct: *mut _ = &mut FfiStruct {
        id: 1,
        name: init_name.clone(),
    };

    let mut id = MaybeUninit::<*mut u32>::new(core::ptr::null_mut());
    let mut name = MaybeUninit::<*const Name>::new(core::ptr::null());

    unsafe {
        assert_eq!(
            FfiResult::ArgIsNull,
            FfiStruct__id(ffi_struct, core::ptr::null_mut())
        );

        assert_eq!(
            FfiResult::Ok,
            FfiStruct__id_mut(ffi_struct, id.as_mut_ptr())
        );
        let id = &mut *id.assume_init();
        assert_eq!(&mut 1, id);

        assert_eq!(
            FfiResult::Ok,
            FfiStruct__name(ffi_struct, name.as_mut_ptr())
        );
        let name_ptr = name.assume_init();

        assert_eq!(init_name, *name_ptr);
    }
}
