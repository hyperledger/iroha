#![allow(unsafe_code, clippy::restriction, clippy::pedantic)]

use std::mem::MaybeUninit;

use getset::{Getters, MutGetters, Setters};
use iroha_ffi::ffi_bindgen;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name(String);

#[ffi_bindgen]
#[derive(Setters, Getters, MutGetters)]
#[getset(get = "pub")]
pub struct FfiStruct {
    #[getset(set = "pub", get_mut = "pub")]
    id: u32,
    name: Option<Name>,
    is_null: Option<Name>,
}

#[test]
fn getset_get() {
    let init_name = Name("Name".to_owned());
    let ffi_struct: *mut _ = &mut FfiStruct {
        id: 1,
        name: Some(init_name.clone()),
        is_null: None,
    };

    let mut id = MaybeUninit::<*mut u32>::new(core::ptr::null_mut());
    let mut name = MaybeUninit::<*const Name>::new(core::ptr::null());
    let mut is_null = MaybeUninit::<*const Name>::new(core::ptr::null());

    unsafe {
        FfiStruct__id_mut(ffi_struct, id.as_mut_ptr());
        let id = &mut *id.assume_init();
        assert_eq!(&mut 1, id);

        FfiStruct__name(ffi_struct, name.as_mut_ptr());
        FfiStruct__is_null(ffi_struct, is_null.as_mut_ptr());

        let name_ptr = name.assume_init();
        let is_null_ptr = is_null.assume_init();

        let name = if !name_ptr.is_null() {
            Some(&*name_ptr)
        } else {
            None
        };
        let is_null = if !is_null_ptr.is_null() {
            Some(&*is_null_ptr)
        } else {
            None
        };

        assert_eq!(Some(&init_name), name);
        assert_eq!(None, is_null);
    }
}
