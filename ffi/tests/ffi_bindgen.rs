use std::{collections::BTreeMap, mem::MaybeUninit};

use iroha_ffi::{ffi_bindgen, FfiResult, Pair};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name(&'static str);
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Value(&'static str);

const DEFAULT_PARAMS: [(Name, Value); 1] = [(Name("Nomen"), Value("Omen"))];

#[ffi_bindgen]
pub struct FfiStruct {
    name: Name,
    params: BTreeMap<Name, Value>,
}

#[ffi_bindgen]
impl FfiStruct {
    pub fn new(name: Name) -> Self {
        Self {
            name,
            params: BTreeMap::default(),
        }
    }
    pub fn with_params(mut self, params: impl IntoIterator<Item = (Name, Value)>) -> Self {
        self.params = params.into_iter().collect();
        self
    }
    pub fn get_param(&self, name: &Name) -> Option<&Value> {
        self.params.get(name)
    }
    pub fn params(&self) -> impl ExactSizeIterator<Item = (&Name, &Value)> {
        self.params.iter()
    }
}

fn get_new_struct() -> *mut FfiStruct {
    let mut ffi_struct = MaybeUninit::new(core::ptr::null_mut());

    let name = Name("X");
    assert_eq!(FfiResult::Ok, unsafe {
        ffi_struct_new(&name, ffi_struct.as_mut_ptr())
    },);

    unsafe {
        let ffi_struct = ffi_struct.assume_init();
        assert!(!ffi_struct.is_null());
        ffi_struct
    }
}

fn get_new_struct_with_params() -> *mut FfiStruct {
    let ffi_struct = get_new_struct();
    let params_ffi: Vec<_> = DEFAULT_PARAMS
        .iter()
        .map(|(key, val)| Pair(key as *const _, val as *const _))
        .collect();
    assert_eq!(FfiResult::Ok, unsafe {
        ffi_struct_with_params(ffi_struct, params_ffi.as_ptr(), params_ffi.len())
    });

    ffi_struct
}

#[test]
fn constructor() {
    let ffi_struct = get_new_struct();

    unsafe {
        assert_eq!(Name("X"), (&*ffi_struct).name);
        assert!((&*ffi_struct).params.is_empty());
    }
}

#[test]
fn builder_method() {
    let ffi_struct = get_new_struct_with_params();

    unsafe {
        assert_eq!(1, (&*ffi_struct).params.len());
        assert_eq!((&*ffi_struct).params, DEFAULT_PARAMS.into_iter().collect());
    }
}

#[test]
fn return_option() {
    let ffi_struct = get_new_struct_with_params();

    let mut param1 = MaybeUninit::new(core::ptr::null());
    let mut param2 = MaybeUninit::new(core::ptr::null());

    let name1 = Name("Non");
    assert_eq!(FfiResult::Ok, unsafe {
        ffi_struct_get_param(ffi_struct, &name1, param1.as_mut_ptr())
    });
    unsafe { assert!(param1.assume_init().is_null()) };

    let name2 = Name("Nomen");
    assert_eq!(FfiResult::Ok, unsafe {
        ffi_struct_get_param(ffi_struct, &name2, param2.as_mut_ptr())
    });

    unsafe {
        assert!(!param2.assume_init().is_null());
        assert_eq!(&Value("Omen"), &*param2.assume_init());
    }
}

#[test]
fn return_iterator() {
    let ffi_struct = get_new_struct_with_params();

    let mut params = MaybeUninit::new(core::ptr::null_mut());
    let mut params_len = MaybeUninit::new(0);

    assert_eq!(FfiResult::Ok, unsafe {
        ffi_struct_params(ffi_struct, params.as_mut_ptr(), params_len.as_mut_ptr())
    });

    unsafe {
        let (params, params_len) = (params.assume_init(), params_len.assume_init());

        assert!(params_len == 1);
        assert!(!params.is_null());

        assert!(core::slice::from_raw_parts_mut(params, params_len)
            .iter()
            .map(|&Pair(key, val)| (&*key, &*val))
            .eq(DEFAULT_PARAMS.iter().map(|pair| (&pair.0, &pair.1))));

        // TODO: Call FFI destructor for the received params vector
    }
}

#[test]
fn drop_ffi_struct() {
    let ffi_struct = get_new_struct_with_params();

    unsafe {
        assert_eq!(FfiResult::Ok, ffi_struct_drop(ffi_struct));
    }
}
