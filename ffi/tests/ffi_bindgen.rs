#![allow(unsafe_code, clippy::restriction, clippy::pedantic)]

use std::{collections::BTreeMap, mem::MaybeUninit};

use iroha_ffi::{ffi_bindgen, gen_ffi_impl, handles, FfiResult, Pair};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name(String);
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Value(String);

fn get_default_params() -> [(Name, Value); 2] {
    [
        (Name(String::from("Nomen")), Value(String::from("Omen"))),
        (Name(String::from("Nomen2")), Value(String::from("Omen2"))),
    ]
}

#[ffi_bindgen]
#[derive(Clone)]
pub struct FfiStruct {
    name: Option<Name>,
    tokens: Vec<Value>,
    params: BTreeMap<Name, Value>,
}

handles! {0, FfiStruct}
gen_ffi_impl! {Drop: FfiStruct}

#[ffi_bindgen]
impl FfiStruct {
    /// New
    pub fn new(name: impl Into<Name>) -> Self {
        Self {
            name: Some(name.into()),
            tokens: Vec::new(),
            params: BTreeMap::default(),
        }
    }

    /// With tokens
    #[must_use]
    pub fn with_tokens(mut self, tokens: impl IntoIterator<Item = impl Into<Value>>) -> Self {
        self.tokens = tokens.into_iter().map(Into::into).collect();
        self
    }

    /// With params
    #[must_use]
    pub fn with_params(mut self, params: impl IntoIterator<Item = (Name, Value)>) -> Self {
        self.params = params.into_iter().collect();
        self
    }

    /// Get param
    pub fn get_param(&self, name: &Name) -> Option<&Value> {
        self.params.get(name)
    }

    /// Params
    pub fn params(&self) -> impl ExactSizeIterator<Item = (&Name, &Value)> {
        self.params.iter()
    }

    /// Fallible int output
    pub fn fallible_int_output(flag: bool) -> Result<u32, &'static str> {
        if flag {
            Ok(42)
        } else {
            Err("fail")
        }
    }
}

fn get_new_struct() -> *mut FfiStruct {
    let name = Name(String::from("X"));

    unsafe {
        let mut ffi_struct = MaybeUninit::new(core::ptr::null_mut());

        assert_eq!(
            FfiResult::Ok,
            FfiStruct__new(&name, ffi_struct.as_mut_ptr())
        );

        let ffi_struct = ffi_struct.assume_init();
        assert!(!ffi_struct.is_null());
        ffi_struct
    }
}

#[allow(trivial_casts)]
fn get_new_struct_with_params() -> *mut FfiStruct {
    let ffi_struct = get_new_struct();
    let params = get_default_params();

    let params_ffi: Vec<_> = params
        .iter()
        .map(|(key, val)| Pair(key as *const _, val as *const _))
        .collect();
    assert_eq!(FfiResult::Ok, unsafe {
        FfiStruct__with_params(ffi_struct, params_ffi.as_ptr(), params_ffi.len())
    });

    ffi_struct
}

#[test]
fn constructor() {
    let ffi_struct = get_new_struct();

    unsafe {
        assert_eq!(Some(Name(String::from('X'))), (*ffi_struct).name);
        assert!((*ffi_struct).params.is_empty());

        assert_eq!(FfiResult::Ok, __drop(FfiStruct::ID, ffi_struct.cast()));
    }
}

#[test]
#[allow(trivial_casts)]
fn into_iter_item_impl_into() {
    let ffi_struct = get_new_struct();

    let tokens = vec![
        Value(String::from("My omen")),
        Value(String::from("Your omen")),
    ];
    let tokens_ffi: Vec<_> = tokens.iter().map(|t| t as *const _).collect();

    unsafe {
        assert_eq!(
            FfiResult::Ok,
            FfiStruct__with_tokens(ffi_struct, tokens_ffi.as_ptr(), tokens_ffi.len())
        );

        assert_eq!(2, (*ffi_struct).tokens.len());
        assert_eq!((*ffi_struct).tokens, tokens);

        assert_eq!(FfiResult::Ok, __drop(FfiStruct::ID, ffi_struct.cast()));
    }
}

#[test]
fn builder_method() {
    let ffi_struct = get_new_struct_with_params();

    unsafe {
        assert_eq!(2, (*ffi_struct).params.len());
        assert_eq!(
            (*ffi_struct).params,
            get_default_params().into_iter().collect()
        );

        assert_eq!(FfiResult::Ok, __drop(FfiStruct::ID, ffi_struct.cast()));
    }
}

#[test]
fn return_option() {
    let ffi_struct = get_new_struct_with_params();

    let mut param1 = MaybeUninit::new(core::ptr::null());
    let mut param2 = MaybeUninit::new(core::ptr::null());

    let name1 = Name(String::from("Non"));
    assert_eq!(FfiResult::Ok, unsafe {
        FfiStruct__get_param(ffi_struct, &name1, param1.as_mut_ptr())
    });
    unsafe { assert!(param1.assume_init().is_null()) };

    let name2 = Name(String::from("Nomen"));
    assert_eq!(FfiResult::Ok, unsafe {
        FfiStruct__get_param(ffi_struct, &name2, param2.as_mut_ptr())
    });

    unsafe {
        assert!(!param2.assume_init().is_null());
        assert_eq!(&Value(String::from("Omen")), &*param2.assume_init());
        assert_eq!(FfiResult::Ok, __drop(FfiStruct::ID, ffi_struct.cast()));
    }
}

#[test]
fn empty_return_iterator() {
    let ffi_struct = get_new_struct_with_params();
    let mut params_len = MaybeUninit::new(0);

    unsafe {
        assert_eq!(
            FfiResult::Ok,
            FfiStruct__params(
                ffi_struct,
                core::ptr::null_mut(),
                0_usize,
                params_len.as_mut_ptr(),
            )
        );
        assert!(params_len.assume_init() == 2);
        assert_eq!(FfiResult::Ok, __drop(FfiStruct::ID, ffi_struct.cast()));
    }
}

#[test]
fn return_iterator() {
    let ffi_struct = get_new_struct_with_params();
    let mut params_len = MaybeUninit::new(0);
    let mut params = Vec::with_capacity(1);

    unsafe {
        assert_eq!(
            FfiResult::Ok,
            FfiStruct__params(
                ffi_struct,
                params.as_mut_ptr(),
                params.capacity(),
                params_len.as_mut_ptr(),
            )
        );

        assert!(params_len.assume_init() == 2);
        params.set_len(1);

        assert!(params
            .iter()
            .map(|&Pair(key, val)| (&*key, &*val))
            .eq(get_default_params()
                .iter()
                .take(1)
                .map(|pair| (&pair.0, &pair.1))));

        assert_eq!(FfiResult::Ok, __drop(FfiStruct::ID, ffi_struct.cast()));
    }
}

#[test]
fn return_result() {
    let mut output = MaybeUninit::new(0);

    unsafe {
        assert_eq!(
            FfiResult::ExecutionFail,
            FfiStruct__fallible_int_output(u8::from(false), output.as_mut_ptr())
        );
        assert_eq!(0, output.assume_init());
        assert_eq!(
            FfiResult::Ok,
            FfiStruct__fallible_int_output(u8::from(true), output.as_mut_ptr())
        );
        assert_eq!(42, output.assume_init());
    }
}
