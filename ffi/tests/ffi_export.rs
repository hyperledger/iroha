#![allow(unsafe_code, clippy::restriction, clippy::pedantic)]

use std::{collections::BTreeMap, mem::MaybeUninit};

use iroha_ffi::{
    ffi_export, gen_ffi_impl, handles, slice::OutBoxedSlice, AsReprCRef, FfiResult, FfiTuple2,
    Handle, IntoFfi, TryFromFfi, TryFromReprC,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, IntoFfi, TryFromFfi)]
pub struct Name(String);
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, IntoFfi, TryFromFfi)]
pub struct Value(String);

fn get_default_params() -> [(Name, Value); 2] {
    [
        (Name(String::from("Nomen")), Value(String::from("Omen"))),
        (Name(String::from("Nomen2")), Value(String::from("Omen2"))),
    ]
}

#[ffi_export]
#[derive(Clone, IntoFfi, TryFromFfi)]
pub struct FfiStruct {
    name: Option<Name>,
    tokens: Vec<Value>,
    params: BTreeMap<Name, Value>,
}

handles! {0, FfiStruct}
gen_ffi_impl! {Drop: FfiStruct}

#[ffi_export]
impl FfiStruct {
    /// New
    pub fn new(name: Name) -> Self {
        Self {
            name: Some(name),
            tokens: Vec::new(),
            params: BTreeMap::default(),
        }
    }

    /// Consume self
    pub fn consume_self(self) {}

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

    /// Tokens
    pub fn tokens(&self) -> &[Value] {
        &self.tokens
    }

    /// Tokens mut
    pub fn name_mut(&mut self) -> Option<&mut Name> {
        self.name.as_mut()
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

fn get_new_struct() -> FfiStruct {
    let name = Name(String::from("X"));

    unsafe {
        let mut ffi_struct = MaybeUninit::new(core::ptr::null_mut());

        assert_eq!(
            FfiResult::Ok,
            FfiStruct__new(IntoFfi::into_ffi(name), ffi_struct.as_mut_ptr())
        );

        let ffi_struct = ffi_struct.assume_init();
        assert!(!ffi_struct.is_null());
        TryFromReprC::try_from_repr_c(ffi_struct, &mut ()).unwrap()
    }
}

#[allow(trivial_casts)]
fn get_new_struct_with_params() -> FfiStruct {
    let mut ffi_struct = get_new_struct();
    let params = get_default_params();

    let params_ffi = params.into_ffi();
    assert_eq!(FfiResult::Ok, unsafe {
        FfiStruct__with_params(IntoFfi::into_ffi(&mut ffi_struct), params_ffi.as_ref())
    });

    ffi_struct
}

#[test]
fn constructor() {
    let ffi_struct = get_new_struct();

    unsafe {
        assert_eq!(Some(Name(String::from('X'))), ffi_struct.name);
        assert!(ffi_struct.params.is_empty());

        assert_eq!(
            FfiResult::Ok,
            __drop(FfiStruct::ID, ffi_struct.into_ffi().cast())
        );
    }
}

#[test]
fn builder_method() {
    let ffi_struct = get_new_struct_with_params();

    unsafe {
        assert_eq!(2, ffi_struct.params.len());
        assert_eq!(
            ffi_struct.params,
            get_default_params().into_iter().collect()
        );

        assert_eq!(
            FfiResult::Ok,
            __drop(FfiStruct::ID, ffi_struct.into_ffi().cast())
        );
    }
}

#[test]
fn consume_self() {
    let ffi_struct = get_new_struct();

    unsafe {
        assert_eq!(
            FfiResult::Ok,
            FfiStruct__consume_self(ffi_struct.into_ffi().cast())
        );
    }
}

#[test]
#[allow(trivial_casts)]
fn into_iter_item_impl_into() {
    let tokens = vec![
        Value(String::from("My omen")),
        Value(String::from("Your omen")),
    ];

    let mut ffi_struct = get_new_struct();
    let tokens_ffi = tokens.clone().into_ffi();

    unsafe {
        assert_eq!(
            FfiResult::Ok,
            FfiStruct__with_tokens(IntoFfi::into_ffi(&mut ffi_struct), tokens_ffi.as_ref())
        );

        assert_eq!(2, ffi_struct.tokens.len());
        assert_eq!(ffi_struct.tokens, tokens);

        assert_eq!(
            FfiResult::Ok,
            __drop(FfiStruct::ID, ffi_struct.into_ffi().cast())
        );
    }
}

#[test]
fn return_option() {
    let ffi_struct = get_new_struct_with_params();

    let mut param1 = MaybeUninit::new(core::ptr::null());
    let mut param2 = MaybeUninit::new(core::ptr::null());

    let name1 = Name(String::from("Non"));
    assert_eq!(FfiResult::Ok, unsafe {
        FfiStruct__get_param(IntoFfi::into_ffi(&ffi_struct), &name1, param1.as_mut_ptr())
    });
    let param1 = unsafe { param1.assume_init() };
    assert!(param1.is_null());
    let mut store = ();
    let param1: Option<&Value> =
        unsafe { TryFromReprC::try_from_repr_c(param1, &mut store).unwrap() };
    assert!(param1.is_none());

    let name2 = Name(String::from("Nomen"));
    assert_eq!(FfiResult::Ok, unsafe {
        FfiStruct__get_param(IntoFfi::into_ffi(&ffi_struct), &name2, param2.as_mut_ptr())
    });

    unsafe {
        let param2 = param2.assume_init();
        assert!(!param2.is_null());
        let mut store = ();
        let param2: Option<&Value> = TryFromReprC::try_from_repr_c(param2, &mut store).unwrap();
        assert_eq!(Some(&Value(String::from("Omen"))), param2);
        assert_eq!(
            FfiResult::Ok,
            __drop(FfiStruct::ID, ffi_struct.into_ffi().cast())
        );
    }
}

#[test]
fn empty_return_iterator() {
    let ffi_struct = get_new_struct_with_params();
    let mut params_len = MaybeUninit::new(0);

    let out_params = OutBoxedSlice::from_uninit_slice(None, &mut params_len);

    unsafe {
        assert_eq!(
            FfiResult::Ok,
            FfiStruct__params(IntoFfi::into_ffi(&ffi_struct), out_params)
        );
        assert!(params_len.assume_init() == 2);
        assert_eq!(
            FfiResult::Ok,
            __drop(FfiStruct::ID, ffi_struct.into_ffi().cast())
        );
    }
}

#[test]
fn return_iterator() {
    let ffi_struct = get_new_struct_with_params();
    let mut params_len = MaybeUninit::new(0);
    let mut params = [MaybeUninit::new(FfiTuple2(
        core::ptr::null(),
        core::ptr::null(),
    ))];

    let out_params = OutBoxedSlice::from_uninit_slice(Some(params.as_mut_slice()), &mut params_len);

    unsafe {
        assert_eq!(
            FfiResult::Ok,
            FfiStruct__params(IntoFfi::into_ffi(&ffi_struct), out_params)
        );

        assert_eq!(params_len.assume_init(), 2);

        let mut store = Default::default();
        let item: (&Name, &Value) =
            <(_, _) as TryFromReprC>::try_from_repr_c(params[0].assume_init(), &mut store).unwrap();
        let expected = get_default_params();
        assert_eq!((&expected[0].0, &expected[0].1), item);

        assert_eq!(
            FfiResult::Ok,
            __drop(FfiStruct::ID, ffi_struct.into_ffi().cast())
        );
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
