#![allow(unsafe_code)]

use std::collections::BTreeMap;

use iroha_ffi::{decl_ffi_fns, ffi, ffi_import, ir::External};

iroha_ffi::handles! {OpaqueStruct, Value}

decl_ffi_fns! {Drop, Clone, Eq}

ffi! {
    /// Opaque value
    #[derive(Clone, PartialEq, Eq)]
    // NOTE: struct's body is replaced by ffi!
    pub struct Value;

    /// Opaque structure
    #[derive(Clone, PartialEq, Eq)]
    // NOTE: struct's body is replaced by ffi!
    pub struct OpaqueStruct;
}

#[ffi_import]
impl Value {
    /// New
    pub fn new(input: String) -> Self {
        unreachable!("replaced by ffi_import")
    }
}

#[ffi_import]
impl OpaqueStruct {
    /// New
    pub fn new(name: u8) -> Self {
        unreachable!("replaced by ffi_import")
    }

    /// With params
    #[must_use]
    pub fn with_params(self, params: impl IntoIterator<Item = (u8, Value)>) -> OpaqueStruct {
        unreachable!("replaced by ffi_import")
    }

    /// Get param
    pub fn get_param(&self, name: &u8) -> Option<&Value> {
        unreachable!("replaced by ffi_import")
    }

    /// Params
    pub fn params(&self) -> impl ExactSizeIterator<Item = &Value> {
        unreachable!("replaced by ffi_import")
    }

    /// Fallible int output
    pub fn fallible_int_output(flag: bool) -> Result<u8, &'static str> {
        unreachable!("replaced by ffi_import")
    }
}

#[ffi_import]
pub fn freestanding_returns_opaque_item(input: &OpaqueStruct) -> &OpaqueStruct {
    unreachable!("replaced by ffi_import")
}

#[ffi_import]
pub fn some_fn(input: &Vec<OpaqueStruct>) {
    unreachable!("replaced by ffi_import")
}

fn make_new_opaque(name: u8, params: BTreeMap<u8, Value>) -> OpaqueStruct {
    let opaque = OpaqueStruct::new(name);
    opaque.with_params(params.into_iter().collect())
}

fn make_opaque_ref(opaque_struct: &OpaqueStruct) -> RefOpaqueStruct {
    RefOpaqueStruct(opaque_struct.as_extern_ptr(), core::marker::PhantomData)
}

#[test]
#[webassembly_test::webassembly_test]
fn constructor() {
    let name = 42_u8;

    let opaque = OpaqueStruct::new(name);
    let mut expected_result = ffi::ExternOpaqueStruct {
        name: Some(name),
        tokens: vec![],
        params: BTreeMap::default(),
    };
    let opaque: &mut ffi::ExternOpaqueStruct = unsafe { core::mem::transmute(opaque) };
    assert_eq!(&mut expected_result, opaque);
}

#[test]
#[webassembly_test::webassembly_test]
fn return_option_ref() {
    let name = 42_u8;

    let value: Value = Value::new("Dummy param value".to_owned());
    let mut params = BTreeMap::default();
    params.insert(name, value.clone());

    let opaque = make_new_opaque(name, params);
    let ref_opaque = make_opaque_ref(&opaque);

    let param: Option<RefValue> = ref_opaque.get_param(&name);
    compare_opaque_eq::<_, ffi::ExternValue>(&value, &param.expect("Defined"));
}

#[test]
#[webassembly_test::webassembly_test]
fn take_and_return_opaque_ref() {
    let name = 42u8;
    let value: Value = Value::new("Dummy param value".to_owned());
    let mut params = BTreeMap::default();
    params.insert(name, value);

    let opaque: OpaqueStruct = make_new_opaque(name, params);
    let ref_opaque: RefOpaqueStruct = make_opaque_ref(&opaque);

    let opaque_ref: RefOpaqueStruct = freestanding_returns_opaque_item(ref_opaque);
    compare_opaque_eq::<_, ffi::ExternOpaqueStruct>(&opaque, &opaque_ref);
}

#[test]
#[webassembly_test::webassembly_test]
fn fallible_output() {
    assert_eq!(Ok(42), OpaqueStruct::fallible_int_output(true));
    // TODO:
    //assert!(OpaqueStruct::fallible_int_output(false).is_err());
}

#[allow(trivial_casts)]
fn compare_opaque_eq<T, U: PartialEq + core::fmt::Debug>(opaque1: &T, opaque2: &T) {
    unsafe {
        let opaque1: &*const U = &*(core::ptr::from_ref(opaque1)).cast::<*const U>();
        let opaque2: &*const U = &*(core::ptr::from_ref(opaque2)).cast::<*const U>();

        assert_eq!(**opaque1, **opaque2)
    }
}

mod ffi {
    use std::{alloc, collections::BTreeMap};

    use iroha_ffi::{
        def_ffi_fns, slice::RefMutSlice, FfiConvert, FfiOutPtr, FfiOutPtrWrite, FfiReturn, FfiType,
    };

    iroha_ffi::handles! {ExternOpaqueStruct, ExternValue}

    def_ffi_fns! {
        Drop: { ExternValue, ExternOpaqueStruct },
        Clone: { ExternValue },
        Eq: { ExternValue, ExternOpaqueStruct },
    }

    iroha_ffi::def_ffi_fns! { dealloc }

    /// Structure that `Value` points to
    #[derive(Debug, Clone, PartialEq, Eq, FfiType)]
    #[ffi_type(opaque)]
    #[repr(C)]
    pub struct ExternValue(pub String);

    /// Structure that `OpaqueStruct` points to
    #[derive(Debug, PartialEq, Eq, FfiType)]
    #[ffi_type(opaque)]
    #[repr(C)]
    pub struct ExternOpaqueStruct {
        pub name: Option<u8>,
        pub tokens: Vec<ExternValue>,
        pub params: BTreeMap<u8, ExternValue>,
    }

    #[no_mangle]
    unsafe extern "C" fn Value__new(
        input: RefMutSlice<u8>,
        output: *mut *mut ExternValue,
    ) -> FfiReturn {
        let string = String::from_utf8(input.into_rust().expect("Defined").to_vec());
        let opaque = Box::new(ExternValue(string.expect("Valid UTF8 string")));
        output.write(Box::into_raw(opaque));
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn OpaqueStruct__new(
        name: <u8 as iroha_ffi::FfiType>::ReprC,
        output: *mut *mut ExternOpaqueStruct,
    ) -> FfiReturn {
        let opaque = Box::new(ExternOpaqueStruct {
            name: Some(FfiConvert::try_from_ffi(name, &mut ()).expect("Valid num")),
            tokens: vec![],
            params: BTreeMap::default(),
        });
        output.write(Box::into_raw(opaque));
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn OpaqueStruct__with_params(
        handle: *mut ExternOpaqueStruct,
        params: <Vec<(u8, ExternValue)> as iroha_ffi::FfiType>::ReprC,
        output: *mut *mut ExternOpaqueStruct,
    ) -> iroha_ffi::FfiReturn {
        let mut handle = *Box::from_raw(handle);
        let mut store = Box::default();
        let params: Vec<(u8, ExternValue)> =
            FfiConvert::try_from_ffi(params, &mut store).expect("Valid");
        handle.params = params.into_iter().collect();
        output.write(Box::into_raw(Box::new(handle)));
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn OpaqueStruct__get_param(
        handle: *const ExternOpaqueStruct,
        param_name: <&u8 as FfiType>::ReprC,
        output: *mut *const ExternValue,
    ) -> FfiReturn {
        let handle = handle.as_ref().expect("Valid");
        let param_name = param_name.as_ref().expect("Valid");
        let value = handle.params.get(param_name);
        FfiOutPtrWrite::write_out(value, output);
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn OpaqueStruct__params(
        handle: *const ExternOpaqueStruct,
        output: *mut <Vec<&ExternValue> as FfiOutPtr>::OutPtr,
    ) -> FfiReturn {
        let handle = handle.as_ref().expect("Valid");
        let params: Vec<_> = handle.params.values().collect();
        FfiOutPtrWrite::write_out(params, output);
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn OpaqueStruct__remove_param(
        handle: *mut ExternOpaqueStruct,
        param_name: <&u8 as FfiType>::ReprC,
        output: *mut *mut ExternValue,
    ) -> FfiReturn {
        let handle = handle.as_mut().expect("Valid");
        let param_name = param_name.as_ref().expect("Valid");
        output.write(handle.params.remove(param_name).into_ffi(&mut ()));
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn OpaqueStruct__fallible_int_output(
        input: <bool as FfiType>::ReprC,
        output: *mut <u8 as FfiOutPtr>::OutPtr,
    ) -> FfiReturn {
        if input == 0 {
            return FfiReturn::ExecutionFail;
        }

        output.write(42);
        FfiReturn::Ok
    }

    #[no_mangle]
    unsafe extern "C" fn __freestanding_returns_opaque_item(
        input: *const ExternOpaqueStruct,
        output: *mut *const ExternOpaqueStruct,
    ) -> FfiReturn {
        output.write(input);
        FfiReturn::Ok
    }
}
