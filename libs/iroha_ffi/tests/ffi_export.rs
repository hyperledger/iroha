#![allow(unsafe_code, clippy::pedantic)]

use std::{alloc, collections::BTreeMap, mem::MaybeUninit};

use iroha_ffi::{
    ffi_export, slice::OutBoxedSlice, FfiConvert, FfiOutPtrRead, FfiReturn, FfiTuple1, FfiTuple2,
    FfiType, LocalRef,
};

iroha_ffi::handles! {OpaqueStruct}
iroha_ffi::def_ffi_fns! { dealloc }

pub trait Target {
    type Target;

    fn target(self) -> Self::Target;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, FfiType)]
pub struct Name(String);
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, FfiType)]
pub struct Value(String);

/// Opaque structure
#[derive(Debug, Clone, PartialEq, Eq, Default, FfiType)]
pub struct OpaqueStruct {
    name: Option<Name>,
    tokens: Vec<Value>,
    params: BTreeMap<Name, Value>,
}

/// Fieldless enum
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FfiType)]
pub enum FieldlessEnum {
    A,
    B,
    C,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FfiType)]
#[repr(transparent)]
pub enum TransparentFieldlessEnum {
    A,
}

/// Data-carrying enum
#[derive(Debug, Clone, PartialEq, Eq, FfiType)]
#[allow(variant_size_differences)]
pub enum DataCarryingEnum {
    A(OpaqueStruct),
    B(u32),
    // TODO: Support this
    //C(T),
    D,
}

/// `ReprC` struct
#[derive(Clone, Copy, PartialEq, Eq, FfiType)]
#[repr(C)]
pub struct RobustReprCStruct<T, U> {
    a: u8,
    b: T,
    c: U,
    d: core::mem::ManuallyDrop<i16>,
}

#[ffi_export]
impl OpaqueStruct {
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
    // Note: `-> OpaqueStruct` used instead of `-> Self` to showcase that such signature supported by `#[ffi_export]`
    pub fn with_params(mut self, params: impl IntoIterator<Item = (Name, Value)>) -> OpaqueStruct {
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

    /// Remove parameter
    pub fn remove_param(&mut self, param: &Name) -> Option<Value> {
        self.params.remove(param)
    }

    /// Fallible int output
    pub fn fallible_int_output(flag: bool) -> Result<u32, &'static str> {
        if flag {
            Ok(42)
        } else {
            Err("fail")
        }
    }

    /// Fallible empty tuple output
    pub fn fallible_empty_tuple_output(flag: bool) -> Result<(), &'static str> {
        if flag {
            Ok(())
        } else {
            Err("fail")
        }
    }
}

#[ffi_export]
/// Take and return boxed slice
pub fn freestanding_with_boxed_slice(item: Box<[u8]>) -> Box<[u8]> {
    item
}

#[ffi_export]
/// Take and return byte
pub fn freestanding_with_option(item: Option<u8>) -> Option<u8> {
    item
}

#[ffi_export]
/// Take and return byte
pub fn freestanding_with_option_with_niche_ref(item: &Option<bool>) -> &Option<bool> {
    item
}

#[ffi_export]
/// Take and return byte
pub fn freestanding_with_option_without_niche_ref(item: &Option<u8>) -> &Option<u8> {
    item
}

#[ffi_export]
/// Take and return byte
pub fn freestanding_with_primitive(byte: u8) -> u8 {
    byte
}

/// Take and return fieldless enum
#[ffi_export]
pub fn freestanding_with_fieldless_enum(enum_: FieldlessEnum) -> FieldlessEnum {
    enum_
}

/// Return data-carrying enum
#[ffi_export]
pub fn freestanding_with_data_carrying_enum(enum_: DataCarryingEnum) -> DataCarryingEnum {
    enum_
}

/// Return array as pointer
#[ffi_export]
pub fn freestanding_with_array(arr: [u8; 1]) -> [u8; 1] {
    arr
}

/// Take and return array reference
#[ffi_export]
pub fn freestanding_with_array_ref(arr: &[u8; 1]) -> &[u8; 1] {
    arr
}

/// Return array wrapped in a tuple
#[ffi_export]
pub fn freestanding_with_array_in_struct(arr: ([u8; 1],)) -> ([u8; 1],) {
    arr
}

/// Return a `#[repr(C)]` union
#[ffi_export]
pub fn freestanding_with_repr_c_struct(
    struct_: RobustReprCStruct<u32, i16>,
) -> RobustReprCStruct<u32, i16> {
    struct_
}

/// Return array wrapped in a tuple
#[ffi_export]
#[allow(clippy::vec_box)]
pub fn get_vec_of_boxed_opaques() -> Vec<Box<OpaqueStruct>> {
    vec![Box::new(get_new_struct())]
}

/// Take and return array
#[ffi_export]
pub fn take_and_return_array_of_opaques(a: [OpaqueStruct; 2]) -> [OpaqueStruct; 2] {
    a
}

/// Receive nested vector
#[ffi_export]
pub fn freestanding_with_nested_vec(_vec: Vec<Vec<Vec<u8>>>) {}

/// Take `&mut String`
#[ffi_export]
#[cfg(feature = "non_robust_ref_mut")]
pub fn take_non_robust_ref_mut(val: &mut str) -> &mut str {
    val
}

#[ffi_export]
pub fn take_vec_ref(a: &Vec<u8>) {
    assert_eq!(a, &vec![1, 2])
}

#[ffi_export]
pub fn take_tuple_ref(a: &(u8, u8)) -> &(u8, u8) {
    a
}

#[ffi_export]
impl Target for OpaqueStruct {
    type Target = Option<Name>;

    fn target(self) -> <Self as Target>::Target {
        self.name
    }
}

#[ffi_export]
pub fn reference_from_slice(a: &[u8]) -> &u8 {
    &a[0]
}

fn get_default_params() -> [(Name, Value); 2] {
    [
        (Name(String::from("Nomen")), Value(String::from("Omen"))),
        (Name(String::from("Nomen2")), Value(String::from("Omen2"))),
    ]
}

fn get_new_struct() -> OpaqueStruct {
    let name = Name(String::from("X"));

    unsafe {
        let mut ffi_struct = MaybeUninit::new(core::ptr::null_mut());

        assert_eq!(
            FfiReturn::Ok,
            OpaqueStruct__new(FfiConvert::into_ffi(name, &mut ()), ffi_struct.as_mut_ptr())
        );

        let ffi_struct = ffi_struct.assume_init();
        FfiConvert::try_from_ffi(ffi_struct, &mut ()).unwrap()
    }
}

fn get_new_struct_with_params() -> OpaqueStruct {
    let ffi_struct = get_new_struct();
    let params = get_default_params().to_vec();

    let mut output = MaybeUninit::new(core::ptr::null_mut());

    let mut store = Default::default();
    let params_ffi = params.into_ffi(&mut store);
    assert_eq!(FfiReturn::Ok, unsafe {
        OpaqueStruct__with_params(
            FfiConvert::into_ffi(ffi_struct, &mut ()),
            params_ffi,
            output.as_mut_ptr(),
        )
    });

    unsafe { FfiConvert::try_from_ffi(output.assume_init(), &mut ()).expect("valid") }
}

#[test]
#[webassembly_test::webassembly_test]
#[cfg(feature = "non_robust_ref_mut")]
fn non_robust_ref_mut() {
    use iroha_ffi::slice::RefMutSlice;

    let mut owned = "queen".to_owned();
    let ffi_struct: &mut str = owned.as_mut();
    let mut output = MaybeUninit::new(RefMutSlice::from_raw_parts_mut(core::ptr::null_mut(), 0));
    let ffi_type: RefMutSlice<u8> = FfiConvert::into_ffi(ffi_struct, &mut ());

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __take_non_robust_ref_mut(ffi_type, output.as_mut_ptr())
        );

        let output: &mut str = FfiOutPtrRead::try_read_out(output.assume_init()).unwrap();
        assert_eq!(output, owned.as_mut());
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn constructor() {
    let ffi_struct = get_new_struct();
    assert_eq!(Some(Name(String::from('X'))), ffi_struct.name);
    assert!(ffi_struct.params.is_empty());
}

#[test]
#[webassembly_test::webassembly_test]
fn builder_method() {
    let ffi_struct = get_new_struct_with_params();

    assert_eq!(2, ffi_struct.params.len());
    assert_eq!(
        ffi_struct.params,
        get_default_params().into_iter().collect()
    );
}

#[test]
#[webassembly_test::webassembly_test]
fn consume_self() {
    let ffi_struct = get_new_struct();

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            OpaqueStruct__consume_self(ffi_struct.into_ffi(&mut ()).cast())
        );
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn into_iter_item_impl_into() {
    let tokens = vec![
        Value(String::from("My omen")),
        Value(String::from("Your omen")),
    ];

    let mut ffi_struct = get_new_struct();
    let mut tokens_store = Box::default();
    let tokens_ffi = tokens.clone().into_ffi(&mut tokens_store);

    let mut output = MaybeUninit::new(core::ptr::null_mut());

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            OpaqueStruct__with_tokens(
                FfiConvert::into_ffi(ffi_struct, &mut ()),
                tokens_ffi,
                output.as_mut_ptr()
            )
        );

        ffi_struct = FfiConvert::try_from_ffi(output.assume_init(), &mut ()).expect("valid");

        assert_eq!(2, ffi_struct.tokens.len());
        assert_eq!(ffi_struct.tokens, tokens);
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn mutate_opaque() {
    let param_name = Name(String::from("Nomen"));
    let mut ffi_struct = get_new_struct_with_params();
    let mut removed = MaybeUninit::new(core::ptr::null_mut());

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            OpaqueStruct__remove_param(
                FfiConvert::into_ffi(&mut ffi_struct, &mut ()),
                &param_name,
                removed.as_mut_ptr(),
            )
        );

        let removed = removed.assume_init();
        let removed = Option::try_from_ffi(removed, &mut ()).unwrap();
        assert_eq!(Some(Value(String::from("Omen"))), removed);
        assert!(!ffi_struct.params.contains_key(&param_name));
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn return_option() {
    let ffi_struct = get_new_struct_with_params();

    let mut param1 = MaybeUninit::new(core::ptr::null());
    let mut param2 = MaybeUninit::new(core::ptr::null());

    let name1 = Name(String::from("Non"));
    assert_eq!(FfiReturn::Ok, unsafe {
        OpaqueStruct__get_param(
            FfiConvert::into_ffi(&ffi_struct, &mut ()),
            &name1,
            param1.as_mut_ptr(),
        )
    });
    let param1 = unsafe { param1.assume_init() };
    assert!(param1.is_null());
    let param1: Option<&Value> = unsafe { FfiConvert::try_from_ffi(param1, &mut ()).unwrap() };
    assert!(param1.is_none());

    let name2 = Name(String::from("Nomen"));
    assert_eq!(FfiReturn::Ok, unsafe {
        OpaqueStruct__get_param(
            FfiConvert::into_ffi(&ffi_struct, &mut ()),
            &name2,
            param2.as_mut_ptr(),
        )
    });

    unsafe {
        let param2 = param2.assume_init();
        assert!(!param2.is_null());
        let param2: Option<&Value> = FfiConvert::try_from_ffi(param2, &mut ()).unwrap();
        assert_eq!(Some(&Value(String::from("Omen"))), param2);
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn take_and_return_boxed_slice() {
    let input: Box<[u8]> = [12u8, 42u8].into();
    let mut output = MaybeUninit::new(OutBoxedSlice::from_raw_parts(core::ptr::null_mut(), 0));
    let mut in_store = Default::default();

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __freestanding_with_boxed_slice(
                FfiConvert::into_ffi(input, &mut in_store),
                output.as_mut_ptr()
            )
        );

        let output = output.assume_init();
        assert_eq!(output.len(), 2);
        let boxed_slice = Box::<[u8]>::try_read_out(output).expect("Valid");
        assert_eq!(boxed_slice, [12u8, 42u8].into());
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn take_and_return_option_without_niche() {
    let input = Some(42);
    let mut output = MaybeUninit::new(FfiTuple2(0, unsafe { core::mem::zeroed() }));

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __freestanding_with_option(FfiConvert::into_ffi(input, &mut ()), output.as_mut_ptr())
        );

        let output = output.assume_init();
        assert_eq!(input, FfiOutPtrRead::try_read_out(output).expect("Valid"));
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn take_and_return_option_with_niche_ref() {
    let input = Some(true);
    let mut output = MaybeUninit::new(0);
    let mut in_store = Default::default();

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __freestanding_with_option_with_niche_ref(
                FfiConvert::into_ffi(&input, &mut in_store),
                output.as_mut_ptr()
            )
        );

        let output = output.assume_init();
        assert_eq!(input, *LocalRef::try_read_out(output).expect("Valid"));
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn take_and_return_option_without_niche_ref() {
    let input = Some(42u8);
    let mut output = MaybeUninit::new(FfiTuple2(0, 0));
    let mut in_store = Default::default();

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __freestanding_with_option_without_niche_ref(
                FfiConvert::into_ffi(&input, &mut in_store),
                output.as_mut_ptr()
            )
        );

        let output = output.assume_init();
        assert_eq!(input, *LocalRef::try_read_out(output).expect("Valid"));
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn return_iterator() {
    let ffi_struct = get_new_struct_with_params();
    let mut out_params = MaybeUninit::new(OutBoxedSlice::from_raw_parts(core::ptr::null_mut(), 0));

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            OpaqueStruct__params(
                FfiConvert::into_ffi(&ffi_struct, &mut ()),
                out_params.as_mut_ptr()
            )
        );

        let out_params = out_params.assume_init();
        assert_eq!(out_params.len(), 2);
        let vec = Vec::<(&Name, &Value)>::try_read_out(out_params).expect("Valid");

        let default_params = get_default_params();
        assert_eq!((&default_params[0].0, &default_params[0].1), vec[0]);
        assert_eq!((&default_params[1].0, &default_params[1].1), vec[1]);
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn return_result() {
    let mut output = MaybeUninit::new(0);

    unsafe {
        assert_eq!(
            FfiReturn::ExecutionFail,
            OpaqueStruct__fallible_int_output(false.into_ffi(&mut ()), output.as_mut_ptr())
        );
        assert_eq!(0, output.assume_init());
        assert_eq!(
            FfiReturn::Ok,
            OpaqueStruct__fallible_int_output(true.into_ffi(&mut ()), output.as_mut_ptr())
        );
        assert_eq!(42, output.assume_init());
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn return_empty_tuple_result() {
    unsafe {
        assert_eq!(
            FfiReturn::ExecutionFail,
            OpaqueStruct__fallible_empty_tuple_output(false.into_ffi(&mut ()))
        );
        assert_eq!(
            FfiReturn::Ok,
            OpaqueStruct__fallible_empty_tuple_output(true.into_ffi(&mut ()))
        );
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn array_to_pointer() {
    let array = [1_u8];
    let mut store = Option::default();
    let ptr: *mut [u8; 1] = array.into_ffi(&mut store);
    let mut output = MaybeUninit::new([0_u8]);

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __freestanding_with_array(ptr, output.as_mut_ptr())
        );

        assert_eq!(
            [1_u8],
            <[u8; 1]>::try_from_ffi(output.assume_init(), &mut ()).unwrap()
        );
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn take_and_return_array_ref() {
    let array = [1_u8];
    let ptr: *const [u8; 1] = (&array).into_ffi(&mut ());
    let mut output = MaybeUninit::new(core::ptr::null());

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __freestanding_with_array_ref(ptr, output.as_mut_ptr())
        );

        assert_eq!(
            &[1_u8; 1],
            <&[u8; 1]>::try_from_ffi(output.assume_init(), &mut ()).unwrap()
        );
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn array_in_struct() {
    let array = ([1_u8],);
    let ffi_arr: FfiTuple1<[u8; 1]> = array.into_ffi(&mut ((),));
    let mut output = MaybeUninit::new(FfiTuple1([0; 1]));

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __freestanding_with_array_in_struct(ffi_arr, output.as_mut_ptr())
        );

        assert_eq!(
            ([1_u8],),
            <([u8; 1],)>::try_from_ffi(output.assume_init(), &mut ((),)).unwrap()
        );
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn repr_c_struct() {
    let struct_ = RobustReprCStruct {
        a: 42,
        b: 7,
        c: 12,
        d: core::mem::ManuallyDrop::new(12),
    };
    let mut output = MaybeUninit::new(RobustReprCStruct {
        a: u8::MAX,
        b: u32::MAX,
        c: i16::MAX,
        d: core::mem::ManuallyDrop::new(-1),
    });

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __freestanding_with_repr_c_struct(struct_, output.as_mut_ptr())
        );

        assert!(output.assume_init() == struct_);
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn primitive_conversion() {
    let byte: u8 = 1;
    let mut output = MaybeUninit::new(0);

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __freestanding_with_primitive(byte.into_ffi(&mut ()), output.as_mut_ptr())
        );

        assert_eq!(1, output.assume_init());
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn fieldless_enum_conversion() {
    let fieldless_enum = FieldlessEnum::A;
    let mut output = MaybeUninit::new(2);

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __freestanding_with_fieldless_enum(
                fieldless_enum.into_ffi(&mut ()),
                output.as_mut_ptr()
            )
        );

        let ret_val = FfiOutPtrRead::try_read_out(output.assume_init());
        assert_eq!(FieldlessEnum::A, ret_val.expect("Conversion failed"));
    }
}

#[test]
#[cfg(target_family = "wasm")]
#[webassembly_test::webassembly_test]
fn primitive_conversion_failed() {
    let byte: u32 = u32::MAX;
    let mut output = MaybeUninit::new(0);

    unsafe {
        assert_eq!(
            FfiReturn::ConversionFailed,
            __freestanding_with_primitive(byte, output.as_mut_ptr())
        );

        assert_eq!(0, output.assume_init());
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn data_carrying_enum_conversion() {
    let data_carrying_enum = DataCarryingEnum::A(get_new_struct());
    let mut output = MaybeUninit::new(__iroha_ffi__ReprCDataCarryingEnum {
        tag: 1,
        payload: __iroha_ffi__DataCarryingEnumPayload {
            B: core::mem::ManuallyDrop::new(42),
        },
    });

    unsafe {
        let mut store = Default::default();
        assert_eq!(
            FfiReturn::Ok,
            __freestanding_with_data_carrying_enum(
                data_carrying_enum.clone().into_ffi(&mut store),
                output.as_mut_ptr()
            )
        );

        let ret_val = FfiOutPtrRead::try_read_out(output.assume_init());
        assert_eq!(data_carrying_enum, ret_val.expect("Conversion failed"));
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn invoke_trait_method() {
    let ffi_struct = get_new_struct_with_params();
    let mut output = MaybeUninit::<*mut Name>::new(core::ptr::null_mut());

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            OpaqueStruct__Target__target(
                FfiConvert::into_ffi(ffi_struct, &mut ()),
                output.as_mut_ptr()
            )
        );
        let name = FfiConvert::try_from_ffi(output.assume_init(), &mut ()).unwrap();
        assert_eq!(Name(String::from("X")), name);
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn nested_vec() {
    let vec: Vec<Vec<Vec<u8>>> = vec![];

    unsafe {
        let mut store = Default::default();
        assert_eq!(
            FfiReturn::Ok,
            __freestanding_with_nested_vec(vec.into_ffi(&mut store))
        );
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn return_vec_of_boxed_opaques() {
    let mut output = MaybeUninit::new(OutBoxedSlice::from_raw_parts(core::ptr::null_mut(), 0));

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __get_vec_of_boxed_opaques(output.as_mut_ptr())
        );
        let output = output.assume_init();
        assert_eq!(output.len(), 1);
        let vec = Vec::<Box<OpaqueStruct>>::try_read_out(output).expect("Valid");
        assert_eq!(Box::new(get_new_struct()), vec[0]);
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn array_of_opaques() {
    let input = [OpaqueStruct::default(), OpaqueStruct::default()];
    let mut output = MaybeUninit::new([core::ptr::null_mut(), core::ptr::null_mut()]);
    let mut store = Option::default();

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __take_and_return_array_of_opaques(
                input.clone().into_ffi(&mut store),
                output.as_mut_ptr()
            )
        );
        let output = output.assume_init();
        let output = <[OpaqueStruct; 2]>::try_from_ffi(output, &mut ()).unwrap();
        assert_eq!(input, output);
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn borrow_vec() {
    let a = vec![1, 2];

    let mut store = Default::default();

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __take_vec_ref(<&Vec<u8>>::into_ffi(&a, &mut store))
        );
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn return_reference_from_slice() {
    let a = vec![1, 2];

    let mut output = MaybeUninit::new(core::ptr::null());

    unsafe {
        assert_eq!(
            FfiReturn::Ok,
            __reference_from_slice(<&[u8]>::into_ffi(&a, &mut ()), output.as_mut_ptr())
        );

        let output = <&u8>::try_read_out(output.assume_init()).unwrap();
        assert_eq!(output, &a[0]);
    }
}

#[test]
#[webassembly_test::webassembly_test]
fn borrow_local() {
    let a = (1_u8, 2_u8);

    let b: LocalRef<(u8, u8)> = {
        let mut store = Default::default();
        let mut output = MaybeUninit::new(FfiTuple2(0, 0));

        unsafe {
            assert_eq!(
                FfiReturn::Ok,
                __take_tuple_ref(<&(u8, u8)>::into_ffi(&a, &mut store), output.as_mut_ptr())
            );

            FfiOutPtrRead::try_read_out(output.assume_init()).expect("Valid")
        }
    };

    assert_eq!(*b, (1, 2));
}
