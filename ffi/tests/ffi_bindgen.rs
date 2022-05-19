#![allow(unsafe_code, clippy::restriction, clippy::pedantic)]

use std::{collections::BTreeMap, mem::MaybeUninit};

use iroha_ffi::{ffi_bindgen, FfiResult, Pair};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name(&'static str);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Value(&'static str);

const DEFAULT_PARAMS: [(Name, Value); 2] = [
    (Name("Nomen"), Value("Omen")),
    (Name("Nomen2"), Value("Omen2")),
];

//#[ffi_bindgen]
//impl FromStr for Name {
//    type Err = ParseError;
//
//    fn from_str(candidate: &str) -> Result<Self, Self::Err> {
//        if candidate.chars().any(char::is_whitespace) {
//            return Err(ParseError {
//                reason: "White space not allowed in `Name` constructs",
//            });
//        }
//        Ok(Self(String::from(candidate)))
//    }
//}

#[ffi_bindgen]
#[derive(getset::Getters)]
#[getset(get = "pub")]
pub struct FfiStruct {
    name: Name,
    #[getset(skip)]
    tokens: Vec<Value>,
    #[getset(skip)]
    params: BTreeMap<Name, Value>,
}

#[ffi_bindgen]
impl FfiStruct {
    pub fn new(name: impl Into<Name>) -> Self {
        Self {
            name: name.into(),
            tokens: Vec::new(),
            params: BTreeMap::default(),
        }
    }
    #[must_use]
    pub fn with_tokens(mut self, tokens: impl IntoIterator<Item = impl Into<Value>>) -> Self {
        self.tokens = tokens.into_iter().map(Into::into).collect();
        self
    }
    #[must_use]
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
    pub fn fallible(flag: bool) -> Result<u32, &'static str> {
        if flag {
            Ok(42)
        } else {
            Err("fail")
        }
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

#[allow(trivial_casts)]
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
        assert_eq!(Name("X"), (*ffi_struct).name);
        assert!((*ffi_struct).params.is_empty());

        ffi_struct_drop(ffi_struct);
    }
}

#[test]
#[allow(trivial_casts)]
fn into_iter_item_impl_into() {
    let ffi_struct = get_new_struct();

    let tokens = vec![Value("My omen"), Value("Your omen")];
    let tokens_ffi: Vec<_> = tokens.iter().map(|t| t as *const _).collect();

    unsafe {
        assert_eq!(
            FfiResult::Ok,
            ffi_struct_with_tokens(ffi_struct, tokens_ffi.as_ptr(), tokens_ffi.len())
        );

        assert_eq!(2, (*ffi_struct).tokens.len());
        assert_eq!((*ffi_struct).tokens, tokens);

        ffi_struct_drop(ffi_struct);
    }
}

#[test]
fn builder_method() {
    let ffi_struct = get_new_struct_with_params();

    unsafe {
        assert_eq!(2, (*ffi_struct).params.len());
        assert_eq!((*ffi_struct).params, DEFAULT_PARAMS.into_iter().collect());

        ffi_struct_drop(ffi_struct);
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

        ffi_struct_drop(ffi_struct);
    }
}

#[test]
fn empty_return_iterator() {
    let ffi_struct = get_new_struct_with_params();
    let mut params_len = MaybeUninit::new(0);

    unsafe {
        assert_eq!(
            FfiResult::Ok,
            ffi_struct_params(
                ffi_struct,
                core::ptr::null_mut(),
                0_usize,
                params_len.as_mut_ptr(),
            )
        );

        assert!(params_len.assume_init() == 2);
        ffi_struct_drop(ffi_struct);
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
            ffi_struct_params(
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
            .eq(DEFAULT_PARAMS.iter().take(1).map(|pair| (&pair.0, &pair.1))));

        ffi_struct_drop(ffi_struct);
    }
}

#[test]
fn return_result() {
    let mut output = MaybeUninit::new(0);

    unsafe {
        assert_eq!(
            FfiResult::ExecutionFail,
            ffi_struct_fallible(u8::from(false), output.as_mut_ptr())
        );
        assert_eq!(0, output.assume_init());
        assert_eq!(
            FfiResult::Ok,
            ffi_struct_fallible(u8::from(true), output.as_mut_ptr())
        );
        assert_eq!(42, output.assume_init());
    }
}

#[test]
fn getset_getter() {
    let ffi_struct = get_new_struct_with_params();

    unsafe {
        assert_eq!(Name("X"), *(*ffi_struct).name());
        ffi_struct_drop(ffi_struct);
    }
}
