use std::collections::BTreeMap;

use getset::Getters;
use iroha_ffi::{ffi_export, ffi_fn, handles, IntoFfi, TryFromReprC};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, IntoFfi, TryFromReprC)]
pub struct Name(&'static str);
#[derive(Debug, Clone, PartialEq, IntoFfi, TryFromReprC)]
pub struct Value(&'static str);

/// FfiStruct
#[derive(Clone, Getters, IntoFfi, TryFromReprC)]
#[getset(get = "pub")]
#[ffi_export]
pub struct FfiStruct {
    /// Name
    name: Name,
    /// Params
    #[getset(skip)]
    params: BTreeMap<Name, Value>,
}

handles! {0, FfiStruct}
ffi_fn! {Drop: FfiStruct}

#[ffi_export]
impl FfiStruct {
    /// New
    pub fn new(name: Name) -> Self {
        Self {
            name,
            params: BTreeMap::default(),
        }
    }

    /// With params
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
}

/// Test
#[ffi_export]
pub fn ffi_duplicate_with_name(a: &FfiStruct, name: Name) -> FfiStruct {
    let mut result = a.clone();
    result.name = name;
    result
}

#[cfg(not(feature = "client"))]
fn main() {
    use core::mem::MaybeUninit;

    use iroha_ffi::{AsReprCRef, Handle};

    let name = Name("X");
    let mut ffi_struct: FfiStruct = unsafe {
        let mut ffi_struct = MaybeUninit::<*mut FfiStruct>::uninit();
        let name = IntoFfi::into_ffi(name.clone());
        FfiStruct__new(name, ffi_struct.as_mut_ptr());
        TryFromReprC::try_from_repr_c(ffi_struct.assume_init(), &mut ()).unwrap()
    };

    let in_params = vec![(Name("Nomen"), Value("Omen"))];
    let mut param: MaybeUninit<*const Value> = MaybeUninit::uninit();
    let mut out_params_data = Vec::with_capacity(2);
    let mut data_len = MaybeUninit::<isize>::uninit();

    let out_params = iroha_ffi::slice::OutBoxedSlice::from_uninit_slice(
        Some(&mut out_params_data[..]),
        &mut data_len,
    );

    unsafe {
        let name = IntoFfi::into_ffi(name.clone());

        FfiStruct__with_params(
            IntoFfi::into_ffi(&mut ffi_struct),
            in_params.clone().into_ffi().as_ref(),
        );
        FfiStruct__get_param(IntoFfi::into_ffi(&ffi_struct), name, param.as_mut_ptr());
        FfiStruct__params(IntoFfi::into_ffi(&ffi_struct), out_params);

        let _param: Option<&Value> =
            TryFromReprC::try_from_repr_c(param.assume_init(), &mut ()).unwrap();
        out_params_data.set_len(data_len.assume_init() as usize);

        __drop(FfiStruct::ID, ffi_struct.into_ffi().cast());
    }

    let ffi_struct = FfiStruct::new(Name("foo")).with_params(in_params.clone());
    let mut param: MaybeUninit<*mut FfiStruct> = MaybeUninit::uninit();

    unsafe {
        let dup_name = Name("bar");
        __ffi_duplicate_with_name(
            (&ffi_struct).into_ffi(),
            dup_name.clone().into_ffi(),
            param.as_mut_ptr(),
        );

        let result = &mut *param.assume_init();

        assert_eq!(result.name, dup_name);
        assert_eq!(result.get_param(&Name("Nomen")), Some(&Value("Omen")));
    }
}

#[cfg(feature = "client")]
fn main() {
    let name = Name("X");

    let mut ffi_struct: FfiStruct::new(name);

    let in_params = vec![(Name("Nomen"), Value("Omen"))];
    FfiStruct::with_params(&mut ffi_struct, in_params);

    let param: Option<&Value> = FfiStruct::get_param(&ffi_struct, name);
    let params: Option<Vec<_>> = FfiStruct::params(ffi_struct);

    ffi_duplicate_with_name(&FfiStruct, Name);
}
