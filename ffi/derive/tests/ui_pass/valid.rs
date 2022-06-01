use std::{collections::BTreeMap, mem::MaybeUninit};

use getset::Getters;
use iroha_ffi::{ffi_bindgen, gen_ffi_impl, handles, Pair};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name(&'static str);
#[derive(Clone)]
pub struct Value(&'static str);

#[ffi_bindgen]
#[derive(Getters)]
#[getset(get = "pub")]
pub struct FfiStruct {
    name: Name,
    #[getset(skip)]
    params: BTreeMap<Name, Value>,
}

handles! {0, FfiStruct}
gen_ffi_impl! {Drop: FfiStruct}

#[ffi_bindgen]
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

fn main() {
    let name = Name("X");

    let ffi_struct = unsafe {
        let mut ffi_struct: MaybeUninit<*mut FfiStruct> = MaybeUninit::uninit();
        FfiStruct__new(&name, ffi_struct.as_mut_ptr());
        ffi_struct.assume_init()
    };

    let in_params: Vec<Pair<*const Name, *const Value>> = vec![(Name("Nomen"), Value("Omen"))]
        .iter()
        .map(|(key, val)| Pair(key as *const _, val as *const _))
        .collect();

    let mut param: MaybeUninit<*const Value> = MaybeUninit::uninit();
    let mut out_params: Vec<Pair<*const Name, *const Value>> = Vec::new();
    let mut params_len: MaybeUninit<usize> = MaybeUninit::uninit();

    unsafe {
        FfiStruct__with_params(ffi_struct, in_params.as_ptr(), in_params.len());
        FfiStruct__get_param(ffi_struct, &name, param.as_mut_ptr());

        FfiStruct__params(
            ffi_struct,
            out_params.as_mut_ptr(),
            out_params.capacity(),
            params_len.as_mut_ptr(),
        );

        __drop(FfiStruct::ID, ffi_struct.cast());
    }
}
