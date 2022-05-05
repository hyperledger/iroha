use iroha_ffi::{ffi_bindgen, FfiResult, Pair};
use std::{collections::BTreeMap, mem::MaybeUninit};

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Name(&'static str);
pub struct Value(&'static str);

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

fn main() -> Result<(), ()> {
    let name = Name("X");

    let mut ffi_struct: MaybeUninit<*mut FfiStruct> = MaybeUninit::uninit();
    if unsafe { ffi_struct_new(&name, ffi_struct.as_mut_ptr()) } != FfiResult::Ok {
        return Err(());
    }
    let ffi_struct = unsafe { ffi_struct.assume_init() };

    let params = vec![(Name("Nomen"), Value("Omen"))];
    let params_ffi: Vec<_> = params
        .iter()
        .map(|(key, val)| Pair(key as *const _, val as *const _)).collect();
    if unsafe { ffi_struct_with_params(ffi_struct, params_ffi.as_ptr(), params.len()) }
        != FfiResult::Ok
    {
        return Err(());
    }

    let mut param: MaybeUninit<*const Value> = MaybeUninit::uninit();
    if unsafe { ffi_struct_get_param(ffi_struct, &name, param.as_mut_ptr()) } != FfiResult::Ok {
        return Err(());
    }

    // TODO: Type should be *const Pair even when transfering ownership because it's not possible to reallocate
    let mut params: MaybeUninit<*mut Pair<*const Name, *const Value>> = MaybeUninit::uninit();
    let mut params_len: MaybeUninit<usize> = MaybeUninit::uninit();
    if unsafe { ffi_struct_params(ffi_struct, params.as_mut_ptr(), params_len.as_mut_ptr()) }
        != FfiResult::Ok
    {
        return Err(());
    }

    if unsafe { ffi_struct_drop(ffi_struct) } != FfiResult::Ok {
        return Err(());
    }

    Ok(())
}
