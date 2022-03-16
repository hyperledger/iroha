#[cfg(all(not(test), not(target_pointer_width = "32")))]
compile_error!("Target architectures other then 32-bit are not supported");

#[cfg(all(not(test), not(all(target_arch = "wasm32", target_os = "unknown"))))]
compile_error!("Targets other then wasm32-unknown-unknown are not supported");

extern crate alloc as core_alloc;

mod alloc;

use core::ops::RangeFrom;

use iroha_data_model::prelude::*;
use parity_scale_codec::{Decode, Encode};

/// Host exports
pub mod host {
    #[link(wasm_import_module = "iroha")]
    extern "C" {
        /// Executes encoded query by providing offset and length
        /// into WebAssembly's linear memory where query is stored
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the provided allocation
        /// but it does transfer ownership of the result to the caller
        pub(super) fn iroha_wasm_execute_query(ptr: usize, len: usize) -> usize;

        /// Executes encoded instruction by providing offset and length
        /// into WebAssembly's linear memory where instruction is stored
        ///
        /// # Warning
        ///
        /// This function doesn't take ownership of the provided allocation
        /// but it does transfer ownership of the result to the caller
        pub(super) fn iroha_wasm_execute_instruction(ptr: usize, len: usize);
    }
}

/// Decode the object from given pointer where first element is the size of the object
/// following it. This can be considered a custom encoding format.
///
/// # Warning
///
/// This method takes ownership of the given pointer
///
/// # Safety
///
/// It's safe to call this function as long as it's safe to construct, from the given
/// pointer, byte array of prefix length and `Box<[u8]>` containing the encoded object
unsafe fn decode_with_length_prefix_from_raw<T: Decode>(ptr: usize) -> T {
    let len_size_bytes = core::mem::size_of::<usize>();

    #[allow(clippy::expect_used)]
    let len = usize::from_be_bytes(
        core::slice::from_raw_parts(ptr as *mut _, len_size_bytes)
            .try_into()
            .expect("Prefix length size(bytes) incorrect. This is a bug."),
    );

    _decode_from_raw_in_range(ptr, len, len_size_bytes..)
}

/// Decode the object from given pointer and length
///
/// # Warning
///
/// This method takes ownership of the given pointer
///
/// # Safety
///
/// It's safe to call this function as long as it's safe to construct, from the given
/// pointer, `Box<[u8]>` containing the encoded object
pub unsafe fn _decode_from_raw<T: Decode>(ptr: usize, len: usize) -> T {
    _decode_from_raw_in_range(ptr, len, 0..)
}

/// Decode the object from given pointer and length in the given range
///
/// # Warning
///
/// This method takes ownership of the given pointer
///
/// # Safety
///
/// It's safe to call this function as long as it's safe to construct, from the given
/// pointer, `Box<[u8]>` containing the encoded object
// `usize` is always pointer sized
#[allow(clippy::cast_possible_truncation)]
unsafe fn _decode_from_raw_in_range<T: Decode>(
    ptr: usize,
    len: usize,
    range: RangeFrom<usize>,
) -> T {
    let bytes = Box::from_raw(core::slice::from_raw_parts_mut(ptr as *mut _, len));

    #[allow(clippy::expect_used, clippy::expect_fun_call)]
    T::decode(&mut &bytes[range]).expect(
        format!(
            "Decoding of {} failed. This is a bug",
            core::any::type_name::<T>()
        )
        .as_str(),
    )
}

#[no_mangle]
/// Multiplexed all functions
unsafe extern "C" fn _iroha_wasm_fn(fn_id: u32, args_ptr: usize, args_len: usize) -> usize {
    42
}

#[no_mangle]
unsafe extern "C" fn _iroha_wasm_execute_query(query_ptr: usize) -> usize {
    // TODO: Should take ownership of the pointer or not?
    let query = &*(query_ptr as *mut QueryBox);

    let query_res: QueryResult = {
        let query_bytes = query.encode();

        decode_with_length_prefix_from_raw(host::iroha_wasm_execute_query(
            query_bytes.as_ptr() as usize,
            query_bytes.len(),
        ))
    };

    Box::into_raw(Box::new(query_res)) as usize
}

#[no_mangle]
unsafe extern "C" fn _iroha_wasm_execute_instruction(isi_ptr: usize) {
    // TODO: Should take ownership of the pointer or not?
    let instruction = &*(isi_ptr as *mut Instruction);
    let isi_bytes = instruction.encode();
    host::iroha_wasm_execute_instruction(isi_bytes.as_ptr() as usize, isi_bytes.len());
}

//macro_rules! boxit {
//    ( $var: ident ) => {
//        Box::new($var).into_raw()
//    };
//}
//
//#[no_mangle]
//// TODO: no_mangle is unsafe. Name functions accordingly
//unsafe extern "C" fn new_handle(handle_id: u32, args_ptr: usize, args_len: usize) -> usize {
//    let bytes = core::slice::from_raw_parts(args_ptr, args_len);
//    // TODO: Guarantee exhaustive match
//    match handle_id {
//        Peer::ID => {
//            let id = Peer::Id::decode(bytes).unwrap();
//            let peer = Peer::new(id);
//            boxit!(peer)
//        },
//        Domain::ID => {
//            let id = Domain::Id::decode(bytes).unwrap();
//            let domain = Domain::new(id);
//            boxit!(domain)
//        },
//        Account::ID => {
//            let id = Account::Id::decode(bytes).unwrap();
//            let account = Account::new(id);
//            boxit!(account)
//        },
//        NewAccount::ID => {
//            let id = NewAccount::Id::decode(bytes).unwrap();
//            let new_account = NewAccount::new(id);
//            boxit!(new_account)
//        },
//
//        Asset::ID => {
//            let (id, value) = (Asset::Id, AssetValue)::decode(bytes).unwrap();
//            let asset = Asset::new(id, value);
//            boxit!(asset)
//        },
//        AssetDefinition::ID => {
//            let (id, value_type, mintable) = (AssetDefinition::Id, AssetValueType, bool)::decode(bytes).unwrap();
//            let asset_definition = AssetDefinition::new(id, value_type, mintable);
//            boxit!(asset_definition)
//        },
//        // TODO: Requires TriggerBuilder?
//        //Trigger::ID => {
//        //    let (id, action) = (Trigger::Id, Action)::decode(bytes).unwrap();
//        //    let trigger = Trigger::new(id, action);
//        //    boxit!(trigger)
//        //},
//        // TODO: Requires RoleBuilder?
//        //#[cfg(feature = "roles")]
//        //Role::ID => {
//        //    let (id, permissions) = (Role::Id, Permissions)::decode(bytes).unwrap();
//        //    let role = Role::new(id, permissions);
//        //    boxit!(role)
//        //},
//        _ => panic!("Unknown handle ID"),
//    }
//}

//fn get_attribute(handle_id: u32, handle: usize, attr_id: u32) -> Result<usize, Trap> {
//    let memory = Self::get_memory(&mut caller)?;
//    let handle_ptr = unsafe { memory.data_ptr().offset(handle) };
//
//    unsafe {
//        match handle_id {
//            Metadata::ID => {
//                let metadata: &Metadata = &*handle_ptr.cast();
//                let attr_ptr = metadata.get_attr(attr_id);
//                attr_ptr.offest_from(memory.data_ptr())
//            }
//            _ => return Err(Trap::new("unknown handle ID")),
//        }
//    }
//
//    match attr_id {
//        _ => Err(Trap::new("unknown attribute ID")),
//    }
//
//    Ok(())
//}
