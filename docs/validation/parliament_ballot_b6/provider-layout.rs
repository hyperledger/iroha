//! Compile-only AES provider layout probe for the standalone B6 resource model.
use std::mem::{align_of, size_of};

#[allow(dead_code)]
struct Provider(aes::Aes256);

#[unsafe(no_mangle)]
pub static B6_SOFT_SIZE: [u8; size_of::<aes::soft::Aes256>()] = [0; size_of::<aes::soft::Aes256>()];
#[unsafe(no_mangle)]
pub static B6_SOFT_ALIGN: [u8; align_of::<aes::soft::Aes256>()] = [0; align_of::<aes::soft::Aes256>()];
#[unsafe(no_mangle)]
pub static B6_AUTO_SIZE: [u8; size_of::<Provider>()] = [0; size_of::<Provider>()];
#[unsafe(no_mangle)]
pub static B6_AUTO_ALIGN: [u8; align_of::<Provider>()] = [0; align_of::<Provider>()];
