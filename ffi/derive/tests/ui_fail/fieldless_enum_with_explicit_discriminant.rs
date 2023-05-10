use iroha_ffi::FfiType;

#[derive(FfiType)]
#[repr(u8)]
enum EnumWithExplicitDiscriminant {
    A = 1,
    B,
    C,
    D,
}

fn main() {}
