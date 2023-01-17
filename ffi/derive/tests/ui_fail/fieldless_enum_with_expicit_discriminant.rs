use iroha_ffi::FfiType;

#[derive(FfiType)]
enum EnumWithExplicitDiscriminant { 
    A = 1,
    B,
    C,
    D,
}

fn main() {}
