use parity_scale_codec::Decode;

mod a {
    use super::*;

    #[derive(Debug, Decode, iroha_derive::DumpDecoded)]
    struct Struct;
}

mod b {
    use super::*;

    #[derive(Debug, Decode, iroha_derive::DumpDecoded)]
    struct Struct;
}
