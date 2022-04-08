use parity_scale_codec::Decode;

mod a {
    use super::*;

    #[derive(Debug, Decode, iroha_derive::DumpDecoded)]
    #[dump_decoded(rename = "-AnotherStruct_0;")]
    struct Struct;
}

iroha_macro::generate_dump_decoded_map!();
