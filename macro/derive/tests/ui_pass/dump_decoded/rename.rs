use parity_scale_codec::Decode;

mod a {
    use super::*;

    #[derive(Debug, Decode, iroha_derive::DumpDecoded)]
    #[dump_decoded(rename = "a::Struct")]
    pub struct Struct;
}

mod b {
    use super::*;

    #[derive(Debug, Decode, iroha_derive::DumpDecoded)]
    pub struct Struct;
}

use b::*;

iroha_derive::generate_dump_decoded_map!();

fn main() {
    let map = iroha_derive::get_dump_decoded_map!();
    assert!(map.contains_key("a::Struct"));
    assert!(map.contains_key("Struct"));
}
