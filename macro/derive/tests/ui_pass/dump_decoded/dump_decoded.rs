use parity_scale_codec::Decode;

#[derive(Debug, Decode, iroha_derive::DumpDecoded)]
struct Struct1;

#[derive(Debug, Decode, iroha_derive::DumpDecoded)]
struct Struct2;

iroha_derive::generate_dump_decoded_map!();

fn main() {
    let map = iroha_derive::get_dump_decoded_map!();
    assert!(map.contains_key("Struct1"));
    assert!(map.contains_key("Struct2"));
}
