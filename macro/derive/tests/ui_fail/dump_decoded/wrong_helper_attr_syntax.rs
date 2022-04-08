use parity_scale_codec::Decode;

#[derive(Debug, Decode, iroha_derive::DumpDecoded)]
#[dump_decoded(rename = AnotherStruct)]
struct Struct;

#[derive(Debug, Decode, iroha_derive::DumpDecoded)]
#[dump_decoded(newname = "AnotherStruct2")]
struct Struct2;
