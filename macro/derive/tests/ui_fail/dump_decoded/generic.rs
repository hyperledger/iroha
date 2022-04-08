use parity_scale_codec::Decode;

#[derive(Debug, Decode, iroha_derive::DumpDecoded)]
struct Struct<T>;
