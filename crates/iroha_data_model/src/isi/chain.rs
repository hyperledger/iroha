//! Shared chain-level maintenance instruction (`specs/sccp.md` §4.7.4).

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Request one block that applies already-due governance or SCCP heartbeat work.
///
/// The canonical wire identity is `iroha.chain.keepalive.v1`. A transaction carries no other
/// instruction, and a block contains at most one. Core must enforce the committed-parent due
/// predicate and K1/K2 block invalidity; decoding this empty DATA value grants no exemption or
/// permission to produce an empty or non-due block. Any Ed25519 authority may submit it when
/// eligible, including an unregistered account (§4.7.4 K3).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::chain::Keepalive")]
pub struct Keepalive {}

impl crate::seal::Instruction for Keepalive {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        isi::test_support::assert_slice_roundtrip,
        sccp::test_support::{assert_rejects_unknown_field, roundtrip},
    };
    use norito::codec::DecodeAll;

    #[test]
    fn keepalive_is_exact_empty_data_with_closed_json_and_frame() {
        let value = Keepalive {};
        roundtrip(&value);
        assert_slice_roundtrip(value);
        assert_rejects_unknown_field(&value, &[]);
        assert_eq!(norito::json::to_json(&value).expect("JSON"), "{}");
        let frame = norito::to_bytes(&value).expect("frame");
        assert_eq!(
            norito::decode_from_bytes::<Keepalive>(&frame).expect("decode"),
            value
        );
        let mut bytes = value.encode();
        bytes.push(0);
        assert!(Keepalive::decode_all(&mut bytes.as_slice()).is_err());
    }
}
