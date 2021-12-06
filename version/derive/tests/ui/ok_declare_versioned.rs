use iroha_version_derive::{declare_versioned, version};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

declare_versioned!(VersionedMessage 1..3, Debug, Clone, iroha_macro::FromVariant);

#[version(n = 1, versioned = "VersionedMessage")]
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Message;

impl Message {
    pub fn handle(&self) {}
}

#[version(n = 2, versioned = "VersionedMessage")]
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize)]
pub struct Message2;

impl Message2 {
    pub fn handle(&self) {
        panic!("Should have been message version 1.")
    }
}

pub fn main() {
    match Message.into() {
        VersionedMessage::V1(message) => message.handle(),
        VersionedMessage::V2(message) => message.handle(),
    }
}
