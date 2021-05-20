use iroha_version_derive::{declare_versioned, version};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

declare_versioned!(VersionedMessage 1..3, Debug, Clone, iroha_derive::FromVariant);

#[version(n = 1, versioned = "VersionedMessage", derive = "Debug, Clone")]
#[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
struct Message;

impl Message {
    pub fn handle(&self) {}
}

#[version(n = 2, versioned = "VersionedMessage", derive = "Debug, Clone")]
#[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
struct Message2;

impl Message2 {
    pub fn handle(&self) {
        panic!("Should have been message version 1.")
    }
}

pub fn main() {
    let versioned_message: VersionedMessage = Message.into();
    match versioned_message {
        VersionedMessage::V1(message) => {
            let message: Message = message.into();
            message.handle();
        }
        VersionedMessage::V2(message) => {
            let message: Message2 = message.into();
            message.handle();
        }
    }
}
