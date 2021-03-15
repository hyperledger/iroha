use iroha_version_derive::{declare_versioned, version};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

declare_versioned!(VersionedMessage 1..2);
#[version(n = 1, versioned = "VersionedMessage")]
#[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
struct Message;

impl Message {
    pub fn handle(&self) {}
}

declare_versioned!(VersionedMessage2 1..2);
#[version(n = 1, versioned = "VersionedMessage2")]
#[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
struct Message2;

impl Message2 {
    pub fn handle(&self) {}
}

pub fn main() {
    let versioned_message: VersionedMessage = Message.into();
    match versioned_message {
        VersionedMessage::V1(message) => {
            let message: Message = message.into();
            message.handle();
        }
    }
    let versioned_message: VersionedMessage2 = Message2.into();
    match versioned_message {
        VersionedMessage2::V1(message) => {
            let message: Message2 = message.into();
            message.handle();
        }
    }
}
