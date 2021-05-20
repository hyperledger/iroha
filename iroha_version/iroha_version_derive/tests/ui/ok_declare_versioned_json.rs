use iroha_version_derive::{declare_versioned_with_json, version_with_json};
use serde::{Deserialize, Serialize};

declare_versioned_with_json!(VersionedMessage 1..3, Debug, Clone, iroha_derive::FromVariant);

#[version_with_json(n = 1, versioned = "VersionedMessage", derive = "Debug, Clone")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message;

impl Message {
    pub fn handle(&self) {}
}

#[version_with_json(n = 2, versioned = "VersionedMessage", derive = "Debug, Clone")]
#[derive(Debug, Clone, Serialize, Deserialize)]
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
