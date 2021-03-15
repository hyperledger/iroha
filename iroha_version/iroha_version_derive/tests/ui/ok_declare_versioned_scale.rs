use iroha_version_derive::{declare_versioned_with_scale, version_with_scale};
use parity_scale_codec::{Decode, Encode};

declare_versioned_with_scale!(VersionedMessage 1..3);

#[version_with_scale(n = 1, versioned = "VersionedMessage")]
#[derive(Debug, Clone, Decode, Encode)]
struct Message;

impl Message {
    pub fn handle(&self) {}
}

#[version_with_scale(n = 2, versioned = "VersionedMessage")]
#[derive(Debug, Clone, Decode, Encode)]
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
