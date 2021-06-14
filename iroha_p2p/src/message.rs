use parity_scale_codec::{Decode, Encode};

use crate::Error;

#[derive(Debug, Clone, Encode, Decode, iroha_actor::Message)]
pub struct Message(pub Vec<u8>);

#[derive(Debug, iroha_actor::Message)]
pub struct MessageResult(pub Result<Message, Error>);

impl MessageResult {
    pub const fn new_message(message: Message) -> Self {
        Self(Ok(message))
    }

    pub const fn new_error(error: Error) -> Self {
        Self(Err(error))
    }
}
