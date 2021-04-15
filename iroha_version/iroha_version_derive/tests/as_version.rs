#[cfg(test)]
mod tests {
    #![allow(unused_results)]

    use iroha_version_derive::{declare_versioned, version};
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    declare_versioned!(VersionedMessage 1..3);

    #[version(n = 1, versioned = "VersionedMessage")]
    #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
    pub struct Message;

    #[version(n = 2, versioned = "VersionedMessage")]
    #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
    pub struct Message2;

    #[test]
    fn as_version() -> Result<(), String> {
        let versioned_message: VersionedMessage = Message.into();
        let _message: Message = versioned_message
            .as_v1()
            .ok_or_else(|| "Should be version 1.".to_owned())?
            .clone()
            .into();
        Ok(())
    }

    #[test]
    fn into_version() -> Result<(), String> {
        let versioned_message: VersionedMessage = Message.into();
        let _message: Message = versioned_message
            .into_v1()
            .ok_or_else(|| "Should be version 1.".to_owned())?
            .into();
        Ok(())
    }
}
