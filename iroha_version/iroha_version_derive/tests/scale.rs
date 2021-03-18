#[cfg(test)]
mod tests {
    #![allow(clippy::items_after_statements, clippy::wildcard_imports)]

    use iroha_version::{
        error::{Error, Result},
        scale::*,
        RawVersioned,
    };
    use iroha_version_derive::{declare_versioned, version};
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    mod model_1 {
        use super::*;

        declare_versioned!(VersionedMessage 1..3);

        #[version(n = 1, versioned = "VersionedMessage")]
        #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
        pub struct Message;

        #[version(n = 2, versioned = "VersionedMessage")]
        #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
        pub struct Message2;
    }

    mod model_2 {
        use super::*;

        declare_versioned!(VersionedMessage 1..4);

        #[version(n = 1, versioned = "VersionedMessage")]
        #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
        pub struct Message;

        #[version(n = 2, versioned = "VersionedMessage")]
        #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
        pub struct Message2;

        #[version(n = 3, versioned = "VersionedMessage")]
        #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
        pub struct Message3(pub String);
    }

    #[test]
    fn supported_version() -> Result<(), String> {
        use model_1::*;

        let versioned_message: VersionedMessage = Message.into();
        let bytes = versioned_message
            .encode_versioned()
            .map_err(|e| e.to_string())?;
        let decoded_message =
            VersionedMessage::decode_versioned(&bytes).map_err(|e| e.to_string())?;
        match decoded_message {
            VersionedMessage::V1(message) => {
                let _: Message = message.into();
                Ok(())
            }
            VersionedMessage::V2(message) => {
                let _: Message2 = message.into();
                Err("Should have been message v1.".to_owned())
            }
        }
    }

    #[test]
    fn unsupported_version() -> Result<(), String> {
        let bytes = {
            use model_2::*;

            let versioned_message: VersionedMessage = Message3("test string".to_string()).into();
            versioned_message
                .encode_versioned()
                .map_err(|e| e.to_string())?
        };

        use model_1::*;
        let raw_string = "test string".encode();
        let decoded_message = VersionedMessage::decode_versioned(&bytes);
        match decoded_message {
            Err(Error::UnsupportedVersion(unsupported_version)) => {
                assert_eq!(unsupported_version.version, 3);
                if let RawVersioned::ScaleBytes(bytes) = unsupported_version.raw {
                    assert_eq!(bytes[1..], raw_string[..]);
                    Ok(())
                } else {
                    Err("Should be scale bytes.".to_owned())
                }
            }
            _ => Err("Should be an unsupported version".to_owned()),
        }
    }
}
