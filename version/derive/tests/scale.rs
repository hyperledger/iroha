#[cfg(test)]
mod tests {
    use iroha_version::{
        error::{Error, Result},
        scale::*,
        RawVersioned,
    };
    use iroha_version_derive::{declare_versioned, version};
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    mod model_1 {
        #![allow(unused_results)]

        use super::*;

        declare_versioned!(VersionedMessage 1..3, Debug, Clone, iroha_macro::FromVariant);

        #[version(version = 1, versioned_alias = "VersionedMessage")]
        #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
        pub struct Message;

        #[version(version = 2, versioned_alias = "VersionedMessage")]
        #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
        pub struct Message2;
    }

    mod model_2 {
        #![allow(unused_results)]

        use super::*;

        declare_versioned!(VersionedMessage 1..4, Debug, Clone, iroha_macro::FromVariant);

        #[version(version = 1, versioned_alias = "VersionedMessage")]
        #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
        pub struct Message;

        #[version(version = 2, versioned_alias = "VersionedMessage")]
        #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
        pub struct Message2;

        #[version(version = 3, versioned_alias = "VersionedMessage")]
        #[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
        pub struct Message3(pub String);
    }

    #[test]
    fn supported_version() -> Result<(), String> {
        use model_1::*;

        let versioned_message: VersionedMessage = Message.into();
        let bytes = versioned_message.encode_versioned();
        let decoded_message =
            VersionedMessage::decode_all_versioned(&bytes).map_err(|e| e.to_string())?;
        match decoded_message {
            VersionedMessage::V1(message) => {
                let _: Message = message;
                Ok(())
            }
            VersionedMessage::V2(message) => {
                let _: Message2 = message;
                Err("Should have been message v1.".to_owned())
            }
        }
    }

    #[test]
    fn unsupported_version() -> Result<(), String> {
        use model_1::*;

        let bytes = {
            use model_2::*;

            let versioned_message: VersionedMessage = Message3("test string".to_string()).into();
            versioned_message.encode_versioned()
        };

        let raw_string = "test string".encode();
        let decoded_message = VersionedMessage::decode_all_versioned(&bytes);
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
