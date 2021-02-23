use iroha_version_derive::{declare_versioned, version};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

declare_versioned!(VersionedMessage 2..1);

#[version(n = 1, versioned = "VersionedMessage")]
#[derive(Debug, Clone, Decode, Encode, Serialize, Deserialize)]
struct Message;

pub fn main() {}
