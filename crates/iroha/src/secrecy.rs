use std::fmt;

use derive_more::Constructor;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Clone, Deserialize, Constructor)]
pub struct SecretString(String);

impl SecretString {
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

const REDACTED: &str = "[REDACTED]";

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        REDACTED.serialize(serializer)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        REDACTED.fmt(f)
    }
}
