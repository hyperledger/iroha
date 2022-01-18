use serde::{Deserialize, Serialize};
use smallstr::SmallString;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmallStr(SmallString<[u8; 32]>);

impl SmallStr {
    #[must_use]
    #[inline]
    pub fn from_str(s: &str) -> Self {
        Self(SmallString::from_str(s))
    }

    #[must_use]
    #[inline]
    pub fn from_string(s: String) -> Self {
        Self(SmallString::from_string(s))
    }
}
