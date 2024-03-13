//! Configuration tools related to Kura specifically.

// use iroha_config_base::{impl_deserialize_from_str, impl_serialize_display};

use serde_with::{DeserializeFromStr, SerializeDisplay};

/// Kura initialization mode.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    strum::EnumString,
    strum::Display,
    DeserializeFromStr,
    SerializeDisplay,
)]
#[strum(serialize_all = "snake_case")]
pub enum InitMode {
    /// Strict validation of all blocks.
    #[default]
    Strict,
    /// Fast initialization with basic checks.
    Fast,
}

#[cfg(test)]
mod tests {
    use crate::kura::InitMode;

    #[test]
    fn init_mode_display_reprs() {
        assert_eq!(format!("{}", InitMode::Strict), "strict");
        assert_eq!(format!("{}", InitMode::Fast), "fast");
        assert_eq!("strict".parse::<InitMode>().unwrap(), InitMode::Strict);
        assert_eq!("fast".parse::<InitMode>().unwrap(), InitMode::Fast);
    }
}
