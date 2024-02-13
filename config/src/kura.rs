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
pub enum Mode {
    /// Strict validation of all blocks.
    #[default]
    Strict,
    /// Fast initialization with basic checks.
    Fast,
}

#[cfg(test)]
mod tests {
    use crate::kura::Mode;

    #[test]
    fn init_mode_display_reprs() {
        assert_eq!(format!("{}", Mode::Strict), "strict");
        assert_eq!(format!("{}", Mode::Fast), "fast");
        assert_eq!("strict".parse::<Mode>().unwrap(), Mode::Strict);
        assert_eq!("fast".parse::<Mode>().unwrap(), Mode::Fast);
    }
}
