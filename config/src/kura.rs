use iroha_config_base::{impl_deserialize_from_str, impl_serialize_display};
use serde::Serializer;

/// Kura initialization mode.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, parse_display::Display, parse_display::FromStr,
)]
#[display(style = "snake_case")]
pub enum Mode {
    /// Strict validation of all blocks.
    #[default]
    Strict,
    /// Fast initialization with basic checks.
    Fast,
}

impl_serialize_display!(Mode);
impl_deserialize_from_str!(Mode);

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
