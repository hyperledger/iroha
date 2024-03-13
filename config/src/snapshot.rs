//! Configuration related to Snapshot specifically

/// Functioning mode of the Snapshot Iroha module
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    strum::Display,
    strum::EnumString,
    serde_with::SerializeDisplay,
    serde_with::DeserializeFromStr,
)]
#[strum(serialize_all = "snake_case")]
pub enum Mode {
    /// Read the snapshot on startup, update periodically
    #[default]
    Normal,
    /// Read the snapshot on startup, do not update
    Readonly,
    /// Do not read or write the snapshot
    Disabled,
}

#[cfg(test)]
mod tests {
    use crate::snapshot::Mode;

    #[test]
    fn mode_display_form() {
        assert_eq!(
            format!("{} {} {}", Mode::Normal, Mode::Readonly, Mode::Disabled),
            "normal readonly disabled"
        );
    }
}
