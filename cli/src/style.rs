//! Style and colouration of Iroha CLI outputs.
use owo_colors::{OwoColorize, Style};

/// Styling information set at run-time for pretty-printing with colour
#[derive(Clone, Copy, Debug)]
pub struct Styling {
    /// Positive highlight
    pub positive: Style,
    /// Negative highlight. Usually error message.
    pub negative: Style,
    /// Neutral highlight
    pub highlight: Style,
    /// Minor message
    pub minor: Style,
}

impl Default for Styling {
    fn default() -> Self {
        Self {
            positive: Style::new().green().bold(),
            negative: Style::new().red().bold(),
            highlight: Style::new().bold(),
            minor: Style::new().green(),
        }
    }
}

/// Determine if message colourisation is to be enabled
pub fn should_disable_color() -> bool {
    supports_color::on(supports_color::Stream::Stdout).is_none()
        || std::env::var("TERMINAL_COLORS")
            .map(|s| !s.as_str().parse().unwrap_or(true))
            .unwrap_or(false)
}

impl Styling {
    #[must_use]
    /// Constructor
    pub fn new() -> Self {
        if should_disable_color() {
            Self::no_color()
        } else {
            Self::default()
        }
    }

    fn no_color() -> Self {
        Self {
            positive: Style::new(),
            negative: Style::new(),
            highlight: Style::new(),
            minor: Style::new(),
        }
    }

    /// Produce documentation for argument group
    pub fn or(&self, arg_group: &[&str; 2]) -> String {
        format!(
            "`{}` (short `{}`)",
            arg_group[0].style(self.positive),
            arg_group[1].style(self.minor)
        )
    }

    /// Convenience method for ".json or .json5" pattern
    pub fn with_json_file_ext(&self, name: &str) -> String {
        let json = format!("{name}.json");
        let json5 = format!("{name}.json5");
        format!(
            "`{}` or `{}`",
            json.style(self.highlight),
            json5.style(self.highlight)
        )
    }
}
