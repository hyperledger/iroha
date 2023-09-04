use std::path::Path;

use color_eyre::Help;
use owo_colors::OwoColorize;

use super::Result;
use crate::util::AbsolutePath;

pub enum PromptAnswer {
    Yes,
    No,
}

impl From<bool> for PromptAnswer {
    fn from(value: bool) -> Self {
        if value {
            Self::Yes
        } else {
            Self::No
        }
    }
}

pub fn prompt_remove_target_file(file: &AbsolutePath) -> Result<PromptAnswer> {
    inquire::Confirm::new(&format!(
        "File {} already exists. Remove it?",
        file.display().blue().bold()
    ))
    .with_default(false)
    .prompt()
    .suggestion("You can pass `--force` flag to remove the file anyway")
    .map(PromptAnswer::from)
}

pub fn log_file_mode_complete(file: &AbsolutePath, file_raw: &Path) {
    println!(
        "✓ Docker compose configuration is ready at:\n\n    {}\
                    \n\n  You could run `{} {} {}`",
        file.display().green().bold(),
        "docker compose -f".blue(),
        file_raw.display().blue().bold(),
        "up".blue(),
    );
}
