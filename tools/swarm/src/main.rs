#![allow(missing_docs)]

mod cli;
mod compose;
mod ui;
mod util;

use clap::Parser;
use cli::Cli;
use color_eyre::{eyre::Context, Result};
use util::AbsolutePath;

use crate::{cli::SourceParsed, compose::ResolvedImageSource};

fn main() -> Result<()> {
    color_eyre::install()?;

    #[allow(unused_variables)]
    let Cli {
        peers,
        seed,
        force,
        no_banner,
        source: image_source,
        out_file: target_file_raw,
        config_dir: config_dir_raw,
        health_check,
        key_pair,
        signature,
    } = Cli::parse();

    let seed = seed.map(String::into_bytes);
    let seed = seed.as_deref();

    let image_source: ResolvedImageSource = {
        let parsed: SourceParsed = image_source.into();
        parsed
            .try_into()
            .wrap_err("Failed to resolve the source of image")?
    };

    let target_file = AbsolutePath::absolutize(&target_file_raw)?;
    let config_dir = AbsolutePath::absolutize(&config_dir_raw)?;

    if target_file.exists() && !force {
        if let ui::PromptAnswer::No = ui::prompt_remove_target_file(&target_file)? {
            return Ok(());
        }
    }

    let banner_enabled = !no_banner;

    compose::DockerComposeBuilder {
        target_file: &target_file,
        config_dir: &config_dir,
        image_source,
        peers,
        seed,
        health_check,
        key_pair,
        signature,
    }
    .build_and_write(banner_enabled)?;

    ui::log_file_mode_complete(&target_file, &target_file_raw);

    Ok(())
}
