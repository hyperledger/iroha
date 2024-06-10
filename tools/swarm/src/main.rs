#![allow(missing_docs)]

/// Docker Compose peer configuration generator for Iroha.
#[allow(clippy::struct_excessive_bools)]
#[derive(clap::Parser, Debug)]
pub struct Args {
    // TODO: optional peer configuration file / other ways to configure peers
    /// Number of peer services in the configuration.
    #[arg(long, short)]
    peers: std::num::NonZeroU16,
    /// The Unicode `seed` string for deterministic key-generation.
    #[arg(long, short)]
    seed: Option<String>,
    /// Includes a healthcheck for every service in the configuration.
    ///
    /// The healthchecks use predefined settings.
    ///
    /// For more details on healthcheck configurations in Docker Compose files, visit:
    /// <https://docs.docker.com/compose/compose-file/compose-file-v3/#healthcheck>
    #[arg(long)]
    healthcheck: bool,
    /// Path to a directory with Iroha configuration.
    /// It will be mapped to a volume for each container.
    ///
    /// The directory should contain `genesis.json` and the executor.
    #[arg(long, short)]
    config_dir: std::path::PathBuf,
    /// Docker image used by the peer services.
    ///
    /// By default, the image is pulled from Docker Hub if not cached.
    /// Pass the `--build` option to build the image from a Dockerfile instead.
    ///
    /// **Note**: Swarm only guarantees that the Docker Compose configuration it generates
    /// is compatible with the same Git revision it is built from itself. Therefore, if the
    /// specified image is not compatible with the version of Swarm you are running,
    /// the generated configuration might not work.
    #[arg(long)]
    image: String,
    /// Build the image from the Dockerfile in the specified directory.
    /// Do not rebuild if the image has been cached.
    ///
    /// The provided path is resolved relative to the current working directory.
    #[arg(long, value_name = "PATH")]
    build: Option<std::path::PathBuf>,
    /// Always pull or rebuild the image even if it is cached locally.
    #[arg(long)]
    no_cache: bool,
    /// Path to the generated configuration.
    ///
    /// If file exists, the app will prompt its overwriting. If the TTY is not
    /// interactive, the app will stop execution with a non-zero exit code.
    /// To overwrite the file anyway, pass the `--force` flag.
    #[arg(long, short)]
    out_file: std::path::PathBuf,
    /// Overwrite the target file if it already exists.
    #[arg(long)]
    force: bool,
    /// Disable the banner in the file saying that the file is generated.
    ///
    /// It includes all passed arguments in order to help with reproducibility.
    #[arg(long)]
    no_banner: bool,
}

impl Args {
    /// If this returns `Ok(true)`, then Swarm is allowed to proceed.
    fn user_allows_overwrite(&self) -> Result<bool, inquire::InquireError> {
        if self.out_file.exists() && !self.force {
            use owo_colors::OwoColorize;
            return inquire::Confirm::new(&format!(
                "File {} already exists. Overwrite it?",
                self.out_file.display().blue().bold()
            ))
            .with_help_message("Pass the `--force` flag to overwrite the file anyway.")
            .with_default(false)
            .prompt();
        }
        Ok(true)
    }

    fn log_file_mode_complete(&self, absolute_path: &std::path::Path) {
        use owo_colors::OwoColorize;
        let relative_path = &self.out_file;
        println!(
            "✓ Docker compose configuration is ready at:\n\n    {}\
                    \n\n  You could run `{} {} {}`",
            absolute_path.display().green().bold(),
            "docker compose -f".blue(),
            relative_path.display().blue().bold(),
            "up".blue(),
        );
    }
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let args: Args = <Args as clap::Parser>::parse();
    if !args.user_allows_overwrite()? {
        return Ok(());
    }

    let swarm = iroha_swarm::Swarm::new(
        args.peers,
        args.seed.as_deref().map(str::as_bytes),
        args.healthcheck,
        &args.config_dir,
        &args.image,
        args.build.as_deref(),
        args.no_cache,
        &args.out_file,
    )?;
    let schema = swarm.build();
    let mut target_file = std::fs::File::create(&args.out_file)?;
    schema.write(&mut target_file, !args.no_banner)?;

    args.log_file_mode_complete(swarm.absolute_target_path());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Args;

    fn parse(args: &str) {
        <Args as clap::Parser>::try_parse_from(args.split(' ')).expect("parse should succeed");
    }

    #[test]
    fn ok_when_pull_image() {
        parse(
            "-p 20 \
            --image hyperledger/iroha \
            --config-dir ./config \
            --out-file sample.yml",
        )
    }

    #[test]
    fn ok_when_build_image() {
        parse(
            "-p 20 \
            --image hyperledger/iroha \
            --build . \
            --config-dir ./config \
            --out-file sample.yml",
        )
    }

    #[test]
    fn fails_when_image_is_omitted() {
        parse(
            "-p 1 \
            --out-file test.yml \
            --config-dir ./",
        )
    }
}
