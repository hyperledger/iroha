#![allow(missing_docs)]

/// Docker Compose configuration generator for Iroha.
#[allow(clippy::struct_excessive_bools)]
#[derive(clap::Parser, Debug)]
pub struct Args {
    // TODO: optional peer configuration file / other ways to configure peers
    /// Number of peer services in the configuration.
    #[arg(long, short, value_name = "COUNT")]
    peers: std::num::NonZeroU16,
    /// UTF-8 seed for deterministic key-generation.
    #[arg(long, short)]
    seed: Option<String>,
    /// Includes a healthcheck for every service in the configuration.
    ///
    /// Healthchecks use predefined settings.
    ///
    /// For more details on healthcheck configuration in Docker Compose files, see:
    /// <https://docs.docker.com/compose/compose-file/compose-file-v3/#healthcheck>
    #[arg(long, short = 'H')]
    healthcheck: bool,
    /// Directory with Iroha configuration.
    /// It will be mapped to a volume for each container.
    ///
    /// The directory should contain `genesis.json` and the executor.
    #[arg(long, short, value_name = "DIR")]
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
    #[arg(long, short, value_name = "NAME")]
    image: String,
    /// Build the image from the Dockerfile in the specified directory.
    /// Do not rebuild if the image has been cached.
    ///
    /// The provided path is resolved relative to the current working directory.
    #[arg(long, short, value_name = "DIR")]
    build: Option<std::path::PathBuf>,
    /// Always pull or rebuild the image even if it is cached locally.
    #[arg(long, short = 'C')]
    no_cache: bool,
    /// Path to the target Compose configuration file.
    ///
    /// If the file exists, the app will prompt its overwriting. If the TTY is not
    /// interactive, the app will stop execution with a non-zero exit code.
    /// To overwrite the file anyway, pass the `--force` flag.
    #[arg(long, short, value_name = "FILE")]
    out_file: std::path::PathBuf,
    /// Print the generated configuration to stdout
    /// instead of writing it to the target file.
    #[arg(long, short = 'P', conflicts_with = "force")]
    print: bool,
    /// Overwrite the target file if it already exists.
    #[arg(long, short = 'F')]
    force: bool,
    /// Do not include the banner with the generation notice in the file.
    ///
    /// The banner includes the passed arguments in order to help with reproducibility.
    #[arg(long, short = 'B')]
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

    if !args.print && !args.user_allows_overwrite()? {
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

    let (mut stdout, mut file);

    let writer: &mut dyn std::io::Write = if args.print {
        stdout = std::io::stdout();
        &mut stdout
    } else {
        file = std::fs::File::create(&args.out_file)?;
        &mut file
    };

    schema.write(
        &mut std::io::BufWriter::new(writer),
        (!args.no_banner).then_some(&[
            &std::env::args().collect::<Vec<_>>().join(" "),
            "",
            "This configuration has been generated by `iroha_swarm` using the above settings.",
            "You should not edit this manually.",
        ]),
    )?;

    if !args.print {
        args.log_file_mode_complete(swarm.absolute_target_path());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Error;

    use super::Args;

    fn parse(args: &str) -> Result<Args, Error> {
        <Args as clap::Parser>::try_parse_from(args.split(' '))
    }

    #[test]
    fn ok_with_flags() {
        assert!(parse(
            "swarm \
            -p 20 \
            -c ./config \
            -i hyperledger/iroha \
            -o sample.yml\
            -HCFB",
        )
        .is_ok())
    }

    #[test]
    fn cannot_mix_print_and_force() {
        assert!(parse(
            "swarm \
            -p 20 \
            -c ./config \
            -i hyperledger/iroha \
            -o sample.yml\
            -PF",
        )
        .is_err())
    }

    #[test]
    fn ok_when_pull_image() {
        assert!(parse(
            "swarm \
            -p 20 \
            -c ./config \
            -i hyperledger/iroha \
            -o sample.yml",
        )
        .is_ok())
    }

    #[test]
    fn ok_when_build_image() {
        assert!(parse(
            "swarm \
            -p 20 \
            -i hyperledger/iroha \
            -b . \
            -c ./config \
            -o sample.yml",
        )
        .is_ok())
    }

    #[test]
    fn fails_when_image_is_omitted() {
        assert!(parse(
            "swarm \
            -p 1 \
            -o test.yml \
            -c ./",
        )
        .is_err())
    }
}
