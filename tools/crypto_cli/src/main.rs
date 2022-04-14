//! `iroha_crypto_cli` is a command line tool used to generate keys for Iroha peers and clients.

use clap::{App, Arg, ArgGroup};
use color_eyre::{
    eyre::{self, eyre, WrapErr},
    Report, Result,
};
use iroha_crypto::{Algorithm, KeyGenConfiguration, KeyPair, PrivateKey};

fn main() -> Result<(), Report> {
    color_eyre::install()?;
    let default_algorithm = Algorithm::default().to_string();
    let matches = App::new("iroha_crypto_cli")
        .version("0.1")
        .author("Soramitsu")
        .about("iroha_crypto_cli is a command line tool used to generate keys for Iroha peers and clients.")
        .arg(
            Arg::with_name("seed")
                .long("seed")
                .value_name("seed")
                .help("Sets a seed for random number generator. Should be used separately from `private_key`.")
                .required(false)
                .takes_value(true)
        )
        .arg(
            Arg::with_name("private_key")
                .long("private_key")
                .value_name("private_key")
                .help("Sets a private key. Should be used separately from `seed`.")
                .required(false)
                .takes_value(true)
        )
        .arg(
            Arg::with_name("algorithm")
                .long("algorithm")
                .value_name("algorithm")
                .help("Function used to generate the key pair.")
                .takes_value(true)
                .possible_value(&Algorithm::Ed25519.to_string())
                .possible_value(&Algorithm::Secp256k1.to_string())
                .possible_value(&Algorithm::BlsNormal.to_string())
                .possible_value(&Algorithm::BlsSmall.to_string())
                .default_value(&default_algorithm)
        )
        .arg(
            Arg::with_name("json")
            .long("json")
            .help("If specified the output will be formatted as json.")
            .takes_value(false)
            .multiple(false)
        )
        .group(
            ArgGroup::with_name("key_gen_options")
                .args(&["seed", "private_key"])
                .required(false)
                .multiple(false)
        )
        .get_matches();
    let seed_option = matches.value_of("seed");
    let private_key_option = matches.value_of("private_key");
    let algorithm = matches
        .value_of("algorithm")
        .ok_or_else(|| eyre!("Failed to get algorithm name."))?
        .parse::<Algorithm>()
        .wrap_err("Failed to parse algorithm.")?;
    let key_gen_configuration = KeyGenConfiguration::default().with_algorithm(algorithm);
    let keypair: KeyPair = seed_option.map_or_else(
        || -> eyre::Result<_> {
            private_key_option.map_or_else(
                || {
                    KeyPair::generate_with_configuration(key_gen_configuration.clone())
                        .wrap_err("failed to generate key pair")
                },
                |private_key| {
                    KeyPair::generate_with_configuration(
                        key_gen_configuration.clone().use_private_key(
                            PrivateKey::from_hex(algorithm, &private_key)
                                .wrap_err("Failed to decode private key.")?,
                        ),
                    )
                    .wrap_err("Failed to generate key pair")
                },
            )
        },
        |seed| -> eyre::Result<_> {
            KeyPair::generate_with_configuration(
                key_gen_configuration
                    .clone()
                    .use_seed(seed.as_bytes().into()),
            )
            .wrap_err("Failed to generate key pair")
        },
    )?;

    #[allow(clippy::print_stdout)]
    if matches.is_present("json") {
        let json =
            serde_json::to_string_pretty(&keypair).wrap_err("Failed to serialize to json.")?;
        println!("{}", json);
    } else {
        println!("Public key (multihash): {}", keypair.public_key());
        println!("Private key: {}", keypair.private_key());
        println!(
            "Digest function: {}",
            keypair.public_key().digest_function()
        );
    }

    Ok(())
}
