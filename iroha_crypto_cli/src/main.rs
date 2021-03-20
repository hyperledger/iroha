//! `iroha_crypto_cli` is a command line tool used to generate keys for Iroha peers and clients.

use clap::{App, Arg, ArgGroup};
use iroha_crypto::{Algorithm, KeyGenConfiguration, KeyPair, PrivateKey};

fn main() {
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
                .possible_value(iroha_crypto::ED_25519)
                .possible_value(iroha_crypto::SECP_256_K1)
                .possible_value(iroha_crypto::BLS_NORMAL)
                .possible_value(iroha_crypto::BLS_SMALL)
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
    let algorithm: Algorithm = matches
        .value_of("algorithm")
        .expect("Failed to get algorithm name.")
        .parse()
        .expect("Failed to parse algorithm.");
    let key_gen_configuration = KeyGenConfiguration::default().with_algorithm(algorithm);
    let keypair = seed_option
        .map_or_else(
            || {
                private_key_option.map_or_else(
                    || KeyPair::generate_with_configuration(key_gen_configuration.clone()),
                    |private_key| {
                        KeyPair::generate_with_configuration(
                            key_gen_configuration.clone().use_private_key(PrivateKey {
                                digest_function: algorithm.to_string(),
                                payload: hex::decode(private_key)
                                    .expect("Failed to decode private key."),
                            }),
                        )
                    },
                )
            },
            |seed| {
                KeyPair::generate_with_configuration(
                    key_gen_configuration
                        .clone()
                        .use_seed(seed.as_bytes().into()),
                )
            },
        )
        .expect("Failed to generate keypair.");
    if matches.is_present("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&keypair).expect("Failed to serialize to json.")
        )
    } else {
        println!("Public key (multihash): {}", &keypair.public_key);
        println!("Private key: {}", &keypair.private_key);
        println!("Digest function: {}", &keypair.public_key.digest_function)
    }
}
