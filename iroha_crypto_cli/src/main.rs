use clap::{App, Arg, ArgGroup};
use iroha_crypto::{Algorithm, KeyGenConfiguration, KeyPair, PrivateKey};

fn main() {
    let default_algorithm = Algorithm::default().to_string();
    let matches = App::new("iroha_crypto_cli")
        .version("0.1")
        .author("Soramitsu")
        .about("iroha_crypto_cli is a command line arguments wrapper around `Ursa`.")
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
                .default_value(&default_algorithm)
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
    let key_gen_configuration = KeyGenConfiguration::default().with_algorithm(algorithm.clone());
    let keypair = if let Some(seed) = seed_option {
        KeyPair::generate_with_configuration(key_gen_configuration.use_seed(seed.as_bytes().into()))
    } else if let Some(private_key) = private_key_option {
        KeyPair::generate_with_configuration(key_gen_configuration.use_private_key(PrivateKey {
            digest_function: algorithm.to_string(),
            payload: hex::decode(private_key).expect("Failed to decode private key."),
        }))
    } else {
        KeyPair::generate_with_configuration(key_gen_configuration)
    }
    .expect("Failed to generate keypair.");
    println!("Public key (multihash): {}", &keypair.public_key);
    println!("Private key: {}", &keypair.private_key);
    println!("Digest function: {}", &keypair.public_key.digest_function)
}
