use clap::{builder::PossibleValue, ArgGroup, ValueEnum};
use color_eyre::eyre::WrapErr as _;
use iroha_crypto::{Algorithm, KeyGenConfiguration, KeyPair, PrivateKey};

use super::*;

/// Use `Kagami` to generate cryptographic key-pairs.
#[derive(ClapArgs, Debug, Clone)]
#[command(group = ArgGroup::new("generate_from").required(false))]
#[command(group = ArgGroup::new("format").required(false))]
pub struct Args {
    /// The algorithm to use for the key-pair generation
    #[clap(default_value_t, long, short)]
    algorithm: AlgorithmArg,
    /// The `private_key` to generate the key-pair from
    #[clap(long, short, group = "generate_from")]
    private_key: Option<String>,
    /// The Unicode `seed` string to generate the key-pair from
    #[clap(long, short, group = "generate_from")]
    seed: Option<String>,
    /// Output the key-pair in JSON format
    #[clap(long, short, group = "format")]
    json: bool,
    /// Output the key-pair without additional text
    #[clap(long, short, group = "format")]
    compact: bool,
}

#[derive(Clone, Debug, Default, derive_more::Display)]
struct AlgorithmArg(Algorithm);

impl ValueEnum for AlgorithmArg {
    fn value_variants<'a>() -> &'a [Self] {
        // TODO: add compile-time check to ensure all variants are enumerated
        &[
            Self(Algorithm::Ed25519),
            Self(Algorithm::Secp256k1),
            Self(Algorithm::BlsNormal),
            Self(Algorithm::BlsSmall),
        ]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(self.0.as_static_str().into())
    }
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        if self.json {
            let key_pair = self.key_pair()?;
            let output =
                serde_json::to_string_pretty(&key_pair).wrap_err("Failed to serialise to JSON.")?;
            writeln!(writer, "{output}")?;
        } else if self.compact {
            let key_pair = self.key_pair()?;
            writeln!(writer, "{}", &key_pair.public_key())?;
            writeln!(writer, "{}", &key_pair.private_key())?;
            writeln!(writer, "{}", &key_pair.public_key().algorithm())?;
        } else {
            let key_pair = self.key_pair()?;
            writeln!(
                writer,
                "Public key (multihash): \"{}\"",
                &key_pair.public_key()
            )?;
            writeln!(
                writer,
                "Private key ({}): \"{}\"",
                &key_pair.public_key().algorithm(),
                &key_pair.private_key()
            )?;
        }
        Ok(())
    }
}

impl Args {
    fn key_pair(self) -> color_eyre::Result<KeyPair> {
        let algorithm = self.algorithm.0;
        let config = KeyGenConfiguration::default().with_algorithm(algorithm);

        let key_pair = match (self.seed, self.private_key) {
            (None, None) => KeyPair::generate_with_configuration(config),
            (None, Some(private_key_hex)) => {
                let private_key = PrivateKey::from_hex(algorithm, private_key_hex.as_ref())
                    .wrap_err("Failed to decode private key")?;
                KeyPair::generate_with_configuration(config.use_private_key(private_key))
            }
            (Some(seed), None) => {
                let seed: Vec<u8> = seed.as_bytes().into();
                KeyPair::generate_with_configuration(config.use_seed(seed))
            }
            _ => unreachable!("Clap group invariant"),
        }
        .wrap_err("Failed to generate key pair")?;

        Ok(key_pair)
    }
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, AlgorithmArg};

    #[test]
    fn algorithm_arg_displays_as_algorithm() {
        assert_eq!(
            format!("{}", AlgorithmArg(Algorithm::Ed25519)),
            format!("{}", Algorithm::Ed25519)
        )
    }
}
