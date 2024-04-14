use clap::{builder::PossibleValue, ArgGroup, ValueEnum};
use color_eyre::eyre::WrapErr as _;
use iroha_crypto::{Algorithm, KeyPair, PrivateKey};

use super::*;

/// Use `Kagami` to generate cryptographic key-pairs.
#[derive(ClapArgs, Clone, Debug)]
#[command(group = ArgGroup::new("generate_from").required(false))]
#[command(group = ArgGroup::new("format").required(false))]
pub struct Args {
    /// An algorithm to use for the key-pair generation
    #[clap(default_value_t, long, short)]
    pub algorithm: AlgorithmArg,
    /// A private key to generate the key-pair from
    ///
    /// `--private-key` specifies the payload of the private key, while `--algorithm`
    /// specifies its algorithm.
    #[clap(long, short, group = "generate_from")]
    pub private_key: Option<String>,
    /// The Unicode `seed` string to generate the key-pair from
    #[clap(long, short, group = "generate_from")]
    pub seed: Option<String>,
    /// Output the key-pair in JSON format
    #[clap(long, short, group = "format")]
    pub json: bool,
    /// Output the key-pair without additional text
    #[clap(long, short, group = "format")]
    pub compact: bool,
}

#[derive(Clone, Debug, Default, derive_more::Display)]
pub struct AlgorithmArg(pub Algorithm);

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

        let key_pair = match (self.seed, self.private_key) {
            (None, None) => KeyPair::random_with_algorithm(algorithm),
            (None, Some(private_key_hex)) => {
                let private_key = PrivateKey::from_hex(algorithm, private_key_hex)
                    .wrap_err("Failed to decode private key")?;
                KeyPair::from(private_key)
            }
            (Some(seed), None) => {
                let seed: Vec<u8> = seed.as_bytes().into();
                KeyPair::from_seed(seed, algorithm)
            }
            _ => unreachable!("Clap group invariant"),
        };

        Ok(key_pair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_arg_displays_as_algorithm() {
        assert_eq!(
            format!("{}", AlgorithmArg(Algorithm::Ed25519)),
            format!("{}", Algorithm::Ed25519)
        )
    }
}
