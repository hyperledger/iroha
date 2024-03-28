use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::{builder::PossibleValue, ArgGroup, Subcommand, ValueEnum};
use color_eyre::{
    eyre::{eyre, WrapErr as _},
    Result,
};
use iroha_crypto::{Algorithm, KeyPair, PrivateKey};
use iroha_data_model::ChainId;
use iroha_genesis::{GenesisNetwork, RawGenesisBlock};
use parity_scale_codec::Encode;

use super::*;

const ED25519_PREFIX: &str = "ed0120";

#[derive(Subcommand, Debug, Clone)]
pub enum Args {
    SignTransaction(SignGenesisArgs),
    GenerateKeyPair(GenerateKeyPairArgs),
}

/// Use `Kagami` to sign genesis block.
#[derive(ClapArgs, Clone, Debug)]
#[command(group = ArgGroup::new("private_key").required(true))]
#[command(group = ArgGroup::new("public_key").required(true))]
#[command(group = ArgGroup::new("format").required(false))]
pub struct SignGenesisArgs {
    /// The algorithm of the provided keypair
    #[clap(default_value_t, long, short)]
    algorithm: AlgorithmArg,
    /// Private key (in string format) to sign genesis block
    #[clap(long, group = "private_key")]
    private_key_string: Option<String>,
    /// Path to private key to sign genesis block
    #[clap(long, group = "private_key")]
    private_key_file: Option<PathBuf>,
    /// Public key in multihash format of the corresponding private key
    #[clap(long, group = "public_key")]
    public_key_string: Option<String>,
    /// Path to public key in multihash format of the corresponding private key
    #[clap(long, group = "public_key")]
    public_key_file: Option<PathBuf>,
    /// Path to json-serialized keypair
    #[clap(long, short, group = "private_key", group = "public_key")]
    keypair_file: Option<PathBuf>,
    /// Unique id of blockchain
    #[clap(long)]
    chain_id: ChainId,
    /// Path to genesis json file
    #[clap(long, short)]
    genesis_file: PathBuf,
    /// Output signed genesis block in JSON format
    #[clap(long, short, default_value_t = true, group = "format")]
    json: bool,
    /// Encode signed genesis block with SCALE (it is only supported with file output)
    #[clap(long, short, default_value_t = false, group = "format")]
    scale: bool,
    /// Path to signed genesis output file (stdout by default)
    #[clap(long, short)]
    out_file: Option<PathBuf>,
}

#[derive(Debug)]
enum KeyStorage<'a> {
    FromFile(Vec<u8>),
    FromCLI(&'a str),
}

fn get_key_raw<'a, P: AsRef<Path>>(
    path: &Option<P>,
    value: &'a Option<String>,
) -> Result<KeyStorage<'a>, std::io::Error> {
    match (path, value) {
        (Some(path_buf), None) => Ok(KeyStorage::FromFile(fs::read(path_buf)?)),
        (None, Some(hex)) => Ok(KeyStorage::FromCLI(hex.as_str())),
        _ => unreachable!("Clap group invariant"),
    }
}

fn read_keypair<P: AsRef<Path>>(path: P) -> Result<KeyPair> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(bytes.as_slice())?)
}

impl SignGenesisArgs {
    fn get_private_key(&self) -> Result<PrivateKey> {
        let private_key_bytes = get_key_raw(&self.private_key_file, &self.private_key_string)?;
        match private_key_bytes {
            KeyStorage::FromFile(bytes) => {
                PrivateKey::from_bytes(self.algorithm.0, bytes.as_slice()).wrap_err_with(|| {
                    eyre!(
                        "Failed to parse private key from bytes for algorithm `{}`",
                        self.algorithm
                    )
                })
            }
            KeyStorage::FromCLI(hex) => {
                PrivateKey::from_hex(self.algorithm.0, hex).wrap_err_with(|| {
                    eyre!(
                        "Failed to parse private key from hex for algorithm `{}`",
                        self.algorithm
                    )
                })
            }
        }
    }

    fn get_public_key(&self) -> Result<PublicKey> {
        let public_key_bytes = get_key_raw(&self.public_key_file, &self.public_key_string)?;
        match public_key_bytes {
            KeyStorage::FromFile(bytes) => {
                PublicKey::from_bytes(self.algorithm.0, bytes.as_slice()).wrap_err_with(|| {
                    eyre!(
                        "Failed to parse public key from bytes for algorithm `{}`",
                        self.algorithm
                    )
                })
            }
            KeyStorage::FromCLI(hex) => {
                if hex.starts_with(ED25519_PREFIX) {
                    PublicKey::from_str(hex).wrap_err_with(|| {
                        eyre!(
                            "Failed to deserialize public key from hex for algorithm `{}`",
                            self.algorithm
                        )
                    })
                } else {
                    PublicKey::from_hex(self.algorithm.0, hex).wrap_err_with(|| {
                        eyre!(
                            "Failed to parse public key from hex for algorithm `{}`",
                            self.algorithm
                        )
                    })
                }
            }
        }
    }
}

impl<T: Write> RunArgs<T> for SignGenesisArgs {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let key_pair = if let Some(path) = self.keypair_file {
            read_keypair(path)?
        } else {
            let (public_key, private_key) = (self.get_public_key()?, self.get_private_key()?);
            KeyPair::new(public_key, private_key)?
        };

        let genesis_block = RawGenesisBlock::from_path(&self.genesis_file)?;
        let genesis_network = GenesisNetwork::new(genesis_block, &self.chain_id, &key_pair);

        let encoded_genesis_network = if self.scale {
            genesis_network.encode()
        } else {
            Vec::default()
        };

        let json_genesis_network = if self.json {
            serde_json::to_string_pretty(&genesis_network)
                .wrap_err("Failed to serialise genesis network to JSON.")?
        } else {
            String::default()
        };

        if let Some(path) = self.out_file {
            if self.scale {
                fs::write(&path, encoded_genesis_network)?;
            } else {
                fs::write(&path, json_genesis_network)?;
            }

            writeln!(
                writer,
                "Genesis was successfully signed and written to `{}`",
                path.display()
            )?;
        } else if self.scale {
            writeln!(
                writer,
                "SCALE encoded data is not supported for console outputs."
            )?;
        } else {
            writeln!(writer, "{json_genesis_network}")?;
        }

        Ok(())
    }
}

/// Use `Kagami` to generate cryptographic key-pairs.
#[derive(ClapArgs, Clone, Debug)]
#[command(group = ArgGroup::new("generate_from").required(false))]
#[command(group = ArgGroup::new("format").required(false))]
pub struct GenerateKeyPairArgs {
    /// An algorithm to use for the key-pair generation
    #[clap(default_value_t, long, short)]
    algorithm: AlgorithmArg,
    /// A private key to generate the key-pair from
    ///
    /// `--private-key` specifies the payload of the private key, while `--algorithm`
    /// specifies its algorithm.
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

impl<T: Write> RunArgs<T> for GenerateKeyPairArgs {
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

impl GenerateKeyPairArgs {
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
    use parity_scale_codec::Decode;

    use super::*;

    #[test]
    fn algorithm_arg_displays_as_algorithm() {
        assert_eq!(
            format!("{}", AlgorithmArg(Algorithm::Ed25519)),
            format!("{}", Algorithm::Ed25519)
        )
    }

    const GENESIS_JSON_PATH: &str = "../../configs/swarm/genesis.json";
    const GEN_KEYPAIR_JSON_PATH: &str = "test_keypair_path_for_crypt0_genesis_kagami.json";
    const GEN_SIGNED_ENCODED_GENESIS_PATH: &str =
        "test_signed_encoded_genesis_path_for_crypt0_genesis_kagami";

    fn genesis_signing_works() -> Result<bool> {
        let keypair_config = GenerateKeyPairArgs {
            algorithm: AlgorithmArg::default(),
            private_key: None,
            seed: None,
            json: true,
            compact: false,
        };

        let mut keypair_json = BufWriter::new(Vec::new());
        keypair_config.run(&mut keypair_json)?;
        let keypair: KeyPair = serde_json::from_slice(keypair_json.buffer())?;

        fs::write(GEN_KEYPAIR_JSON_PATH, keypair_json.buffer())?;

        let chain_id = ChainId::from("0123456");
        let crypto_genesis_config = SignGenesisArgs {
            algorithm: AlgorithmArg::default(),
            private_key_string: None,
            private_key_file: None,
            public_key_string: None,
            public_key_file: None,
            keypair_file: Some(PathBuf::from_str(GEN_KEYPAIR_JSON_PATH)?),
            chain_id: chain_id.clone(),
            genesis_file: PathBuf::from_str(GENESIS_JSON_PATH)?,
            out_file: Some(PathBuf::from_str(GEN_SIGNED_ENCODED_GENESIS_PATH)?),
            scale: true,
            json: false,
        };

        let mut genesis_buf_writer = BufWriter::new(Vec::new());

        crypto_genesis_config.run(&mut genesis_buf_writer)?;

        let raw_genesis = RawGenesisBlock::from_path(GENESIS_JSON_PATH)?;
        let signed_genesis_manually = GenesisNetwork::new(raw_genesis, &chain_id, &keypair);

        let signed_genesis_from_file_encoded = fs::read(GEN_SIGNED_ENCODED_GENESIS_PATH)?;
        let maybe_signed_genesis_from_file: GenesisNetwork =
            GenesisNetwork::decode(&mut signed_genesis_from_file_encoded.as_slice())?;

        Ok(signed_genesis_manually
            .into_transactions()
            .into_iter()
            .zip(
                maybe_signed_genesis_from_file
                    .into_transactions()
                    .into_iter(),
            )
            .all(|(a, b)| {
                a.0.metadata() == b.0.metadata()
                    && a.0.authority() == b.0.authority()
                    && a.0.chain_id() == b.0.chain_id()
                    && a.0.time_to_live() == b.0.time_to_live()
                    && a.0.instructions() == b.0.instructions()
                    && a.0.nonce() == b.0.nonce()
                    && a.0.signatures() == b.0.signatures()
            }))
    }

    #[test]
    fn test_genesis_signing_works() {
        let result = genesis_signing_works();
        let _ = fs::remove_file(GEN_KEYPAIR_JSON_PATH);
        let _ = fs::remove_file(GEN_SIGNED_ENCODED_GENESIS_PATH);
        assert!(result.is_ok_and(|result| result));
    }
}
