//! Re-sign a Norito-framed genesis block with the configured genesis key.
use eyre::{Result, eyre};
use iroha_crypto::{Algorithm, KeyPair, PrivateKey, SignatureOf};
use iroha_data_model::block::{BlockSignature, SignedBlock};
use std::{
    env,
    fs::{self, File},
    io::Read as _,
    path::{Path, PathBuf},
};
const MAX_GENESIS_PRIVATE_KEY_FILE_BYTES: usize = 4 * 1024;
fn main() -> Result<()> {
    iroha_genesis::init_instruction_registry();
    let args = Args::parse()?;
    let key_pair = args.load_key_pair()?;
    let block = iroha_genesis::read_signed_genesis(&args.input)?;
    let resigned = resign_block(&block, &key_pair)?;
    let framed = resigned.encode_wire()?;
    if framed.len() > iroha_genesis::SIGNED_GENESIS_MAX_BYTES_V1 {
        return Err(eyre!(
            "re-signed genesis body is {} bytes, exceeding the {}-byte first-release limit",
            framed.len(),
            iroha_genesis::SIGNED_GENESIS_MAX_BYTES_V1
        ));
    }
    fs::write(&args.output, framed)?;
    println!(
        "event=genesis_resign input={} output={} signer={} old_signatures={} new_signatures=1",
        args.input.display(),
        args.output.display(),
        key_pair.public_key(),
        block.signatures().count()
    );
    Ok(())
}
struct Args {
    input: PathBuf,
    output: PathBuf,
    private_key: Option<String>,
    private_key_file: Option<PathBuf>,
    seed: Option<String>,
    algorithm: Algorithm,
}
impl Args {
    fn parse() -> Result<Self> {
        let mut input = None;
        let mut output = None;
        let mut private_key = None;
        let mut private_key_file = None;
        let mut seed = None;
        let mut algorithm = Algorithm::default();
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--input" => input = Some(next_value(&mut args, "--input")?.into()),
                "--output" => output = Some(next_value(&mut args, "--output")?.into()),
                "--private-key" => private_key = Some(next_value(&mut args, "--private-key")?),
                "--private-key-file" => {
                    private_key_file = Some(next_value(&mut args, "--private-key-file")?.into());
                }
                "--seed" => seed = Some(next_value(&mut args, "--seed")?),
                "--algorithm" => {
                    algorithm = next_value(&mut args, "--algorithm")?
                        .parse()
                        .map_err(|err| eyre!("invalid --algorithm: {err}"))?;
                }
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                other => return Err(eyre!("unknown argument: {other}")),
            }
        }
        let key_sources = [
            private_key.is_some(),
            private_key_file.is_some(),
            seed.is_some(),
        ]
        .into_iter()
        .filter(|enabled| *enabled)
        .count();
        if key_sources != 1 {
            return Err(eyre!(
                "pass exactly one of --private-key, --private-key-file, or --seed"
            ));
        }
        Ok(Self {
            input: input.ok_or_else(|| eyre!("missing --input"))?,
            output: output.ok_or_else(|| eyre!("missing --output"))?,
            private_key,
            private_key_file,
            seed,
            algorithm,
        })
    }
    fn load_key_pair(&self) -> Result<KeyPair> {
        match (&self.private_key, &self.private_key_file, &self.seed) {
            (Some(hex), None, None) => self.load_private_key_hex(hex),
            (None, Some(path), None) => {
                let hex = read_genesis_private_key_file(path)?;
                self.load_private_key_hex(hex.trim())
            }
            (None, None, Some(seed)) => {
                KeyPair::try_from_seed(seed.as_bytes().to_vec(), self.algorithm)
                    .map_err(|err| eyre!("derive seeded genesis key pair: {err}"))
            }
            _ => unreachable!("validated by Args::parse"),
        }
    }
    fn load_private_key_hex(&self, hex: &str) -> Result<KeyPair> {
        let private_key = PrivateKey::from_hex(self.algorithm, hex)
            .map_err(|err| eyre!("decode genesis private key: {err}"))?;
        KeyPair::from_private_key(private_key)
            .map_err(|err| eyre!("derive genesis key pair from private key: {err}"))
    }
}
fn read_genesis_private_key_file(path: &Path) -> Result<String> {
    let max_bytes_u64 =
        u64::try_from(MAX_GENESIS_PRIVATE_KEY_FILE_BYTES).expect("private-key file limit fits u64");
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| eyre!("inspect genesis private key file: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes_u64 {
        return Err(eyre!(
            "genesis private key must be a direct regular file of at most {MAX_GENESIS_PRIVATE_KEY_FILE_BYTES} bytes"
        ));
    }
    let mut file =
        File::open(path).map_err(|error| eyre!("open genesis private key file: {error}"))?;
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| eyre!("genesis private key file length does not fit usize"))?;
    let mut hex = String::with_capacity(capacity.saturating_add(1));
    file.by_ref()
        .take(metadata.len().saturating_add(1))
        .read_to_string(&mut hex)
        .map_err(|error| eyre!("read genesis private key file: {error}"))?;
    if hex.len() > MAX_GENESIS_PRIVATE_KEY_FILE_BYTES {
        return Err(eyre!(
            "genesis private key file exceeds the {MAX_GENESIS_PRIVATE_KEY_FILE_BYTES}-byte limit"
        ));
    }
    Ok(hex)
}
fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| eyre!("{flag} requires a value"))
        .and_then(|value| {
            if value.is_empty() {
                Err(eyre!("{flag} requires a non-empty value"))
            } else {
                Ok(value)
            }
        })
}
fn print_help() {
    println!(
        "Usage: genesis_resign --input genesis.signed.nrt --output fixed.nrt \\
         (--seed SEED | --private-key HEX | --private-key-file PATH) [--algorithm ed25519]"
    );
}
fn validate_resignable_genesis(block: &SignedBlock) -> Result<()> {
    if !block.header().is_genesis() {
        return Err(eyre!("refusing to re-sign a non-genesis block"));
    }
    if !block.has_results() {
        return Err(eyre!(
            "refusing to re-sign a resultless genesis proposal; materialize execution results first"
        ));
    }
    block
        .validate_output_merkle_cache()
        .map_err(|error| eyre!("invalid genesis execution outputs: {error}"))?;
    if block.output_results().any(|result| result.is_err()) {
        return Err(eyre!(
            "refusing to re-sign genesis containing rejected execution results"
        ));
    }
    let result_count = block.execution_outputs().len();
    let minimum_committed_fragments = u64::try_from(result_count)
        .map_err(|_| eyre!("genesis result count exceeds the canonical u64 range"))?;
    let actual_committed_fragments = block
        .committed_fragment_count()
        .ok_or_else(|| eyre!("genesis execution result is missing its committed fragment count"))?;
    if actual_committed_fragments < minimum_committed_fragments {
        return Err(eyre!(
            "refusing to re-sign genesis with committed fragment count {actual_committed_fragments}; minimum {minimum_committed_fragments} for {result_count} successful result rows"
        ));
    }
    Ok(())
}
fn resign_block(block: &SignedBlock, key_pair: &KeyPair) -> Result<SignedBlock> {
    validate_resignable_genesis(block)?;
    let mut resigned = block.clone();
    let signature = BlockSignature::new(
        0,
        SignatureOf::try_from_hash(key_pair.private_key(), resigned.hash())
            .map_err(|error| eyre!("sign canonical genesis block: {error}"))?,
    );
    resigned
        .replace_signatures(iroha_data_model::block::BlockSignatures::try_from_iter([
            signature,
        ])?)
        .map_err(|error| eyre!("replace genesis signatures: {error}"))?;
    Ok(resigned)
}
#[cfg(test)]
mod tests {
    use super::{MAX_GENESIS_PRIVATE_KEY_FILE_BYTES, read_genesis_private_key_file, resign_block};
    use iroha_crypto::KeyPair;
    use iroha_data_model::{
        account::AccountId,
        block::{
            SignedBlock,
            consensus::MAX_EXECUTED_BLOCK_WIRE_BYTES,
            execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
            output_budget::ExecutionOutputLimits,
        },
        transaction::{FeePaymentIntent, TransactionBuilder, TransactionResult},
        trigger::DataTriggerSequence,
    };
    /// Sign a one-transaction genesis proposal with `key`.
    fn genesis_proposal(key: &KeyPair) -> SignedBlock {
        let authority = AccountId::new(key.public_key().clone());
        let transaction = TransactionBuilder::new_genesis(
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .sign(key.private_key());
        SignedBlock::genesis(vec![transaction], key.private_key(), None, None)
    }
    /// Attach one successful network output with `committed_fragment_count`.
    fn attach_successful_output(block: &mut SignedBlock, committed_fragment_count: u64) {
        block
            .set_execution_outputs(
                vec![ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                    input_index: 0,
                    result: TransactionResult::new(Ok(DataTriggerSequence::default())),
                    completions: Vec::new(),
                })],
                committed_fragment_count,
                std::collections::BTreeMap::default(),
                Vec::new(),
                iroha_data_model::nexus::AxtPolicySnapshot::default(),
                std::collections::BTreeSet::default(),
                &ExecutionOutputLimits {
                    max_outputs: 16,
                    max_output_bytes: 1024 * 1024,
                    max_total_output_bytes: 4 * 1024 * 1024,
                    max_executed_wire_bytes: MAX_EXECUTED_BLOCK_WIRE_BYTES,
                },
            )
            .expect("attach executed genesis result");
    }
    #[test]
    fn private_key_reader_rejects_first_byte_over_limit() {
        let directory = tempfile::tempdir().expect("create private-key reader directory");
        let path = directory.path().join("genesis.private_key");
        std::fs::write(&path, vec![b'a'; MAX_GENESIS_PRIVATE_KEY_FILE_BYTES + 1])
            .expect("write oversized private-key file");
        let error = read_genesis_private_key_file(&path)
            .expect_err("oversized private-key file must fail closed");
        assert!(error.to_string().contains("at most"));
    }
    #[test]
    fn resign_preserves_the_exact_genesis_body() {
        let original_key = KeyPair::random();
        let replacement_key = KeyPair::random();
        let mut block = genesis_proposal(&original_key);
        attach_successful_output(&mut block, 3);
        assert!(block.has_results());
        let resigned = resign_block(&block, &replacement_key).expect("re-sign genesis");
        assert_eq!(resigned.payload(), block.payload());
        assert_eq!(resigned.has_results(), block.has_results());
        assert_eq!(resigned.committed_fragment_count(), Some(3));
        let signatures = resigned.signatures().collect::<Vec<_>>();
        assert_eq!(signatures.len(), 1);
        signatures[0]
            .signature()
            .verify_hash(replacement_key.public_key(), resigned.hash())
            .expect("replacement signature verifies");
    }
    #[test]
    fn resign_rejects_resultless_genesis_proposal() {
        let original_key = KeyPair::random();
        let replacement_key = KeyPair::random();
        let proposal = genesis_proposal(&original_key);
        let error = resign_block(&proposal, &replacement_key)
            .expect_err("resultless genesis must not be blessed by re-signing");
        assert!(error.to_string().contains("resultless genesis proposal"));
    }
    #[test]
    fn resign_rejects_committed_fragment_count_below_result_count() {
        let original_key = KeyPair::random();
        let replacement_key = KeyPair::random();
        let mut block = genesis_proposal(&original_key);
        attach_successful_output(&mut block, 0);
        let error = resign_block(&block, &replacement_key)
            .expect_err("too-small fragment count must not be re-signed");
        assert!(error.to_string().contains("minimum 1"));
    }
}
