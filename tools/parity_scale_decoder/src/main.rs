//! Parity Scale decoder tool for Iroha data types. For usage run with `--help`
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
#![allow(clippy::print_stdout, clippy::use_debug, clippy::unnecessary_wraps)]

use core::num::NonZeroU64;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    fs, io,
    path::PathBuf,
    time::Duration,
};

use clap::Parser;
use colored::*;
use eyre::{eyre, Result};
use iroha_crypto::*;
use iroha_data_model::{
    account::NewAccount,
    asset::NewAssetDefinition,
    block::{
        error::BlockRejectionReason,
        stream::{
            BlockMessage, BlockSubscriptionRequest, VersionedBlockMessage,
            VersionedBlockSubscriptionRequest,
        },
        BlockHeader, CommittedBlock, VersionedCommittedBlock,
    },
    domain::NewDomain,
    ipfs::IpfsPath,
    predicate::{
        ip_addr::{Ipv4Predicate, Ipv6Predicate},
        numerical::{Interval, SemiInterval, SemiRange},
        string::StringPredicate,
        value::{AtIndex, Container, ValueOfKey, ValuePredicate},
        GenericPredicateBox, NonTrivial, PredicateBox,
    },
    prelude::*,
    query::error::{FindError, QueryExecutionFail},
    transaction::{error::TransactionLimitError, SignedTransaction, TransactionLimits},
    validator::Validator,
    VersionedCommittedBlockWrapper,
};
use iroha_primitives::{
    addr::{Ipv4Addr, Ipv6Addr},
    conststr::ConstString,
    fixed::{FixNum, Fixed},
};
use parity_scale_codec::DecodeAll;

macro_rules! insert_into_map {
    ( $map:ident, $t:ty) => {{
        let type_id = <$t as iroha_schema::TypeId>::id();
        #[allow(trivial_casts)]
        $map.insert(type_id, <$t as DumpDecoded>::dump_decoded as DumpDecodedPtr)
    }};
}

/// Generate map with types and `dump_decoded()` ptr
pub fn generate_map() -> DumpDecodedMap {
    let mut map = iroha_schema_gen::generate_map!(insert_into_map);

    #[allow(trivial_casts)]
    map.insert(
        <iroha_schema::Compact<u128> as iroha_schema::TypeId>::id(),
        <parity_scale_codec::Compact<u32> as DumpDecoded>::dump_decoded as DumpDecodedPtr,
    );

    map
}

/// Parity Scale decoder tool for Iroha data types
#[derive(Debug, Parser)]
#[clap(version, about, author)]
enum Args {
    /// Show all available types
    ListTypes,
    /// Decode type from binary
    Decode(DecodeArgs),
}

#[derive(Debug, clap::Args)]
struct DecodeArgs {
    /// Path to the binary with encoded Iroha structure
    binary: PathBuf,
    /// Type that is expected to be encoded in binary.
    /// If not specified then a guess will be attempted
    #[clap(short, long = "type")]
    type_name: Option<String>,
}

/// Function pointer to [`DumpDecoded::dump_decoded()`]
///
/// Function pointer is used cause trait object cannot be used
/// due to [`Sized`] bound in [`Decode`] trait
pub type DumpDecodedPtr = fn(&[u8], &mut dyn io::Write) -> Result<(), eyre::Error>;

/// Map (Type Name -> `dump_decode()` ptr)
pub type DumpDecodedMap = BTreeMap<String, DumpDecodedPtr>;

/// Types implementing this trait can be decoded from bytes
/// with *Parity Scale Codec* and dumped to something implementing [`Write`](std::io::Write)
pub trait DumpDecoded: Debug + DecodeAll {
    /// Decode `Self` from `input` and dump to `w`
    ///
    /// # Errors
    /// - If decoding from *Parity Scale Codec* fails
    /// - If writing into `w` fails
    fn dump_decoded(mut input: &[u8], w: &mut dyn io::Write) -> Result<()> {
        let obj = <Self as DecodeAll>::decode_all(&mut input)?;
        #[allow(clippy::use_debug)]
        writeln!(w, "{obj:#?}")?;
        Ok(())
    }
}

impl<T: Debug + DecodeAll> DumpDecoded for T {}

fn main() -> Result<()> {
    let args = Args::parse();

    let map = generate_map();
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());

    match args {
        Args::Decode(decode_args) => {
            let decoder = Decoder::new(decode_args, &map);
            decoder.decode(&mut writer)
        }
        Args::ListTypes => list_types(&map, &mut writer),
    }
}

/// Type decoder
struct Decoder<'map> {
    args: DecodeArgs,
    map: &'map DumpDecodedMap,
}

impl<'map> Decoder<'map> {
    /// Create new `Decoder` with `args` and `map`
    pub fn new(args: DecodeArgs, map: &'map DumpDecodedMap) -> Self {
        Self { args, map }
    }

    /// Decode type and print to `writer`
    pub fn decode<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let bytes = fs::read(self.args.binary.clone())?;

        if let Some(type_name) = &self.args.type_name {
            return self.decode_by_type(type_name, &bytes, writer);
        }
        self.decode_by_guess(&bytes, writer)
    }

    /// Decode concrete `type` from `bytes` and print to `writer`
    fn decode_by_type<W: io::Write>(
        &self,
        type_name: &str,
        bytes: &[u8],
        writer: &mut W,
    ) -> Result<()> {
        self.map.get(type_name).map_or_else(
            || Err(eyre!("Unknown type: `{type_name}`")),
            |dump_decoded| dump_decoded(bytes, writer),
        )
    }

    /// Try to decode every type from `bytes` and print to `writer`
    ///
    // TODO: Can be parallelized when there will be too many types
    fn decode_by_guess<W: io::Write>(&self, bytes: &[u8], writer: &mut W) -> Result<()> {
        let count = self
            .map
            .iter()
            .filter_map(|(type_name, dump_decoded)| {
                let mut buf = Vec::new();
                dump_decoded(bytes, &mut buf).ok()?;
                let formatted = String::from_utf8(buf).ok()?;
                writeln!(writer, "{}:\n{}", type_name.italic().cyan(), formatted).ok()
            })
            .count();
        match count {
            0 => writeln!(writer, "No compatible types found"),
            1 => writeln!(writer, "{} compatible type found", "1".bold()),
            n => writeln!(writer, "{} compatible types found", n.to_string().bold()),
        }
        .map_err(Into::into)
    }
}

/// Print all supported types from `map` to `writer`
fn list_types<W: io::Write>(map: &DumpDecodedMap, writer: &mut W) -> Result<()> {
    for key in map.keys() {
        writeln!(writer, "{key}")?;
    }
    if !map.is_empty() {
        writeln!(writer)?;
    }

    match map.len() {
        0 => writeln!(writer, "No type is supported"),
        1 => writeln!(writer, "{} type is supported", "1".bold()),
        n => writeln!(writer, "{} types are supported", n.to_string().bold()),
    }
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use iroha_data_model::{ipfs::IpfsPath, prelude::*};

    use super::*;

    #[test]
    fn decode_account_sample() {
        let limits = MetadataLimits::new(256, 256);
        let mut metadata = Metadata::new();
        metadata
            .insert_with_limits(
                "hat".parse().expect("Valid"),
                Value::Name("white".parse().expect("Valid")),
                limits,
            )
            .expect("Valid");
        let account =
            Account::new("alice@wonderland".parse().expect("Valid"), []).with_metadata(metadata);

        decode_sample("account.bin", String::from("NewAccount"), &account);
    }

    #[test]
    fn decode_domain_sample() {
        let limits = MetadataLimits::new(256, 256);
        let mut metadata = Metadata::new();
        metadata
            .insert_with_limits(
                "Is_Jabberwocky_alive".parse().expect("Valid"),
                Value::Bool(true),
                limits,
            )
            .expect("Valid");
        let domain = Domain::new("wonderland".parse().expect("Valid"))
            .with_logo(
                IpfsPath::from_str("/ipfs/Qme7ss3ARVgxv6rXqVPiikMJ8u2NLgmgszg13pYrDKEoiu")
                    .expect("Valid"),
            )
            .with_metadata(metadata);

        decode_sample("domain.bin", String::from("NewDomain"), &domain);
    }

    #[test]
    fn decode_trigger_sample() {
        let account_id =
            <Account as Identifiable>::Id::from_str("alice@wonderland").expect("Valid");
        let rose_definition_id = <AssetDefinition as Identifiable>::Id::new(
            "rose".parse().expect("Valid"),
            "wonderland".parse().expect("Valid"),
        );
        let rose_id = <Asset as Identifiable>::Id::new(rose_definition_id, account_id.clone());
        let trigger_id = "mint_rose".parse().expect("Valid");
        let action = Action::<FilterBox, Executable>::new(
            vec![MintBox::new(1_u32, rose_id)],
            Repeats::Indefinitely,
            account_id,
            FilterBox::Data(DataEventFilter::BySome(DataEntityFilter::ByAccount(
                AcceptAll,
            ))),
        );
        let trigger = Trigger::new(trigger_id, action);

        decode_sample(
            "trigger.bin",
            String::from("Trigger<FilterBox, Executable>"),
            &trigger,
        );
    }

    fn decode_sample<T: Debug>(sample_path: &str, type_id: String, expected: &T) {
        let mut binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        binary.push("samples/");
        binary.push(sample_path);
        let args = DecodeArgs {
            binary,
            type_name: Some(type_id),
        };

        let map = generate_map();
        let decoder = Decoder::new(args, &map);
        let mut buf = Vec::new();
        decoder.decode(&mut buf).expect("Decoding failed");
        let output = String::from_utf8(buf).expect("Invalid UTF-8");
        let expected_output = format!("{expected:#?}\n");

        assert_eq!(output, expected_output,);
    }
}
