//! Parity Scale decoder tool for Iroha data types. For usage run with `--help`

#![allow(clippy::print_stdout, clippy::use_debug, clippy::unnecessary_wraps)]

use std::{collections::BTreeMap, fmt::Debug, fs, io, io::Write, path::PathBuf};

use clap::Parser;
use eyre::{eyre, Result};
use iroha_data_model::prelude::*;
use parity_scale_codec::Decode;

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
    type_id: Option<String>,
}

/// Function pointer to [`DumpDecoded::dump_decoded()`]
///
/// Function pointer is used cause trait object can not be used
/// due to [`Sized`] bound in [`Decode`] trait
pub type DumpDecodedPtr = fn(&[u8], &mut dyn Write) -> Result<(), eyre::Error>;

/// Map (Type Name -> `dump_decode()` ptr)
pub type DumpDecodedMap = BTreeMap<&'static str, DumpDecodedPtr>;

/// Types implementing this trait can be decoded from bytes
/// with *Parity Scale Codec* and dumped to something implementing [`Write`]
pub trait DumpDecoded: Debug + Decode {
    /// Decode `Self` from `input` and dump to `w`
    ///
    /// # Errors
    /// - If decoding from *Parity Scale Codec* fails
    /// - If writing into `w` fails
    fn dump_decoded(mut input: &[u8], w: &mut dyn Write) -> Result<(), eyre::Error> {
        let obj = <Self as Decode>::decode(&mut input)?;
        #[allow(clippy::use_debug)]
        writeln!(w, "{:#?}", obj)?;
        Ok(())
    }
}

impl<T: Debug + Decode> DumpDecoded for T {}

fn main() -> Result<()> {
    let args = Args::parse();

    let map = generate_map();
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());

    match args {
        Args::Decode(decode_args) => decode(decode_args, &map, &mut writer),
        Args::ListTypes => list_types(&map, &mut writer),
    }
}

macro_rules! generate_map {
    ($($type:tt),* $(,)?) => {
        #[allow(trivial_casts)]
        DumpDecodedMap::from([
            $((stringify!($type), <$type as DumpDecoded>::dump_decoded as DumpDecodedPtr)),*
        ])
    };
}

#[allow(clippy::too_many_lines)]
fn generate_map() -> DumpDecodedMap {
    generate_map!(
        Account,
        AccountEvent,
        AccountEventFilter,
        AccountFilter,
        AccountId,
        Action,
        Add,
        And,
        Asset,
        AssetDefinition,
        AssetDefinitionEntry,
        AssetDefinitionEvent,
        AssetDefinitionEventFilter,
        AssetDefinitionFilter,
        AssetDefinitionId,
        AssetEvent,
        AssetEventFilter,
        AssetFilter,
        AssetId,
        AssetValue,
        AssetValueType,
        BlockRejectionReason,
        BurnBox,
        Contains,
        ContainsAll,
        ContainsAny,
        ContextValue,
        DataEntityFilter,
        DataEvent,
        DataEventFilter,
        Divide,
        Domain,
        DomainEvent,
        DomainEventFilter,
        DomainFilter,
        DomainId,
        Equal,
        Executable,
        ExecuteTriggerBox,
        ExecuteTriggerEvent,
        ExecuteTriggerEventFilter,
        ExecutionTime,
        Expression,
        FailBox,
        FindAccountById,
        FindAccountKeyValueByIdAndKey,
        FindAccountsByDomainId,
        FindAccountsByName,
        FindAllAccounts,
        FindAllAssets,
        FindAllAssetsDefinitions,
        FindAllDomains,
        FindAllParameters,
        FindAllPeers,
        FindAllRoles,
        FindAssetById,
        FindAssetDefinitionKeyValueByIdAndKey,
        FindAssetKeyValueByIdAndKey,
        FindAssetQuantityById,
        FindAssetsByAccountId,
        FindAssetsByAssetDefinitionId,
        FindAssetsByDomainId,
        FindAssetsByDomainIdAndAssetDefinitionId,
        FindAssetsByName,
        FindDomainById,
        FindDomainKeyValueByIdAndKey,
        FindPermissionTokensByAccountId,
        FindRolesByAccountId,
        FindTransactionByHash,
        FindTransactionsByAccountId,
        GenesisDomain,
        GrantBox,
        Greater,
        IfExpression,
        IfInstruction,
        Instruction,
        InstructionExecutionFail,
        Less,
        Metadata,
        MetadataLimits,
        MintBox,
        Mod,
        Multiply,
        Not,
        NotPermittedFail,
        Or,
        Pair,
        Payload,
        Peer,
        PeerEvent,
        PeerEventFilter,
        PeerFilter,
        PeerId,
        PendingTransactions,
        PermissionToken,
        PipelineEntityKind,
        PipelineEvent,
        PipelineEventFilter,
        PipelineStatus,
        QueryBox,
        QueryRequest,
        QueryResult,
        RaiseTo,
        RegisterBox,
        RejectedTransaction,
        RejectionReason,
        RemoveKeyValueBox,
        Repeats,
        RevokeBox,
        Role,
        RoleEvent,
        RoleEventFilter,
        RoleFilter,
        RoleId,
        SequenceBox,
        SetKeyValueBox,
        SignatureCheckCondition,
        SignedQueryRequest,
        Subtract,
        TimeEvent,
        TimeEventFilter,
        TimeInterval,
        TimeSchedule,
        Transaction,
        TransactionRejectionReason,
        TransactionValue,
        TransferBox,
        Trigger,
        TriggerEvent,
        TriggerEventFilter,
        TriggerFilter,
        TriggerId,
        UnregisterBox,
        UnsatisfiedSignatureConditionFail,
        ValidTransaction,
        VersionedPendingTransactions,
        VersionedQueryResult,
        VersionedRejectedTransaction,
        VersionedSignedQueryRequest,
        VersionedTransaction,
        VersionedValidTransaction,
        WasmExecutionFail,
        Where,
    )
}

fn decode<W: io::Write>(args: DecodeArgs, map: &DumpDecodedMap, writer: &mut W) -> Result<()> {
    let bytes = fs::read(args.binary)?;

    if let Some(type_id) = args.type_id {
        return decode_by_type(map, &type_id, &bytes, writer);
    }
    decode_by_guess(map, &bytes, writer)
}

fn decode_by_type<W: io::Write>(
    map: &DumpDecodedMap,
    type_id: &str,
    bytes: &[u8],
    writer: &mut W,
) -> Result<()> {
    map.get(type_id).map_or_else(
        || Err(eyre!("Unknown type: `{type_id}`")),
        |dump_decoded| dump_decoded(bytes, writer),
    )
}

fn decode_by_guess<W: io::Write>(map: &DumpDecodedMap, bytes: &[u8], writer: &mut W) -> Result<()> {
    let count = map
        .values()
        .filter_map(|dump_decoded| {
            dump_decoded(bytes, writer)
                .ok()
                .and_then(|_| writeln!(writer).ok())
        })
        .count();
    match count {
        0 => writeln!(writer, "No compatible types found"),
        1 => writeln!(writer, "1 compatible type found"),
        n => writeln!(writer, "{n} compatible types found"),
    }
    .map_err(Into::into)
}

fn list_types<W: io::Write>(map: &DumpDecodedMap, writer: &mut W) -> Result<()> {
    for key in map.keys() {
        writeln!(writer, "{key}")?;
    }

    match map.len() {
        0 => writeln!(writer, "No type is supported"),
        1 => writeln!(writer, "\n1 type is supported"),
        n => writeln!(writer, "\n{n} types are supported"),
    }
    .map_err(Into::into)
}
