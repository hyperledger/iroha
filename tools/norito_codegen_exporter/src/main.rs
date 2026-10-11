//! Export Norito metadata for SDK code generation and documentation.
//!
//! This binary emits deterministic instruction and builder metadata. The
//! package library also owns canonical Norito RPC fixture generation and
//! verification so SDK pipelines and repository automation share one
//! implementation.
use anyhow::{Context, Result};
use clap::Parser;
use iroha_data_model::{instruction_registry, isi::InstructionRegistry};
use iroha_schema::{
    ArrayMeta, BitmapMeta, EnumMeta, IntoSchema, MapMeta, MetaMapEntry, Metadata, NamedFieldsMeta,
    ResultMeta, UnnamedFieldsMeta,
};
use norito::{
    derive::JsonDeserialize,
    json::{self, Map, Number, Value},
};
use sha2::{Digest, Sha256};
use std::{
    any::TypeId,
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
macro_rules! for_each_instruction_type {
    ($macro:ident) => {
        $macro!(iroha_data_model::isi::RegisterBox);
        $macro!(iroha_data_model::isi::UnregisterBox);
        $macro!(iroha_data_model::isi::MintBox);
        $macro!(iroha_data_model::isi::BurnBox);
        $macro!(iroha_data_model::isi::transfer::TransferAssetBatch);
        $macro!(iroha_data_model::isi::TransferBox);
        $macro!(iroha_data_model::isi::repo::RepoInstructionBox);
        $macro!(iroha_data_model::isi::settlement::SettlementInstructionBox);
        $macro!(iroha_data_model::isi::SetParameter);
        $macro!(iroha_data_model::isi::SetKeyValueBox);
        $macro!(iroha_data_model::isi::SetAssetKeyValue);
        $macro!(iroha_data_model::isi::RemoveKeyValueBox);
        $macro!(iroha_data_model::isi::RemoveAssetKeyValue);
        $macro!(iroha_data_model::isi::GrantBox);
        $macro!(iroha_data_model::isi::RevokeBox);
        $macro!(iroha_data_model::isi::ExecuteTrigger);
        $macro!(iroha_data_model::isi::Upgrade);
        $macro!(iroha_data_model::isi::Log);
        $macro!(iroha_data_model::isi::CustomInstruction);
        $macro!(iroha_data_model::isi::verifying_keys::RegisterVerifyingKey);
        $macro!(iroha_data_model::isi::verifying_keys::UpdateVerifyingKey);
        $macro!(iroha_data_model::isi::sorafs::RegisterPinManifest);
        $macro!(iroha_data_model::isi::sorafs::AssertSorafsPublicationV1);
        $macro!(iroha_data_model::isi::sorafs::InitializeSorafsProviderAdmissionV1);
        $macro!(iroha_data_model::isi::sorafs::ApprovePinManifest);
        $macro!(iroha_data_model::isi::sorafs::RetirePinManifest);
        $macro!(iroha_data_model::isi::sorafs::BindManifestAlias);
        $macro!(iroha_data_model::isi::sorafs::RegisterCapacityDeclaration);
        $macro!(iroha_data_model::isi::sorafs::RecordCapacityTelemetry);
        $macro!(iroha_data_model::isi::sorafs::RegisterCapacityDispute);
        $macro!(iroha_data_model::isi::sorafs::IssueReplicationOrder);
        $macro!(iroha_data_model::isi::sorafs::CompleteReplicationOrder);
        $macro!(iroha_data_model::isi::sorafs::ReviseReplicationOrderAssignments);
        $macro!(iroha_data_model::isi::sorafs::ExpireReplicationOrder);
        $macro!(iroha_data_model::isi::sorafs::RegisterProviderOwner);
        $macro!(iroha_data_model::isi::sorafs::UnregisterProviderOwner);
        $macro!(iroha_data_model::isi::sorafs::SetProviderIngestCompletionAuthority);
        $macro!(iroha_data_model::isi::sorafs::RevokeProviderIngestCompletionAuthority);
        $macro!(iroha_data_model::isi::smart_contract_code::RegisterSmartContractCode);
        $macro!(iroha_data_model::isi::smart_contract_code::DeactivateContractInstance);
        $macro!(iroha_data_model::isi::smart_contract_code::ActivateContractInstance);
        $macro!(iroha_data_model::isi::smart_contract_code::SetContractParliamentDelegation);
        $macro!(iroha_data_model::isi::smart_contract_code::OfferContractOwnership);
        $macro!(iroha_data_model::isi::smart_contract_code::AcceptContractOwnership);
        $macro!(iroha_data_model::isi::smart_contract_code::CancelContractOwnershipOffer);
        $macro!(iroha_data_model::isi::smart_contract_code::CommitContractDeployment);
        $macro!(iroha_data_model::isi::smart_contract_code::RegisterSmartContractBytes);
        $macro!(iroha_data_model::isi::smart_contract_code::UploadSmartContractCodeChunk);
        $macro!(iroha_data_model::isi::smart_contract_code::FinalizeSmartContractCodeUpload);
        $macro!(iroha_data_model::isi::smart_contract_code::CancelSmartContractCodeUpload);
        $macro!(iroha_data_model::isi::smart_contract_code::RemoveSmartContractBytes);
        $macro!(iroha_data_model::isi::zk::VerifyProof);
        $macro!(iroha_data_model::isi::kaigi::CreateKaigi);
        $macro!(iroha_data_model::isi::kaigi::JoinKaigi);
        $macro!(iroha_data_model::isi::kaigi::LeaveKaigi);
        $macro!(iroha_data_model::isi::kaigi::EndKaigi);
        $macro!(iroha_data_model::isi::kaigi::RecordKaigiUsage);
        $macro!(iroha_data_model::isi::kaigi::SetKaigiRelayManifest);
        $macro!(iroha_data_model::isi::kaigi::RegisterKaigiRelay);
        $macro!(iroha_data_model::isi::kaigi::UnregisterKaigiRelay);
        $macro!(iroha_data_model::isi::kaigi::ReportKaigiRelayHealth);
        $macro!(iroha_data_model::isi::zk::RegisterZkAsset);
        $macro!(iroha_data_model::isi::zk::ScheduleConfidentialPolicyTransition);
        $macro!(iroha_data_model::isi::zk::CancelConfidentialPolicyTransition);
        $macro!(iroha_data_model::isi::zk::CreateElection);
        $macro!(iroha_data_model::isi::zk::SubmitBallot);
        $macro!(iroha_data_model::isi::zk::FinalizeElection);
        $macro!(iroha_data_model::isi::ministry::SubmitAgendaProposal);
        $macro!(iroha_data_model::isi::governance::ProposeDeployContract);
        $macro!(iroha_data_model::isi::governance::ProposeContractLifecycleGovernance);
        $macro!(iroha_data_model::isi::governance::ProposeContractEmergencyHold);
        $macro!(iroha_data_model::isi::governance::ProposeGlobalDataTriggerPermissionGovernance);
        $macro!(iroha_data_model::isi::governance::CastZkBallot);
        $macro!(iroha_data_model::isi::governance::CastPlainBallot);
        $macro!(iroha_data_model::isi::governance::UpdatePlainConviction);
        $macro!(iroha_data_model::isi::governance::CreateParliamentGovernanceAttemptV1);
        $macro!(iroha_data_model::isi::governance::SubmitParliamentLifecycleTransitionV1);
        $macro!(iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade);
        $macro!(iroha_data_model::isi::runtime_upgrade::ActivateRuntimeUpgrade);
        $macro!(iroha_data_model::isi::runtime_upgrade::CancelRuntimeUpgrade);
    };
}
/// Command line arguments accepted by the exporter.
#[derive(Parser, Debug)]
#[command(
    name = "norito_codegen_exporter",
    about = "Emit manifests consumed by the Android Norito doc toolchain"
)]
struct Args {
    /// Output directory that will host the manifest and builder metadata.
    #[arg(long)]
    out: PathBuf,
    /// Default Kotlin/Java package recorded in the builder manifest.
    #[arg(long, default_value = "iroha.android.codegen")]
    package: String,
    /// Stability annotation (e.g., experimental/beta/ga) used by builders.
    #[arg(long, default_value = "experimental")]
    stability: String,
    /// Optional feature gates recorded for every builder entry.
    #[arg(long = "feature", action = clap::ArgAction::Append)]
    features: Vec<String>,
    /// Optional rustdoc JSON file used to fill documentation fields.
    #[arg(long)]
    doc_json: Option<PathBuf>,
    /// Pretty-print JSON output for easier diffing.
    #[arg(long)]
    pretty: bool,
}
fn main() -> Result<()> {
    let args = Args::parse();
    run(args)
}
fn run(args: Args) -> Result<()> {
    fs::create_dir_all(&args.out)
        .with_context(|| format!("create output directory {}", args.out.display()))?;
    let registry = instruction_registry::default();
    let doc_index = if let Some(doc_path) = &args.doc_json {
        Some(
            load_doc_index(doc_path)
                .with_context(|| format!("load rustdoc JSON from {}", doc_path.display()))?,
        )
    } else {
        None
    };
    let specs = gather_instruction_specs(&registry, doc_index.as_ref());
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format timestamp")?;
    let manifest = build_manifest(&specs, &timestamp);
    let manifest_path = args.out.join("instruction_manifest.json");
    write_json_with_digest(&manifest_path, &manifest, args.pretty)?;
    let builder_index = build_builder_index(
        &specs,
        &timestamp,
        &args.package,
        &args.stability,
        &args.features,
    );
    let builder_index_path = args.out.join("builder_index.json");
    write_json_with_digest(&builder_index_path, &builder_index, args.pretty)?;
    let examples_dir = args.out.join("instruction_examples");
    write_examples(&examples_dir, &specs, &timestamp, args.pretty)?;
    Ok(())
}
type TypeIndex = HashMap<TypeId, MetaMapEntry>;
type DocIndex = HashMap<String, String>;
#[derive(JsonDeserialize)]
struct RustdocCrate {
    #[norito(default)]
    paths: HashMap<String, RustdocPath>,
    #[norito(default)]
    index: HashMap<String, RustdocItem>,
}
#[derive(JsonDeserialize)]
struct RustdocPath {
    path: Vec<String>,
}
#[derive(JsonDeserialize)]
struct RustdocItem {
    #[norito(default)]
    docs: Option<String>,
}
#[derive(Debug, Clone)]
struct InstructionSpec {
    discriminant: String,
    type_name: &'static str,
    schema_hash_hex: String,
    layout: Value,
    documentation: String,
}
impl InstructionSpec {
    fn new<T>(registry: &InstructionRegistry, docs: Option<&DocIndex>) -> Self
    where
        T: IntoSchema + 'static,
    {
        let type_name = std::any::type_name::<T>();
        let wire_id = required_instruction_wire_id(registry, type_name).to_owned();
        let layout = layout_for::<T>();
        let schema_hash_hex = hex_lower(&norito::core::type_name_schema_hash::<T>());
        let documentation = docs
            .and_then(|map| map.get(base_type_name(type_name)))
            .map(|doc| doc.trim())
            .filter(|doc| !doc.is_empty())
            .map(str::to_owned)
            .or_else(|| layout_documentation(&layout))
            .unwrap_or_else(|| {
                format!("Schema summary unavailable for `{type_name}`; consult the layout table.")
            });
        Self {
            discriminant: wire_id,
            type_name,
            schema_hash_hex,
            layout,
            documentation,
        }
    }
    fn manifest_value(&self) -> Value {
        object([
            (
                "discriminant".into(),
                Value::String(self.discriminant.clone()),
            ),
            ("type_name".into(), Value::String(self.type_name.to_owned())),
            (
                "schema_hash".into(),
                Value::String(self.schema_hash_hex.clone()),
            ),
            ("layout".into(), self.layout.clone()),
            (
                "documentation".into(),
                Value::String(self.documentation.clone()),
            ),
        ])
    }
    fn builder_value(&self, package: &str, stability: &str, features: &[String]) -> Value {
        let builder_name = self.builder_name();
        object([
            (
                "discriminant".into(),
                Value::String(self.discriminant.clone()),
            ),
            ("builder_name".into(), Value::String(builder_name.clone())),
            ("type_name".into(), Value::String(self.type_name.to_owned())),
            ("package".into(), Value::String(package.to_owned())),
            ("stability".into(), Value::String(stability.to_owned())),
            (
                "feature_gates".into(),
                Value::Array(features.iter().cloned().map(Value::String).collect()),
            ),
            (
                "notes".into(),
                Value::String(builder_notes(package, &builder_name, &self.layout)),
            ),
        ])
    }
    fn example_value(&self, timestamp: &str) -> Value {
        object([
            (
                "discriminant".into(),
                Value::String(self.discriminant.clone()),
            ),
            ("type_name".into(), Value::String(self.type_name.to_owned())),
            ("generated_at".into(), Value::String(timestamp.to_owned())),
            ("layout".into(), self.layout.clone()),
        ])
    }
    fn builder_name(&self) -> String {
        format!("{}Builder", sanitize_identifier(self.type_name))
    }
}
fn required_instruction_wire_id(
    registry: &InstructionRegistry,
    type_name: &'static str,
) -> &'static str {
    registry.wire_id(type_name).unwrap_or_else(|| {
        panic!("instruction type `{type_name}` has no registered V1 wire identifier")
    })
}
fn build_manifest(specs: &[InstructionSpec], timestamp: &str) -> Value {
    object([
        ("version".into(), Value::Number(Number::U64(1))),
        ("generated_at".into(), Value::String(timestamp.to_owned())),
        (
            "instructions".into(),
            Value::Array(specs.iter().map(InstructionSpec::manifest_value).collect()),
        ),
    ])
}
fn build_builder_index(
    specs: &[InstructionSpec],
    timestamp: &str,
    package: &str,
    stability: &str,
    features: &[String],
) -> Value {
    object([
        ("generated_at".into(), Value::String(timestamp.to_owned())),
        ("package".into(), Value::String(package.to_owned())),
        ("stability".into(), Value::String(stability.to_owned())),
        (
            "builders".into(),
            Value::Array(
                specs
                    .iter()
                    .map(|spec| spec.builder_value(package, stability, features))
                    .collect(),
            ),
        ),
    ])
}
fn builder_notes(package: &str, builder_name: &str, layout: &Value) -> String {
    let fqcn = if package.is_empty() {
        builder_name.to_owned()
    } else {
        format!("{package}.{builder_name}")
    };
    match describe_layout(layout) {
        Some(summary) => format!("Builder `{fqcn}` — {summary}"),
        None => format!("Builder `{fqcn}`"),
    }
}
fn layout_documentation(layout: &Value) -> Option<String> {
    describe_layout(layout).map(|summary| format!("Schema summary: {summary}."))
}
fn describe_layout(layout: &Value) -> Option<String> {
    let kind = layout.get("kind")?.as_str()?;
    match kind {
        "struct" => summarize_fields(layout, "struct"),
        "tuple" => summarize_fields(layout, "tuple"),
        "enum" => summarize_enum(layout),
        "array" => {
            let ty = layout.get("type").and_then(Value::as_str)?;
            let len = layout.get("len").and_then(Value::as_u64);
            let descr = len
                .map(|len| format!("array[{len}] of {ty}"))
                .unwrap_or_else(|| format!("array of {ty}"));
            Some(descr)
        }
        "vec" => layout
            .get("type")
            .and_then(Value::as_str)
            .map(|ty| format!("vec<{ty}> payload")),
        "map" => {
            let key = layout.get("key").and_then(Value::as_str)?;
            let value = layout.get("value").and_then(Value::as_str)?;
            Some(format!("map<{key}, {value}> payload"))
        }
        "option" => layout
            .get("type")
            .and_then(Value::as_str)
            .map(|ty| format!("option<{ty}> payload")),
        "result" => {
            let ok = layout.get("ok").and_then(Value::as_str)?;
            let err = layout.get("err").and_then(Value::as_str)?;
            Some(format!("result<ok={ok}, err={err}> payload"))
        }
        "bitmap" => summarize_bitmap(layout),
        "fixed_point" => {
            let base = layout.get("base").and_then(Value::as_str)?;
            let decimals = layout.get("decimal_places").and_then(Value::as_u64)?;
            Some(format!("fixed_point<{base}, {decimals}dp> payload"))
        }
        "int" => layout
            .get("mode")
            .and_then(Value::as_str)
            .map(|mode| format!("int ({mode}) payload")),
        "string" => Some("string payload".to_owned()),
        "bool" => Some("bool payload".to_owned()),
        other => Some(format!("layout kind `{other}`")),
    }
}
fn summarize_fields(layout: &Value, label: &str) -> Option<String> {
    let fields = layout.get("fields")?.as_array()?;
    if fields.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for field in fields {
        let name = field
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let ty = field.get("type").and_then(Value::as_str).unwrap_or("?");
        if name.is_empty() {
            parts.push(ty.to_owned());
        } else {
            parts.push(format!("{name}: {ty}"));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("{label} fields: {}", parts.join(", ")))
    }
}
fn summarize_enum(layout: &Value) -> Option<String> {
    let variants = layout.get("variants")?.as_array()?;
    if variants.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for variant in variants {
        let tag = variant
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("variant");
        let payload = variant.get("payload");
        match payload {
            Some(Value::String(payload)) if !payload.is_empty() => {
                parts.push(format!("{tag} ({payload})"));
            }
            _ => parts.push(tag.to_owned()),
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("enum variants: {}", parts.join(", ")))
    }
}
fn summarize_bitmap(layout: &Value) -> Option<String> {
    let repr = layout.get("repr").and_then(Value::as_str)?;
    let masks = layout.get("masks")?.as_array()?;
    let mut mask_labels = Vec::new();
    for mask in masks {
        let name = mask.get("name").and_then(Value::as_str).unwrap_or("mask");
        let value = mask.get("mask").and_then(Value::as_u64);
        if let Some(value) = value {
            mask_labels.push(format!("{name}=0x{value:x}"));
        } else {
            mask_labels.push(name.to_owned());
        }
    }
    Some(if mask_labels.is_empty() {
        format!("bitmap<{repr}>")
    } else {
        format!("bitmap<{repr}> masks: {}", mask_labels.join(", "))
    })
}
fn load_doc_index(path: &Path) -> Result<DocIndex> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let parsed: RustdocCrate =
        json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    let RustdocCrate { paths, index } = parsed;
    let mut docs = HashMap::new();
    for (item_id, rustdoc_path) in paths {
        let segments = rustdoc_path.path;
        if segments.is_empty() {
            continue;
        }
        let fq = segments.join("::");
        if !fq.starts_with("iroha_data_model::") {
            continue;
        }
        let doc_value = index
            .get(&item_id)
            .and_then(|item| item.docs.as_deref())
            .map(str::trim)
            .filter(|doc| !doc.is_empty());
        if let Some(doc) = doc_value {
            docs.entry(fq).or_insert_with(|| doc.to_owned());
        }
    }
    Ok(docs)
}
fn gather_instruction_specs(
    registry: &InstructionRegistry,
    docs: Option<&DocIndex>,
) -> Vec<InstructionSpec> {
    let mut specs = Vec::new();
    macro_rules! push_spec {
        ($ty:ty) => {
            specs.push(InstructionSpec::new::<$ty>(registry, docs));
        };
    }
    for_each_instruction_type!(push_spec);
    specs.sort_by(|a, b| a.discriminant.cmp(&b.discriminant));
    specs
}
fn layout_for<T: IntoSchema + 'static>() -> Value {
    let schema = T::schema();
    let type_index: TypeIndex = schema.into_iter().collect();
    let type_id = TypeId::of::<T>();
    let metadata = type_index
        .get(&type_id)
        .map(|entry| entry.metadata.clone())
        .unwrap_or_else(|| {
            panic!(
                "missing schema metadata for `{}`",
                std::any::type_name::<T>()
            )
        });
    metadata_to_value(&metadata, &type_index)
}
fn base_type_name(full: &str) -> &str {
    full.split_once('<').map(|(head, _)| head).unwrap_or(full)
}
fn metadata_to_value(meta: &Metadata, index: &TypeIndex) -> Value {
    match meta {
        Metadata::Struct(named) => struct_metadata(named, index),
        Metadata::Tuple(tuple) => tuple_metadata(tuple, index),
        Metadata::Enum(enum_meta) => enum_metadata(enum_meta, index),
        Metadata::Int(mode) => object([
            ("kind".into(), Value::String("int".to_owned())),
            ("mode".into(), Value::String(format!("{mode:?}"))),
        ]),
        Metadata::Float(mode) => object([
            ("kind".into(), Value::String("float".to_owned())),
            ("mode".into(), Value::String(format!("{mode:?}"))),
        ]),
        Metadata::String => object([("kind".into(), Value::String("string".to_owned()))]),
        Metadata::Bool => object([("kind".into(), Value::String("bool".to_owned()))]),
        Metadata::FixedPoint(meta) => object([
            ("kind".into(), Value::String("fixed_point".to_owned())),
            (
                "base".into(),
                Value::String(lookup_type_name(index, meta.base)),
            ),
            (
                "decimal_places".into(),
                Value::Number(Number::U64(meta.decimal_places as u64)),
            ),
        ]),
        Metadata::Array(meta) => array_metadata(meta, index),
        Metadata::Vec(meta) => object([
            ("kind".into(), Value::String("vec".to_owned())),
            (
                "type".into(),
                Value::String(lookup_type_name(index, meta.ty)),
            ),
        ]),
        Metadata::Map(meta) => map_metadata(meta, index),
        Metadata::Option(inner) => object([
            ("kind".into(), Value::String("option".to_owned())),
            (
                "type".into(),
                Value::String(lookup_type_name(index, *inner)),
            ),
        ]),
        Metadata::Result(meta) => result_metadata(meta, index),
        Metadata::Bitmap(meta) => bitmap_metadata(meta, index),
    }
}
fn struct_metadata(named: &NamedFieldsMeta, index: &TypeIndex) -> Value {
    object([
        ("kind".into(), Value::String("struct".to_owned())),
        (
            "fields".into(),
            Value::Array(
                named
                    .declarations
                    .iter()
                    .map(|decl| field_value(Some(decl.name.clone()), decl.ty, index))
                    .collect(),
            ),
        ),
    ])
}
fn tuple_metadata(tuple: &UnnamedFieldsMeta, index: &TypeIndex) -> Value {
    object([
        ("kind".into(), Value::String("tuple".to_owned())),
        (
            "fields".into(),
            Value::Array(
                tuple
                    .types
                    .iter()
                    .enumerate()
                    .map(|(idx, ty)| field_value(Some(format!("_{idx}")), *ty, index))
                    .collect(),
            ),
        ),
    ])
}
fn enum_metadata(enum_meta: &EnumMeta, index: &TypeIndex) -> Value {
    object([
        ("kind".into(), Value::String("enum".to_owned())),
        (
            "variants".into(),
            Value::Array(
                enum_meta
                    .variants
                    .iter()
                    .map(|variant| {
                        let payload = variant
                            .ty
                            .map(|ty| Value::String(lookup_type_name(index, ty)))
                            .unwrap_or(Value::Null);
                        object([
                            ("tag".into(), Value::String(variant.tag.clone())),
                            (
                                "discriminant".into(),
                                Value::Number(Number::U64(variant.discriminant as u64)),
                            ),
                            ("payload".into(), payload),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}
fn array_metadata(meta: &ArrayMeta, index: &TypeIndex) -> Value {
    object([
        ("kind".into(), Value::String("array".to_owned())),
        (
            "type".into(),
            Value::String(lookup_type_name(index, meta.ty)),
        ),
        ("len".into(), Value::Number(Number::U64(meta.len as u64))),
    ])
}
fn map_metadata(meta: &MapMeta, index: &TypeIndex) -> Value {
    object([
        ("kind".into(), Value::String("map".to_owned())),
        (
            "key".into(),
            Value::String(lookup_type_name(index, meta.key)),
        ),
        (
            "value".into(),
            Value::String(lookup_type_name(index, meta.value)),
        ),
    ])
}
fn result_metadata(meta: &ResultMeta, index: &TypeIndex) -> Value {
    object([
        ("kind".into(), Value::String("result".to_owned())),
        ("ok".into(), Value::String(lookup_type_name(index, meta.ok))),
        (
            "err".into(),
            Value::String(lookup_type_name(index, meta.err)),
        ),
    ])
}
fn bitmap_metadata(meta: &BitmapMeta, index: &TypeIndex) -> Value {
    object([
        ("kind".into(), Value::String("bitmap".to_owned())),
        (
            "repr".into(),
            Value::String(lookup_type_name(index, meta.repr)),
        ),
        (
            "masks".into(),
            Value::Array(
                meta.masks
                    .iter()
                    .map(|mask| {
                        object([
                            ("name".into(), Value::String(mask.name.clone())),
                            ("mask".into(), Value::Number(Number::U64(mask.mask))),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}
fn field_value(name: Option<String>, ty: TypeId, index: &TypeIndex) -> Value {
    object([
        (
            "name".into(),
            name.map(Value::String).unwrap_or(Value::Null),
        ),
        ("type".into(), Value::String(lookup_type_name(index, ty))),
    ])
}
fn lookup_type_name(index: &TypeIndex, ty: TypeId) -> String {
    index
        .get(&ty)
        .map(|entry| entry.type_name.clone())
        .unwrap_or_else(|| format!("{ty:?}"))
}
fn object(pairs: impl IntoIterator<Item = (String, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert(key, value);
    }
    Value::Object(map)
}
fn sanitize_identifier(input: &str) -> String {
    let mut out = String::new();
    for c in input.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    while out.starts_with('_') {
        out.remove(0);
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    if out.is_empty() {
        return "Instruction".to_owned();
    }
    if out
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        out.insert(0, '_');
    }
    out
}
fn write_json_with_digest(path: &Path, value: &Value, pretty: bool) -> Result<()> {
    let json = if pretty {
        json::to_json_pretty(value)?
    } else {
        json::to_json(value)?
    };
    fs::write(path, json.as_bytes()).with_context(|| format!("write {}", path.display()))?;
    write_digest_file(path, json.as_bytes())
}
fn write_digest_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let hex = hex_lower(&digest);
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "artifact".to_owned());
    let digest_entry = format!("{hex}  {file_name}\n");
    let digest_path = path.with_file_name(format!("{file_name}.sha256"));
    fs::write(&digest_path, digest_entry)
        .with_context(|| format!("write {}", digest_path.display()))
}
fn write_examples(
    dir: &Path,
    specs: &[InstructionSpec],
    timestamp: &str,
    pretty: bool,
) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("create examples dir {}", dir.display()))?;
    for spec in specs {
        let path = dir.join(format!("{}.json", spec.discriminant));
        let value = spec.example_value(timestamp);
        let json = if pretty {
            json::to_json_pretty(&value)?
        } else {
            json::to_json(&value)?
        };
        fs::write(&path, json.as_bytes()).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("write! to String is infallible");
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_schema::IntoSchema;
    use std::fs;
    use tempfile::NamedTempFile;
    #[derive(IntoSchema)]
    struct Sample {
        value: u32,
    }
    #[allow(dead_code)]
    #[derive(IntoSchema)]
    struct LayoutStruct {
        foo: u32,
        bar: String,
    }
    #[allow(dead_code)]
    #[derive(IntoSchema)]
    enum LayoutEnum {
        Unit,
        Payload(u32),
    }
    #[test]
    fn sanitize_identifier_collapses_noise() {
        assert_eq!(
            sanitize_identifier("iroha::register::Register<iroha::Domain>"),
            "iroha_register_Register_iroha_Domain"
        );
        assert_eq!(sanitize_identifier("123start"), "_123start");
        assert_eq!(sanitize_identifier(""), "Instruction");
    }
    #[test]
    fn layout_exposes_struct_fields() {
        let sample = Sample { value: 42 };
        assert_eq!(sample.value, 42);
        let layout = layout_for::<Sample>();
        let Value::Object(map) = layout else {
            panic!("expected struct metadata object");
        };
        assert_eq!(map.get("kind").and_then(Value::as_str), Some("struct"));
        let Some(Value::Array(fields)) = map.get("fields") else {
            panic!("missing fields array");
        };
        assert!(
            fields.iter().any(|field| match field {
                Value::Object(field_map) =>
                    field_map.get("name").and_then(Value::as_str) == Some("value")
                        && field_map.get("type").and_then(Value::as_str) == Some("u32"),
                _ => false,
            }),
            "expected `value: u32` field in layout"
        );
    }
    #[test]
    #[should_panic(expected = "has no registered V1 wire identifier")]
    fn instruction_spec_rejects_type_name_fallback() {
        let _ = InstructionSpec::new::<Sample>(&instruction_registry::default(), None);
    }
    #[test]
    fn grouped_instruction_families_export_only_canonical_v1_wire_ids() {
        let registry = instruction_registry::default();
        let specs = gather_instruction_specs(&registry, None);
        let mut exported_wire_ids = std::collections::BTreeSet::new();
        for spec in &specs {
            assert_eq!(
                registry.wire_id(spec.type_name),
                Some(spec.discriminant.as_str()),
                "exported type must have its own registered V1 wire identifier"
            );
            assert!(
                exported_wire_ids.insert(spec.discriminant.as_str()),
                "duplicate exported V1 wire identifier: {}",
                spec.discriminant
            );
        }
        for (type_name, wire_id) in [
            (
                std::any::type_name::<iroha_data_model::isi::RegisterBox>(),
                "iroha.register",
            ),
            (
                std::any::type_name::<iroha_data_model::isi::UnregisterBox>(),
                "iroha.unregister",
            ),
            (
                std::any::type_name::<iroha_data_model::isi::MintBox>(),
                "iroha.mint",
            ),
            (
                std::any::type_name::<iroha_data_model::isi::BurnBox>(),
                "iroha.burn",
            ),
            (
                std::any::type_name::<iroha_data_model::isi::TransferBox>(),
                "iroha.transfer",
            ),
            (
                std::any::type_name::<iroha_data_model::isi::repo::RepoInstructionBox>(),
                "iroha.repo",
            ),
            (
                std::any::type_name::<iroha_data_model::isi::settlement::SettlementInstructionBox>(
                ),
                "iroha.settlement",
            ),
            (
                std::any::type_name::<iroha_data_model::isi::SetKeyValueBox>(),
                "iroha.set_key_value",
            ),
            (
                std::any::type_name::<iroha_data_model::isi::RemoveKeyValueBox>(),
                "iroha.remove_key_value",
            ),
            (
                std::any::type_name::<iroha_data_model::isi::GrantBox>(),
                "iroha.grant",
            ),
            (
                std::any::type_name::<iroha_data_model::isi::RevokeBox>(),
                "iroha.revoke",
            ),
        ] {
            let matching = specs
                .iter()
                .filter(|spec| spec.type_name == type_name)
                .collect::<Vec<_>>();
            assert_eq!(
                matching.len(),
                1,
                "one canonical grouped export for {type_name}"
            );
            assert_eq!(matching[0].discriminant, wire_id);
        }
        for wire_id in ["iroha.mint", "iroha.burn", "iroha.transfer"] {
            let spec = specs
                .iter()
                .find(|spec| spec.discriminant == wire_id)
                .expect("canonical asset quantity family export");
            let layout = describe_layout(&spec.layout).expect("grouped instruction layout");
            assert!(
                layout.contains("Quantity"),
                "{wire_id} must retain Quantity"
            );
            assert!(
                !layout.contains("Numeric"),
                "{wire_id} must not export the retired Numeric asset quantity"
            );
        }
    }
    #[test]
    fn kaigi_relay_instructions_are_exported_with_canonical_wire_ids() {
        let specs = gather_instruction_specs(&instruction_registry::default(), None);
        for (type_name, wire_id) in [
            (
                std::any::type_name::<iroha_data_model::isi::kaigi::UnregisterKaigiRelay>(),
                "iroha.instruction.v1::kaigi::UnregisterKaigiRelay",
            ),
            (
                std::any::type_name::<iroha_data_model::isi::kaigi::ReportKaigiRelayHealth>(),
                "iroha.instruction.v1::kaigi::ReportKaigiRelayHealth",
            ),
        ] {
            let spec = specs
                .iter()
                .find(|spec| spec.type_name == type_name)
                .unwrap_or_else(|| {
                    panic!("Kaigi relay instruction `{type_name}` must be exported")
                });
            assert_eq!(spec.discriminant, wire_id);
        }
    }
    #[test]
    fn generic_privacy_types_and_retired_kagemusha_instructions_are_absent() {
        let registry = instruction_registry::default();
        let specs = gather_instruction_specs(&registry, None);
        assert_eq!(specs.len(), 80, "first-release generated instruction count");
        let governance_specs = specs
            .iter()
            .filter(|spec| spec.type_name.contains("::isi::governance::"))
            .collect::<Vec<_>>();
        assert_eq!(
            governance_specs.len(),
            9,
            "first-release generated governance instruction count"
        );
        for expected in [
            std::any::type_name::<iroha_data_model::isi::governance::ProposeDeployContract>(),
            std::any::type_name::<
                iroha_data_model::isi::governance::ProposeContractLifecycleGovernance,
            >(),
            std::any::type_name::<iroha_data_model::isi::governance::ProposeContractEmergencyHold>(
            ),
            std::any::type_name::<
                iroha_data_model::isi::governance::ProposeGlobalDataTriggerPermissionGovernance,
            >(),
            std::any::type_name::<iroha_data_model::isi::governance::CastZkBallot>(),
            std::any::type_name::<iroha_data_model::isi::governance::CastPlainBallot>(),
            std::any::type_name::<iroha_data_model::isi::governance::UpdatePlainConviction>(),
            std::any::type_name::<
                iroha_data_model::isi::governance::CreateParliamentGovernanceAttemptV1,
            >(),
            std::any::type_name::<
                iroha_data_model::isi::governance::SubmitParliamentLifecycleTransitionV1,
            >(),
        ] {
            assert!(
                governance_specs
                    .iter()
                    .any(|spec| spec.type_name == expected),
                "missing first-release Parliament lifecycle instruction `{expected}`"
            );
        }
        let retired = [
            ("zk", ["Sh", "ield"].concat()),
            ("zk", ["Zk", "Transfer"].concat()),
            ("zk", ["Un", "shield"].concat()),
            ("escrow", ["OpenAnonymous", "AssetEscrow"].concat()),
            ("escrow", ["AcceptAnonymous", "AssetEscrow"].concat()),
            ("escrow", ["MarkAnonymous", "EscrowPaymentSent"].concat()),
            ("escrow", ["ReleaseAnonymous", "AssetEscrow"].concat()),
            ("escrow", ["CancelAnonymous", "AssetEscrow"].concat()),
            ("escrow", ["OpenAnonymous", "EscrowDispute"].concat()),
            ("escrow", ["ResolveAnonymous", "EscrowDispute"].concat()),
        ];
        for (module, type_name) in retired {
            assert!(
                specs
                    .iter()
                    .all(|spec| { spec.type_name.rsplit("::").next() != Some(type_name.as_str()) }),
                "retired generic privacy type must not be generated: {type_name}"
            );
            let source_entry = format!("$macro!(iroha_data_model::isi::{module}::{type_name})");
            assert!(
                !include_str!("main.rs").contains(&source_entry),
                "retired generic privacy type must not remain in exporter inventory: {type_name}"
            );
        }
        for retired_wire_id in [
            "iroha.kagemusha.v1.top_up",
            "iroha.kagemusha.v1.ordinary_top_up",
            "iroha.kagemusha.v1.redeem",
        ] {
            assert!(
                !registry.contains(retired_wire_id),
                "retired KAGEMUSHA instruction must not be registered: {retired_wire_id}"
            );
        }
    }
    #[test]
    fn provider_ingest_completion_export_is_the_six_field_hard_cut() {
        let specs = gather_instruction_specs(&instruction_registry::default(), None);
        let expected_type =
            std::any::type_name::<iroha_data_model::isi::sorafs::CompleteReplicationOrder>();
        let spec = specs
            .iter()
            .find(|spec| spec.type_name == expected_type)
            .expect("complete replication order export");
        let fields = spec
            .layout
            .get("fields")
            .and_then(Value::as_array)
            .expect("complete replication order fields");
        let field_names = fields
            .iter()
            .map(|field| {
                field
                    .get("name")
                    .and_then(Value::as_str)
                    .expect("named completion field")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            field_names,
            [
                "order_id",
                "provider_id",
                "completion_epoch",
                "expected_authority",
                "expected_assignment_revision",
                "finalized_anchor",
            ]
        );
    }
    #[test]
    fn metadata_to_value_renders_float_mode() {
        let index = TypeIndex::new();
        let layout = metadata_to_value(&Metadata::Float(iroha_schema::FloatMode::Binary64), &index);
        let Value::Object(map) = layout else {
            panic!("expected float metadata object");
        };
        assert_eq!(map.get("kind").and_then(Value::as_str), Some("float"));
        assert_eq!(map.get("mode").and_then(Value::as_str), Some("Binary64"));
    }
    #[test]
    fn describe_layout_produces_struct_summary() {
        let layout = layout_for::<LayoutStruct>();
        let summary = describe_layout(&layout).expect("summary");
        assert!(
            summary.contains("foo") && summary.contains("bar"),
            "summary should list struct fields: {summary}"
        );
    }
    #[test]
    fn describe_layout_produces_enum_summary() {
        let layout = layout_for::<LayoutEnum>();
        let summary = describe_layout(&layout).expect("summary");
        assert!(
            summary.contains("Unit") && summary.contains("Payload"),
            "summary should list enum variants: {summary}"
        );
    }
    #[test]
    fn builder_notes_include_fqcn() {
        let layout = layout_for::<LayoutStruct>();
        let notes = builder_notes("iroha.android.codegen", "FooBuilder", &layout);
        assert!(
            notes.contains("iroha.android.codegen.FooBuilder"),
            "expected fully qualified builder name in notes: {notes}"
        );
        assert!(
            notes.contains("foo") && notes.contains("bar"),
            "expected struct fields reference in notes: {notes}"
        );
    }
    #[test]
    fn layout_documentation_falls_back_to_summary() {
        let layout = layout_for::<LayoutStruct>();
        let doc = layout_documentation(&layout).expect("fallback documentation");
        assert!(
            doc.contains("Schema summary") && doc.contains("foo") && doc.contains("bar"),
            "fallback doc should reference struct fields: {doc}"
        );
    }
    #[test]
    fn load_doc_index_prefers_data_model_entries() {
        let tmp = NamedTempFile::new().expect("temp file");
        let rustdoc = r#"
        {
            "paths": {
                "1": { "crate_id": 0, "path": ["iroha_data_model", "example", "Thing"], "kind": "struct" },
                "2": { "crate_id": 0, "path": ["other", "IgnoreMe"], "kind": "struct" }
            },
            "index": {
                "1": { "docs": " Example docs " },
                "2": { "docs": "Other docs" }
            }
        }"#;
        fs::write(tmp.path(), rustdoc).expect("write rustdoc json");
        let index = load_doc_index(tmp.path()).expect("load docs");
        assert_eq!(
            index.get("iroha_data_model::example::Thing"),
            Some(&"Example docs".to_string())
        );
        assert!(!index.contains_key("other::IgnoreMe"));
    }
}
