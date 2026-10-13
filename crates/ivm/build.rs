//! Generate canonical IVM assets and authenticate source-owned optional CUDA bytes.

#[cfg(feature = "cuda")]
use std::ffi::OsStr;
#[cfg(feature = "cuda")]
use std::path::Path;
use std::path::PathBuf;
use std::{collections::BTreeSet, env, error::Error, fmt::Write as _, fs};
#[cfg(any(feature = "cuda", test))]
#[path = "src/cuda_build_policy.rs"]
mod cuda_build_policy;
#[cfg(any(feature = "cuda", test))]
#[path = "src/cuda_bundle_files.rs"]
mod cuda_bundle_files;
#[cfg(any(feature = "cuda", test))]
#[path = "src/cuda_provenance.rs"]
mod cuda_provenance;
#[cfg(feature = "cuda")]
use cuda_build_policy::CUDA_SOURCES;
#[cfg(any(feature = "cuda", test))]
use cuda_build_policy::cuda_stems;
#[cfg(feature = "cuda")]
use cuda_bundle_files::validate_ptx_bytes;
#[cfg(any(feature = "cuda", test))]
const CUDA_PTX_STEMS: [&str; 10] = cuda_stems();
const ISO20022_SCHEMA_SPEC_PATH: &str = "src/assets/iso20022_schema_v1/schema_v1.tsv";
const ISO20022_SCHEMA_ASSET: &str = include_str!("src/assets/iso20022_schema_v1/schema_v1.tsv");
const METAL_SOURCES: [(&str, &str); 9] = [
    (
        "metal_vadd32",
        include_str!("src/assets/text_v1/metal_vadd32.metal"),
    ),
    (
        "metal_vadd64",
        include_str!("src/assets/text_v1/metal_vadd64.metal"),
    ),
    ("metal_bitwise", include_str!("src/metal_bitwise.metal")),
    (
        "metal_sha256_compress",
        include_str!("src/assets/text_v1/metal_sha256_compress.metal"),
    ),
    (
        "metal_sha256_leaves",
        include_str!("src/assets/text_v1/metal_sha256_leaves.metal"),
    ),
    (
        "metal_sha256_pairs_reduce",
        include_str!("src/assets/text_v1/metal_sha256_pairs_reduce.metal"),
    ),
    (
        "metal_keccak_f1600",
        include_str!("src/assets/text_v1/metal_keccak_f1600.metal"),
    ),
    (
        "metal_aes_rounds",
        include_str!("src/assets/text_v1/metal_aes_rounds.metal"),
    ),
    ("metal_ed25519", include_str!("src/metal_ed25519.metal")),
];
const METAL_SOURCE_DIGEST: &str =
    "9c8f09f49746b6909d1565b6bc3175bb77e86c796bf911c07a722bd540218de5";
const METAL_LIBRARY_DIGEST: &str =
    "fe62a035ab7481646e64c2f272f38669c353b95f5ab79ec5876d412f88237170";
fn main() {
    println!("cargo:rerun-if-changed=spec/syscalls.toml");
    #[cfg(feature = "cuda")]
    if let Err(err) = build_cuda_artifacts() {
        panic!("ivm cuda build failed: {err}");
    }
    if env::var("TARGET").is_ok_and(|target| target.contains("apple-darwin"))
        && env::var_os("CARGO_FEATURE_METAL").is_some()
    {
        verify_metal_bundle().expect("ivm Metal bundle provenance check failed");
    }
    if let Err(err) = generate_syscall_signatures() {
        panic!("ivm syscall signature generation failed: {err}");
    }
    if let Err(err) = generate_iso20022_schema() {
        panic!("ivm ISO 20022 schema generation failed: {err}");
    }
}

fn verify_metal_bundle() -> Result<(), String> {
    use sha2::Digest as _;

    let mut sources = sha2::Sha256::new();
    for (name, source) in METAL_SOURCES {
        sources.update((name.len() as u64).to_le_bytes());
        sources.update(name.as_bytes());
        sources.update((source.len() as u64).to_le_bytes());
        sources.update(source.as_bytes());
    }
    if format!("{:x}", sources.finalize()) != METAL_SOURCE_DIGEST {
        return Err("Metal source bytes differ from the pinned bundle inputs".into());
    }
    let binary = include_bytes!("metal/v1/ivm_kernels.metallib");
    if format!("{:x}", sha2::Sha256::digest(binary)) != METAL_LIBRARY_DIGEST {
        return Err("Metal library bytes differ from the pinned bundle".into());
    }
    Ok(())
}
struct IsoField {
    pattern: String,
    requirement: String,
    max_occurs: String,
    kind: String,
    values: String,
}
struct IsoSchema {
    owner: String,
    message_type: String,
    fields: Vec<IsoField>,
    aliases: Vec<(String, String)>,
}
fn decode_table_field(raw: &str, line: usize, column: usize) -> Result<String, Box<dyn Error>> {
    let mut decoded = String::with_capacity(raw.len());
    let mut characters = raw.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            if character.is_control() {
                return Err(format!(
                    "{ISO20022_SCHEMA_SPEC_PATH}:{line}:{column} contains an unescaped control character"
                )
                .into());
            }
            decoded.push(character);
            continue;
        }
        let escaped = characters.next().ok_or_else(|| {
            format!("{ISO20022_SCHEMA_SPEC_PATH}:{line}:{column} ends with an incomplete escape")
        })?;
        decoded.push(match escaped {
            '\\' => '\\',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            _ => {
                return Err(format!(
                    "{ISO20022_SCHEMA_SPEC_PATH}:{line}:{column} has unsupported escape `\\{escaped}`"
                )
                .into());
            }
        });
    }
    Ok(decoded)
}
fn iso_field_kind(kind: &str, values: &str) -> Result<String, Box<dyn Error>> {
    let simple = match kind {
        "text" => Some("FieldKind::Text"),
        "numeric" => Some("FieldKind::Numeric"),
        "amount" => Some("FieldKind::Amount"),
        "instrument" => Some("FieldKind::Instrument"),
        "date" => Some("FieldKind::Date"),
        "datetime" => Some("FieldKind::DateTime"),
        "identifier:isin" => Some("FieldKind::Identifier(IdentifierKind::Isin)"),
        "identifier:cusip" => Some("FieldKind::Identifier(IdentifierKind::Cusip)"),
        "identifier:lei" => Some("FieldKind::Identifier(IdentifierKind::Lei)"),
        "identifier:bic" => Some("FieldKind::Identifier(IdentifierKind::Bic)"),
        "identifier:mic" => Some("FieldKind::Identifier(IdentifierKind::Mic)"),
        "identifier:iban" => Some("FieldKind::Identifier(IdentifierKind::Iban)"),
        "identifier:currency" => Some("FieldKind::Identifier(IdentifierKind::Currency)"),
        "enum" => None,
        _ => return Err(format!("unknown ISO 20022 field kind `{kind}`").into()),
    };
    if let Some(expression) = simple {
        if values != "-" {
            return Err(format!("non-enum ISO 20022 field kind `{kind}` has enum values").into());
        }
        return Ok(expression.to_owned());
    }
    if values == "-" {
        return Err("ISO 20022 enum field has no values".into());
    }
    let mut seen = BTreeSet::new();
    let mut expression = String::from("FieldKind::Enum(&[");
    for (index, value) in values.split('|').enumerate() {
        if value.is_empty() || value.contains('|') || !seen.insert(value) {
            return Err(format!("invalid or duplicate ISO 20022 enum value `{value}`").into());
        }
        if index > 0 {
            expression.push_str(", ");
        }
        write!(&mut expression, "{value:?}")?;
    }
    expression.push_str("])");
    Ok(expression)
}
fn generate_iso20022_schema() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed={ISO20022_SCHEMA_SPEC_PATH}");
    if !ISO20022_SCHEMA_ASSET.ends_with('\n') || ISO20022_SCHEMA_ASSET.contains('\r') {
        return Err("ISO 20022 schema asset must use canonical LF lines with a final LF".into());
    }
    let mut lines = ISO20022_SCHEMA_ASSET.split_terminator('\n');
    if lines.next() != Some("ivm-iso20022-schema-v1\t19\t200\t193") {
        return Err("unexpected ISO 20022 schema version/count header".into());
    }
    if lines.next() != Some("record\towner\tkey\trequirement\tmax_occurs\tkind\tvalues\ttarget") {
        return Err("unexpected ISO 20022 schema column header".into());
    }
    let mut schemas = Vec::<IsoSchema>::with_capacity(19);
    let mut owners = BTreeSet::new();
    let mut message_types = BTreeSet::new();
    let mut field_count = 0;
    let mut alias_count = 0;
    for (row_index, record) in lines.enumerate() {
        let line = row_index + 3;
        let columns = record
            .split('\t')
            .enumerate()
            .map(|(column_index, raw)| decode_table_field(raw, line, column_index + 1))
            .collect::<Result<Vec<_>, _>>()?;
        if columns.len() != 8 || columns.iter().any(String::is_empty) {
            return Err(format!(
                "{ISO20022_SCHEMA_SPEC_PATH}:{line} must have eight non-empty fields"
            )
            .into());
        }
        match columns[0].as_str() {
            "schema" => {
                if columns[3..].iter().any(|value| value != "-") {
                    return Err(
                        format!("schema record on line {line} has non-sentinel fields").into(),
                    );
                }
                let owner = &columns[1];
                if !owner
                    .chars()
                    .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit())
                    || !owners.insert(owner.clone())
                {
                    return Err(format!("invalid or duplicate schema owner `{owner}`").into());
                }
                let message_type = &columns[2];
                let mut parts = message_type.split('.');
                if !matches!(parts.next(), Some(prefix) if prefix.chars().all(|c| c.is_ascii_lowercase()))
                    || !matches!(parts.next(), Some(version) if version.len() == 3 && version.chars().all(|c| c.is_ascii_digit()))
                    || parts.next().is_some()
                    || !message_types.insert(message_type.clone())
                {
                    return Err(format!(
                        "invalid or duplicate ISO 20022 message type `{message_type}`"
                    )
                    .into());
                }
                schemas.push(IsoSchema {
                    owner: owner.clone(),
                    message_type: message_type.clone(),
                    fields: Vec::new(),
                    aliases: Vec::new(),
                });
            }
            "field" => {
                let schema = schemas
                    .last_mut()
                    .ok_or("ISO 20022 field appears before its schema record")?;
                if columns[1] != schema.owner || columns[7] != "-" {
                    return Err(format!("field record on line {line} is outside its owner").into());
                }
                if !matches!(columns[3].as_str(), "required" | "optional") {
                    return Err(
                        format!("field record on line {line} has invalid requirement").into(),
                    );
                }
                if columns[4] != "none" {
                    let maximum = columns[4].parse::<usize>()?;
                    if maximum == 0 {
                        return Err(
                            format!("field record on line {line} has a zero maximum").into()
                        );
                    }
                }
                iso_field_kind(&columns[5], &columns[6])?;
                if schema
                    .fields
                    .iter()
                    .any(|field| field.pattern == columns[2])
                {
                    return Err(format!("duplicate field pattern `{}`", columns[2]).into());
                }
                schema.fields.push(IsoField {
                    pattern: columns[2].clone(),
                    requirement: columns[3].clone(),
                    max_occurs: columns[4].clone(),
                    kind: columns[5].clone(),
                    values: columns[6].clone(),
                });
                field_count += 1;
            }
            "alias" => {
                let schema = schemas
                    .last_mut()
                    .ok_or("ISO 20022 alias appears before its schema record")?;
                if columns[1] != schema.owner || columns[3..7].iter().any(|value| value != "-") {
                    return Err(format!("alias record on line {line} is outside its owner").into());
                }
                if schema.aliases.iter().any(|(alias, _)| alias == &columns[2]) {
                    return Err(format!("duplicate alias `{}`", columns[2]).into());
                }
                schema
                    .aliases
                    .push((columns[2].clone(), columns[7].clone()));
                alias_count += 1;
            }
            kind => return Err(format!("unknown ISO 20022 schema record `{kind}`").into()),
        }
    }
    if schemas.len() != 19 || field_count != 200 || alias_count != 193 {
        return Err(format!(
            "ISO 20022 schema inventory drifted: schemas={} fields={field_count} aliases={alias_count}",
            schemas.len()
        )
        .into());
    }
    if schemas.iter().any(|schema| schema.fields.is_empty()) {
        return Err("ISO 20022 schema has no fields".into());
    }

    let mut generated = String::from(
        "// @generated by crates/ivm/build.rs from the versioned ISO 20022 schema asset.\n\
         // Do not edit this file directly.\n\n\
         fn schema_for(message_type: &str) -> Option<&'static MessageSchema> {\n\
             match canonical_message_type(message_type).as_ref() {\n",
    );
    for schema in &schemas {
        writeln!(
            &mut generated,
            "        {:?} => Some(&{}_SCHEMA),",
            schema.message_type, schema.owner
        )?;
    }
    generated.push_str("        _ => None,\n    }\n}\n");
    for schema in &schemas {
        writeln!(
            &mut generated,
            "const {}_FIELDS: &[FieldSpec] = &[",
            schema.owner
        )?;
        for field in &schema.fields {
            let kind = iso_field_kind(&field.kind, &field.values)?;
            match field.max_occurs.as_str() {
                "none" => writeln!(
                    &mut generated,
                    "    FieldSpec::{}({:?}, {}),",
                    field.requirement, field.pattern, kind
                )?,
                maximum => writeln!(
                    &mut generated,
                    "    FieldSpec::limited({:?}, {}, {}, {}),",
                    field.pattern,
                    field.requirement == "required",
                    maximum,
                    kind
                )?,
            }
        }
        generated.push_str("];\n");
        writeln!(
            &mut generated,
            "const {}_ALIASES: &[AliasSpec] = &[",
            schema.owner
        )?;
        for (alias, canonical) in &schema.aliases {
            writeln!(
                &mut generated,
                "    AliasSpec {{ alias: {alias:?}, canonical: {canonical:?} }},"
            )?;
        }
        writeln!(
            &mut generated,
            "];\nconst {}_SCHEMA: MessageSchema = MessageSchema {{ fields: {}_FIELDS, aliases: {}_ALIASES }};",
            schema.owner, schema.owner, schema.owner
        )?;
    }
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::write(out_dir.join("iso20022_schema_v1.rs"), generated)?;
    Ok(())
}
fn generate_syscall_signatures() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let specification = fs::read_to_string(manifest_dir.join("spec/syscalls.toml"))?;
    let mut current_number = None;
    let mut current_argument_count = None;
    let mut signatures = Vec::new();
    for line in specification.lines() {
        if let Some(raw) = line
            .strip_prefix("number = \"")
            .and_then(|raw| raw.strip_suffix('"'))
        {
            let number = u32::from_str_radix(
                raw.strip_prefix("0x")
                    .ok_or("syscall number must use a 0x prefix")?,
                16,
            )?;
            if current_number.replace(number).is_some() || current_argument_count.is_some() {
                return Err("syscall number missing an args or ret declaration".into());
            }
            continue;
        }
        if let Some(arguments) = line.strip_prefix("args = \"") {
            let number = current_number.ok_or("syscall args missing number")?;
            if current_argument_count.is_some() {
                return Err(format!("syscall {number:#x} has duplicate args declarations").into());
            }
            current_argument_count = Some(register_window_len(number, "args", arguments, false)?);
            continue;
        }
        let Some(returns) = line.strip_prefix("ret = \"") else {
            continue;
        };
        let number = current_number.take().ok_or("syscall ret missing number")?;
        let argument_count = current_argument_count
            .take()
            .ok_or("syscall ret missing args declaration")?;
        let return_count = register_window_len(number, "ret", returns, true)?;
        signatures.push((number, argument_count, return_count));
    }
    if current_number.is_some() || current_argument_count.is_some() {
        return Err("final syscall number missing an args or ret declaration".into());
    }
    signatures.sort_unstable();
    if signatures.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err("duplicate syscall number in spec/syscalls.toml".into());
    }
    let mut generated = String::from(
        "// Generated from spec/syscalls.toml; do not edit.\n\
         /// Return the exact public input-register window for an ABI syscall.\n\
         pub(crate) fn syscall_public_input_registers(number: u32) -> &'static [usize] {\n\
             match number {\n",
    );
    for &(number, count, _) in &signatures {
        generated.push_str(&format!("        {number:#08x} => SYSCALL_ARGS_{count},\n"));
    }
    generated.push_str(
        "        _ => SYSCALL_ARGS_6,\n\
         }\n\
         }\n\
         /// Return the exact public output-register window for an ABI syscall.\n\
         pub(crate) fn syscall_public_output_registers(number: u32) -> &'static [usize] {\n\
             match number {\n",
    );
    for (number, _, count) in signatures {
        generated.push_str(&format!("        {number:#08x} => SYSCALL_ARGS_{count},\n"));
    }
    generated.push_str(
        "        _ => SYSCALL_ARGS_0,\n\
         }\n\
         }\n",
    );
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::write(out_dir.join("syscall_signatures.rs"), generated)?;
    Ok(())
}
fn register_window_len(
    number: u32,
    field: &str,
    declaration: &str,
    implicit_r10: bool,
) -> Result<usize, Box<dyn Error>> {
    let mut registers = declared_registers(declaration)?;
    let declaration = declaration.strip_suffix('"').unwrap_or(declaration);
    if implicit_r10 && declaration != "-" && registers.is_empty() {
        registers.push(10);
    }
    registers.sort_unstable();
    registers.dedup();
    if registers
        .iter()
        .enumerate()
        .any(|(offset, &register)| register != 10 + offset)
    {
        return Err(format!(
            "syscall {number:#x} {field} must use a contiguous V1 public register window starting at r10"
        )
        .into());
    }
    Ok(registers.len())
}
fn declared_registers(declaration: &str) -> Result<Vec<usize>, Box<dyn Error>> {
    let bytes = declaration.as_bytes();
    let mut registers = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let starts_register = bytes[index] == b'r'
            && bytes.get(index + 1).is_some_and(u8::is_ascii_digit)
            && (index == 0
                || (!bytes[index - 1].is_ascii_alphanumeric() && bytes[index - 1] != b'_'));
        if !starts_register {
            index += 1;
            continue;
        }
        let start = index + 1;
        let mut end = start;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        let register = declaration[start..end].parse::<usize>()?;
        if !(10..=15).contains(&register) {
            return Err(format!(
                "syscall register r{register} exceeds the V1 public window r10..r15"
            )
            .into());
        }
        registers.push(register);
        index = end;
    }
    Ok(registers)
}
#[cfg(feature = "cuda")]
fn build_cuda_artifacts() -> Result<(), Box<dyn Error>> {
    use cuda_build_policy::REVIEWED_CUDA_BUNDLE_PINS;
    use cuda_bundle_files::{BundlePresence, bundle_presence};
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let cuda_dir = manifest_dir.join("cuda");
    println!("cargo:rerun-if-changed={}", cuda_dir.display());
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::create_dir_all(&out_dir)?;
    let mut observed = BTreeSet::new();
    let mut unexpected_bundle = Vec::new();
    for entry in fs::read_dir(&cuda_dir)? {
        let path = entry?.path();
        if path.extension() == Some(OsStr::new("cu")) {
            let stem = path
                .file_stem()
                .and_then(OsStr::to_str)
                .ok_or_else(|| format!("CUDA source has a non-UTF-8 stem: {}", path.display()))?;
            observed.insert(stem.to_owned());
        }
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| format!("CUDA bundle entry has a non-UTF-8 name: {}", path.display()))?;
        let is_bundle =
            path.extension() == Some(OsStr::new("ptx")) || name.starts_with("provenance");
        let expected = ["provenance.v1", "provenance.v1.sig", "provenance.v1.pub"].contains(&name)
            || CUDA_PTX_STEMS
                .iter()
                .any(|stem| name.strip_suffix(".ptx") == Some(*stem));
        if is_bundle && !expected {
            unexpected_bundle.push(path);
        }
    }
    if let Some(error) = cuda_source_inventory_error(&observed) {
        return Err(error.into());
    }
    if !unexpected_bundle.is_empty() {
        return Err(format!("unexpected CUDA bundle entries: {unexpected_bundle:?}").into());
    }
    let mut present = [false; 13];
    for (index, stem) in CUDA_PTX_STEMS.iter().enumerate() {
        let source = cuda_dir.join(format!("{stem}.cu"));
        println!("cargo:rerun-if-changed={}", source.display());
        present[index] = original_bundle_path_present(&cuda_dir.join(format!("{stem}.ptx")))?;
    }
    for (index, name) in ["provenance.v1", "provenance.v1.sig", "provenance.v1.pub"]
        .iter()
        .enumerate()
    {
        present[index + 10] = original_bundle_path_present(&cuda_dir.join(name))?;
    }
    let presence = bundle_presence(REVIEWED_CUDA_BUNDLE_PINS.is_some(), &present)?;
    if presence == BundlePresence::Absent {
        // Absence never conceals changed source inputs or an inaccessible inode.
        for source in CUDA_SOURCES {
            let path = cuda_dir.join(format!("{}.cu", source.stem));
            let bytes = cuda_bundle_files::read_regular_file(&path, None)?;
            if !cuda_provenance::matches_sha256(&bytes, source.sha256) {
                return Err(format!(
                    "CUDA source {} differs from the reviewed original bytes",
                    source.stem
                )
                .into());
            }
        }
        fs::write(
            out_dir.join("cuda_bundle.rs"),
            "static CANDIDATE: Option<Candidate> = None;\n",
        )?;
        return Ok(());
    }
    let pins = REVIEWED_CUDA_BUNDLE_PINS.ok_or("source CUDA approval absent")?;
    let verified = cuda_bundle_files::verify_bundle(
        &cuda_dir,
        &CUDA_PTX_STEMS,
        pins.public_key_sha256,
        pins.manifest_sha256,
    )?;
    // This remains a signed claim; the release owner independently measures its
    // genuine pinned image. No compiler/toolkit child runs in ordinary Cargo.
    println!(
        "cargo:rustc-env=IVM_CUDA_SIGNED_IMAGE_SHA256={}",
        verified.cuda_image_sha256
    );
    let mut generated = String::from(
        "static CANDIDATE: Option<Candidate> = Some(Candidate {\nmanifest: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/provenance.v1\")),\npublic_key: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/provenance.v1.pub\")),\nsignature: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/provenance.v1.sig\")),\nfamilies: [\n",
    );
    for (index, source) in CUDA_SOURCES.iter().enumerate() {
        let stem = source.stem;
        if !cuda_provenance::matches_sha256(&verified.sources[index], source.sha256) {
            return Err(
                format!("CUDA source {stem} differs from the reviewed original bytes").into(),
            );
        }
        let target = out_dir.join(format!("{stem}.ptx"));
        validate_ptx_bytes(&target, &verified.artifacts[index])?;
        fs::write(&target, &verified.artifacts[index])?;
        fs::write(out_dir.join(format!("{stem}.cu")), &verified.sources[index])?;
        writeln!(
            &mut generated,
            "FamilyInput {{ source: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{stem}.cu\")), ptx: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{stem}.ptx\")), nul: concat!(include_str!(concat!(env!(\"OUT_DIR\"), \"/{stem}.ptx\")), \"\\0\").as_bytes() }},"
        )?;
    }
    generated.push_str("] });\n");
    fs::write(out_dir.join("provenance.v1"), &verified.manifest)?;
    fs::write(out_dir.join("provenance.v1.pub"), verified.public_key)?;
    fs::write(out_dir.join("provenance.v1.sig"), verified.signature)?;
    fs::write(out_dir.join("cuda_bundle.rs"), generated)?;
    Ok(())
}
/// Missing alone is absence. A dangling link, nonregular inode or I/O refusal
/// is retained as supplied/inaccessible material and can never enable CPU absence.
#[cfg(feature = "cuda")]
fn original_bundle_path_present(path: &Path) -> Result<bool, Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        Ok(metadata) => {
            println!("cargo:rerun-if-changed={}", path.display());
            if !metadata.file_type().is_file() {
                return Err(format!("{} must be a regular file", path.display()).into());
            }
            Ok(true)
        }
    }
}
#[cfg(any(feature = "cuda", test))]
fn cuda_source_inventory_error(observed: &BTreeSet<String>) -> Option<String> {
    let expected: BTreeSet<String> = CUDA_PTX_STEMS
        .iter()
        .map(|stem| (*stem).to_owned())
        .collect();
    if observed == &expected {
        return None;
    }
    let missing: Vec<_> = expected.difference(observed).map(String::as_str).collect();
    let unexpected: Vec<_> = observed.difference(&expected).map(String::as_str).collect();
    Some(format!(
        "CUDA source inventory must contain exactly ten production families; missing: {missing:?}; unexpected: {unexpected:?}"
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cuda_source_inventory_requires_all_ten_families() {
        let mut stems: BTreeSet<String> =
            CUDA_PTX_STEMS.iter().map(|stem| (*stem).into()).collect();
        assert_eq!(cuda_source_inventory_error(&stems), None);
        stems.remove("signature");
        assert!(
            cuda_source_inventory_error(&stems)
                .unwrap()
                .contains("signature")
        );
        stems.insert("signature".into());
        stems.insert("float_diagnostic".into());
        assert!(
            cuda_source_inventory_error(&stems)
                .unwrap()
                .contains("float_diagnostic")
        );
    }
}
