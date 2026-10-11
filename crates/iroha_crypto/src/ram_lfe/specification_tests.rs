//! Source checks for `specs/ram_lfe_execution_proof.md`.
//!
//! The current-path inventory names the symbols that refuse, sign or attest
//! today. These tests fail when a named symbol leaves its cited file or when a
//! stated call order changes, so the table cannot drift from the source silently.
//!
//! The normalizing-lowering sections are pinned the same way: their tables are
//! compared with the cleartext oracle and with the recorded cost summary, every
//! obligation and every listed requirement is pinned to its text and names
//! tests and plan tasks that exist, the example tapes of the text are run
//! through the oracle, and the canonical frames and function identities are
//! compared with the vectors recorded before the amendment that added those
//! sections.

use super::{RamLfeBackend, RamLfeError};
use std::path::PathBuf;

const MARKER: &str = "<!-- ram-lfe-current-paths -->";
/// Stable refusal code of the SDK input-encryption helpers.
const REFUSAL_CODE: &str = "ram_lfe_encryption_unavailable";

/// A tracked text file with Unix line endings, whatever the checkout wrote.
pub(super) fn repository_file(path: &str) -> String {
    let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path);
    unix_lines(
        &std::fs::read_to_string(&full).unwrap_or_else(|error| {
            panic!("inventory cites {path}, which cannot be read: {error}")
        }),
    )
}

/// Replace every Windows line ending by a Unix one, so a source check that
/// looks for text across a line break does not depend on the checkout.
fn unix_lines(text: &str) -> String {
    text.replace("\r\n", "\n")
}

#[test]
fn source_checks_do_not_depend_on_the_line_endings_of_the_checkout() {
    assert_eq!(
        unix_lines("#[test]\r\nfn name()\r\n"),
        "#[test]\nfn name()\n"
    );
    assert_eq!(unix_lines("a\nb\r\n\r\nc"), "a\nb\n\nc");
    // A lone carriage return is not a line ending and is kept.
    assert_eq!(unix_lines("a\rb"), "a\rb");
    // The files these tests read have no carriage return left.
    for path in [
        "specs/ram_lfe_execution_proof.md",
        "crates/iroha_crypto/src/ram_lfe/normal_form_tests.rs",
        "crates/iroha_torii/src/identifier_resolution.rs",
    ] {
        assert!(!repository_file(path).contains("\r\n"), "{path}");
    }
}

fn backticked(cell: &str) -> Vec<&str> {
    cell.split('`').skip(1).step_by(2).collect()
}

/// One inventory row: the symbols it names, the file it cites and its statement.
struct Row<'a> {
    symbols: Vec<&'a str>,
    file: &'a str,
    statement: &'a str,
}

fn inventory(document: &str) -> Vec<Row<'_>> {
    let start = document
        .find(MARKER)
        .expect("specification carries the current-path inventory")
        + MARKER.len();
    let rows: Vec<Row<'_>> = document[start..]
        .lines()
        .skip_while(|line| !line.starts_with('|'))
        .take_while(|line| line.starts_with('|'))
        // Header and separator.
        .skip(2)
        .map(|line| {
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            assert_eq!(cells.len(), 3, "inventory row has three cells: {line}");
            let files = backticked(cells[1]);
            assert_eq!(files.len(), 1, "inventory row cites one file: {line}");
            Row {
                symbols: backticked(cells[0]),
                file: files[0],
                statement: cells[2],
            }
        })
        .collect();
    assert!(!rows.is_empty(), "inventory has rows");
    rows
}

fn specification() -> String {
    repository_file("specs/ram_lfe_execution_proof.md")
}

/// Rows of the one table that follows a marker: trimmed cells, without the
/// header and the separator.
fn marked_table<'a>(document: &'a str, marker: &str) -> Vec<Vec<&'a str>> {
    assert_eq!(
        document.matches(marker).count(),
        1,
        "specification carries {marker} exactly once"
    );
    let start = document.find(marker).expect("counted above") + marker.len();
    let rows: Vec<Vec<&str>> = document[start..]
        .lines()
        .skip_while(|line| !line.starts_with('|'))
        .take_while(|line| line.starts_with('|'))
        .skip(2)
        .map(|line| line.trim_matches('|').split('|').map(str::trim).collect())
        .collect();
    assert!(!rows.is_empty(), "{marker} has rows");
    rows
}

/// A cell that is one code span.
fn code(cell: &str) -> &str {
    cell.strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))
        .unwrap_or_else(|| panic!("`{cell}` is not one code span"))
}

/// A cell that is one number, with or without thousands separators.
fn number(cell: &str) -> u64 {
    cell.replace(',', "")
        .parse()
        .unwrap_or_else(|_| panic!("`{cell}` is not a number"))
}

/// The document with every run of whitespace as one space, for sentences that
/// wrap.
fn unwrapped(document: &str) -> String {
    document.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The text under one `###` heading, up to the next heading of any level.
fn subsection<'a>(document: &'a str, heading: &str) -> &'a str {
    let start = document
        .find(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("specification has no section {heading}"))
        + 1;
    let body = &document[start + heading.len()..];
    let end = body.find("\n#").map_or(body.len(), |end| end + 1);
    &body[..end]
}

/// Every list item of a text, each with its continuation lines as one line.
fn list_items(text: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if let Some(first) = line.strip_prefix("- ") {
            let mut item = first.trim().to_owned();
            while let Some(more) = lines.next_if(|more| more.starts_with("  ")) {
                item.push(' ');
                item.push_str(more.trim());
            }
            items.push(item);
        }
    }
    items
}

/// The one paragraph that starts with `opening`, as one line. The opening is
/// compared after unwrapping, so it may run past a line break.
fn paragraph(document: &str, opening: &str) -> String {
    let mut found = document
        .split("\n\n")
        .map(unwrapped)
        .filter(|paragraph| paragraph.starts_with(opening));
    let paragraph = found
        .next()
        .unwrap_or_else(|| panic!("specification has no paragraph `{opening}`"));
    assert!(
        found.next().is_none(),
        "specification has two paragraphs `{opening}`"
    );
    paragraph
}

#[test]
fn text_helpers_read_sections_items_and_paragraphs() {
    let document = "# T\n\n### A\n\nfirst\nline\n\n- one\n  more\n- two\n\n\
                    **P.** x\ny\n\n### B\n\n- three\n\n## C\n\ntail\n";
    assert_eq!(
        subsection(document, "### A"),
        "\n\nfirst\nline\n\n- one\n  more\n- two\n\n**P.** x\ny\n\n"
    );
    assert_eq!(subsection(document, "### B"), "\n\n- three\n\n");
    assert_eq!(subsection(document, "## C"), "\n\ntail\n");
    assert_eq!(
        list_items(subsection(document, "### A")),
        ["one more", "two"]
    );
    assert_eq!(list_items(document), ["one more", "two", "three"]);
    assert_eq!(paragraph(document, "**P.**"), "**P.** x y");
    assert_eq!(paragraph(document, "**P.** x y"), "**P.** x y");
    assert_eq!(paragraph(document, "first"), "first line");
}

/// The recorded cost model and measurements of the RNS-BGV starting candidates.
#[cfg(feature = "json")]
pub(super) fn cost_summary() -> norito::json::Value {
    norito::json::from_str(&repository_file("specs/fhe_bgv_cost_summary.json"))
        .expect("the cost summary is JSON")
}

/// Follow object keys from a JSON value.
#[cfg(feature = "json")]
pub(super) fn json_at<'a>(
    value: &'a norito::json::Value,
    path: &[&str],
) -> &'a norito::json::Value {
    path.iter().fold(value, |value, key| {
        value
            .get(*key)
            .unwrap_or_else(|| panic!("the cost summary has no `{key}` under {path:?}"))
    })
}

/// Read one classified number of the cost summary: `{"class", "unit", "value"}`.
#[cfg(feature = "json")]
pub(super) fn json_count(value: &norito::json::Value, key: &str) -> u64 {
    json_at(value, &[key, "value"])
        .as_u64()
        .unwrap_or_else(|| panic!("`{key}` of the cost summary is not a count"))
}

#[test]
fn every_inventory_symbol_exists_in_its_cited_file() {
    let document = specification();
    let rows = inventory(&document);
    let mut checked = 0;
    for row in &rows {
        assert!(
            !row.symbols.is_empty(),
            "row for {} names a symbol",
            row.file
        );
        assert!(!row.statement.is_empty());
        let source = repository_file(row.file);
        for symbol in &row.symbols {
            for segment in symbol.split("::") {
                assert!(
                    source.contains(segment),
                    "{} no longer contains `{segment}` of `{symbol}`",
                    row.file
                );
            }
            checked += 1;
        }
    }
    // Every component the inventory covers has at least one row.
    for prefix in [
        "crates/iroha_crypto/",
        "crates/iroha_data_model/",
        "crates/iroha_core/",
        "crates/iroha_torii/",
        "IrohaSwift/",
        "kotlin/",
        "java/",
        "javascript/",
        "python/",
        "csharp/",
    ] {
        assert!(
            rows.iter().any(|row| row.file.starts_with(prefix)),
            "inventory has no row under {prefix}"
        );
    }
    assert!(checked >= rows.len());
}

#[test]
fn inventory_links_the_machine_readable_consumer_inventory() {
    // The complete consumer inventory belongs to another task. Its checker
    // names the file it validates; the specification must link that file.
    let checker = repository_file("scripts/check_fhe_ownership_map.py");
    let path = checker
        .lines()
        .find_map(|line| line.strip_prefix("DEFAULT_MAP = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("the ownership checker declares its default inventory");
    let link = path
        .strip_prefix("specs/")
        .expect("the inventory is a tracked specification file");
    assert!(
        specification().contains(&format!("]({link})")),
        "specification must link the consumer inventory {path}"
    );
    assert!(!repository_file(path).is_empty());
}

#[test]
fn backend_refusal_is_what_the_inventory_states() {
    assert_eq!(
        RamLfeBackend::BfvAffineV1.require_production_support(),
        Err(RamLfeError::InsecureBfvProfile)
    );
    assert_eq!(
        RamLfeBackend::BfvProgrammedV1.require_production_support(),
        Err(RamLfeError::InsecureBfvProfile)
    );
    assert_eq!(
        RamLfeBackend::HkdfSha3_512PrfV1.require_production_support(),
        Ok(())
    );
}

/// Text of one function of the Torii resolver, from its name to the closing
/// brace at the indentation of its `fn` line.
fn method_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("Torii resolver has no `{name}`"));
    let line_start = source[..start].rfind('\n').map_or(0, |newline| newline + 1);
    let indentation: String = source[line_start..]
        .chars()
        .take_while(|character| *character == ' ')
        .collect();
    let body = &source[start..];
    let end = body
        .find(&format!("\n{indentation}}}\n"))
        .unwrap_or_else(|| panic!("`{name}` has no closing brace at its indentation"));
    &body[..end]
}

fn position(body: &str, needle: &str) -> usize {
    body.find(needle)
        .unwrap_or_else(|| panic!("expected `{needle}` in the method body"))
}

#[test]
fn torii_call_order_is_what_the_inventory_states() {
    let source = repository_file("crates/iroha_torii/src/identifier_resolution.rs");

    // The encrypted execution refuses the insecure backends first and then
    // every backend except the programmed one.
    let execute = method_body(&source, "execute_encrypted");
    assert!(
        position(execute, "require_supported_program_policy(")
            < position(execute, "UnsupportedBackend(")
    );
    let supported = method_body(&source, "require_supported_program_policy");
    assert_eq!(supported.matches("require_production_support()").count(), 2);

    // The general identifier path runs the encrypted execution before it
    // looks at the opening.
    let derive = method_body(&source, "derive_encrypted");
    assert!(
        position(derive, "self.execute_encrypted(") < position(derive, "validate_output_opening(")
    );

    // The phone path checks the pinned contract shape first and only then
    // runs the encrypted execution.
    let phone = method_body(&source, "derive_phone_retail_encrypted");
    assert!(
        position(phone, "InvalidPhoneCanonicality(") < position(phone, "self.execute_encrypted(")
    );
    assert!(position(phone, "is_phone_retail()") < position(phone, "self.execute_encrypted("));
}

#[test]
fn sdk_refusals_are_what_the_inventory_states() {
    let document = specification();
    let rows = inventory(&document);
    let sdk_row = |prefix: &str| {
        rows.iter()
            .find(|row| row.file.starts_with(prefix))
            .unwrap_or_else(|| panic!("inventory has no row under {prefix}"))
    };
    // Swift, Kotlin, Java and JavaScript refuse input encryption.
    for prefix in ["kotlin/", "java/", "javascript/"] {
        let row = sdk_row(prefix);
        assert!(
            repository_file(row.file).contains(REFUSAL_CODE),
            "{} no longer refuses with {REFUSAL_CODE}",
            row.file
        );
    }
    assert!(repository_file(sdk_row("IrohaSwift/").file).contains("ramLfeEncryptionUnavailable"));
    // Python and C# carry receipt and policy models and no encryption helper,
    // so the files the inventory cites carry no refusal either.
    for prefix in ["python/", "csharp/"] {
        let row = sdk_row(prefix);
        assert!(
            !repository_file(row.file).contains(REFUSAL_CODE),
            "{} gained an input-encryption refusal; update the inventory",
            row.file
        );
    }
}

// ---- canonical vectors recorded before the normalizing-lowering amendment ----

use super::{
    HiddenRamFheInstruction as Op, HiddenRamFheProgram, RamLfeClassV1,
    RamLfeEncryptionKeyCommitmentV1, RamLfeEvaluationKeyCommitmentV1, RamLfeFunctionIdentityV1,
    RamLfeOpeningKeyCommitmentV1, RamLfePolicyV1, RamLfePrfKeyCommitmentV1, RamLfeProfileIdV1,
    RamLfeProgramKeyV1, RamLfeQueryLimitV1, RamLfeRelationIdV1,
    ram_lfe_v1_plaintext_semantics_hash,
};

/// The affine fixture tape of `canonical_tests.rs`.
const PINNED_AFFINE_TAPE: [Op; 5] = [
    Op::LoadInput(0, 1),
    Op::LoadState(1, 3),
    Op::Add(2, 0, 1),
    Op::MulPlain(2, 2, 5),
    Op::Output(2),
];

/// One instruction of every opcode, within rank 16.
const PINNED_BOUNDED_TAPE: [Op; 12] = [
    Op::LoadInput(0, 1),
    Op::LoadConst(1, 256),
    Op::Mul(2, 0, 1),
    Op::SelectEqZero(3, 0, 1, 2),
    Op::StoreState(4, 3),
    Op::LoadState(1, 4),
    Op::AddPlain(1, 1, 7),
    Op::SubPlain(1, 1, 9),
    Op::MulPlain(1, 1, 128),
    Op::Add(0, 0, 1),
    Op::Output(0),
    Op::Output(3),
];

fn pinned_program(instructions: &[Op]) -> HiddenRamFheProgram {
    let mut builder = HiddenRamFheProgram::builder().unwrap();
    for &instruction in instructions {
        builder.push(instruction).unwrap();
    }
    builder.finish().unwrap()
}

fn pinned_identity(class: RamLfeClassV1, instructions: &[Op]) -> RamLfeFunctionIdentityV1 {
    RamLfeFunctionIdentityV1::commit(
        class,
        &RamLfeProgramKeyV1::from_bytes([7; 32]).unwrap(),
        &pinned_program(instructions),
        RamLfeQueryLimitV1::new(1000, 3).unwrap(),
    )
    .unwrap()
}

fn pinned_policy() -> RamLfePolicyV1 {
    RamLfePolicyV1 {
        function: pinned_identity(RamLfeClassV1::Affine, &PINNED_AFFINE_TAPE),
        profile: RamLfeProfileIdV1::from_descriptor(b"profile").unwrap(),
        encryption_key: RamLfeEncryptionKeyCommitmentV1::commit(b"encryption").unwrap(),
        evaluation_key: RamLfeEvaluationKeyCommitmentV1::commit(b"evaluation").unwrap(),
        opening_key: RamLfeOpeningKeyCommitmentV1::commit(b"opening").unwrap(),
        prf_key: RamLfePrfKeyCommitmentV1::commit(b"prf").unwrap(),
        relation: RamLfeRelationIdV1::from_descriptor(b"relation").unwrap(),
    }
}

/// Every canonical byte string of the contract the amendment must leave unchanged.
fn canonical_vectors() -> Vec<(&'static str, String)> {
    let frame = |value: &dyn Fn() -> Vec<u8>| hex::encode(value());
    let affine = pinned_identity(RamLfeClassV1::Affine, &PINNED_AFFINE_TAPE);
    let bounded = pinned_identity(RamLfeClassV1::Bounded, &PINNED_BOUNDED_TAPE);
    let refresh = pinned_identity(RamLfeClassV1::Refresh, &PINNED_BOUNDED_TAPE);
    let policy = pinned_policy();
    vec![
        (
            "plaintext semantics digest",
            hex::encode(ram_lfe_v1_plaintext_semantics_hash().as_ref()),
        ),
        (
            "class frame affine.v1",
            frame(&|| norito::encode_canonical(&RamLfeClassV1::Affine).unwrap()),
        ),
        (
            "class frame bounded.v1",
            frame(&|| norito::encode_canonical(&RamLfeClassV1::Bounded).unwrap()),
        ),
        (
            "class frame refresh.v1",
            frame(&|| norito::encode_canonical(&RamLfeClassV1::Refresh).unwrap()),
        ),
        (
            "tape frame affine fixture",
            hex::encode(
                pinned_program(&PINNED_AFFINE_TAPE)
                    .to_bytes()
                    .unwrap()
                    .as_slice(),
            ),
        ),
        (
            "tape frame bounded fixture",
            hex::encode(
                pinned_program(&PINNED_BOUNDED_TAPE)
                    .to_bytes()
                    .unwrap()
                    .as_slice(),
            ),
        ),
        (
            "function commitment affine.v1",
            hex::encode(affine.function.as_bytes()),
        ),
        (
            "initializer commitment affine.v1",
            hex::encode(affine.initializer.as_bytes()),
        ),
        (
            "function identity frame affine.v1",
            frame(&|| norito::encode_canonical(&affine).unwrap()),
        ),
        (
            "function identity affine.v1",
            hex::encode(affine.id().unwrap().as_hash().as_ref()),
        ),
        (
            "function identity frame bounded.v1",
            frame(&|| norito::encode_canonical(&bounded).unwrap()),
        ),
        (
            "function identity bounded.v1",
            hex::encode(bounded.id().unwrap().as_hash().as_ref()),
        ),
        (
            "function identity frame refresh.v1",
            frame(&|| norito::encode_canonical(&refresh).unwrap()),
        ),
        (
            "function identity refresh.v1",
            hex::encode(refresh.id().unwrap().as_hash().as_ref()),
        ),
        (
            "policy frame",
            frame(&|| norito::encode_canonical(&policy).unwrap()),
        ),
        (
            "policy commitment",
            hex::encode(policy.commitment().unwrap().as_hash().as_ref()),
        ),
    ]
}

/// Canonical byte strings recorded on 2026-10-06 from the contract as it stood
/// before the normalizing-lowering amendment (`canonical.rs`, `class.rs`,
/// `program.rs` and `initialization.rs` at commit `13343a33c1`). The amendment
/// changes no canonical type, class rule, descriptor or function identity, so
/// every string must stay byte-identical.
const CANONICAL_VECTORS_BEFORE_THE_AMENDMENT: [(&str, &str); 16] = [
    (
        "plaintext semantics digest",
        "9e9e03d525dbe2b636182afacf550dbc2b9df921d86de2334ccd5f3d6ae26cc5",
    ),
    (
        "class frame affine.v1",
        "4e5254300000488f37c1a2d9ad1f86de8d9c33daa7d20004000000000000004b9f1b1e3586a5f40000000000",
    ),
    (
        "class frame bounded.v1",
        "4e5254300000488f37c1a2d9ad1f86de8d9c33daa7d2000400000000000000973e373c6b0c4be90001000000",
    ),
    (
        "class frame refresh.v1",
        "4e5254300000488f37c1a2d9ad1f86de8d9c33daa7d2000400000000000000f3dc425a899278cf0002000000",
    ),
    (
        "tape frame affine fixture",
        "4e52543000004ee23d06145bb2aa2d4ceee4793a0bd4000201000000000000aaafe0754fef11b7020101020400022000f801f0000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000010000000000000003000000000000000000000000000000000000000000000000000000000000000400000000000000020000000000000000000000000000000100000000000000000000000000000000000000000000000700000000000000020000000000000002000000000000000500000000000000000000000000000000000000000000000a0000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "tape frame bounded fixture",
        "4e52543000004ee23d06145bb2aa2d4ceee4793a0bd400520200000000000051338780ed02939b020101020400022000c80440020000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000300000000000000010000000000000000010000000000000000000000000000000000000000000000000000000000000800000000000000020000000000000000000000000000000100000000000000000000000000000000000000000000000900000000000000030000000000000000000000000000000100000000000000020000000000000000000000000000000200000000000000040000000000000003000000000000000000000000000000000000000000000000000000000000000100000000000000010000000000000004000000000000000000000000000000000000000000000000000000000000000500000000000000010000000000000001000000000000000700000000000000000000000000000000000000000000000600000000000000010000000000000001000000000000000900000000000000000000000000000000000000000000000700000000000000010000000000000001000000000000008000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0000000000000003000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "function commitment affine.v1",
        "7288d7be51b502877dea8e24ada39831d7c8214c31b680eb01f990ec4f2d6698",
    ),
    (
        "initializer commitment affine.v1",
        "48f906f760329d779c032df1b77ce76ddd8d706801ba55976725eacc13c27d23",
    ),
    (
        "function identity frame affine.v1",
        "4e525430000000e3f84ff411bd31f432873d0a0150ec007900000000000000c9ab825cc6e0807e020400000000209e9e03d525dbe2b636182afacf550dbc2b9df921d86de2334ccd5f3d6ae26cc521207288d7be51b502877dea8e24ada39831d7c8214c31b680eb01f990ec4f2d6698212048f906f760329d779c032df1b77ce76ddd8d706801ba55976725eacc13c27d230e08e8030000000000000403000000",
    ),
    (
        "function identity affine.v1",
        "9bd080be150e1323b545166c91e8c3856390175691ebcd953722d8b0f58ceb75",
    ),
    (
        "function identity frame bounded.v1",
        "4e525430000000e3f84ff411bd31f432873d0a0150ec007900000000000000f736dc06b176336b020401000000209e9e03d525dbe2b636182afacf550dbc2b9df921d86de2334ccd5f3d6ae26cc521204edc456f9aa3e5b2c7dc8b73f876a5d9831d0b042050051bda5e3075f1d4f8072120732ed6f31547c3ea17bbe00c7a5d8b41895a77170cb56c9677f1cc2aefac369a0e08e8030000000000000403000000",
    ),
    (
        "function identity bounded.v1",
        "6709650c273c3db74f344852d3f435bd90bbdeb1cabd42d481fa1e5be716c27d",
    ),
    (
        "function identity frame refresh.v1",
        "4e525430000000e3f84ff411bd31f432873d0a0150ec007900000000000000d8860f3cb686a6c5020402000000209e9e03d525dbe2b636182afacf550dbc2b9df921d86de2334ccd5f3d6ae26cc5212044a76309ef8dd72c67837939863ec769ccbfbb16f77a6f934e6a35ae9af180052120ee8f3bc4b800bf77672ec367b3b942a43ed2a10a0223459068449744fcde9ab70e08e8030000000000000403000000",
    ),
    (
        "function identity refresh.v1",
        "bbb9254f0a6c068409cc1ee97c811e80699ccbbf014151a8f28d4e2b6f5f8fab",
    ),
    (
        "policy frame",
        "4e5254300000dd45a409050691ef018b919c78a65014004601000000000000be239823ced4e86d02790400000000209e9e03d525dbe2b636182afacf550dbc2b9df921d86de2334ccd5f3d6ae26cc521207288d7be51b502877dea8e24ada39831d7c8214c31b680eb01f990ec4f2d6698212048f906f760329d779c032df1b77ce76ddd8d706801ba55976725eacc13c27d230e08e80300000000000004030000002120fa30abb9febcce8cebdf72d0c73cfdc6139ab2ca429518405913d016fa10f06b21209147e67eaf7fa9f29204003f13518214f00027eb4cbd4346973277d37e8bc72321203b885118769b60652600e9d0be6b1a4f5967942784fd00377ef0f9c484949ebd2120ad5dc99bb001b96f8765ca9a239185069bf2d6bc5617816f5ad4d4bf5ea3cd512120af081b4c79b9bba02342fa426149c7d9f49725475b33995371da62661563634f21200e4b85332589c2a2d6be542915a33ecdd9627ce21c306ee28e4905f442da3c79",
    ),
    (
        "policy commitment",
        "411743239f4e94ce772d04de59f73f3f32e8f9f79b92f9d39eb6330c5311268f",
    ),
];

#[test]
fn canonical_frames_and_identities_are_unchanged_by_the_lowering_amendment() {
    let actual = canonical_vectors();
    let actual: Vec<(&str, &str)> = actual
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    assert_eq!(actual, CANONICAL_VECTORS_BEFORE_THE_AMENDMENT);

    // The same fixture is pinned by the commitment tests that predate the
    // amendment. Both pins name one value, so neither can be replaced alone.
    let earlier = repository_file("crates/iroha_crypto/src/ram_lfe/canonical_tests.rs");
    for name in [
        "function commitment affine.v1",
        "initializer commitment affine.v1",
        "function identity affine.v1",
        "policy commitment",
    ] {
        let (_, value) = CANONICAL_VECTORS_BEFORE_THE_AMENDMENT
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .expect("pinned vector");
        assert!(
            earlier.contains(&format!("\"{value}\"")),
            "{name} is no longer the vector the commitment tests pin"
        );
    }
    let earlier = repository_file("crates/iroha_crypto/src/ram_lfe/class_tests.rs");
    assert!(earlier.contains(CANONICAL_VECTORS_BEFORE_THE_AMENDMENT[0].1));

    // The class is part of the identity: the three frames and their three
    // digests are six different strings, although `bounded.v1` and
    // `refresh.v1` commit the same tape under the same key.
    let identities: std::collections::BTreeSet<&str> = actual
        .iter()
        .filter(|(name, _)| name.starts_with("function identity "))
        .map(|(_, value)| *value)
        .collect();
    assert_eq!(identities.len(), 6);
}

// ---- normalizing lowering ----

use super::{
    RAM_LFE_V1_NORMAL_BASE_COLUMNS, RAM_LFE_V1_NORMAL_COEFFICIENT_MAGNITUDE,
    RAM_LFE_V1_NORMAL_CONSTANT_COLUMN, RAM_LFE_V1_NORMAL_INPUT_COLUMN,
    RAM_LFE_V1_NORMAL_LANE_COLUMN, RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR,
    RamLfeNormalGateKindV1, RamLfeNormalRoleV1, RamLfeNormalShapeV1, RamLfeOpcodeV1,
};

#[test]
fn specification_states_the_normalizing_lowering_contract() {
    let text = unwrapped(&specification());
    for sentence in [
        "**Logical rank bounds ciphertext multiplication depth, not physical noise.**",
        "**Instruction-by-instruction evaluation of the existing candidates does not hold the \
         maximum shape.**",
        "A V1 tape is never evaluated on ciphertexts instruction by instruction.",
        "The lowering is mandatory for all three classes.",
        "It changes no canonical type.",
        "Every coefficient is computed exactly in F257 and is reduced before any encrypted \
         evaluation",
        "- **State updates.**",
        "- **Output snapshots.**",
        "- **Aliasing.**",
        "- **Nonlinear boundaries.**",
        "- **Refresh points.**",
        "**one fixed public schedule for each class profile**",
        "- **A function of the public profile only.**",
        "- **Padded to the class maximum.**",
        "- **Multiplications are concealed.**",
        "Rank 16 does not mean at most sixteen multiplication operations",
        "- **Dummy work and hidden routing preserve semantics.**",
        "Their noise and their work are inside the bound",
        "- **No visible failure.**",
        "- **The private refresh accounting stays private.**",
        "It must not become an observable physical schedule",
        "- **A fixed schedule alone does not establish circuit privacy.**",
        "The `NL-S` rows are the semantic-equivalence obligations.",
        "The `NL-L` rows are the leakage obligations",
        "No encrypted normalizer exists",
        // The existing candidates stay unqualified, and folding does not
        // qualify them.
        "They are counterexamples, not a qualification. The candidates are unqualified.",
        "Folding does not make the existing candidates adequate: task C.3 derives and measures \
         the worst-case noise and work of the complete padded construction, including key \
         switches, masking and sanitization.",
        // The private refresh accounting of the class never schedules a
        // physical refresh.
        "it is never the physical refresh schedule",
        // What the relation must prove about the padded output and about the
        // witnesses of the lowering.
        "decrypts, in the 64 padded output slots, to what the cleartext reference outputs \
         followed by zeros.",
        "A normal form, a routing or a refresh placement supplied as an unconstrained witness \
         is not acceptable.",
    ] {
        assert!(
            text.contains(sentence),
            "specification no longer states: {sentence}"
        );
    }
    // The oracle says of itself what the specification says of it.
    let oracle = repository_file("crates/iroha_crypto/src/ram_lfe/normal_form.rs");
    assert!(oracle.contains("TODO(R.3): this is a cleartext oracle."));
    assert!(oracle.contains("TODO(R.3): only tests call this oracle."));
}

#[test]
fn normal_form_tables_are_what_the_oracle_computes() {
    let document = specification();

    // Columns.
    assert_eq!(RAM_LFE_V1_NORMAL_CONSTANT_COLUMN, 0);
    assert_eq!(RAM_LFE_V1_NORMAL_INPUT_COLUMN, 1);
    assert_eq!(RAM_LFE_V1_NORMAL_LANE_COLUMN, 65);
    assert_eq!(RAM_LFE_V1_NORMAL_BASE_COLUMNS, 97);
    assert_eq!(RAM_LFE_V1_NORMAL_COEFFICIENT_MAGNITUDE, 128);
    let text = unwrapped(&document);
    assert!(text.contains("| 97 + g | The result of gate g, in gate order. |"));
    assert!(text.contains("centered representative of magnitude at most 128"));

    // Gates: name, operand forms and ciphertext multiplications.
    let gates = marked_table(&document, "<!-- ram-lfe-v1-normal-gates -->");
    assert_eq!(gates.len(), RamLfeNormalGateKindV1::ALL.len());
    for (row, kind) in gates.iter().zip(RamLfeNormalGateKindV1::ALL) {
        assert_eq!(row.len(), 4);
        assert_eq!(code(row[0]), kind.as_str());
        assert_eq!(row[1].split(',').count(), kind.operand_count(), "{kind}");
        assert_eq!(number(row[3]), u64::from(kind.ciphertext_multiplications()));
    }
    // The selection gate is the formula of the unchanged descriptor.
    let formula = "nonzero+(1-cond^256)*(zero-nonzero)";
    assert!(gates[1][2].replace(' ', "").contains(formula));
    assert!(RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR.contains(&format!("dst={formula};")));

    // Roles: every opcode, in tag order.
    let roles = marked_table(&document, "<!-- ram-lfe-v1-normal-roles -->");
    assert_eq!(roles.len(), RamLfeOpcodeV1::ALL.len());
    for (row, opcode) in roles.iter().zip(RamLfeOpcodeV1::ALL) {
        assert_eq!(row.len(), 3);
        assert_eq!(code(row[0]), opcode.name());
        assert_eq!(row[1], RamLfeNormalRoleV1::of(opcode).as_str(), "{opcode}");
        assert!(!row[2].is_empty());
    }

    // Shape: the largest normal form of every class.
    let shapes = marked_table(&document, "<!-- ram-lfe-v1-normal-shape -->");
    assert_eq!(shapes.len(), RamLfeClassV1::ALL.len());
    for (row, class) in shapes.iter().zip(RamLfeClassV1::ALL) {
        let shape = RamLfeNormalShapeV1::of(class);
        assert_eq!(code(row[0]), class.as_str());
        let numbers: Vec<u64> = row[1..].iter().map(|cell| number(cell)).collect();
        assert_eq!(
            numbers,
            [
                u64::from(shape.nonlinear_gates),
                u64::from(shape.refreshes),
                u64::from(shape.outputs),
                u64::from(shape.columns),
                u64::from(shape.depth),
                u64::from(shape.ciphertext_multiplications),
            ],
            "{class}"
        );
        // The shape restates the class limits the unchanged descriptor commits.
        assert!(RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR.contains(&format!(
            "class={class};opcodes={};max-rank={};max-refreshes={}\n",
            RamLfeOpcodeV1::ALL
                .iter()
                .filter(|opcode| class.admits(**opcode))
                .map(|opcode| opcode.tag().to_string())
                .collect::<Vec<_>>()
                .join(","),
            shape.depth,
            shape.refreshes,
        )));
    }
    assert!(text.contains("A form has at most 416 terms of centered magnitude at most 128."));
    assert_eq!(RamLfeNormalShapeV1::of(RamLfeClassV1::Refresh).columns, 416);
}

// ---- pinned specification text: begin ----
// The constants below are the text of `specs/ram_lfe_execution_proof.md`, with
// every run of whitespace as one space. A sentence changed in the specification
// is changed here in the same change, and a reviewer sees both sides.

/// Every obligation of the normalizing lowering: its id, its owners and its
/// complete text. A changed, moved or deleted obligation fails a test here.
const LOWERING_OBLIGATIONS: [(&str, &str, &str); 14] = [
    (
        "NL-S1",
        "R.0",
        "**Reference equality.** For every class, every member tape, every lane vector and \
         every admitted input, the normal form evaluates to the ordered output of the \
         cleartext reference: the same scalars, the same count, the same order. The equality \
         does not depend on admission: it holds for every 64 scalars of F257 in the input \
         slots.",
    ),
    (
        "NL-S2",
        "R.0",
        "**Machine equality.** The forms the registers and the lanes hold after the last \
         instruction evaluate to the last row of the reference trace, so every state update \
         is resolved exactly.",
    ),
    (
        "NL-S3",
        "R.0",
        "**Boundaries.** Every `Mul`, every `SelectEqZero` and every scheduled refresh is \
         exactly one gate, in execution order. The ciphertext multiplications of the gates \
         are those of the class accounting, and the depth is at most the logical rank.",
    ),
    (
        "NL-S4",
        "R.0",
        "**Class on the tape.** Normalization refuses exactly the tapes class membership \
         refuses, with the same error, and a tape has the same normal form under every class \
         that admits it.",
    ),
    (
        "NL-S5",
        "R.0",
        "**Reduced coefficients.** Every coefficient is exact and canonical, and a plaintext \
         run of any length contributes one coefficient for each column. Runs that give the \
         same forms leave no trace; a normal form is not canonical for the function of its \
         tape.",
    ),
    (
        "NL-S6",
        "R.3, R.7, R.9",
        "**Encrypted equality.** The output ciphertext of the encrypted evaluation decrypts \
         to the output of `NL-S1` in the 64 padded output slots, with the unused slots zero, \
         for every member tape up to the maximum shape. Those 64 slots are the vector an \
         opening commits.",
    ),
    (
        "NL-S7",
        "R.3, R.7, R.9",
        "**Proved, not asserted.** The execution relation proves, for the tape the function \
         commitment commits, that the evaluated normal form is the normalization of that tape \
         and that the tape is a member of the committed class. A normal form supplied as an \
         unconstrained witness is not accepted.",
    ),
    (
        "NL-L1",
        "R.0",
        "**One shape for each class.** Every member tape normalizes within the shape of its \
         class, and every bound of the shape is reached: all of them by one tape, except that \
         64 outputs leave at most 192 nonlinear gates.",
    ),
    (
        "NL-L2",
        "R.3, R.7, R.9",
        "**One schedule for each class profile.** Levels, ciphertext sizes, evaluation keys, \
         key switches, refresh slots and operation, access and proof shapes are identical for \
         every member tape.",
    ),
    (
        "NL-L3",
        "C.3, R.3, R.7, R.9",
        "**Padded bound.** The worst-case physical noise and the work of the complete padded \
         schedule, with dummy work, key switches, masking and sanitization, are derived and \
         measured at the maximum shape. No evaluation of a member tape fails.",
    ),
    (
        "NL-L4",
        "R.3, R.7, R.9",
        "**Dummy work and routing.** Dummy operations and hidden routing change no column and \
         no output, and the unused output slots are zero.",
    ),
    (
        "NL-L5",
        "R.9",
        "**Private refresh accounting.** The physical refresh slots are fixed by the profile. \
         The number and the placement of the logical refreshes of a tape are not observable.",
    ),
    (
        "NL-L6",
        "R.11",
        "**Time and access.** What an observer outside the evaluator can time or measure for \
         one execution does not depend on the tape. Work whose duration depends on the tape, \
         such as normalizing it in cleartext, is not observable for a request.",
    ),
    (
        "NL-L7",
        "R.11",
        "**Circuit privacy.** The leakage bound of the normalized evaluation under the fixed \
         schedule is established with its sanitization and its maximum-shape physical noise. \
         A fixed schedule is not a substitute.",
    ),
];

/// Every listed requirement of the three sections the normalizing-lowering
/// amendment added, complete and in order.
const LOWERING_REQUIREMENTS: [(&str, &[&str]); 3] = [
    (
        "### Logical rank and physical noise",
        &[
            "**Plaintext operations.** `Add`, `AddPlain`, `SubPlain` and `MulPlain` leave \
             rank unchanged and each grows the noise of a ciphertext. One multiplication by a \
             hidden constant multiplies a worst-case noise bound by up to `(257 - 1) / 2 = \
             128`, seven bits, at constant rank, and every class admits a run of 254 of them \
             on one loaded input at rank 0.",
            "**The number of ciphertext multiplications.** Rank 16 does not mean at most \
             sixteen multiplication operations. A `bounded.v1` tape of 255 independent \
             `SelectEqZero` instructions has rank 10 and 2,550 ciphertext multiplications; \
             one of 255 independent `Mul` instructions has rank 1.",
            "**Everything else an encrypted evaluation does**: key switches, modulus \
             switches, masks, broadcasts, output zeroing, sanitization and refresh.",
        ],
    ),
    (
        "### Normalizing lowering",
        &[
            "**State updates.** `StoreState` and `LoadState` are resolved in tape order. A \
             lane holds the form that was stored, not what the source register became \
             afterwards, and a later store replaces an earlier one. The forms refer only to \
             the columns of this execution, so nothing reaches another execution.",
            "**Output snapshots.** An output is the form its register held when its `Output` \
             executed. A later write to the register does not change it. The outputs keep \
             their order and their count.",
            "**Aliasing.** Every source is read before the destination is written, as in the \
             reference. A destination may be any of its sources and a source may be named \
             more than once.",
            "**Nonlinear boundaries.** Every `Mul` and every `SelectEqZero` stays exactly one \
             gate, in tape order, with the formula of the descriptor. No gate is merged, \
             split, reordered, replaced by a cheaper one or removed. That holds for a gate \
             whose operands are constants, for one whose operands folded to zero and for one \
             whose result nothing reads.",
            "**Refresh points.** For `refresh.v1`, every point of the canonical schedule is \
             one `Refresh` gate over the form of the scheduled register, placed immediately \
             before the instruction that required it. The register then holds the gate's \
             column. Another register or lane that holds the same form is not refreshed.",
            "A scaling moved across a gate stays in the coefficients. `LoadInput(0,1); \
             Mul(1,0,0); Output(1)` and `LoadInput(0,1); MulPlain(0,0,2); Mul(1,0,0); \
             MulPlain(1,1,193); Output(1)` both output the square of input slot 1, because `2 \
             * 2 * 193` is 1 modulo 257. The operand forms of the first carry the coefficient \
             1 and its output form the coefficient 1; those of the second carry 2 and 193.",
            "A nonzero scaling of a `SelectEqZero` condition selects the same branch and \
             stays in the condition form.",
            "A gate nothing reads and a gate over constants stay gates.",
        ],
    ),
    (
        "### Fixed public schedule",
        &[
            "**A function of the public profile only.** The schedule fixes the level of every \
             ciphertext at every step, every ciphertext size, the evaluation keys it requires \
             and their sizes, the number, kind and position of every key switch, modulus \
             switch, ciphertext multiplication, mask and broadcast, the refresh slots, the \
             sequence of operations and of memory and key accesses, the shape and size of the \
             proof and the size of every message.",
            "**Padded to the class maximum.** The schedule provides for the largest normal \
             form of the class in the table above. A tape with fewer gates, outputs or \
             refreshes, with shorter forms or with zero coefficients runs the same schedule. \
             No hidden count selects a shorter schedule, a lower level, a smaller ciphertext, \
             a skipped operation or an early exit.",
            "**Multiplications are concealed.** The number and the placement of the \
             ciphertext multiplications of a tape are hidden by the padding, and so is the \
             kind of every gate. Rank 16 does not mean at most sixteen multiplication \
             operations: the schedule of `bounded.v1` covers 255 nonlinear gates at depth 16.",
            "**Dummy work and hidden routing preserve semantics.** Padding is dummy work (a \
             gate slot no gate of the tape uses, an output slot beyond the output count, a \
             refresh slot without a logical refresh) and hidden routing (which column feeds \
             which slot). Neither changes a column or an output of the normal form, and the \
             unused output slots are zero. Their noise and their work are inside the bound: \
             the worst-case noise bound and the work, memory and proof budgets are those of \
             the complete padded schedule, with every key switch, mask, dummy operation and \
             sanitization step, and never those of one tape.",
            "**No visible failure.** Because the bound is that of the padded schedule, every \
             member tape and every well-formed input evaluates within it. An evaluation never \
             fails, is refused, is retried or takes another path because of the tape.",
            "**The private refresh accounting stays private.** The lazy schedule of the class \
             accounting (`RamLfeClassReportV1::refresh_points`) is a function of the hidden \
             tape. It decides membership and gives the `Refresh` gates of the normal form. It \
             must not become an observable physical schedule: the physical refresh slots, \
             their number and their positions are fixed by the profile, the logical refreshes \
             are routed into them privately, and an unused slot performs a dummy refresh.",
            "**A fixed schedule alone does not establish circuit privacy.** It hides what the \
             shape of the computation would disclose. It does not hide what the evaluated \
             ciphertext carries: its noise depends on the hidden coefficients and on the \
             values routed through it even when every level and size is fixed. \
             Hidden-function privacy against the opener needs the circuit-private evaluation \
             and sanitization of task R.11, established for the normalized evaluation under \
             this schedule.",
        ],
    ),
];

/// Paragraphs that state a rule in full: each is pinned whole, by its opening words.
const PINNED_PARAGRAPHS: [&str; 17] = [
    "What the lowering removes is what need not survive: the instruction count, which folded \
     opcodes a run used, which registers and lanes carried a value, and the number, length \
     and placement of plaintext runs. Plaintext runs that give the same forms leave no trace: \
     two tapes whose gates have the same kinds and the same operand forms, in order, and \
     whose output forms are equal have one normal form, whatever instructions produced those \
     forms.",
    "**A normal form is not canonical for the function a tape computes.** Two tapes that \
     compute one function can have different normal forms:",
    "Nothing may therefore rest on equal functions having equal normal forms. What an \
     evaluated ciphertext discloses about the coefficients is bounded by the sanitization of \
     `NL-L7` and by nothing in the lowering.",
    "What they receive is the 64 output slots an [opening commits](#commitments): the ordered \
     output followed by zeros. The number of outputs the tape emitted is known to the program \
     owner, who holds the tape, and an opening conveys it to nobody else. From the 64 scalars \
     the opener and the beneficiary can infer only that this number reaches at least the last \
     nonzero slot; a trailing zero the tape emitted is indistinguishable from padding. \
     Validators and everyone else see the hiding output commitment and no scalar.",
    "**Opened output.** Every V1 opening commits the 64 decrypted output slots: the ordered \
     output of the execution followed by zeros (`RamLfeOrderedOutputV1::padded_for_opening`). \
     The ordered-output frame of an opening therefore always has `output_count` 64. This is \
     an acceptance rule for openings, not an invariant of a type: the frame, the output \
     commitment and the ordered-output owner are unchanged and still admit 1 to 64 scalars, \
     and the cleartext reference keeps exactly the scalars the tape emitted, in order. The \
     opener never holds the tape and cannot tell a trailing zero the tape emitted from \
     padding, so it has no other vector to commit. An opening conveys the number of outputs \
     the tape emitted to nobody; the program owner, who holds the tape, is the only party \
     that knows it. The same 64 slots are what the decryption proof binds to the output \
     ciphertext, what the output commitment commits and the output component of the \
     identifier-PRF derivation. The hiding commitment shows validators no count, so the \
     decryption proof of task R.8 enforces the rule. A differential check against the \
     cleartext reference compares the opened slots with the reference output padded with \
     zeros to 64. Tests show the rule on a short output, on trailing zeros the tape emitted \
     and on 64 outputs.",
    "The normalizer is a cleartext oracle for the program owner and for tests, like the \
     reference. It reads the hidden tape and is not constant time. Its buffers are heap \
     allocations of fixed capacity that are cleared when they drop. A class refusal is \
     returned before any buffer exists, so the only error returned while a buffer holds data \
     is an allocation failure. Tests observe the cleared scalars when a form and its \
     evaluations end, when a refused reservation returns an error after the refresh schedule \
     and the initial symbolic machine of a normalization or the plaintext column values of an \
     evaluation were written, and during unwinding. After its last reservation a \
     normalization returns no error, so no error is returned while a folded form holds data. \
     No encrypted normalizer exists; task R.3 builds it and compares it with this oracle.",
    "Never public: the tape, its instruction count, opcodes, indexes and immediates, the \
     output count, the program key, the state lanes, the plaintext input, the plaintext \
     output and every refresh point. The [normal form](#normalizing-lowering) of the tape is \
     as private as the tape: its gates, their kinds, number and order, and every coefficient. \
     Evaluation and proof shapes follow one [fixed public schedule](#fixed-public-schedule) \
     for each class profile, padded to the class maximum; a private count never selects a \
     smaller one.",
    "**Logical rank bounds ciphertext multiplication depth, not physical noise.** The rank \
     rules of the descriptor count the dependency depth of ciphertext multiplications and \
     nothing else. Rank does not count:",
    "Rank therefore decides class membership. It decides no level, no modulus chain and no \
     failure probability, and the limit 16 is a recorded candidate, not a property of any \
     encryption profile.",
    "The contract does not answer this by enlarging a modulus chain, and it adds no \
     plaintext-depth limit to a class: the admitted tapes, the class rules, the descriptor \
     and every function identity stay as they are. It answers it by the lowering below.",
    "A V1 tape is never evaluated on ciphertexts instruction by instruction. It is evaluated \
     through its **normal form**, by a **normalizing lowering** that is proved to preserve \
     the cleartext reference. The lowering is mandatory for all three classes.",
    "It changes no canonical type. The function identity commits the tape, the class is \
     decided on the tape by `RamLfeClassV1::membership`, and the plaintext-semantics \
     descriptor is the one above. A normal form has no canonical encoding and enters no \
     commitment.",
    "A **folded** instruction leaves no operation of its own: a run of any number of them \
     between two boundaries becomes the coefficients of the forms that read it. Every \
     coefficient is computed exactly in F257 and is reduced before any encrypted evaluation, \
     which multiplies by its centered representative of magnitude at most 128.",
    "**Depth.** The multiplication depth of a column is zero for the constant, an input slot, \
     a lane and a `Refresh` gate. The depth of a form is the highest depth of a column with a \
     nonzero coefficient. A `Mul` gate has the higher depth of its two forms plus one; a \
     `SelectEqZero` gate has the highest of the condition plus ten and each branch plus one. \
     The depth of a normal form is at most the logical rank of its tape, and can be lower \
     when a coefficient folds to zero. The class is decided on the tape and never on the \
     normal form: a tape outside its class is refused even when its normal form would be \
     shallower.",
    "The encrypted evaluation of a normal form follows **one fixed public schedule for each \
     class profile**: each pair of a class and an encryption profile that a policy can name. \
     The policy's `profile` and `relation` commit it; a prover or an evaluator chooses none \
     of it.",
    "The `NL-S` rows are the semantic-equivalence obligations. The execution relation must \
     prove them against the cleartext reference: task R.3 for `affine.v1`, extended by R.7 to \
     the `Mul` and `SelectEqZero` gates and by R.9 to the `Refresh` gates. The `NL-L` rows \
     are the leakage obligations that follow from the fixed public schedule.",
    "Until the rows without a check are met, no class is usable. This contract registers no \
     production policy and makes no security claim for the existing candidates.",
];
// ---- pinned specification text: end ----

#[test]
fn lowering_obligations_are_pinned_to_their_text() {
    let document = specification();
    let rows = marked_table(
        &document,
        "<!-- ram-lfe-normalizing-lowering-obligations -->",
    );
    assert_eq!(rows.len(), LOWERING_OBLIGATIONS.len());
    for (row, (id, owners, text)) in rows.iter().zip(LOWERING_OBLIGATIONS) {
        assert_eq!(code(row[0]), id);
        assert_eq!(row[1], text, "text of {id}");
        assert_eq!(row[2], owners, "owners of {id}");
        // A title and at least one sentence after it.
        let (title, body) = text
            .strip_prefix("**")
            .and_then(|rest| rest.split_once(".** "))
            .unwrap_or_else(|| panic!("{id} has no title"));
        assert!(!title.is_empty() && body.ends_with('.'), "{id}");
    }
    // No two obligations share a title or a text, so two rows cannot be swapped
    // or merged without failing the comparison above.
    let texts: std::collections::BTreeSet<&str> = LOWERING_OBLIGATIONS
        .iter()
        .map(|(_, _, text)| *text)
        .collect();
    assert_eq!(texts.len(), LOWERING_OBLIGATIONS.len());
    let titles: std::collections::BTreeSet<&str> = LOWERING_OBLIGATIONS
        .iter()
        .map(|(_, _, text)| text.split(".**").next().expect("title"))
        .collect();
    assert_eq!(titles.len(), LOWERING_OBLIGATIONS.len());
}

#[test]
fn lowering_requirements_are_pinned_to_their_text() {
    let document = specification();
    for (heading, requirements) in LOWERING_REQUIREMENTS {
        let items = list_items(subsection(&document, heading));
        let items: Vec<&str> = items.iter().map(String::as_str).collect();
        assert_eq!(items, requirements, "list items of {heading}");
    }
    // The five things the lowering must preserve and the seven properties of
    // the fixed public schedule are all there, by title and in order.
    let titles = |heading: &str| -> Vec<&'static str> {
        LOWERING_REQUIREMENTS
            .iter()
            .find(|(candidate, _)| *candidate == heading)
            .expect("pinned section")
            .1
            .iter()
            .filter_map(|item| item.strip_prefix("**"))
            .filter_map(|item| item.split_once(".**"))
            .map(|(title, _)| title)
            .collect()
    };
    assert_eq!(
        titles("### Normalizing lowering"),
        [
            "State updates",
            "Output snapshots",
            "Aliasing",
            "Nonlinear boundaries",
            "Refresh points",
        ]
    );
    assert_eq!(
        titles("### Fixed public schedule"),
        [
            "A function of the public profile only",
            "Padded to the class maximum",
            "Multiplications are concealed",
            "Dummy work and hidden routing preserve semantics",
            "No visible failure",
            "The private refresh accounting stays private",
            "A fixed schedule alone does not establish circuit privacy",
        ]
    );

    let text = unwrapped(&document);
    for pinned in PINNED_PARAGRAPHS {
        let opening: String = pinned.chars().take(48).collect();
        assert_eq!(paragraph(&document, &opening), pinned);
        assert_eq!(text.matches(pinned).count(), 1);
    }
}

/// A count with a comma between thousands, as the specification writes it.
fn grouped(count: u32) -> String {
    if count < 1000 {
        count.to_string()
    } else {
        format!("{},{:03}", count / 1000, count % 1000)
    }
}

#[test]
fn joint_bounds_and_the_opening_rule_are_what_the_code_states() {
    use super::{RAM_LFE_V1_MAX_INSTRUCTIONS, RAM_LFE_V1_MAX_OUTPUTS, RamLfeOrderedOutputV1};

    assert_eq!(grouped(0), "0");
    assert_eq!(grouped(999), "999");
    assert_eq!(grouped(2550), "2,550");
    assert_eq!(grouped(1_000), "1,000");

    // The paragraph on joint bounds, rebuilt from the shape of each class.
    let document = specification();
    let bounded = RamLfeNormalShapeV1::of(RamLfeClassV1::Bounded);
    let refresh = RamLfeNormalShapeV1::of(RamLfeClassV1::Refresh);
    let expected = format!(
        "**The bounds are reached together, except the outputs.** One member tape of {gates} \
         `SelectEqZero` instructions and one output reaches every other bound of its class at \
         once: for `refresh.v1` {} nonlinear gates, {} refreshes, {} columns, depth {} and {} \
         ciphertext multiplications, and for `bounded.v1` {} nonlinear gates, {} columns, \
         depth {} and {} ciphertext multiplications. Only the output bound and the gate bound \
         exclude each other, because an output and a nonlinear gate are one instruction each \
         and a tape has at most {instructions}: a tape with {outputs} outputs has at most \
         {remaining} nonlinear gates, and it still reaches the refresh and depth bounds. The \
         fixed public schedule provides every gate, refresh and output slot whatever the tape \
         uses, so the noise and the work to derive are those of all bounds of a row together.",
        refresh.nonlinear_gates,
        refresh.refreshes,
        refresh.columns,
        refresh.depth,
        grouped(refresh.ciphertext_multiplications),
        bounded.nonlinear_gates,
        bounded.columns,
        bounded.depth,
        grouped(bounded.ciphertext_multiplications),
        gates = RAM_LFE_V1_MAX_INSTRUCTIONS - 1,
        instructions = RAM_LFE_V1_MAX_INSTRUCTIONS,
        outputs = RAM_LFE_V1_MAX_OUTPUTS,
        remaining = RAM_LFE_V1_MAX_INSTRUCTIONS - RAM_LFE_V1_MAX_OUTPUTS,
    );
    assert_eq!(
        paragraph(&document, "**The bounds are reached together"),
        expected
    );
    assert_eq!(bounded.refreshes, 0);
    assert_eq!(
        usize::from(refresh.nonlinear_gates),
        RAM_LFE_V1_MAX_INSTRUCTIONS - 1
    );
    // The oracle says of its shape what the specification says.
    let oracle = repository_file("crates/iroha_crypto/src/ram_lfe/normal_form.rs");
    let documentation = unwrapped(&oracle).replace("/// ", "");
    assert!(documentation.contains(&format!(
        "a tape has at most {}: a tape with {} outputs has at most {} nonlinear gates.",
        RAM_LFE_V1_MAX_INSTRUCTIONS,
        RAM_LFE_V1_MAX_OUTPUTS,
        RAM_LFE_V1_MAX_INSTRUCTIONS - RAM_LFE_V1_MAX_OUTPUTS
    )));
    assert!(!documentation.contains("not reached together"));
    assert!(!unwrapped(&document).contains("not reached together"));
    // The test that reaches the bounds together exists and is cited.
    let tests = repository_file("crates/iroha_crypto/src/ram_lfe/normal_form_tests.rs");
    assert!(tests.contains("fn joint_maximum_tape(class: RamLfeClassV1) -> Vec<Op> {"));
    assert!(tests.contains("fn joint_maximum_tape_with_every_output("));

    // The opening rule names the function that pads, and that function gives
    // the 64 slots the rule states.
    let rule = paragraph(&document, "**Opened output.**");
    assert!(rule.contains("(`RamLfeOrderedOutputV1::padded_for_opening`)"));
    assert!(rule.contains(&format!(
        "always has `output_count` {RAM_LFE_V1_MAX_OUTPUTS}"
    )));
    let output = RamLfeOrderedOutputV1::from_scalars(&[5, 0, 256]).unwrap();
    let opened = output.padded_for_opening();
    assert_eq!(opened.scalars().len(), RAM_LFE_V1_MAX_OUTPUTS);
    assert_eq!(opened.scalars()[..3], [5, 0, 256]);
    assert!(opened.scalars()[3..].iter().all(|&scalar| scalar == 0));
    // The frame and the owners the rule calls unchanged still admit 1 to 64.
    assert!(RamLfeOrderedOutputV1::from_scalars(&[]).is_err());
    assert!(RamLfeOrderedOutputV1::from_scalars(&[0; 64]).is_ok());
    assert!(RamLfeOrderedOutputV1::from_scalars(&[0; 65]).is_err());
    let reference = repository_file("crates/iroha_crypto/src/ram_lfe/reference_tests.rs");
    for name in [
        "an_opening_commits_the_sixty_four_padded_output_slots",
        "opened_slots_of_two_tapes_differ_only_where_their_outputs_do",
    ] {
        assert!(
            reference.contains(&format!("#[test]\nfn {name}()")),
            "{name}"
        );
    }

    // The clearing statement names what the tests of the oracle observe.
    for name in [
        "normal_form_is_redacted_and_its_buffers_clear_on_success_and_error",
        "buffers_clear_when_an_error_returns_after_they_were_written",
        "normal_form_buffers_clear_during_unwinding",
    ] {
        assert!(tests.contains(&format!("#[test]\nfn {name}()")), "{name}");
    }
    assert!(oracle.contains("fn reserve(cells: &mut Vec<u16>, capacity: usize)"));
    // Every buffer the oracle owns is reserved by the one function a test can
    // refuse: the file allocates nowhere else.
    assert_eq!(oracle.matches("try_reserve").count(), 1);
    for other in [
        "Vec::with_capacity(",
        "vec![",
        "Box::new(",
        ".to_vec()",
        ".collect",
    ] {
        assert!(!oracle.contains(other), "the oracle allocates with {other}");
    }
    // After its last reservation a normalization returns no error: nothing
    // between `Folding::new` and the result is fallible, and the folding
    // steps return no `Result`.
    let folding = oracle
        .split_once("let mut folding = Folding::new(shape)?;")
        .and_then(|(_, rest)| rest.split_once("Ok(folding.finish(class, report))"))
        .map(|(body, _)| body)
        .expect("the normalization folds between its last reservation and its result");
    assert!(folding.contains("folding.step(instruction);"));
    assert!(folding.contains("folding.refresh(point[1]);"));
    assert!(!folding.contains('?') && !folding.contains("Err("));
    for infallible in [
        "fn step(&mut self, instruction: HiddenRamFheInstruction) {",
        "fn refresh(&mut self, register: u16) {",
        "fn gate(&mut self, kind: RamLfeNormalGateKindV1, registers: &[u16]) -> usize {",
        "fn finish(mut self, class: RamLfeClassV1, report: RamLfeClassReportV1) \
         -> RamLfeNormalFormV1 {",
    ] {
        assert!(oracle.contains(infallible), "{infallible}");
    }
}

/// A tape the specification writes as `Name(a,b); Name(a)`.
fn written_tape(text: &str) -> Vec<Op> {
    text.split(';')
        .map(|instruction| {
            let (name, arguments) = instruction
                .trim()
                .strip_suffix(')')
                .and_then(|rest| rest.split_once('('))
                .unwrap_or_else(|| panic!("`{instruction}` is not an instruction"));
            let arguments: Vec<u64> = arguments
                .split(',')
                .map(|argument| {
                    argument
                        .trim()
                        .parse()
                        .unwrap_or_else(|_| panic!("`{instruction}` has a bad operand"))
                })
                .collect();
            let index = |position: usize| u16::try_from(arguments[position]).expect("index");
            match (name, arguments.len()) {
                ("LoadInput", 2) => Op::LoadInput(index(0), index(1)),
                ("LoadState", 2) => Op::LoadState(index(0), index(1)),
                ("StoreState", 2) => Op::StoreState(index(0), index(1)),
                ("LoadConst", 2) => Op::LoadConst(index(0), arguments[1]),
                ("Add", 3) => Op::Add(index(0), index(1), index(2)),
                ("AddPlain", 3) => Op::AddPlain(index(0), index(1), arguments[2]),
                ("SubPlain", 3) => Op::SubPlain(index(0), index(1), arguments[2]),
                ("MulPlain", 3) => Op::MulPlain(index(0), index(1), arguments[2]),
                ("Mul", 3) => Op::Mul(index(0), index(1), index(2)),
                ("SelectEqZero", 4) => Op::SelectEqZero(index(0), index(1), index(2), index(3)),
                ("Output", 1) => Op::Output(index(0)),
                _ => panic!("`{instruction}` is not an instruction of the tape"),
            }
        })
        .collect()
}

#[test]
fn written_tapes_are_parsed_with_the_parameter_order_of_the_descriptor() {
    assert_eq!(
        written_tape(
            "LoadInput(0,1); LoadState(1, 2); StoreState(3,1); LoadConst(2,256); Add(0,1,2); \
             AddPlain(1,0,7); SubPlain(1,1,9); MulPlain(2,1,128); Mul(3,0,1); \
             SelectEqZero(0,1,2,3); Output(3)"
        ),
        [
            Op::LoadInput(0, 1),
            Op::LoadState(1, 2),
            Op::StoreState(3, 1),
            Op::LoadConst(2, 256),
            Op::Add(0, 1, 2),
            Op::AddPlain(1, 0, 7),
            Op::SubPlain(1, 1, 9),
            Op::MulPlain(2, 1, 128),
            Op::Mul(3, 0, 1),
            Op::SelectEqZero(0, 1, 2, 3),
            Op::Output(3),
        ]
    );
    // The name and the parameter count of every opcode are the descriptor's.
    for opcode in RamLfeOpcodeV1::ALL {
        let line = RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR
            .lines()
            .find(|line| line.starts_with(&format!("opcode={}:{}(", opcode.tag(), opcode.name())))
            .unwrap_or_else(|| panic!("descriptor has no line for {opcode}"));
        let parameters = line
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(parameters, _)| parameters.split(',').count())
            .expect("parameter list");
        let operands = vec!["0"; parameters].join(",");
        let tape = written_tape(&format!("{}({operands})", opcode.name()));
        assert_eq!(tape.len(), 1);
        assert_eq!(tape[0].opcode(), opcode);
    }
    for malformed in ["Mul(0,0)", "Jump(1)", "Output(0", "Output(x)"] {
        assert!(
            std::panic::catch_unwind(|| written_tape(malformed)).is_err(),
            "{malformed}"
        );
    }
}

#[test]
fn example_tapes_of_the_specification_are_one_function_with_two_normal_forms() {
    use super::{
        RamLfeInitialMemoryV1, RamLfeReferenceInputV1, ram_lfe_reference_execute_v1,
        ram_lfe_reference_normalize_v1,
    };

    // The item that says a scaling moved across a gate stays in the
    // coefficients carries its two tapes and its three coefficients.
    let document = specification();
    let items = list_items(subsection(&document, "### Normalizing lowering"));
    let item = items
        .iter()
        .find(|item| item.starts_with("A scaling moved across a gate stays in the coefficients."))
        .expect("the example of a moved scaling");
    let spans = backticked(item);
    assert_eq!(spans.len(), 3, "two tapes and the product that is one");
    let tapes = [written_tape(spans[0]), written_tape(spans[1])];
    let product: u32 = spans[2]
        .split('*')
        .map(|factor| factor.trim().parse::<u32>().expect("a factor"))
        .product();
    assert_eq!((spans[2], product % 257), ("2 * 2 * 193", 1));
    assert!(item.ends_with(
        "The operand forms of the first carry the coefficient 1 and its output form the \
         coefficient 1; those of the second carry 2 and 193."
    ));

    let programs = [pinned_program(&tapes[0]), pinned_program(&tapes[1])];
    // One function: the square of input slot 1, for every scalar of the field
    // there and for both field edges in every other slot.
    let lanes = RamLfeInitialMemoryV1::from_lanes(&[0; 32]).unwrap();
    for value in 0..=256_u16 {
        for other in [0_u16, 256] {
            let mut slots = [other; 64];
            slots[1] = value;
            let input = RamLfeReferenceInputV1::from_field_slots(&slots);
            let square = u16::try_from(u32::from(value) * u32::from(value) % 257).unwrap();
            for program in &programs {
                let execution =
                    ram_lfe_reference_execute_v1(RamLfeClassV1::Bounded, program, &lanes, &input)
                        .unwrap();
                assert_eq!(execution.output().scalars(), [square]);
            }
        }
    }
    // Two normal forms, with exactly the coefficients the text gives.
    let column = RAM_LFE_V1_NORMAL_INPUT_COLUMN + 1;
    let gate = RAM_LFE_V1_NORMAL_BASE_COLUMNS;
    for (program, (operand, output)) in programs.iter().zip([(1_u16, 1_u16), (2, 193)]) {
        let normal = ram_lfe_reference_normalize_v1(RamLfeClassV1::Bounded, program).unwrap();
        assert_eq!((normal.gate_count(), normal.output_count()), (1, 1));
        assert_eq!(normal.gate_kind(0), Some(RamLfeNormalGateKindV1::Mul));
        for side in 0..2 {
            let form = normal.gate_operand(0, side).unwrap();
            let terms: Vec<(usize, u16)> = form
                .iter()
                .copied()
                .enumerate()
                .filter(|&(_, coefficient)| coefficient != 0)
                .collect();
            assert_eq!(terms, [(column, operand)]);
        }
        let form = normal.output_form(0).unwrap();
        let terms: Vec<(usize, u16)> = form
            .iter()
            .copied()
            .enumerate()
            .filter(|&(_, coefficient)| coefficient != 0)
            .collect();
        assert_eq!(terms, [(gate, output)]);
    }
    // The test of the oracle that shows the same, and the two other items.
    let tests = repository_file("crates/iroha_crypto/src/ram_lfe/normal_form_tests.rs");
    assert!(
        tests.contains("#[test]\nfn a_normal_form_is_not_canonical_for_the_function_of_its_tape()")
    );
    assert!(
        !unwrapped(&document).contains("through different plaintext runs have one normal form")
    );
}

#[test]
fn lowering_obligations_name_existing_tests_and_plan_tasks() {
    const IDS: [&str; 14] = [
        "NL-S1", "NL-S2", "NL-S3", "NL-S4", "NL-S5", "NL-S6", "NL-S7", "NL-L1", "NL-L2", "NL-L3",
        "NL-L4", "NL-L5", "NL-L6", "NL-L7",
    ];
    let document = specification();
    let rows = marked_table(
        &document,
        "<!-- ram-lfe-normalizing-lowering-obligations -->",
    );
    let ids: Vec<&str> = rows.iter().map(|row| code(row[0])).collect();
    assert_eq!(ids, IDS);

    let plan = repository_file("specs/zk_delivery_plan.md");
    let tests = repository_file("crates/iroha_crypto/src/ram_lfe/normal_form_tests.rs");
    let (mut checked, mut open) = (Vec::new(), Vec::new());
    for row in &rows {
        assert_eq!(row.len(), 4, "obligation row has four cells");
        assert!(row[1].starts_with("**"), "{} has a title", row[0]);
        let owners: Vec<&str> = row[2].split(',').map(str::trim).collect();
        for owner in &owners {
            assert!(
                plan.contains(&format!("\n### {owner} ")),
                "{} names {owner}, which is not a task of the delivery plan",
                row[0]
            );
        }
        if row[3] == "none" {
            // Nothing checks it: it is an obligation of a task that is not this one.
            assert!(!owners.contains(&"R.0"), "{} is unchecked", row[0]);
            open.push(code(row[0]));
        } else {
            assert_eq!(owners, ["R.0"], "{} is checked by the oracle", row[0]);
            let names = backticked(row[3]);
            assert!(!names.is_empty());
            for name in names {
                assert!(
                    tests.contains(&format!("#[test]\nfn {name}()")),
                    "{} names the test `{name}`, which does not exist",
                    row[0]
                );
            }
            checked.push(code(row[0]));
        }
    }
    assert_eq!(
        checked,
        ["NL-S1", "NL-S2", "NL-S3", "NL-S4", "NL-S5", "NL-L1"]
    );
    assert_eq!(
        open,
        [
            "NL-S6", "NL-S7", "NL-L2", "NL-L3", "NL-L4", "NL-L5", "NL-L6", "NL-L7"
        ]
    );
    // The relation that must prove equivalence is R.3, extended by R.7 and R.9.
    for row in rows
        .iter()
        .filter(|row| ["`NL-S6`", "`NL-S7`"].contains(&row[0]))
    {
        assert_eq!(row[2], "R.3, R.7, R.9");
    }
}

#[cfg(feature = "json")]
#[test]
fn maximum_shape_counterexamples_are_the_recorded_cost_summary() {
    use norito::json::Value;

    let document = specification();
    let summary = cost_summary();

    // No candidate holds every family planned for it.
    let need = marked_table(&document, "<!-- ram-lfe-maximum-shape-need -->");
    assert_eq!(need.len(), RamLfeClassV1::ALL.len());
    let mut candidates = Vec::new();
    for (row, class) in need.iter().zip(RamLfeClassV1::ALL) {
        let model = json_at(&summary, &["class_cost_model", class.as_str()]);
        let profile = model
            .get("profile")
            .and_then(Value::as_str)
            .expect("candidate of the class");
        assert_eq!(code(row[0]), class.as_str());
        assert_eq!(code(row[1]), profile);
        assert_eq!(
            number(row[2]),
            json_count(model, "main_primes_in_candidate")
        );
        assert_eq!(
            number(row[3]),
            json_count(model, "main_primes_for_every_planned_family")
        );
        assert!(number(row[3]) > number(row[2]), "{class}");
        assert_eq!(
            model
                .get("holds_every_planned_family")
                .and_then(Value::as_bool),
            Some(false),
            "{class}"
        );
        assert_eq!(
            json_at(
                &summary,
                &["tape_lowering", "candidates", profile, "intended_class"]
            )
            .as_str(),
            Some(class.as_str())
        );
        candidates.push((profile, number(row[2])));
    }

    // The refused families are exactly the plans that do not fit, each of a
    // tape the candidate's class admits.
    let mut expected = Vec::new();
    for &(profile, primes) in &candidates {
        let plans = json_at(
            &summary,
            &["tape_lowering", "candidates", profile, "families"],
        )
        .as_object()
        .expect("family plans");
        let mut refused = Vec::new();
        for (family, plan) in plans {
            match plan.get("fits").and_then(Value::as_bool) {
                Some(true) => {}
                Some(false) => {
                    let needed = json_count(plan, "minimal_main_primes");
                    assert!(needed > primes, "{profile} {family}");
                    refused.push((
                        profile.to_owned(),
                        family.clone(),
                        json_count(
                            json_at(&summary, &["tape_lowering", "families", family.as_str()]),
                            "peak_rank",
                        ),
                        json_count(plan, "refused_at_instruction"),
                        needed,
                    ));
                }
                None => panic!("{profile} {family} records no result"),
            }
        }
        refused.sort();
        assert!(!refused.is_empty(), "{profile} refuses a family");
        expected.extend(refused);
    }
    let actual: Vec<(String, String, u64, u64, u64)> =
        marked_table(&document, "<!-- ram-lfe-maximum-shape-counterexamples -->")
            .iter()
            .map(|row| {
                (
                    code(row[0]).to_owned(),
                    code(row[1]).to_owned(),
                    number(row[2]),
                    number(row[3]),
                    number(row[4]),
                )
            })
            .collect();
    assert_eq!(actual, expected);
    // Logical rank does not explain a refusal: rank-0 tapes are refused.
    assert!(actual.iter().any(|row| row.2 == 0));

    // The longest run of constant multiplications each candidate holds.
    let runs = marked_table(&document, "<!-- ram-lfe-plaintext-run-limits -->");
    assert_eq!(runs.len(), candidates.len());
    for (row, &(profile, _)) in runs.iter().zip(&candidates) {
        assert_eq!(code(row[0]), profile);
        let fit = json_at(
            &summary,
            &[
                "tape_lowering",
                "candidates",
                profile,
                "sequential_constant_multiplications_that_fit",
            ],
        );
        for (cell, key) in row[1..]
            .iter()
            .zip(["after_rank_0", "after_rank_10", "after_rank_16"])
        {
            let recorded = fit.get(key).map_or_else(
                || "not admitted".to_owned(),
                |entry| {
                    format!(
                        "{} of {}",
                        json_count(entry, "fit"),
                        json_count(entry, "instruction_limit")
                    )
                },
            );
            assert_eq!(*cell, recorded, "{profile} {key}");
        }
    }

    // The figure quoted for the folded affine map is the recorded projection.
    let affine = json_at(&summary, &["class_cost_model", "affine.v1"]);
    let primes = json_count(affine, "minimal_main_primes_for_affine_map");
    assert!(
        unwrapped(&document).contains(&format!("of the affine candidate at {primes} main primes"))
    );
    assert_eq!(
        json_at(affine, &["minimal_main_primes_for_affine_map", "class"]).as_str(),
        Some("projection")
    );
}
