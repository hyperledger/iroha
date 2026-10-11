//! Generate Kotodama V1 lexical, diagnostic, and translation tables.
use std::{
    collections::BTreeSet,
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};
const TRANSLATION_SPEC_PATH: &str = "src/i18n/translations/messages.v1.tsv";
const TRANSLATION_OFFSET_OUTPUT: &str = "kotodama_i18n_v1_offsets.bin";
const TRANSLATION_HEADER: &str = "kotodama-i18n-v1\t76\t15";
const TRANSLATION_LANGUAGE_COUNT: usize = 76;
const TRANSLATION_MESSAGE_COUNT: usize = 15;
const DIAGNOSTIC_EXPLANATIONS_SPEC_PATH: &str =
    "src/assets/diagnostics_v1/diagnostic_explanations_v1.tsv";
const COMPILE_FAIL_CASES_SPEC_PATH: &str = "src/assets/diagnostics_v1/compile_fail_cases_v1.tsv";
const SECRET_REJECT_CASES_SPEC_PATH: &str = "src/assets/diagnostics_v1/secret_reject_cases_v1.tsv";
const DIAGNOSTIC_EXPLANATIONS_ASSET: &str =
    include_str!("src/assets/diagnostics_v1/diagnostic_explanations_v1.tsv");
const COMPILE_FAIL_CASES_ASSET: &str =
    include_str!("src/assets/diagnostics_v1/compile_fail_cases_v1.tsv");
const SECRET_REJECT_CASES_ASSET: &str =
    include_str!("src/assets/diagnostics_v1/secret_reject_cases_v1.tsv");
const TRANSLATION_LANGUAGES: &str = "English\tJapanese\tSimplifiedChinese\tTraditionalChinese\tThai\tKhmer\tVietnamese\tKorean\tArabic\tHebrew\tRussian\tBurmese\tHindi\tUrdu\tSinhala\tTamil\tFrench\tUkrainian\tPolish\tSwedish\tGerman\tGreek\tItalian\tKazakh\tMongolian\tJavanese\tMadurese\tBalinese\tMinangkabau\tAncientEgyptianHieroglyph\tDzongkha\tSerbian\tTurkish\tArmenian\tAmharic\tHausa\tTibetan\tKashmiri\tNepali\tAfrikaans\tSpanish\tFarsi\tOldAkkadian\tQuechua\tAymara\tBengali\tBalochi\tBashkir\tBrahui\tPortuguese\tPunjabi\tSindhi\tPashto\tSaraiki\tTatar\tSomali\tSundanese\tShona\tSwahili\tOromo\tIgbo\tYoruba\tZulu\tDutch\tDanish\tNorse\tFinnish\tEstonian\tLatvian\tHungarian\tCzech\tLao\tIndonesian\tPijin\tDivehi\tManchurian";
const TRANSLATION_FIELDS: [(&str, &[&str]); TRANSLATION_MESSAGE_COUNT] = [
    ("no_functions", &[]),
    ("unsupported_binary_op", &["op"]),
    ("unknown_param", &["name"]),
    ("read_file", &["path", "error"]),
    ("parser_error", &["error"]),
    ("semantic_error", &["error"]),
    ("lint_unused_state", &["name"]),
    ("lint_state_shadowed_param", &["func", "name"]),
    ("lint_state_shadowed_binding", &["func", "name"]),
    ("lint_state_shadowed_map_binding", &["func", "name"]),
    ("lint_unused_parameter", &["func", "name"]),
    ("lint_unreachable_after_return", &["context"]),
    ("lint_ok", &[]),
    ("lint_usage", &[]),
    ("lint_usage_help", &[]),
];
fn decode_table_field(raw: &str, path: &str, line: usize, column: usize) -> String {
    let mut decoded = String::with_capacity(raw.len());
    let mut characters = raw.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            assert!(
                !character.is_control(),
                "{path}:{line}:{column} contains an unescaped control character"
            );
            decoded.push(character);
            continue;
        }
        let escaped = characters
            .next()
            .unwrap_or_else(|| panic!("{path}:{line}:{column} ends with an incomplete escape"));
        decoded.push(match escaped {
            '\\' => '\\',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            _ => panic!("{path}:{line}:{column} has unsupported escape `\\{escaped}`"),
        });
    }
    decoded
}
/// Parse one versioned table whose header is `<table-name>\t<record count>`.
///
/// The header's declared count is authoritative and must equal the number of
/// records, so adding a row only touches the asset itself.
fn parse_versioned_table(
    path: &str,
    asset: &str,
    table_name: &str,
    expected_schema: &[&str],
) -> Vec<Vec<String>> {
    println!("cargo:rerun-if-changed={path}");
    assert!(asset.ends_with('\n'), "{path} must end with a newline");
    assert!(
        !asset.contains('\r'),
        "{path} must use canonical LF line endings"
    );
    let mut lines = asset.split_terminator('\n');
    let header = lines.next().expect("versioned table header row");
    let expected_rows = header
        .strip_prefix(table_name)
        .and_then(|rest| rest.strip_prefix('\t'))
        .and_then(|count| count.parse::<usize>().ok())
        .unwrap_or_else(|| {
            panic!("{path} header must be `{table_name}<TAB><record count>`, found `{header}`")
        });
    let schema = lines.next().expect("versioned table schema row");
    assert!(
        schema.split('\t').eq(expected_schema.iter().copied()),
        "unexpected field schema in {path}: expected `{}`",
        expected_schema.join("<TAB>")
    );
    let mut rows = Vec::with_capacity(expected_rows);
    for (row_index, record) in lines.enumerate() {
        assert!(!record.is_empty(), "{path} has an empty record");
        let columns = record
            .split('\t')
            .enumerate()
            .map(|(column_index, value)| {
                decode_table_field(value, path, row_index + 3, column_index + 1)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            columns.len(),
            expected_schema.len(),
            "{path}:{} has {} fields; expected {} ({}). Use `-` for an optional field with no value",
            row_index + 3,
            columns.len(),
            expected_schema.len(),
            expected_schema.join(", ")
        );
        assert!(
            columns.iter().all(|column| !column.is_empty()),
            "{path}:{} has an empty field",
            row_index + 3
        );
        rows.push(columns);
    }
    assert_eq!(
        rows.len(),
        expected_rows,
        "{path} declares {expected_rows} records in its header but contains {}",
        rows.len()
    );
    rows
}
/// Optional table field: `-` means no value.
fn optional_field(value: &str) -> Option<&str> {
    (value != "-").then_some(value)
}
fn is_diagnostic_phase(value: &str) -> bool {
    matches!(
        value,
        "Lex" | "Parse" | "Resolve" | "Semantic" | "Lowering" | "Artifact"
    )
}
fn write_diagnostic_tables(out_dir: &Path) {
    let explanations = parse_versioned_table(
        DIAGNOSTIC_EXPLANATIONS_SPEC_PATH,
        DIAGNOSTIC_EXPLANATIONS_ASSET,
        "kotodama-diagnostic-explanations-v1",
        &[
            "code",
            "phase",
            "summary",
            "help",
            "bad_example",
            "fixed_example",
        ],
    );
    let mut seen_codes = BTreeSet::new();
    let mut generated = String::from(
        "// @generated by crates/kotodama_lang/build.rs from the versioned diagnostic asset.\n\
         // Do not edit this file directly.\n\n\
         /// Canonical diagnostic explanation registry used by `koto explain` and docs.\n\
         pub const DIAGNOSTIC_EXPLANATIONS: &[DiagnosticExplanation] = &[\n",
    );
    for row in explanations {
        assert!(is_diagnostic_phase(&row[1]), "unknown diagnostic phase");
        assert!(
            row[0]
                .chars()
                .all(|character| character.is_ascii_uppercase()
                    || character.is_ascii_digit()
                    || character == '_'),
            "invalid diagnostic code `{}`",
            row[0]
        );
        assert!(
            seen_codes.insert(row[0].clone()),
            "duplicate diagnostic code"
        );
        let bad_example = optional_field(&row[4]);
        let fixed_example = optional_field(&row[5]);
        assert_eq!(
            bad_example.is_some(),
            fixed_example.is_some(),
            "diagnostic `{}` must give both a bad and a fixed example, or neither",
            row[0]
        );
        writeln!(
            &mut generated,
            "    DiagnosticExplanation {{ code: {:?}, phase: DiagnosticPhase::{}, summary: {:?}, help: {:?}, bad_example: {:?}, fixed_example: {:?} }},",
            row[0], row[1], row[2], row[3], bad_example, fixed_example
        )
        .expect("write diagnostic explanation table");
    }
    generated.push_str("];\n");
    fs::write(
        out_dir.join("kotodama_diagnostic_explanations.rs"),
        generated,
    )
    .expect("write generated Kotodama diagnostic explanations");

    let compile_fail_cases = parse_versioned_table(
        COMPILE_FAIL_CASES_SPEC_PATH,
        COMPILE_FAIL_CASES_ASSET,
        "kotodama-compile-fail-cases-v1",
        &["name", "source", "phase", "code", "message", "line"],
    );
    let mut seen_names = BTreeSet::new();
    let mut generated = String::from(
        "// @generated by crates/kotodama_lang/build.rs from the versioned compile-fail asset.\n\
         // Do not edit this file directly.\n\n\
         const CASES: &[CompileFailCase] = &[\n",
    );
    for row in compile_fail_cases {
        assert!(
            seen_names.insert(row[0].clone()),
            "duplicate compile-fail case name"
        );
        assert!(is_diagnostic_phase(&row[2]), "unknown compile-fail phase");
        let line = row[5]
            .parse::<usize>()
            .expect("compile-fail source line must be an unsigned integer");
        assert!(
            line > 0 && line <= row[1].lines().count(),
            "compile-fail source line is outside the fixture"
        );
        writeln!(
            &mut generated,
            "    CompileFailCase {{ name: {:?}, source: {:?}, phase: DiagnosticPhase::{}, code: {:?}, message: {:?}, line: {} }},",
            row[0], row[1], row[2], row[3], row[4], line
        )
        .expect("write compile-fail case table");
    }
    generated.push_str("];\n");
    fs::write(out_dir.join("kotodama_compile_fail_cases.rs"), generated)
        .expect("write generated Kotodama compile-fail cases");

    let reject_cases = parse_versioned_table(
        SECRET_REJECT_CASES_SPEC_PATH,
        SECRET_REJECT_CASES_ASSET,
        "kotodama-secret-reject-cases-v1",
        &["name", "source", "code", "primary"],
    );
    let mut seen_names = BTreeSet::new();
    let mut generated = String::from(
        "// @generated by crates/kotodama_lang/build.rs from the versioned secret-flow asset.\n\
         // Do not edit this file directly.\n\n\
         const REJECT_CASES: &[RejectCase] = &[\n",
    );
    for row in reject_cases {
        assert!(
            seen_names.insert(row[0].clone()),
            "duplicate secret-flow case name"
        );
        assert!(
            row[1].contains(&row[3]),
            "secret-flow primary text is absent from the source fixture"
        );
        writeln!(
            &mut generated,
            "    RejectCase {{ name: {:?}, source: {:?}, code: {:?}, primary: {:?} }},",
            row[0], row[1], row[2], row[3]
        )
        .expect("write secret-flow rejection table");
    }
    generated.push_str("];\n");
    fs::write(out_dir.join("kotodama_secret_reject_cases.rs"), generated)
        .expect("write generated Kotodama secret-flow cases");
}
fn validate_translation_placeholders(
    message: &str,
    required: &[&str],
    language: &str,
    field: &str,
) {
    let mut found = vec![false; required.len()];
    let bytes = message.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'{' => {
                let name_start = cursor + 1;
                let mut name_end = name_start;
                while name_end < bytes.len() && bytes[name_end] != b'}' {
                    assert_ne!(
                        bytes[name_end], b'{',
                        "nested placeholder in {language}.{field}"
                    );
                    name_end += 1;
                }
                assert!(
                    name_end < bytes.len(),
                    "unterminated placeholder in {language}.{field}"
                );
                let name = &message[name_start..name_end];
                let mut allowed = false;
                let mut required_index = 0;
                while required_index < required.len() {
                    if required[required_index] == name {
                        allowed = true;
                        found[required_index] = true;
                    }
                    required_index += 1;
                }
                assert!(
                    allowed,
                    "unknown placeholder `{{{name}}}` in {language}.{field}"
                );
                cursor = name_end + 1;
            }
            b'}' => panic!("unmatched closing brace in {language}.{field}"),
            _ => cursor += 1,
        }
    }
    let mut required_index = 0;
    while required_index < required.len() {
        assert!(
            found[required_index],
            "missing placeholder `{{{}}}` in {language}.{field}",
            required[required_index]
        );
        required_index += 1;
    }
}
fn write_translation_offsets(out_dir: &Path) {
    println!("cargo:rerun-if-changed={TRANSLATION_SPEC_PATH}");
    let languages = TRANSLATION_LANGUAGES.split('\t').collect::<Vec<_>>();
    assert_eq!(languages.len(), TRANSLATION_LANGUAGE_COUNT);
    let asset = fs::read_to_string(TRANSLATION_SPEC_PATH)
        .expect("read versioned Kotodama translation asset as UTF-8");
    assert!(
        asset.ends_with('\n'),
        "Kotodama translation asset must end with a newline"
    );
    let mut lines = asset.split_inclusive('\n');
    let header_line = lines.next().expect("translation asset version header");
    assert_eq!(
        header_line.strip_suffix('\n'),
        Some(TRANSLATION_HEADER),
        "unexpected Kotodama translation asset version/count header"
    );
    let schema_line = lines.next().expect("translation asset field schema");
    let schema = schema_line
        .strip_suffix('\n')
        .expect("translation asset schema line terminator");
    let mut schema_columns = schema.split('\t');
    assert_eq!(schema_columns.next(), Some("language"));
    let mut message_index = 0;
    while message_index < TRANSLATION_FIELDS.len() {
        assert_eq!(
            schema_columns.next(),
            Some(TRANSLATION_FIELDS[message_index].0),
            "translation message field {} is out of order",
            message_index
        );
        message_index += 1;
    }
    assert_eq!(
        schema_columns.next(),
        None,
        "translation asset has an unexpected message field"
    );
    let mut asset_offset = header_line.len() + schema_line.len();
    let mut offsets = Vec::with_capacity(
        TRANSLATION_LANGUAGE_COUNT * TRANSLATION_MESSAGE_COUNT * 2 * std::mem::size_of::<u32>(),
    );
    let mut language_index = 0;
    while language_index < languages.len() {
        let line_with_terminator = match lines.next() {
            Some(line) => line,
            None => panic!("missing translation row {language_index}"),
        };
        let record = line_with_terminator
            .strip_suffix('\n')
            .expect("translation record line terminator");
        assert!(
            !record.contains('\r'),
            "translation row {language_index} contains a carriage return"
        );
        let columns = record.split('\t').collect::<Vec<_>>();
        assert_eq!(
            columns.len(),
            TRANSLATION_MESSAGE_COUNT + 1,
            "translation row {language_index} has the wrong field count"
        );
        assert_eq!(
            columns[0], languages[language_index],
            "translation language row {language_index} is out of order"
        );
        let mut relative_start = columns[0].len() + 1;
        message_index = 0;
        while message_index < TRANSLATION_FIELDS.len() {
            let message = columns[message_index + 1];
            assert!(
                !message.is_empty(),
                "empty translation for {}.{}",
                columns[0],
                TRANSLATION_FIELDS[message_index].0
            );
            validate_translation_placeholders(
                message,
                TRANSLATION_FIELDS[message_index].1,
                columns[0],
                TRANSLATION_FIELDS[message_index].0,
            );
            let start = asset_offset + relative_start;
            let end = start + message.len();
            offsets.extend_from_slice(
                &u32::try_from(start)
                    .expect("translation asset exceeds four gigabytes")
                    .to_le_bytes(),
            );
            offsets.extend_from_slice(
                &u32::try_from(end)
                    .expect("translation asset exceeds four gigabytes")
                    .to_le_bytes(),
            );
            relative_start += message.len() + 1;
            message_index += 1;
        }
        assert_eq!(relative_start, record.len() + 1);
        asset_offset += line_with_terminator.len();
        language_index += 1;
    }
    assert!(
        lines.next().is_none(),
        "translation asset has rows after the language catalog"
    );
    assert_eq!(asset_offset, asset.len());
    fs::write(out_dir.join(TRANSLATION_OFFSET_OUTPUT), offsets)
        .expect("write Kotodama translation offsets");
}
fn regex_escape_literal(spelling: &str) -> String {
    let mut escaped = String::with_capacity(spelling.len().saturating_mul(2));
    for character in spelling.chars() {
        if matches!(
            character,
            '\\' | '.' | '^' | '$' | '|' | '?' | '*' | '+' | '(' | ')' | '[' | ']' | '{' | '}'
        ) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}
fn markdown_code(spelling: &str) -> String {
    format!("`{}`", spelling.replace('|', "\\|"))
}
fn main() {
    const SPEC_PATH: &str = "grammar/v1.lex";
    println!("cargo:rerun-if-changed={SPEC_PATH}");
    let spec = fs::read_to_string(SPEC_PATH).expect("read normative Kotodama V1 lexical grammar");
    let mut keywords = Vec::<(String, String)>::new();
    let mut operators = Vec::<(String, String)>::new();
    let mut seen_spellings = BTreeSet::new();
    for (line_index, raw_line) in spec.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let columns = raw_line.split('\t').collect::<Vec<_>>();
        match columns.as_slice() {
            ["keyword", spelling, variant] => {
                assert!(
                    !spelling.is_empty(),
                    "empty keyword on line {}",
                    line_index + 1
                );
                assert!(
                    variant
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric())
                        && variant
                            .chars()
                            .next()
                            .is_some_and(|character| character.is_ascii_uppercase()),
                    "invalid token variant `{variant}` on line {}",
                    line_index + 1
                );
                assert!(
                    seen_spellings.insert((*spelling).to_owned()),
                    "duplicate lexical spelling `{spelling}` on line {}",
                    line_index + 1
                );
                keywords.push(((*spelling).to_owned(), (*variant).to_owned()));
            }
            ["operator", spelling, variant] => {
                assert!(
                    !spelling.is_empty(),
                    "empty operator on line {}",
                    line_index + 1
                );
                assert!(
                    variant
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric())
                        && variant
                            .chars()
                            .next()
                            .is_some_and(|character| character.is_ascii_uppercase()),
                    "invalid syntax kind `{variant}` on line {}",
                    line_index + 1
                );
                assert!(
                    seen_spellings.insert((*spelling).to_owned()),
                    "duplicate lexical spelling `{spelling}` on line {}",
                    line_index + 1
                );
                operators.push(((*spelling).to_owned(), (*variant).to_owned()));
            }
            _ => panic!(
                "invalid lexical grammar record on line {}: expected tab-separated `keyword<TAB>spelling<TAB>TokenVariant` or `operator<TAB>spelling<TAB>SyntaxKind`",
                line_index + 1
            ),
        }
    }
    for (variant, expected) in [
        ("Seiyaku", ["seiyaku", "誓約"]),
        ("Kotoage", ["kotoage", "言挙げ"]),
        ("Hajimari", ["hajimari", "始まり"]),
        ("Kaizen", ["kaizen", "改善"]),
    ] {
        let actual = keywords
            .iter()
            .filter_map(|(spelling, current_variant)| {
                (current_variant == variant).then_some(spelling.as_str())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "the `{variant}` feature must have exactly its romanized and Japanese spellings"
        );
    }
    for forbidden in ["contract", "entry", "init", "upgrade"] {
        assert!(
            !keywords.iter().any(|(spelling, _)| spelling == forbidden),
            "English compatibility alias `{forbidden}` must not enter Kotodama V1"
        );
    }
    let mut generated = String::from(
        "// @generated by crates/kotodama_lang/build.rs from grammar/v1.lex.\n\
         // Do not edit this file directly.\n\n\
         define_v1_keywords! {\n",
    );
    for (spelling, variant) in &keywords {
        writeln!(&mut generated, "    {spelling:?} => {variant},")
            .expect("write generated keyword table");
    }
    generated.push_str("}\n\n");
    generated.push_str(
        "/// Canonical V1 operator and punctuation spellings generated for language tooling.\n\
         pub const V1_OPERATORS: &[&str] = &[\n",
    );
    for (spelling, _) in &operators {
        writeln!(&mut generated, "    {spelling:?},").expect("write generated operator table");
    }
    generated.push_str("];\n\n");
    let mut sorted_operator_kinds = operators.clone();
    sorted_operator_kinds.sort_unstable_by(|left, right| {
        right
            .0
            .len()
            .cmp(&left.0.len())
            .then_with(|| left.0.cmp(&right.0))
    });
    generated.push_str(
        "/// Longest-first scanner table generated from the normative V1 grammar.\n\
         pub(crate) const V1_PUNCTUATION_KINDS: &[(&str, SyntaxKind)] = &[\n",
    );
    for (spelling, variant) in &sorted_operator_kinds {
        writeln!(&mut generated, "    ({spelling:?}, SyntaxKind::{variant}),")
            .expect("write generated punctuation scanner table");
    }
    generated.push_str("];\n\n");
    let keyword_pattern = format!(
        r"(?<![\p{{L}}\p{{N}}_])(?:{})(?![\p{{L}}\p{{N}}_])",
        keywords
            .iter()
            .map(|(spelling, _)| regex_escape_literal(spelling))
            .collect::<Vec<_>>()
            .join("|")
    );
    let operator_pattern = format!(
        "(?:{})",
        sorted_operator_kinds
            .iter()
            .map(|(spelling, _)| regex_escape_literal(spelling))
            .collect::<Vec<_>>()
            .join("|")
    );
    writeln!(
        &mut generated,
        "/// Generated TextMate/LSP matcher for canonical V1 keywords.\npub const V1_KEYWORD_EDITOR_PATTERN: &str = {keyword_pattern:?};"
    )
    .expect("write generated keyword editor pattern");
    writeln!(
        &mut generated,
        "/// Generated TextMate/LSP matcher for canonical V1 operators.\npub const V1_OPERATOR_EDITOR_PATTERN: &str = {operator_pattern:?};"
    )
    .expect("write generated operator editor pattern");
    let mut keyword_docs = String::from("| Spelling | Token |\n| --- | --- |\n");
    for (spelling, variant) in &keywords {
        writeln!(
            &mut keyword_docs,
            "| {} | `{variant}` |",
            markdown_code(spelling)
        )
        .expect("write generated keyword documentation");
    }
    let mut operator_docs = String::from("| Spelling |\n| --- |\n");
    for (spelling, _) in &operators {
        writeln!(&mut operator_docs, "| {} |", markdown_code(spelling))
            .expect("write generated operator documentation");
    }
    writeln!(
        &mut generated,
        "/// Generated normative Markdown keyword table.\npub const V1_KEYWORD_DOC_TABLE: &str = {keyword_docs:?};"
    )
    .expect("write generated keyword documentation constant");
    writeln!(
        &mut generated,
        "/// Generated normative Markdown operator table.\npub const V1_OPERATOR_DOC_TABLE: &str = {operator_docs:?};"
    )
    .expect("write generated operator documentation constant");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    write_diagnostic_tables(&out_dir);
    write_translation_offsets(&out_dir);
    fs::write(out_dir.join("kotodama_v1_lexical.rs"), generated)
        .expect("write generated Kotodama lexical tables");
}
