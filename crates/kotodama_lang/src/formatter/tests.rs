//! Unit and golden coverage for the canonical Kotodama V1 formatter.
use super::*;
use crate::source::SourceId;
use std::path::{Path, PathBuf};
fn format(source: &str) -> String {
    let source = SourceFile::new(SourceId(0), "format.ko", source);
    format_source(&source, FrontendBudget::v1()).expect("valid source")
}
/// Significant tokens of `text` with separators and parentheses removed.
///
/// Formatting may only canonicalize separators, trailing commas and redundant condition
/// parentheses; every other token, comment and literal must survive with its exact spelling and
/// in its original order.
fn preserved_tokens(text: &str) -> Vec<(SyntaxKind, String)> {
    let source = SourceFile::new(SourceId(0), "tokens.ko", text);
    let lexed = crate::syntax::lex(&source, FrontendBudget::v1());
    lexed
        .tokens
        .iter()
        .filter(|token| {
            !matches!(
                token.kind,
                SyntaxKind::Whitespace
                    | SyntaxKind::Missing
                    | SyntaxKind::Eof
                    | SyntaxKind::Comma
                    | SyntaxKind::Semicolon
                    | SyntaxKind::LParen
                    | SyntaxKind::RParen
            )
        })
        .map(|token| {
            let text = source.slice(token.range).unwrap_or_default();
            let text = if token.kind.is_line_comment() {
                text.trim_end()
            } else {
                text
            };
            (token.kind, text.to_owned())
        })
        .collect()
}
/// Assert that formatting `text` is lossless and idempotent, returning the formatted text.
fn assert_stable(name: &str, text: &str) -> Option<String> {
    let source = SourceFile::new(SourceId(0), name, text);
    let formatted = format_source(&source, FrontendBudget::v1()).ok()?;
    assert_eq!(
        preserved_tokens(text),
        preserved_tokens(&formatted),
        "formatting {name} changed a comment, literal or token"
    );
    let again = SourceFile::new(SourceId(0), name, formatted.as_str());
    let reformatted = format_source(&again, FrontendBudget::v1())
        .unwrap_or_else(|diagnostics| panic!("formatted {name} no longer parses: {diagnostics:?}"));
    assert_eq!(
        reformatted, formatted,
        "formatting {name} is not idempotent"
    );
    Some(formatted)
}
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("kotodama_lang lives two levels below the repository root")
        .to_path_buf()
}
/// Every checked-in `.ko` source, as listed by Git (untracked outputs and scratch trees excluded).
fn repository_sources() -> Vec<PathBuf> {
    let root = repository_root();
    let output = std::process::Command::new("git")
        .args(["-C", root.to_str().expect("UTF-8 repository root")])
        .args(["ls-files", "-z", "--", "*.ko"])
        .output()
        .expect("run git source inventory");
    assert!(
        output.status.success(),
        "git source inventory failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|raw| root.join(std::str::from_utf8(raw).expect("tracked path is UTF-8")))
        .filter(|path| path.is_file())
        .collect()
}
/// Exact-output goldens as `(name, input, expected)`.
///
/// The fixtures use a `.txt` extension so repository source gates, which format-check and
/// compile every checked-in `.ko` file, never treat the deliberately unformatted inputs (or
/// the parse-only expectations) as deployable sources.
const GOLDEN_CASES: &[(&str, &str, &str)] = &[
    (
        "trailing_comments",
        include_str!("../../fixtures/fmt/trailing_comments.input.txt"),
        include_str!("../../fixtures/fmt/trailing_comments.expected.txt"),
    ),
    (
        "attributes",
        include_str!("../../fixtures/fmt/attributes.input.txt"),
        include_str!("../../fixtures/fmt/attributes.expected.txt"),
    ),
    (
        "generics",
        include_str!("../../fixtures/fmt/generics.input.txt"),
        include_str!("../../fixtures/fmt/generics.expected.txt"),
    ),
    (
        "records",
        include_str!("../../fixtures/fmt/records.input.txt"),
        include_str!("../../fixtures/fmt/records.expected.txt"),
    ),
    (
        "headers",
        include_str!("../../fixtures/fmt/headers.input.txt"),
        include_str!("../../fixtures/fmt/headers.expected.txt"),
    ),
    (
        "branded",
        include_str!("../../fixtures/fmt/branded.input.txt"),
        include_str!("../../fixtures/fmt/branded.expected.txt"),
    ),
    (
        "conditions",
        include_str!("../../fixtures/fmt/conditions.input.txt"),
        include_str!("../../fixtures/fmt/conditions.expected.txt"),
    ),
    (
        "wrapping",
        include_str!("../../fixtures/fmt/wrapping.input.txt"),
        include_str!("../../fixtures/fmt/wrapping.expected.txt"),
    ),
    (
        "test_module",
        include_str!("../../fixtures/fmt/test_module.input.txt"),
        include_str!("../../fixtures/fmt/test_module.expected.txt"),
    ),
    (
        "nested_breaks",
        include_str!("../../fixtures/fmt/nested_breaks.input.txt"),
        include_str!("../../fixtures/fmt/nested_breaks.expected.txt"),
    ),
];
#[test]
fn golden_fixtures_format_exactly_and_idempotently() {
    for (name, input, expected) in GOLDEN_CASES {
        let formatted =
            assert_stable(name, input).unwrap_or_else(|| panic!("golden input {name} must parse"));
        assert_lines_within_target(name, &formatted);
        assert_eq!(&formatted, expected, "golden {name} drifted:\n{formatted}");
        assert_eq!(
            assert_stable(name, expected).as_deref(),
            Some(*expected),
            "golden {name} expectation is not canonical"
        );
    }
}
#[test]
fn every_repository_source_formats_losslessly_and_idempotently() {
    let sources = repository_sources();
    assert!(
        sources.len() > 100,
        "expected the repository .ko corpus, found {}",
        sources.len()
    );
    let mut formatted_sources = 0_usize;
    for path in sources {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let name = path.display().to_string();
        if let Some(formatted) = assert_stable(&name, &text) {
            assert_lines_within_target(&name, &formatted);
            formatted_sources += 1;
        }
    }
    assert!(
        formatted_sources > 100,
        "only {formatted_sources} sources formatted"
    );
}
/// Assert that every line of `formatted` over the column target is held there by what cannot be
/// split: an identifier or literal of at least 40 characters, or comments without which the line's code fits.
fn assert_lines_within_target(name: &str, formatted: &str) {
    let source = SourceFile::new(SourceId(0), name, formatted);
    let lexed = crate::syntax::lex(&source, FrontendBudget::v1());
    let mut line_start = 0_usize;
    for (number, line) in formatted.split_inclusive('\n').enumerate() {
        let line_end = line_start + line.len();
        let width = line.trim_end_matches(['\r', '\n']).chars().count();
        if width > TARGET_COLUMNS {
            let mut comment_width = 0_usize;
            let mut long_literal = false;
            for token in &lexed.tokens {
                let (start, end) = (token.range.start as usize, token.range.end as usize);
                if start >= line_end || end <= line_start {
                    continue;
                }
                let on_line = formatted[start.max(line_start)..end.min(line_end)]
                    .trim_end_matches(['\r', '\n'])
                    .chars()
                    .count();
                match token.kind {
                    // A comment and the space that separates it from the code.
                    SyntaxKind::LineComment | SyntaxKind::DocComment | SyntaxKind::BlockComment => {
                        comment_width += on_line + 1;
                    }
                    SyntaxKind::Ident
                    | SyntaxKind::String
                    | SyntaxKind::Bytes
                    | SyntaxKind::Number => {
                        long_literal |= formatted[start..end].chars().count() >= 40;
                    }
                    _ => {}
                }
            }
            assert!(
                long_literal || width.saturating_sub(comment_width) <= TARGET_COLUMNS,
                "{name}:{}: {width} columns with a break point available:\n{line}",
                number + 1
            );
        }
        line_start = line_end;
    }
}
#[test]
fn lines_over_the_target_must_hold_an_unbreakable_token() {
    assert_lines_within_target("ok.ko", &format!("// {}\n", "x".repeat(120)));
    let wide = format!(
        "seiyaku W {{\n    fn f() {{ g({}); }}\n}}\n",
        "a, ".repeat(40)
    );
    let result = std::panic::catch_unwind(|| assert_lines_within_target("wide.ko", &wide));
    assert!(
        result.is_err(),
        "a breakable over-long line must be reported"
    );
    // A comment only excuses the columns it occupies itself.
    assert_lines_within_target(
        "trailing.ko",
        &format!("    let int x = 1; // {}\n", "x".repeat(120)),
    );
    let led = format!("    /* note */ let int x = {};\n", "a + ".repeat(25));
    let result = std::panic::catch_unwind(|| assert_lines_within_target("led.ko", &led));
    assert!(
        result.is_err(),
        "a comment must not excuse over-long code on its line"
    );
}
/// Rewrite the whitespace of `text` without moving any token to another line.
///
/// Line breaks (and therefore blank lines and comment placement) are kept; indentation and
/// the spaces within each line are replaced by deterministic, varying runs, and a space is
/// inserted between adjacent tokens.
fn reflow_within_lines(text: &str) -> String {
    let source = SourceFile::new(SourceId(0), "reflow.ko", text);
    let lexed = crate::syntax::lex(&source, FrontendBudget::v1());
    let mut output = String::with_capacity(text.len() * 2);
    let mut previous_was_token = false;
    for (index, token) in lexed.tokens.iter().enumerate() {
        let spelling = source.slice(token.range).unwrap_or_default();
        match token.kind {
            SyntaxKind::Missing | SyntaxKind::Eof => {}
            SyntaxKind::Whitespace => {
                let newlines = spelling.matches('\n').count();
                for _ in 0..newlines {
                    output.push('\n');
                }
                let spaces = if newlines == 0 {
                    1 + index % 3
                } else {
                    index % 7
                };
                output.extend(std::iter::repeat_n(' ', spaces));
                previous_was_token = false;
            }
            _ => {
                if previous_was_token && !output.ends_with('\n') {
                    output.push(' ');
                }
                output.push_str(spelling);
                previous_was_token = true;
            }
        }
    }
    output
}
/// Join every single line break of `text` whose neighbours are code tokens.
///
/// Blank lines and the whitespace around comments are kept, so only layout the formatter must
/// not depend on changes.
fn join_code_lines(text: &str) -> String {
    let source = SourceFile::new(SourceId(0), "join.ko", text);
    let lexed = crate::syntax::lex(&source, FrontendBudget::v1());
    let tokens = &lexed.tokens;
    let is_comment = |index: Option<&GreenToken>| {
        index.is_some_and(|token| {
            matches!(
                token.kind,
                SyntaxKind::LineComment | SyntaxKind::DocComment | SyntaxKind::BlockComment
            )
        })
    };
    let mut output = String::with_capacity(text.len());
    for (index, token) in tokens.iter().enumerate() {
        let spelling = source.slice(token.range).unwrap_or_default();
        let joinable = token.kind == SyntaxKind::Whitespace
            && spelling.matches('\n').count() == 1
            && index > 0
            && !is_comment(tokens.get(index - 1))
            && !is_comment(tokens.get(index + 1));
        output.push_str(if joinable { " " } else { spelling });
    }
    output
}
#[test]
fn join_code_lines_keeps_blank_lines_and_comment_lines() {
    assert_eq!(
        join_code_lines("seiyaku J {\n    fn f() {\n        g(); // c\n\n        h();\n    }\n}\n"),
        "seiyaku J { fn f() { g(); // c\n\n        h(); } } "
    );
}
#[test]
fn formatting_ignores_single_line_breaks_between_code_tokens() {
    let goldens = GOLDEN_CASES
        .iter()
        .map(|(name, input, _)| ((*name).to_owned(), (*input).to_owned()));
    let repository = repository_sources().into_iter().filter_map(|path| {
        let text = std::fs::read_to_string(&path).ok()?;
        Some((path.display().to_string(), text))
    });
    let mut compared = 0_usize;
    for (name, text) in goldens.chain(repository) {
        let original = SourceFile::new(SourceId(0), name.as_str(), text.as_str());
        let Ok(expected) = format_source(&original, FrontendBudget::v1()) else {
            continue;
        };
        let joined = join_code_lines(&text);
        let source = SourceFile::new(SourceId(0), name.as_str(), joined.as_str());
        let formatted =
            format_source(&source, FrontendBudget::v1()).unwrap_or_else(|diagnostics| {
                panic!("joined {name} no longer parses: {diagnostics:?}")
            });
        assert_eq!(
            formatted, expected,
            "formatting {name} depends on line breaks between code tokens"
        );
        compared += 1;
    }
    assert!(compared > 100, "only {compared} sources compared");
}
#[test]
fn reflow_within_lines_keeps_tokens_and_line_breaks() {
    let reflowed = reflow_within_lines("seiyaku R{\n  fn f(){ g(1,2); } // note\n\n}\n");
    assert_eq!(
        preserved_tokens(&reflowed),
        preserved_tokens("seiyaku R{\n  fn f(){ g(1,2); } // note\n\n}\n")
    );
    assert_eq!(reflowed.matches('\n').count(), 4, "{reflowed:?}");
    assert!(reflowed.contains("g ( 1 , 2 ) ;"), "{reflowed:?}");
}
#[test]
fn formatting_ignores_indentation_and_spacing_within_lines() {
    let goldens = GOLDEN_CASES
        .iter()
        .map(|(name, input, _)| ((*name).to_owned(), (*input).to_owned()));
    let repository = repository_sources().into_iter().filter_map(|path| {
        let text = std::fs::read_to_string(&path).ok()?;
        Some((path.display().to_string(), text))
    });
    let mut compared = 0_usize;
    for (name, text) in goldens.chain(repository) {
        let original = SourceFile::new(SourceId(0), name.as_str(), text.as_str());
        let Ok(expected) = format_source(&original, FrontendBudget::v1()) else {
            continue;
        };
        let reflowed = reflow_within_lines(&text);
        let source = SourceFile::new(SourceId(0), name.as_str(), reflowed.as_str());
        let formatted =
            format_source(&source, FrontendBudget::v1()).unwrap_or_else(|diagnostics| {
                panic!("reflowed {name} no longer parses: {diagnostics:?}")
            });
        assert_eq!(
            formatted, expected,
            "formatting {name} depends on indentation or spacing within a line"
        );
        compared += 1;
    }
    assert!(compared > 100, "only {compared} sources compared");
}
#[test]
fn canonicalizes_blocks_operators_and_declarations() {
    let formatted = format(
        "seiyaku Demo{ permission Write; state int count;hajimari(){count=0;}kotoage fn bump(int value) authorize(Write) ->int {var int total=count+value;if total>10{total=10;}return total;}view fn read() authorize(anyone) ->int {return count;}}",
    );
    assert_eq!(
        formatted,
        concat!(
            "seiyaku Demo {\n",
            "    permission Write;\n",
            "    state int count;\n",
            "    hajimari() {\n",
            "        count = 0;\n",
            "    }\n\n",
            "    kotoage fn bump(int value) authorize(Write) -> int {\n",
            "        var int total = count + value;\n",
            "        if total > 10 {\n",
            "            total = 10;\n",
            "        }\n",
            "        return total;\n",
            "    }\n\n",
            "    view fn read() authorize(anyone) -> int {\n",
            "        return count;\n",
            "    }\n",
            "}\n",
        )
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn preserves_comments_literals_and_canonical_keywords() {
    let source = "seiyaku Demo{/* exact */view fn text() authorize(anyone) ->string {// keep me\nreturn r#\"a  b\"#;}}";
    let formatted = format(source);
    assert_eq!(
        formatted,
        concat!(
            "seiyaku Demo {\n",
            "    /* exact */ view fn text() authorize(anyone) -> string { // keep me\n",
            "        return r#\"a  b\"#;\n",
            "    }\n",
            "}\n",
        )
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn preserves_decimal_literal_spelling_idempotently() {
    let formatted =
        format("seiyaku Demo{view fn value() authorize(anyone) ->decimal {return 1.250_0;}}");
    assert!(formatted.contains("return 1.250_0;"));
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn formats_named_struct_literals_with_multiline_trailing_commas() {
    let formatted = format(
        "seiyaku Demo{struct Transfer{int source,string destination,quantity amount}fn build(int source,string destination)->Transfer{return Transfer{amount:10,source,destination};}}",
    );
    assert!(
        formatted.contains(concat!(
            "return Transfer {\n",
            "            amount: 10,\n",
            "            source,\n",
            "            destination,\n",
            "        };",
        )),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn formats_imported_record_literals_and_patterns_from_syntax() {
    let formatted = format(
        "module Tests{koto_test{target:\"target.ko\"}fn make(int count)->Remote::Record{return Remote::Record{count,active:true};}fn read(Remote::Record record)->int{let Remote::Record{count,active:_}=record;count}}",
    );
    assert!(
        formatted.contains(concat!(
            "return Remote::Record {\n",
            "            count,\n",
            "            active: true,\n",
            "        };",
        )),
        "{formatted}"
    );
    assert!(
        formatted.contains("let Remote::Record { count, active: _ } = record;\n"),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn formats_fragment_imports_exports_and_record_braces_idempotently() {
    let formatted = format(
        "import\"./record.ko\"as Remote;export fn make(int count)->Remote::Record{return Remote::Record{count,active:true};}fn read(Remote::Record record)->int{let Remote::Record{count,active:_}=record;count}",
    );
    assert!(formatted.starts_with("import \"./record.ko\" as Remote;\n"));
    assert!(formatted.contains("export fn make(int count) -> Remote::Record {\n"));
    assert!(
        formatted.contains(concat!(
            "return Remote::Record {\n",
            "        count,\n",
            "        active: true,\n",
            "    };",
        )),
        "{formatted}"
    );
    assert!(
        formatted.contains("let Remote::Record { count, active: _ } = record;\n"),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn wraps_long_named_calls_at_one_hundred_columns_with_trailing_comma() {
    let formatted = format(
        "seiyaku Demo{fn target(string first,string second,string third){}fn run(){target(first:\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",second:\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",third:\"cccccccccccccccccccccccccccccccccccccccc\");}}",
    );
    assert!(formatted.contains("target(\n"), "{formatted}");
    assert!(formatted.contains("third: \"cccccccccccccccccccccccccccccccccccccccc\",\n"));
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn wraps_when_canonical_spaces_cross_the_compressed_source_boundary() {
    // With nineteen-character literals the compressed source span ends at
    // column 100 exactly. Canonical spaces after the two commas and three
    // colons take the inline rendering to column 105.
    let formatted = format(
        "seiyaku Demo{fn target(string first,string second,string third){}fn run(){target(first:\"aaaaaaaaaaaaaaaaaaa\",second:\"bbbbbbbbbbbbbbbbbbb\",third:\"ccccccccccccccccccc\");}}",
    );
    assert!(formatted.contains("target(\n"), "{formatted}");
    assert!(
        formatted
            .lines()
            .all(|line| line.chars().count() <= TARGET_COLUMNS),
        "formatter exceeded the {TARGET_COLUMNS}-column target:\n{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn unicode_literal_bytes_do_not_cause_spurious_wrapping() {
    let snow = "雪".repeat(30);
    let source =
        format!("seiyaku Demo{{fn target(string value){{}}fn run(){{target(value:\"{snow}\");}}}}");
    let formatted = format(&source);
    assert!(
        formatted.contains(&format!("target(value: \"{snow}\");")),
        "{formatted}"
    );
    assert!(!formatted.contains("target(\n"), "{formatted}");
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn branded_unicode_and_comments_remain_stable_in_multiline_calls() {
    let formatted = format(
        "誓約 Branding{ permission Run; 始まり(){}言挙げ fn run() authorize(Run) {target(first:\"雪\",// 保持\nsecond:\"月\",third:\"星\");}改善(){}}",
    );
    for spelling in [
        "誓約",
        "始まり",
        "言挙げ",
        "改善",
        "// 保持",
        "\"雪\"",
        "\"月\"",
        "\"星\"",
    ] {
        assert!(
            formatted.contains(spelling),
            "missing `{spelling}`:\n{formatted}"
        );
    }
    assert_eq!(
        formatted,
        concat!(
            "誓約 Branding {\n",
            "    permission Run;\n",
            "    始まり() {}\n",
            "\n",
            "    言挙げ fn run() authorize(Run) {\n",
            "        target(\n",
            "            first: \"雪\", // 保持\n",
            "            second: \"月\",\n",
            "            third: \"星\",\n",
            "        );\n",
            "    }\n",
            "\n",
            "    改善() {}\n",
            "}\n",
        ),
        "the trailing comment stays on the argument it annotated"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn wraps_long_list_literals_with_trailing_commas_idempotently() {
    let source = concat!(
        "seiyaku Lists{fn labels()->List<string,8>{[",
        "\"primary-label-with-a-deliberately-long-stable-spelling\",",
        "\"secondary-label-with-a-deliberately-long-stable-spelling\",",
        "\"tertiary-label-with-a-deliberately-long-stable-spelling\"",
        "]}}"
    );
    let formatted = format(source);
    assert!(formatted.contains("[\n"), "{formatted}");
    assert!(
        formatted.contains("\"tertiary-label-with-a-deliberately-long-stable-spelling\",\n"),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn preserves_list_comprehension_comments_and_literal_spelling() {
    let source = "seiyaku Lists{fn values()->List<int,4>{let List<int,4> source = [1,2];[value*10 for value in source if value>0]// stable\n}}";
    let formatted = format(source);
    assert!(
        formatted.contains("[value * 10 for value in source if value > 0]"),
        "{formatted}"
    );
    assert!(formatted.contains("// stable"));
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn formats_native_json_with_stable_keys_literals_and_trailing_commas() {
    let formatted = format(
        r#"seiyaku JsonDemo{fn build(string label)->Json{json{owner:"alice","exact-key":label,amount:1.250_0,labels:json["primary",label]}}}"#,
    );
    assert!(
        formatted.contains(concat!(
            "json {\n",
            "            owner: \"alice\",\n",
            "            \"exact-key\": label,\n",
            "            amount: 1.250_0,\n",
            "            labels: json [\"primary\", label],\n",
            "        }",
        )),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn formats_amount_div_round_named_arguments_within_the_target() {
    let formatted = format(
        "seiyaku Amounts{fn rounded(quantity very_long_dividend_value,quantity very_long_divisor_value)->quantity{very_long_dividend_value.div_round(divisor:very_long_divisor_value,scale:28,mode:Rounding::nearest_even)}}",
    );
    assert!(formatted.contains(".div_round(\n"), "{formatted}");
    assert!(
        formatted.contains("mode: Rounding::nearest_even,\n"),
        "{formatted}"
    );
    assert!(
        formatted.lines().all(|line| line.chars().count() <= 100),
        "formatter exceeded the 100-column target:\n{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn authorize_modifier_stays_on_one_line_even_without_a_break_point() {
    let formatted = format(
        "seiyaku Demo{ permission ThisRoleNameIsDeliberatelyLongEnoughThatTheHeaderCannotFitWithinTheTarget; kotoage fn settle() authorize(ThisRoleNameIsDeliberatelyLongEnoughThatTheHeaderCannotFitWithinTheTarget) {}}",
    );
    assert_eq!(
        formatted,
        concat!(
            "seiyaku Demo {\n",
            "    permission ThisRoleNameIsDeliberatelyLongEnoughThatTheHeaderCannotFitWithinTheTarget;\n",
            "    kotoage fn settle() authorize(ThisRoleNameIsDeliberatelyLongEnoughThatTheHeaderCannotFitWithinTheTarget) {}\n",
            "}\n",
        )
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn long_declaration_heads_break_parameters_before_authorize() {
    let formatted = format(
        "seiyaku Pools{ permission Admin; kotoage fn quote_or_deposit(AccountId trader,Name pool,quantity amount_a,quantity amount_b) authorize(Admin) ->quantity {return amount_a;}}",
    );
    assert_eq!(
        formatted,
        concat!(
            "seiyaku Pools {\n",
            "    permission Admin;\n",
            "    kotoage fn quote_or_deposit(\n",
            "        AccountId trader,\n",
            "        Name pool,\n",
            "        quantity amount_a,\n",
            "        quantity amount_b,\n",
            "    ) authorize(Admin) -> quantity {\n",
            "        return amount_a;\n",
            "    }\n",
            "}\n",
        )
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn distinguishes_generic_delimiters_from_comparisons() {
    let formatted = format(
        "seiyaku Demo{state StateMap<string,Option<int>> values;view fn less(int a,int b) authorize(anyone) ->bool {return a<b;}}",
    );
    assert!(formatted.contains("StateMap<string, Option<int>>"));
    assert!(formatted.contains("return a < b;"));
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn formats_tail_match_and_postfix_propagation_idempotently() {
    let formatted = format(
        "seiyaku Demo{fn unwrap(Option<int> value)->int{match value{Option::some(item)=>item,Option::none=>0}}fn choose(bool flag,Option<int> value,int fallback)->int{flag?value?:fallback}}",
    );
    assert!(
        formatted.contains(concat!(
            "match value {\n",
            "            Option::some(item) => item,\n",
            "            Option::none => 0,\n",
            "        }",
        )),
        "{formatted}"
    );
    assert!(
        formatted.contains("flag ? value? : fallback"),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn formats_list_ternary_and_propagation_indexing_without_ambiguity() {
    let formatted = format(
        "seiyaku Demo{fn choose(bool flag)->List<int,1>{flag?[1]:[2]}fn head(Option<List<int,1>> value)->Option<int>{Option::some(value?[0])}}",
    );
    assert!(formatted.contains("flag ? [1] : [2]"), "{formatted}");
    assert!(formatted.contains("Option::some(value?[0])"), "{formatted}");
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn refuses_to_rewrite_invalid_sources() {
    let source = SourceFile::new(SourceId(0), "bad.ko", "seiyaku Demo { return ; }");
    let diagnostics = format_source(&source, FrontendBudget::v1())
        .expect_err("invalid source must not be formatted");
    assert!(!diagnostics.diagnostics.is_empty());
}
#[test]
fn refuses_output_expansion_beyond_the_source_budget() {
    let mut text = String::from("seiyaku Demo { view fn run() authorize(anyone) {");
    for _ in 0..16 {
        text.push_str("if true {");
    }
    for _ in 0..14_000 {
        text.push_str("value = 0;");
    }
    for _ in 0..16 {
        text.push('}');
    }
    text.push_str("} }");
    assert!(text.len() < MAX_SOURCE_BYTES);
    let source = SourceFile::new(SourceId(0), "expansion.ko", text);
    let diagnostics = format_source(&source, FrontendBudget::v1())
        .expect_err("formatter expansion must remain bounded");
    assert_eq!(diagnostics.diagnostics[0].code, "K0001");
}
/// Run the formatter's token preparation on `text` and hand the prepared tokens to `check`.
fn with_tokens<R>(text: &str, check: impl FnOnce(&[Tok<'_>]) -> R) -> R {
    let source = SourceFile::new(SourceId(0), "tokens.ko", text);
    let crate::syntax::ProgramParseOutput { tree, program, .. } =
        crate::syntax::parse_source_or_fragment(&source, FrontendBudget::v1());
    assert!(program.is_some(), "test source must parse: {text}");
    let ranges = parsed_type_ranges(&source, FrontendBudget::v1()).expect("type ranges");
    let roles = SyntaxRoles::collect(tree.root());
    let tokens = prepare_tokens(&source, &tree.into_tokens(), &roles, &ranges);
    check(&tokens)
}
fn spelled(tokens: &[Tok<'_>]) -> String {
    tokens
        .iter()
        .map(|token| token.text)
        .collect::<Vec<_>>()
        .join(" ")
}
#[test]
fn every_source_policy_type_formats_type_arguments_without_spaces() {
    for name in kotodama_surface::source_policy::V1_SOURCE_TYPE_NAMES {
        let formatted = format(&format!(
            "seiyaku Demo{{view fn read({name} < Name , int > value)authorize(anyone)->{name} < Name >{{return value;}}}}"
        ));
        assert!(
            formatted.contains(&format!("{name}<Name, int> value"))
                && formatted.contains(&format!("-> {name}<Name> {{")),
            "{name}:\n{formatted}"
        );
    }
    let formatted = format(
        "module Paths{fn read(Remote::Record < StateCursor < Name > > value)->Option< Remote::Record<int> >{return value;}}",
    );
    assert!(
        formatted.contains(
            "fn read(Remote::Record<StateCursor<Name>> value) -> Option<Remote::Record<int>> {"
        ),
        "{formatted}"
    );
}
#[test]
fn parsed_type_ranges_merge_nested_type_arguments() {
    let text = "seiyaku Demo{state StateMap<Name,Option<int>> values;}";
    let source = SourceFile::new(SourceId(0), "ranges.ko", text);
    let ranges = parsed_type_ranges(&source, FrontendBudget::v1()).expect("valid source");
    let spelled = ranges
        .iter()
        .map(|range| source.slice(*range).unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(spelled, ["StateMap<Name,Option<int>>"]);
}
#[test]
fn syntax_roles_classify_braces_lists_and_parameters() {
    with_tokens(
        "seiyaku Demo{struct P{int a}error enum E{#[message(\"m\")]A=1}fn f(Option<int> x)->P{let List<int,2> l=[1,2];match x{Option::some(v)=>P{a:v},Option::none=>P{a:0}}}}",
        |tokens| {
            let roles = tokens
                .iter()
                .filter(|token| token.role != Role::Plain)
                .map(|token| (token.text, token.role))
                .collect::<Vec<_>>();
            let list = Role::List {
                trailing_comma: true,
                json: false,
            };
            assert_eq!(
                roles,
                [
                    ("{", Role::Brace(BraceKind::Block)),
                    ("{", Role::Brace(BraceKind::StructFields)),
                    ("}", Role::ItemBlockEnd),
                    ("{", Role::Brace(BraceKind::EnumVariants)),
                    ("#", Role::AttributeStart),
                    ("]", Role::AttributeEnd),
                    ("}", Role::ItemBlockEnd),
                    ("(", Role::ParamParen),
                    ("<", Role::GenericOpen),
                    (">", Role::GenericClose),
                    ("{", Role::Brace(BraceKind::Block)),
                    ("<", Role::GenericOpen),
                    (">", Role::GenericClose),
                    ("[", list),
                    ("{", Role::Brace(BraceKind::Match)),
                    ("{", Role::Brace(BraceKind::Record)),
                    ("{", Role::Brace(BraceKind::Record)),
                    ("}", Role::ItemBlockEnd),
                ]
            );
        },
    );
}
#[test]
fn last_significant_token_skips_trailing_trivia() {
    let source = SourceFile::new(
        SourceId(0),
        "last.ko",
        "seiyaku Demo { fn f() {} // done\n}",
    );
    let output = crate::syntax::parse_source_or_fragment(&source, FrontendBudget::v1());
    let token = last_significant_token(output.tree.root()).expect("tokens");
    assert_eq!(token.kind, SyntaxKind::RBrace);
    assert_eq!(token.range.start as usize, source.text().len() - 1);
}
#[test]
fn delimiter_partners_match_nested_groups_and_generics() {
    with_tokens("seiyaku Demo{fn f(Option<int> v){g([v]);}}", |tokens| {
        let partners = delimiter_partners(tokens);
        for (index, token) in tokens.iter().enumerate() {
            let expected_closer = match (token.kind, token.role) {
                (SyntaxKind::LParen, _) => Some(SyntaxKind::RParen),
                (SyntaxKind::LBracket, _) => Some(SyntaxKind::RBracket),
                (SyntaxKind::LBrace, _) => Some(SyntaxKind::RBrace),
                (SyntaxKind::Less, Role::GenericOpen) => Some(SyntaxKind::Greater),
                _ => None,
            };
            if let Some(closer) = expected_closer {
                let close = partners[index].expect("every opener has a partner");
                assert_eq!(tokens[close].kind, closer);
                assert_eq!(partners[close], Some(index));
            }
        }
    });
}
#[test]
fn record_separators_normalize_to_single_commas() {
    with_tokens(
        "module R{struct Pair{int first;int second,;;bool third Option<int> fourth}error enum F{A=1;B=2}koto_test{target:\"t.ko\";}}",
        |tokens| {
            assert_eq!(
                spelled(tokens),
                "module R { struct Pair { int first , int second , bool third , Option < int > fourth } error enum F { A = 1 , B = 2 } koto_test { target : \"t.ko\" , } }"
            );
        },
    );
}
#[test]
fn redundant_condition_parentheses_are_removed_only_around_whole_conditions() {
    with_tokens(
        "seiyaku C{fn f(int a,int b)->int{if ((a>b)){return 1;}if (a) == (b) {return 2;}if (a>b)&&(b>a){return 3;}return 4;}}",
        |tokens| {
            let spelled = spelled(tokens);
            assert!(spelled.contains("if a > b {"), "{spelled}");
            assert!(spelled.contains("if ( a ) == ( b ) {"), "{spelled}");
            assert!(spelled.contains("if ( a > b ) && ( b > a ) {"), "{spelled}");
        },
    );
}
#[test]
fn tuple_parentheses_break_without_a_trailing_comma() {
    with_tokens(
        "seiyaku T{fn f()->(int,int){let (a,b)=(1,2);g(a,b);return (a,b);}}",
        |tokens| {
            let tuples = tokens
                .iter()
                .filter(|token| token.role == Role::TupleParen)
                .count();
            // The return type, the pattern, its value and the returned tuple; never the call.
            assert_eq!(tuples, 4);
        },
    );
}
#[test]
fn demote_unbalanced_generics_turns_stray_markers_into_operators() {
    let marker = |kind, role| Tok {
        kind,
        text: "",
        start: 0,
        newlines_before: 0,
        role,
        segment: false,
    };
    let mut tokens = [
        marker(SyntaxKind::Less, Role::GenericOpen),
        marker(SyntaxKind::LParen, Role::Plain),
        marker(SyntaxKind::Greater, Role::GenericClose),
        marker(SyntaxKind::RParen, Role::Plain),
    ];
    demote_unbalanced_generics(&mut tokens);
    assert!(tokens.iter().all(|token| token.role == Role::Plain));
}
#[test]
fn record_is_compact_requires_one_member_without_comments_or_nesting() {
    for (text, compact) in [
        ("seiyaku R{fn f()->Json{json{a:1}}}", true),
        ("seiyaku R{fn f()->Json{json{a:1,}}}", true),
        ("seiyaku R{fn f()->Json{json{a:1,b:2}}}", false),
        ("seiyaku R{fn f()->Json{json{a:json{b:1}}}}", false),
        ("seiyaku R{fn f()->Json{json{/* c */a:1}}}", false),
        ("seiyaku R{fn f()->Json{json{}}}", true),
    ] {
        with_tokens(text, |tokens| {
            let partners = delimiter_partners(tokens);
            let open = tokens
                .iter()
                .position(|token| token.role == Role::Brace(BraceKind::Record))
                .expect("record brace");
            let close = partners[open].expect("partner");
            assert_eq!(record_is_compact(tokens, open, close), compact, "{text}");
        });
    }
}
#[test]
fn operator_class_orders_loosest_operators_first() {
    with_tokens(
        "seiyaku O{fn f(int a,bool b)->int{return b?a:a||b&&a==a+a*a;}}",
        |tokens| {
            let classes = tokens
                .iter()
                .enumerate()
                .filter_map(|(index, token)| {
                    operator_class(tokens, index, false).map(|class| (token.text, class))
                })
                .collect::<Vec<_>>();
            assert_eq!(
                classes,
                [
                    ("?", 0),
                    ("||", 1),
                    ("&&", 2),
                    ("==", 3),
                    ("+", 4),
                    ("*", 5)
                ]
            );
        },
    );
}
#[test]
fn prefix_operators_follow_keywords_and_operators_with_one_space() {
    let formatted = format(
        "seiyaku P{fn f(bool a,bool b,int c)->int{if ! a&&!b{return - c;}let int d=c- -c;return !(a)?c:d;}}",
    );
    assert!(formatted.contains("if !a && !b {"), "{formatted}");
    assert!(formatted.contains("return -c;"), "{formatted}");
    assert!(formatted.contains("let int d = c - -c;"), "{formatted}");
    assert!(formatted.contains("return !(a) ? c : d;"), "{formatted}");
    assert!(needs_space(
        Some(SyntaxKind::AndAnd),
        false,
        SyntaxKind::Bang,
        true
    ));
    assert!(!needs_space(
        Some(SyntaxKind::Bang),
        true,
        SyntaxKind::LParen,
        false
    ));
    assert!(prefix_position(Some(SyntaxKind::KwIf)));
}
#[test]
fn branded_path_segments_call_without_a_space_in_either_script() {
    let formatted = format(
        "誓約 Mixed{ permission A; permission B; kotoage fn a() authorize(A) {let string x=context::kotoage ();let string y=context::言挙げ ();ledger::seiyaku::grant_permission(context::authority(),permission:A);}言挙げ fn b() authorize(B) {}始まり(){}kaizen(){}}",
    );
    assert_eq!(
        formatted,
        concat!(
            "誓約 Mixed {\n",
            "    permission A;\n",
            "    permission B;\n",
            "    kotoage fn a() authorize(A) {\n",
            "        let string x = context::kotoage();\n",
            "        let string y = context::言挙げ();\n",
            "        ledger::seiyaku::grant_permission(context::authority(), permission: A);\n",
            "    }\n\n",
            "    言挙げ fn b() authorize(B) {}\n\n",
            "    始まり() {}\n\n",
            "    kaizen() {}\n",
            "}\n",
        )
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn blank_lines_collapse_to_one_and_never_open_or_close_a_block() {
    let formatted = format(
        "seiyaku Demo {\n\n\n    state int a;\n\n\n\n    state int b;\n    fn f() {\n\n        a = 1;\n\n\n        b = 2;\n\n    }\n\n}\n",
    );
    assert_eq!(
        formatted,
        concat!(
            "seiyaku Demo {\n",
            "    state int a;\n\n",
            "    state int b;\n",
            "    fn f() {\n",
            "        a = 1;\n\n",
            "        b = 2;\n",
            "    }\n",
            "}\n",
        )
    );
}
#[test]
fn separators_bind_before_trailing_comments() {
    let formatted = format(
        "seiyaku S{fn f(){value = 1 // why\n;g(1, // first\n2 // second\n);}fn g(int a,int b){}}",
    );
    assert_eq!(
        formatted,
        concat!(
            "seiyaku S {\n",
            "    fn f() {\n",
            "        value = 1; // why\n",
            "        g(\n",
            "            1, // first\n",
            "            2, // second\n",
            "        );\n",
            "    }\n\n",
            "    fn g(int a, int b) {}\n",
            "}\n",
        )
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn single_line_lists_drop_trailing_commas() {
    let formatted =
        format("seiyaku L{fn f(){g(1,2,);let List<int,2> l=[1,2,];}fn g(int a,int b,){}}");
    assert!(formatted.contains("g(1, 2);"), "{formatted}");
    assert!(formatted.contains("[1, 2];"), "{formatted}");
    assert!(formatted.contains("fn g(int a, int b) {}"), "{formatted}");
}
#[test]
fn brace_kinds_stay_inline_only_where_their_layout_allows() {
    for (text, kind, inline) in [
        (
            "module R{fn f(P p){let P{a,b,..}=p;}}",
            BraceKind::Pattern,
            true,
        ),
        (
            "module R{fn f(P p){let P{/* c */a}=p;}}",
            BraceKind::Pattern,
            false,
        ),
        ("module R{fn f()->P{P{a:1}}}", BraceKind::Record, true),
        ("module R{fn f()->P{P{a:1,b:2}}}", BraceKind::Record, false),
        ("module R{struct P{int a}}", BraceKind::StructFields, false),
        (
            "module R{error enum E{A=1}}",
            BraceKind::EnumVariants,
            false,
        ),
    ] {
        with_tokens(text, |tokens| {
            let partners = delimiter_partners(tokens);
            let open = tokens
                .iter()
                .position(|token| token.role == Role::Brace(kind))
                .unwrap_or_else(|| panic!("{kind:?} brace in {text}"));
            let close = partners[open].expect("partner");
            assert_eq!(kind.may_stay_inline(tokens, open, close), inline, "{text}");
        });
    }
}
#[test]
fn struct_patterns_stay_on_one_line_when_they_fit() {
    let formatted = format(
        "module R{struct P{int first,int second}fn f(P p)->int{let P{first,second}=p;let P{first:a_deliberately_long_binding_name,second:another_deliberately_long_binding}=p;first}}",
    );
    assert!(
        formatted.contains("        let P { first, second } = p;\n"),
        "{formatted}"
    );
    assert!(
        formatted.contains(concat!(
            "        let P {\n",
            "            first: a_deliberately_long_binding_name,\n",
            "            second: another_deliberately_long_binding,\n",
            "        } = p;\n",
        )),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn starts_method_call_requires_a_named_call() {
    with_tokens(
        "module M{fn f(P p)->int{p.items.get(0).value()}}",
        |tokens| {
            let calls = tokens
                .iter()
                .enumerate()
                .filter(|&(index, _)| starts_method_call(tokens, index))
                .map(|(index, _)| tokens[index + 1].text)
                .collect::<Vec<_>>();
            assert_eq!(calls, ["get", "value"]);
        },
    );
}
#[test]
fn long_method_chains_break_before_each_call() {
    let formatted = format(
        "module M{fn f(P p)->int{return p.balances_for_account(1).unwrap_or_default().lookup_entry(2).unwrap_or_zero().finish();}fn g(P p)->int{return p.balances_for_account(111111111111111111111111111111111111111111111111111111111111111111111111);}}",
    );
    assert!(
        formatted.contains(concat!(
            "        return p\n",
            "            .balances_for_account(1)\n",
            "            .unwrap_or_default()\n",
            "            .lookup_entry(2)\n",
            "            .unwrap_or_zero()\n",
            "            .finish();\n",
        )),
        "{formatted}"
    );
    // A single call breaks its argument list rather than its receiver.
    assert!(
        formatted.contains("        return p.balances_for_account(\n"),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn block_comments_hug_parentheses_and_brackets() {
    let formatted = format(
        "module C{fn f( /* lead */ int a,int b /* tail */ )->int{g( /* none */ );[ /* x */ a ][0]}}",
    );
    assert!(
        formatted.contains("fn f(/* lead */ int a, int b /* tail */) -> int {"),
        "{formatted}"
    );
    assert!(formatted.contains("g(/* none */);"), "{formatted}");
    assert!(formatted.contains("[/* x */ a][0]"), "{formatted}");
    assert_eq!(format(&formatted), formatted);
    let closer = Tok {
        kind: SyntaxKind::RParen,
        text: ")",
        ..Tok::separator(SyntaxKind::Comma, 0)
    };
    let comma = Tok::separator(SyntaxKind::Comma, 0);
    let name = Tok {
        kind: SyntaxKind::Ident,
        text: "b",
        ..comma
    };
    assert!(closes_tightly(&[closer], 0));
    assert!(closes_tightly(&[comma, closer], 0));
    assert!(!closes_tightly(&[comma, name, closer], 0));
    assert!(!closes_tightly(&[comma], 0));
    assert!(!closes_tightly(&[closer], 1));
}
#[test]
fn projection_measures_block_comments_like_the_printer() {
    let text = "module C{fn f(/* a */ int x /* b */){}}";
    with_tokens(text, |tokens| {
        let printer = Printer::new(tokens);
        let open = tokens
            .iter()
            .position(|token| token.role == Role::ParamParen)
            .expect("parameter list");
        let close = printer.partners[open].expect("partner");
        let mut line = Projection::new(&printer);
        for index in open..=close {
            assert!(line.token(index));
        }
        assert_eq!(line.column, "(/* a */ int x /* b */)".chars().count());
        assert_eq!(line.last_char, Some(')'));
        line.space();
        assert_eq!(line.last_char, Some(' '));
        line.trim_trailing_spaces();
        assert_eq!(line.last_char, None);
    });
}
#[test]
fn unbreakable_values_move_onto_a_continuation_line() {
    let long = "a string literal long enough that the statement cannot fit within one hundred";
    let formatted = format(&format!(
        "module A{{fn f(Option<int> v)->string{{let string message_with_a_long_name=\"{long}\";message_with_a_long_name=\"{long}\";match v{{Option::some(x)=>\"{long} columns\",Option::none=>\"short\"}}}}}}"
    ));
    assert!(
        formatted.contains(&format!(
            "        let string message_with_a_long_name =\n            \"{long}\";\n"
        )),
        "{formatted}"
    );
    assert!(
        formatted.contains(&format!(
            "        message_with_a_long_name =\n            \"{long}\";\n"
        )),
        "{formatted}"
    );
    assert!(
        formatted.contains(&format!(
            "            Option::some(x) =>\n                \"{long} columns\",\n"
        )),
        "{formatted}"
    );
    assert!(
        formatted.contains("            Option::none => \"short\",\n"),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn group_can_break_only_for_non_empty_layout_groups() {
    with_tokens(
        "module G{fn f(int a)->int{g();g(a);let List<int,1> l=[a];(a);P{a:a}}}",
        |tokens| {
            let printer = Printer::new(tokens);
            let breakable = tokens
                .iter()
                .enumerate()
                .filter(|(_, token)| {
                    matches!(
                        token.kind,
                        SyntaxKind::LParen | SyntaxKind::LBracket | SyntaxKind::LBrace
                    )
                })
                .map(|(index, token)| (token.text, printer.group_can_break(index)))
                .collect::<Vec<_>>();
            assert_eq!(
                breakable,
                [
                    ("{", false), // module body
                    ("(", true),  // parameter list
                    ("{", false), // function body
                    ("(", false), // empty call
                    ("(", true),  // call with an argument
                    ("[", true),  // list literal
                    ("(", false), // grouping parentheses
                    ("{", true),  // struct literal
                ]
            );
        },
    );
}
#[test]
fn trigger_filters_end_with_a_semicolon_unless_they_end_with_a_block() {
    let formatted = format(
        "seiyaku T{trigger a->run{on time pre_commit // every block\nrepeats 2;}trigger b->run{metadata{tag:\"x\";}on pipeline block approved}trigger c->run{on data account created{}repeats indefinitely;}trigger d->run{on time schedule(start_ms:0,period_ms:10)authority alice;}trigger e->run{on execute trigger on}fn run(){}}",
    );
    assert!(
        formatted.contains(concat!(
            "    trigger a -> run {\n",
            "        on time pre_commit; // every block\n",
            "        repeats 2;\n",
            "    }\n",
        )),
        "{formatted}"
    );
    assert!(
        formatted.contains("        on pipeline block approved;\n"),
        "{formatted}"
    );
    assert!(
        formatted.contains("        on data account created {}\n        repeats indefinitely;\n"),
        "{formatted}"
    );
    assert!(
        formatted.contains(
            "        on time schedule(start_ms: 0, period_ms: 10);\n        authority alice;\n"
        ),
        "{formatted}"
    );
    assert!(
        formatted.contains("        on execute trigger on;\n"),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn trigger_filter_last_follows_the_closed_filter_grammar() {
    for (filter, last) in [
        ("time pre_commit", "pre_commit"),
        ("time schedule(start_ms: 0, period_ms: 10)", ")"),
        ("execute trigger wake", "wake"),
        ("data any", "any"),
        ("data account created { account_id alice; }", "}"),
        ("pipeline transaction", "transaction"),
        ("pipeline block approved", "approved"),
    ] {
        let text = format!("seiyaku T{{trigger t->run{{on {filter};}}fn run(){{}}}}");
        with_tokens(&text, |tokens| {
            let partners = delimiter_partners(tokens);
            let on = tokens
                .iter()
                .position(|token| token.text == "on")
                .expect("on field");
            let body = tokens
                .iter()
                .enumerate()
                .filter(|(_, token)| token.kind == SyntaxKind::LBrace)
                .nth(1)
                .map(|(index, _)| index)
                .expect("trigger body");
            let close = partners[body].expect("closed trigger body");
            let found = trigger_filter_last(tokens, &partners, on, close).expect("filter end");
            assert_eq!(tokens[found].text, last, "{filter}");
            // Prepared tokens terminate a scalar filter with `;` and a block filter with nothing.
            let terminator = next_code(tokens, found + 1, close).map(|next| tokens[next].kind);
            let expected = (last != "}").then_some(SyntaxKind::Semicolon);
            assert_eq!(terminator, expected, "{filter}");
        });
    }
}
#[test]
fn comment_forced_breaks_continue_the_statement_one_level_deeper() {
    let formatted = format(
        "seiyaku C{state StateMap<Name, // 鍵\nint> Weird;fn f(int a,int b)->int{let int x=a+ // 左辺\nb;let int y=a\n// 右辺の説明\n+b;return x+y;}}",
    );
    assert_eq!(
        formatted,
        concat!(
            "seiyaku C {\n",
            "    state StateMap<Name, // 鍵\n",
            "        int> Weird;\n",
            "    fn f(int a, int b) -> int {\n",
            "        let int x = a + // 左辺\n",
            "            b;\n",
            "        let int y = a\n",
            "            // 右辺の説明\n",
            "            + b;\n",
            "        return x + y;\n",
            "    }\n",
            "}\n",
        )
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn follows_attribute_skips_comments_between_attribute_and_item() {
    with_tokens("module A{#[test]\n// note\nfn t(){}fn u(){}}", |tokens| {
        let printer = Printer::new(tokens);
        let position = |text: &str, nth: usize| {
            tokens
                .iter()
                .enumerate()
                .filter(|(_, token)| token.text.trim_end() == text)
                .nth(nth)
                .map(|(index, _)| index)
                .expect("token")
        };
        assert!(printer.follows_attribute(position("fn", 0)));
        assert!(printer.follows_attribute(position("// note", 0)));
        assert!(!printer.follows_attribute(position("fn", 1)));
    });
    let formatted = format("module A{#[test]\n// note\nfn t(){}}");
    assert_eq!(
        formatted,
        "module A {\n    #[test]\n    // note\n    fn t() {}\n}\n"
    );
}
#[test]
fn layered_breaks_nest_tighter_operators_one_level_deeper() {
    let operand = "aaaaaaaaaa";
    let sum = [operand; 10].join("+");
    let text = format!("seiyaku L{{fn f(bool c,int {operand})->int{{return c?{sum}:0;}}}}");
    with_tokens(&text, |tokens| {
        let printer = Printer::new(tokens);
        let start = tokens
            .iter()
            .position(|token| token.kind == SyntaxKind::KwReturn)
            .expect("return");
        let region = printer.region_at(start);
        let level_of = |kind: SyntaxKind| {
            tokens
                .iter()
                .enumerate()
                .filter(|(index, token)| *index > start && token.kind == kind)
                .map(|(index, _)| region.break_level(index))
                .collect::<Vec<_>>()
        };
        assert_eq!(level_of(SyntaxKind::Question), vec![Some(1)]);
        assert_eq!(level_of(SyntaxKind::Colon), vec![Some(1)]);
        assert_eq!(level_of(SyntaxKind::Plus), vec![Some(2); 9]);
        assert_eq!(region.break_level(start), None);
        assert!(
            region.breaks.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "breaks are sorted by token index"
        );
    });
    let formatted = format(&text);
    assert!(
        formatted.contains("            ? aaaaaaaaaa\n                + aaaaaaaaaa\n"),
        "{formatted}"
    );
    assert!(formatted.contains("\n            : 0;\n"), "{formatted}");
}
#[test]
fn layered_breaks_keep_short_lines_and_lone_method_calls_intact() {
    let text = "module L{fn f(bool c,P p)->int{return c?p.value_for_the_account_with_a_long_name(1)+first_operand_value+second_operand_value:0;}}";
    with_tokens(text, |tokens| {
        let printer = Printer::new(tokens);
        let start = tokens
            .iter()
            .position(|token| token.kind == SyntaxKind::KwReturn)
            .expect("return");
        let region = printer.region_at(start);
        assert!(
            region.breaks.iter().all(|&(_, level)| level == 1),
            "a continuation line that fits is not split again: {:?}",
            region.breaks
        );
        assert!(
            region
                .breaks
                .iter()
                .all(|&(at, _)| tokens[at].kind != SyntaxKind::Dot),
            "a lone method call stays with its receiver"
        );
    });
}
#[test]
fn canonicalize_terminators_drop_the_semicolon_after_trigger_blocks() {
    let formatted = format(
        "seiyaku T{trigger a->run{on data account created{account_id alice;}; // matched\nmetadata{tag:\"a\";};repeats 1;}fn run(){}}",
    );
    assert_eq!(
        formatted,
        concat!(
            "seiyaku T {\n",
            "    trigger a -> run {\n",
            "        on data account created {\n",
            "            account_id alice;\n",
            "        } // matched\n",
            "        metadata {\n",
            "            tag: \"a\";\n",
            "        }\n",
            "        repeats 1;\n",
            "    }\n",
            "\n",
            "    fn run() {}\n",
            "}\n",
        )
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn canonicalize_terminators_end_every_fixture_action_with_a_semicolon() {
    let formatted = format(
        "module FTests{koto_test{target:\"f.ko\"}fixture actors{actor(\"issuer\") // first\ngrant_permission(\"issuer\",\"Entry\")grant_permission(\"issuer\",\"Exit\");}#[test(fixture=actors)]fn t(){assert(true);}}",
    );
    assert!(
        formatted.contains(concat!(
            "    fixture actors {\n",
            "        actor(\"issuer\"); // first\n",
            "        grant_permission(\"issuer\", \"Entry\");\n",
            "        grant_permission(\"issuer\", \"Exit\");\n",
            "    }\n",
        )),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
    with_tokens("module FTests{fixture f{a()b();}}", |tokens| {
        let semicolons = tokens
            .iter()
            .filter(|token| token.kind == SyntaxKind::Semicolon)
            .count();
        assert_eq!(semicolons, 2, "{}", spelled(tokens));
    });
    // A supplied terminator follows block comments on the action's line, as a written one does.
    let commented = format(
        "module FTests{fixture actors{actor(\"issuer\") /* first */\ngrant_permission(\"issuer\",\"Entry\") /* second */;}}",
    );
    assert!(
        commented.contains(concat!(
            "        actor(\"issuer\") /* first */;\n",
            "        grant_permission(\"issuer\", \"Entry\") /* second */;\n",
        )),
        "{commented}"
    );
    assert_eq!(format(&commented), commented);
}
#[test]
fn layered_breaks_measure_each_line_at_the_level_it_starts_on() {
    // A synthetic ten-token region on one line at indentation 0. `||` at 2 breaks first; the
    // continuation from 2 is too long and breaks at `>` (6); its first line, still starting at
    // level 1, breaks at `+` (4). The line from 2 to 4 is 99 columns at level 1, so the `*` at 3
    // must stay on it.
    let extents = [
        (0, 5),
        (6, 7),
        (8, 9),
        (10, 103),
        (104, 105),
        (106, 130),
        (131, 132),
        (133, 140),
        (141, 150),
        (151, 160),
    ];
    let candidates = [(1, 2), (5, 3), (4, 4), (3, 6)];
    with_tokens("module L{}", |tokens| {
        let printer = Printer::new(tokens);
        assert_eq!(
            printer.layered_breaks(0, 10, 1, &extents, &candidates),
            vec![(2, 1), (4, 3), (6, 2)]
        );
    });
}
/// Insert `comment` before every `stride`-th significant token of `text`.
fn sprinkle_comments(text: &str, comment: &str, stride: usize) -> String {
    let source = SourceFile::new(SourceId(0), "sprinkle.ko", text);
    let lexed = crate::syntax::lex(&source, FrontendBudget::v1());
    let mut output = String::with_capacity(text.len() * 2);
    let mut significant = 0_usize;
    for token in &lexed.tokens {
        let spelling = source.slice(token.range).unwrap_or_default();
        if !token.kind.is_trivia() && !matches!(token.kind, SyntaxKind::Missing | SyntaxKind::Eof) {
            if significant % stride == stride - 1 {
                output.push_str(comment);
            }
            significant += 1;
        }
        output.push_str(spelling);
    }
    output
}
#[test]
fn sprinkle_comments_inserts_before_every_stride_token() {
    assert_eq!(
        sprinkle_comments("a b c d", "/*x*/", 2),
        "a /*x*/b c /*x*/d"
    );
}
/// Comments may sit between any two tokens; formatting must keep every one of them, still parse,
/// and reach a fixed point in one pass, whatever the comment style and density.
#[test]
fn comments_anywhere_stay_lossless_and_idempotent() {
    let goldens = GOLDEN_CASES
        .iter()
        .map(|(name, input, _)| ((*name).to_owned(), (*input).to_owned()));
    let repository = repository_sources().into_iter().filter_map(|path| {
        let text = std::fs::read_to_string(&path).ok()?;
        Some((path.display().to_string(), text))
    });
    let mut checked = 0_usize;
    for (name, text) in goldens.chain(repository) {
        let original = SourceFile::new(SourceId(0), name.as_str(), text.as_str());
        if format_source(&original, FrontendBudget::v1()).is_err() {
            continue;
        }
        for (comment, stride) in [
            (" /* 注 */ ", 5),
            (" // 注\n", 7),
            ("\n// own line\n", 11),
            (" /* a */ ", 2),
            ("\n\n/* c\n d */\n\n", 4),
            (" /*f*/", 1),
            (" // x\n", 1),
        ] {
            let commented = sprinkle_comments(&text, comment, stride);
            assert_stable(&format!("{name} with {comment:?}/{stride}"), &commented)
                .unwrap_or_else(|| panic!("{name} with comments no longer parses"));
        }
        checked += 1;
    }
    assert!(checked > 100, "only {checked} sources checked");
}
#[test]
fn bind_separators_before_comments_moves_separators_and_keeps_blank_lines() {
    with_tokens(
        "seiyaku B{fn f(){g(1 /* a */ ,2);let int x=1 // why\n;\nlet int y=2 /* c */\n\n;let int z=3;}fn g(int a,int b){}}",
        |tokens| {
            let text = spelled(tokens);
            assert!(text.contains("( 1 /* a */ , 2 )"), "{text}");
            assert!(text.contains("x = 1 ; // why"), "{text}");
            assert!(text.contains("y = 2 /* c */ ; let"), "{text}");
            // The second `let` starts the line after `;`; the third keeps the blank line written
            // before its `;`.
            let lets = tokens
                .iter()
                .filter(|token| token.kind == SyntaxKind::KwLet)
                .map(|token| token.newlines_before)
                .collect::<Vec<_>>();
            assert_eq!(lets, vec![0, 1, 2]);
        },
    );
    let formatted =
        format("seiyaku B{fn f(){let int x=1 // why\n;\nlet int y=2 /* c */\n\n;let int z=3;}}");
    assert_eq!(
        formatted,
        concat!(
            "seiyaku B {\n",
            "    fn f() {\n",
            "        let int x = 1; // why\n",
            "        let int y = 2 /* c */;\n",
            "\n",
            "        let int z = 3;\n",
            "    }\n",
            "}\n",
        )
    );
}
#[test]
fn ends_region_with_comments_only_for_comments_before_the_region_end() {
    let text = "seiyaku E{fn f(){g(1,\n2 /* mid */ + 3 // last\n/* own */\n);}fn g(int a,int b){}}";
    with_tokens(text, |tokens| {
        let position = |spelling: &str| {
            tokens
                .iter()
                .position(|token| token.text.trim_end() == spelling)
                .expect("token")
        };
        let mut printer = Printer::new(tokens);
        let region = printer.region_at(position("2"));
        assert_eq!(tokens[region.end].kind, SyntaxKind::RParen);
        printer.regions.push(region);
        assert!(!printer.ends_region_with_comments(position("/* mid */")));
        assert!(printer.ends_region_with_comments(position("// last")));
        assert!(printer.ends_region_with_comments(position("/* own */")));
        assert!(!printer.ends_region_with_comments(position("3")));
    });
    let formatted = format(text);
    assert!(
        formatted
            .contains("            2 /* mid */ + 3, // last\n            /* own */\n        );\n"),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn long_attributes_end_their_region_before_the_item() {
    let message =
        "the caller does not hold the permission required to settle this particular market";
    let formatted = format(&format!(
        "seiyaku A{{error enum Faults{{#[message(\"{message}\")]NotPermitted=1}}fn run(){{}}}}"
    ));
    assert!(
        formatted.contains(&format!(
            "        #[message(\"{message}\")]\n        NotPermitted = 1,\n"
        )),
        "{formatted}"
    );
    with_tokens(
        &format!("seiyaku A{{error enum Faults{{#[message(\"{message}\")]NotPermitted=1}}}}"),
        |tokens| {
            let printer = Printer::new(tokens);
            let hash = tokens
                .iter()
                .position(|token| token.role == Role::AttributeStart)
                .expect("attribute");
            let region = printer.region_at(hash);
            assert_eq!(tokens[region.end - 1].role, Role::AttributeEnd);
            assert!(region.breaks.is_empty());
        },
    );
}
#[test]
fn trailing_commas_and_comments_measure_the_same_in_both_passes() {
    // Without the trailing comma the last argument fits at exactly 100 columns; the comma written
    // at the multi-line closer pushes it to 101, so it breaks on the first pass as it will on the
    // next. A same-line block comment keeps the comma after it and never counts; a line comment
    // follows the comma.
    let argument = "a".repeat(85);
    for (trailing, written) in [("", "),"), (" /* c */", ") /* c */,"), (" // c", "), // c")] {
        let text = format!(
            "module T{{fn f(int {argument})->int{{return g(\nouter_value,\nh({argument}){trailing}\n);}}}}"
        );
        let formatted = format(&text);
        assert_eq!(format(&formatted), formatted, "{trailing:?}");
        assert!(
            formatted.contains("            h(\n"),
            "the trailing comma counts toward the width:\n{formatted}"
        );
        assert!(
            formatted.contains(&format!("            {written}\n        );\n")),
            "{formatted}"
        );
    }
}
#[test]
fn closer_takes_trailing_comma_only_for_the_innermost_multiline_list() {
    with_tokens("module C{fn f(){g(1,2);}}", |tokens| {
        let open = tokens
            .iter()
            .position(|token| token.role == Role::BreakableParen)
            .expect("argument list");
        let close = delimiter_partners(tokens)[open].expect("closed");
        let mut printer = Printer::new(tokens);
        assert!(!printer.closer_takes_trailing_comma(close));
        for (multiline, trailing_comma, expected) in [
            (true, true, true),
            (false, false, false),
            (true, false, false),
        ] {
            printer.groups.push(Group {
                kind: GroupKind::Paren,
                multiline,
                trailing_comma,
                close,
            });
            assert_eq!(printer.closer_takes_trailing_comma(close), expected);
            assert!(!printer.closer_takes_trailing_comma(close - 1));
            printer.groups.pop();
        }
    });
}
#[test]
fn same_line_block_comments_keep_their_separator_after_them() {
    let formatted = format(
        "module C{fn f(int amount,int fee)->int{g(amount /* nanos */,fee);g(1 /* x */,);let int x=1 /* one */;let int y=2 // two\n;return x+y;}fn g(int a,int b){}}",
    );
    assert!(
        formatted.contains("        g(amount /* nanos */, fee);\n"),
        "{formatted}"
    );
    assert!(formatted.contains("        g(1 /* x */);\n"), "{formatted}");
    assert!(
        formatted.contains("        let int x = 1 /* one */;\n"),
        "{formatted}"
    );
    assert!(
        formatted.contains("        let int y = 2; // two\n"),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
    let wide = format(
        "module C{fn f()->int{return compute_something_long(first_argument_value /* x */,second_argument_value, // y\nthird_argument /* z */);}}",
    );
    assert!(
        wide.contains(concat!(
            "        return compute_something_long(\n",
            "            first_argument_value /* x */,\n",
            "            second_argument_value, // y\n",
            "            third_argument /* z */,\n",
            "        );\n",
        )),
        "{wide}"
    );
    assert_eq!(format(&wide), wide);
}
#[test]
fn block_comments_after_a_multiline_opener_lead_the_first_member() {
    let formatted = format(
        "module L{fn f()->Json{let int v=compute_something_long(/* lead */ first_argument_value,second_argument_value,third_argument);json{/* c */ a:1,b:2}}fn g(){ /* first */ h(); /* end */\n}}",
    );
    assert!(
        formatted.contains(concat!(
            "        let int v = compute_something_long(\n",
            "            /* lead */ first_argument_value,\n",
        )),
        "{formatted}"
    );
    assert!(
        formatted
            .contains("        json {\n            /* c */ a: 1,\n            b: 2,\n        }\n"),
        "{formatted}"
    );
    assert!(
        formatted.contains("    fn g() {\n        /* first */ h(); /* end */\n    }\n"),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn leading_block_comments_start_their_members_region() {
    let sum =
        "first_value + second_value + first_value + second_value + first_value + second_value";
    let formatted = format(&format!(
        "module R{{fn f(int first_value,int second_value)->int{{/* note */ let int chosen={sum};return chosen;}}}}"
    ));
    assert!(
        formatted.contains(concat!(
            "        /* note */ let int chosen = first_value\n",
            "            + second_value\n",
        )),
        "{formatted}"
    );
    assert_lines_within_target("leading.ko", &formatted);
    assert_eq!(format(&formatted), formatted);
}
#[test]
fn comment_placement_helpers_follow_the_printer_state() {
    let text = "module H{fn f(){g(/* a */ x /* b */ /* c */,y);/* d */\n}}";
    with_tokens(text, |tokens| {
        let position = |spelling: &str| {
            tokens
                .iter()
                .position(|token| token.text == spelling)
                .expect("token")
        };
        let mut printer = Printer::new(tokens);
        assert!(printer.comment_leads_code(position("/* a */")));
        assert!(!printer.comment_leads_code(position("/* b */")));
        assert!(!printer.comment_leads_code(position("/* d */")));
        assert!(!printer.comment_leads_code(position("x")));
        assert!(printer.separator_follows(position("/* c */")));
        assert!(!printer.separator_follows(position("/* b */")));
        let open = tokens
            .iter()
            .position(|token| token.role == Role::BreakableParen)
            .expect("argument list");
        let close = printer.partners[open].expect("closed");
        // Directly after a multi-line opener, a comment leading code starts the member's line;
        // inside a single-line group every comment trails.
        printer.groups.push(Group {
            kind: GroupKind::Paren,
            multiline: true,
            trailing_comma: true,
            close,
        });
        printer.group_start = true;
        assert!(!printer.comment_is_trailing(position("/* a */")));
        printer.group_start = false;
        assert!(printer.comment_is_trailing(position("/* a */")));
        printer.line_comment_open = true;
        assert!(!printer.comment_is_trailing(position("/* a */")));
        printer.line_comment_open = false;
        printer.groups.last_mut().expect("group").multiline = false;
        printer.group_start = true;
        assert!(printer.comment_is_trailing(position("/* a */")));
    });
}

#[test]
fn formats_instance_and_chain_permission_declarations_in_canonical_order() {
    let source = r#"誓約 Policies{permission Admin;import permission "CanSetParameters" as ChainAdmin;kotoage fn update()authorize(Admin)->int{1}view fn inspect()authorize(ChainAdmin)->int{2}言挙げ fn open()authorize(anyone){}}"#;
    let output = format(source);
    assert!(output.contains("permission Admin;\n"), "{output}");
    assert!(
        output.contains("import permission \"CanSetParameters\" as ChainAdmin;"),
        "{output}"
    );
    assert!(
        output.contains("kotoage fn update() authorize(Admin) -> int"),
        "{output}"
    );
    assert_eq!(format(&output), output);
}

#[test]
fn data_and_error_enums_share_canonical_multiline_variant_formatting() {
    let source = "module Values{export enum Status{Active=1;Paused=2}error enum Failure{#[message(\"Not found\")]Missing=1}}";
    let formatted = format(source);
    assert!(
        formatted.contains("enum Status {\n        Active = 1,\n        Paused = 2,\n    }"),
        "{formatted}"
    );
    assert!(formatted.contains("error enum Failure"), "{formatted}");
    assert_eq!(format(&formatted), formatted);
}

#[test]
fn native_event_declarations_and_emissions_use_shared_record_formatting() {
    let source = "seiyaku Events{event Transfer{int first;int second;}kotoage fn run()authorize(anyone){emit Transfer{second:2,first:1};}}";
    let output = format(source);
    assert!(
        output.contains("event Transfer {\n        int first,\n        int second,\n    }"),
        "{output}"
    );
    assert!(
        output
            .contains("emit Transfer {\n            second: 2,\n            first: 1,\n        };"),
        "{output}"
    );
    assert_eq!(format(&output), output);
}

#[test]
fn typed_test_argument_records_format_as_closed_records() {
    let source = r#"module Checks { koto_test { target: "counter.ko" } #[test] fn check() { test::invoke_kotoage(kotoage:"increment",arguments:{step:1}); } }"#;
    let formatted = format(source);
    assert!(formatted.contains("arguments: { step: 1 }"), "{formatted}");
    assert_eq!(format(&formatted), formatted);
}

#[test]
fn imported_contract_and_exact_type_bindings_preserve_spelling_and_nominal_paths() {
    let source = r#"誓約 App{import 誓約 "./pool.to" as Pool;import type "data@1.0.0::Data::Status" from Pool as PreviousStatus;view fn run(bytes address,Pool::Data::Payload value)authorize(anyone)->Pool::Data::Payload{let pool=Pool::at(address:address);pool.echo(payload:value)}}"#;
    let formatted = assert_stable("contract-import.ko", source).expect("contract import parses");
    assert!(formatted.contains("import 誓約 \"./pool.to\" as Pool;"));
    assert!(
        formatted.contains("import type \"data@1.0.0::Data::Status\" from Pool as PreviousStatus;")
    );
    assert!(formatted.contains("Pool::Data::Payload value"));
    assert!(formatted.contains("pool.echo(payload: value)"));
}

#[test]
fn authored_doc_comments_preserve_text_and_declaration_attachment() {
    let source = "seiyaku Guide {\n/// First **paragraph**.\n///\n/// Second paragraph.\nview fn read() authorize(anyone)->int{1}\n}";
    let formatted = format(source);
    assert!(
        formatted.contains("/// First **paragraph**.\n    ///\n    /// Second paragraph."),
        "{formatted}"
    );
    assert_eq!(format(&formatted), formatted);
    let snapshot = crate::editor::EditorSnapshot::single("guide.ko", &formatted, false);
    let signature = snapshot
        .declaration_signatures(SourceId(0))
        .into_iter()
        .find(|signature| signature.name == "read")
        .unwrap();
    assert_eq!(
        signature.authored_documentation,
        "First **paragraph**.\n\nSecond paragraph."
    );
}
