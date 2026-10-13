//! Deterministic source-text scans used only by the inventory tests.
//!
//! These helpers read repository files as text. They detect drift between the
//! inventory tables and their source owners; they never execute proof code and
//! are not evidence of proof coverage.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

/// Opcode constant modules of `ivm_abi::instruction::wide` that hold admitted opcodes.
pub(super) const OPCODE_MODULES: [&str; 6] =
    ["arithmetic", "memory", "control", "system", "crypto", "zk"];

/// Result adapters whose error argument is already a direct trap token.
const ADAPTERS: [&str; 4] = ["ok_or", "ok_or_else", "map_err", "transpose"];

/// Helper constructors of `VMError` and the variants each one builds.
const HELPER_CONSTRUCTORS: [(&str, &[&str]); 2] = [
    ("metered", &["Metered"]),
    ("metered_not_implemented", &["Metered", "NotImplemented"]),
];

/// Associated functions that convert an existing error and construct nothing
/// at the call site; the variant is attributed to the conversion's own file.
const CONVERSIONS: [&str; 1] = ["from"];

/// Keywords that can directly precede a parenthesis without being a call.
const KEYWORDS: [&str; 9] = [
    "if", "while", "match", "return", "for", "loop", "in", "as", "fn",
];

/// Marker of the fetch-decode-execute loop inside `run_with_host_ref`.
const LOOP_MARKER: &str = "// Fetch-Decode-Execute loop";
/// Head of the interpreter's opcode dispatch.
const DISPATCH: &str = "match wide_op {";

/// Register-tag accessors an interpreter arm can call directly, as
/// `(inventory name, source needle)`.
pub(super) const TAG_ACCESSORS: [(&str, &str); 2] = [("tag", ".tag("), ("set_tag", ".set_tag(")];

/// Tokens that mark a function of the interpreter as a privacy helper: it
/// reads or writes a privacy tag, the private-byte ranges or raises the
/// privacy trap itself.
const PRIVACY_MARKERS: [&str; 5] = [
    ".tag(",
    ".set_tag(",
    "VMError::PrivacyViolation",
    "private_memory_bytes",
    "has_private(",
];

/// Workspace root containing `crates/`.
pub(super) fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

/// Read one repository-relative file.
pub(super) fn read(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// Drop every `#[cfg(test)]`-gated item: module declarations, imports,
/// constants, fields, statements, functions and inline test modules.
///
/// The gated item ends on the first line where every bracket opened since its
/// start is closed and the line ends with `;`, `,` or `}`. Brackets inside
/// string literals and comments are not special-cased; a misjudged extent
/// makes a source-checked test fail instead of hiding a difference.
pub(super) fn non_test_source(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < lines.len() {
        if lines[index].trim() != "#[cfg(test)]" {
            out.push_str(lines[index]);
            out.push('\n');
            index += 1;
            continue;
        }
        let mut end = index + 1;
        while end < lines.len() {
            let trimmed = lines[end].trim();
            if !(trimmed.is_empty() || trimmed.starts_with("#[")) {
                break;
            }
            end += 1;
        }
        let mut depth = 0_i64;
        while end < lines.len() {
            let line = lines[end];
            end += 1;
            for byte in line.bytes() {
                match byte {
                    b'(' | b'[' | b'{' => depth += 1,
                    b')' | b']' | b'}' => depth -= 1,
                    _ => {}
                }
            }
            if depth <= 0 && line.trim_end().ends_with([';', ',', '}']) {
                break;
            }
        }
        index = end;
    }
    out
}

/// Read one repository-relative file without its test-only items.
pub(super) fn read_non_test(relative: &str) -> String {
    non_test_source(&read(relative))
}

/// Drop every `//` comment, documentation included, so prose never counts as
/// code. A `//` inside a string literal on the same line is kept.
pub(super) fn strip_line_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let bytes = line.as_bytes();
        let mut in_string = false;
        let mut cut = bytes.len();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'\\' if in_string => index += 1,
                b'"' => {
                    let char_literal = index > 0
                        && bytes[index - 1] == b'\''
                        && bytes.get(index + 1) == Some(&b'\'');
                    if !char_literal {
                        in_string = !in_string;
                    }
                }
                b'/' if !in_string && bytes.get(index + 1) == Some(&b'/') => {
                    cut = index;
                    break;
                }
                _ => {}
            }
            index += 1;
        }
        out.push_str(&line[..cut]);
        out.push('\n');
    }
    out
}

/// Non-test, comment-free code of one repository-relative file.
pub(super) fn read_code(relative: &str) -> String {
    strip_line_comments(&read_non_test(relative))
}

/// Names of the non-test child modules declared as `mod name;`.
fn child_modules(non_test: &str) -> Vec<String> {
    non_test
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let declaration = if line.starts_with("pub") {
                &line[line.find(" mod ")? + 1..]
            } else {
                line
            };
            let name = declaration.strip_prefix("mod ")?.strip_suffix(';')?;
            is_identifier(name).then(|| name.to_owned())
        })
        .collect()
}

/// Every non-test module file reachable from `root`, sorted.
pub(super) fn module_files(root: &str) -> Vec<String> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        let base = path
            .strip_suffix(".rs")
            .unwrap_or_else(|| panic!("module file {path} must end with .rs"))
            .to_owned();
        for child in child_modules(&read_non_test(&path)) {
            let file = format!("{base}/{child}.rs");
            assert!(
                repo_root().join(&file).is_file(),
                "module {child} declared in {path} has no file {file}"
            );
            pending.push(file);
        }
        files.push(path);
    }
    files.sort();
    files
}

/// Every `.rs` file below a repository-relative directory, sorted.
pub(super) fn rust_files(directory: &str) -> Vec<String> {
    fn visit(root: &Path, directory: &Path, out: &mut Vec<String>) {
        let entries = std::fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()));
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                visit(root, &path, out);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let relative = path.strip_prefix(root).expect("path below workspace root");
                out.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let root = repo_root();
    let mut out = Vec::new();
    visit(&root, &root.join(directory), &mut out);
    out.sort();
    out
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(is_identifier_byte)
}

/// Longest identifier starting at `start`.
fn identifier_at(text: &str, start: usize) -> &str {
    let bytes = text.as_bytes();
    let mut end = start;
    while end < bytes.len() && is_identifier_byte(bytes[end]) {
        end += 1;
    }
    &text[start..end]
}

/// Identifiers that directly follow `prefix` at an identifier boundary.
pub(super) fn tokens_after(text: &str, prefix: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut from = 0;
    while let Some(found) = text[from..].find(prefix) {
        let start = from + found;
        let boundary = start == 0 || !is_identifier_byte(text.as_bytes()[start - 1]);
        let name = identifier_at(text, start + prefix.len());
        if boundary && !name.is_empty() {
            out.insert(name.to_owned());
        }
        from = start + prefix.len();
    }
    out
}

/// `(module, NAME)` pairs of every `wide::<module>::<NAME>` opcode constant path.
pub(super) fn opcode_tokens(text: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for module in OPCODE_MODULES {
        for name in tokens_after(text, &format!("wide::{module}::")) {
            if name.as_bytes()[0].is_ascii_uppercase() {
                out.insert((module.to_owned(), name));
            }
        }
    }
    out
}

/// Byte offsets at which `needle` starts on an identifier boundary.
fn boundary_matches(text: &str, needle: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(found) = text[from..].find(needle) {
        let start = from + found;
        if start == 0 || !is_identifier_byte(text.as_bytes()[start - 1]) {
            out.push(start);
        }
        from = start + needle.len();
    }
    out
}

fn skip_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

/// Offset just past the string literal opening at `open`.
fn skip_string(bytes: &[u8], open: usize) -> usize {
    let mut index = open + 1;
    while index < bytes.len() && bytes[index] != b'"' {
        if bytes[index] == b'\\' {
            index += 1;
        }
        index += 1;
    }
    index + 1
}

/// Offset just past the character literal opening at `open`; `None` for a
/// lifetime or any other apostrophe.
fn skip_char_literal(bytes: &[u8], open: usize) -> Option<usize> {
    if bytes.get(open + 1) == Some(&b'\\') && bytes.get(open + 3) == Some(&b'\'') {
        return Some(open + 4);
    }
    (bytes.get(open + 2) == Some(&b'\'')).then_some(open + 3)
}

/// Offset just past the bracket that closes the one at `open`, ignoring
/// brackets inside string and character literals.
pub(super) fn matching_close(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0_usize;
    let mut index = open;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                index = skip_string(bytes, index);
                continue;
            }
            b'\'' => {
                if let Some(next) = skip_char_literal(bytes, index) {
                    index = next;
                    continue;
                }
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// `(name, body)` of every function defined with a body in `code`, in source
/// order. The body includes its braces.
pub(super) fn functions(code: &str) -> Vec<(String, String)> {
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    for start in boundary_matches(code, "fn ") {
        let name = identifier_at(code, start + 3);
        if name.is_empty() {
            continue;
        }
        let mut index = start + 3 + name.len();
        let mut depth = 0_usize;
        let open = loop {
            match bytes.get(index) {
                None | Some(b';') if depth == 0 => break None,
                None => break None,
                Some(b'(' | b'[') => depth += 1,
                Some(b')' | b']') => depth = depth.saturating_sub(1),
                Some(b'{') if depth == 0 => break Some(index),
                Some(_) => {}
            }
            index += 1;
        };
        if let Some(open) = open
            && let Some(close) = matching_close(code, open)
        {
            out.push((name.to_owned(), code[open..close].to_owned()));
        }
    }
    out
}

/// Body of the single function named `name` in `code`.
pub(super) fn function_body(code: &str, name: &str) -> String {
    let mut bodies: Vec<String> = functions(code)
        .into_iter()
        .filter(|(candidate, _)| candidate == name)
        .map(|(_, body)| body)
        .collect();
    assert_eq!(bodies.len(), 1, "exactly one function `{name}` is expected");
    bodies.remove(0)
}

/// Snake-case names of every function or method called in `code`.
pub(super) fn called_names(code: &str) -> BTreeSet<String> {
    let bytes = code.as_bytes();
    let mut out = BTreeSet::new();
    for open in 0..bytes.len() {
        if bytes[open] != b'(' {
            continue;
        }
        let mut start = open;
        while start > 0 && is_identifier_byte(bytes[start - 1]) {
            start -= 1;
        }
        let name = &code[start..open];
        let snake = name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte == b'_');
        if !snake || KEYWORDS.contains(&name) || code[..start].ends_with("fn ") {
            continue;
        }
        out.insert(name.to_owned());
    }
    out
}

/// Leading expression of every non-`VMError` argument given to `Err(`.
///
/// `Err(error)` and the patterns `Err(payload) =>` both count: the set pins
/// how many distinct stored or bound errors a region names.
pub(super) fn err_arguments(code: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for start in boundary_matches(code, "Err(") {
        let Some(close) = matching_close(code, start + 3) else {
            continue;
        };
        let argument = code[start + 4..close - 1].trim();
        if !argument.contains("VMError::") {
            out.insert(argument.to_owned());
        }
    }
    out
}

/// Whether the `VMError` path spanning `start..end` is matched or compared
/// rather than constructed.
///
/// A path is a pattern when the text after its payload and closing
/// parentheses begins a match arm, an or-pattern, a guard or a binding, or
/// when it sits in the pattern argument of `matches!`. It is a comparison
/// next to `==`/`!=` or inside an equality assertion. Anything else is a
/// construction, so an unrecognized shape is reported rather than hidden.
fn is_matched_not_constructed(code: &str, start: usize, end: usize) -> bool {
    let bytes = code.as_bytes();
    let mut index = skip_whitespace(bytes, end);
    if matches!(bytes.get(index), Some(b'(' | b'{')) {
        match matching_close(code, index) {
            Some(close) => index = close,
            None => return false,
        }
    }
    while index < bytes.len() && (bytes[index].is_ascii_whitespace() || bytes[index] == b')') {
        index += 1;
    }
    let rest = &code[index..];
    if rest.starts_with('=')
        || rest.starts_with("!=")
        || (rest.starts_with('|') && !rest.starts_with("||"))
        || rest.starts_with("if ")
        || rest.starts_with("if\n")
    {
        return true;
    }
    let mut depth = 0_usize;
    let mut cursor = start;
    while cursor > 0 {
        cursor -= 1;
        match bytes[cursor] {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' if depth > 0 => depth -= 1,
            b'{' => break,
            b'(' => {
                let head = &code[..cursor];
                let pattern_argument = head.ends_with("matches!") && {
                    let mut nesting = 0_usize;
                    code[cursor + 1..start].bytes().any(|byte| {
                        match byte {
                            b'(' | b'[' | b'{' => nesting += 1,
                            b')' | b']' | b'}' => nesting = nesting.saturating_sub(1),
                            _ => {}
                        }
                        byte == b',' && nesting == 0
                    })
                };
                let equality_assertion = ["assert_eq!", "assert_ne!"]
                    .iter()
                    .any(|name| head.ends_with(name));
                if pattern_argument || equality_assertion {
                    return true;
                }
            }
            b';' if depth == 0 => break,
            _ => {}
        }
    }
    // A comparison operand: the path, optionally qualified and wrapped in
    // constructor calls or a reference, directly follows `==` or `!=`.
    let path_text = |text: char| text.is_ascii_alphanumeric() || "_:".contains(text);
    let mut head = code[..start].trim_end_matches(path_text);
    while let Some(inner) = head.strip_suffix('(') {
        head = inner.trim_end_matches(path_text);
    }
    let head = head.trim_end().trim_end_matches('&').trim_end();
    head.ends_with("==") || head.ends_with("!=")
}

/// Byte ranges of the bodies of every `impl` block whose self type is
/// `VMError`, where `Self::` denotes the error type.
fn vm_error_impl_ranges(code: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for start in boundary_matches(code, "impl") {
        let Some(open) = code[start..].find('{').map(|offset| start + offset) else {
            continue;
        };
        let header = code[start..open].trim_end();
        let self_type = header.rsplit([' ', ':']).next().unwrap_or_default();
        if header.contains([';', '(', ')']) || self_type != "VMError" {
            continue;
        }
        if let Some(close) = matching_close(code, open) {
            out.push((open, close));
        }
    }
    out
}

/// Offset of the `use` keyword when the path at `start` is part of an import:
/// a `use` precedes it with nothing but path text in between.
fn import_use_start(code: &str, start: usize) -> Option<usize> {
    let statement_start = code[..start].rfind([';', '}']).map_or(0, |index| index + 1);
    let offset = boundary_matches(&code[statement_start..start], "use ").pop()?;
    let use_start = statement_start + offset;
    (!code[use_start + 4..start].contains(['(', ')', '='])).then_some(use_start)
}

/// Variants named by `use ...VMError::...;` imports, each with the byte range
/// of the scope the import is visible in.
fn variant_imports(code: &str, variants: &[&str]) -> Vec<(Vec<String>, (usize, usize))> {
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    for start in boundary_matches(code, "VMError::") {
        let Some(use_start) = import_use_start(code, start) else {
            continue;
        };
        let after = start + "VMError::".len();
        let statement_end = code[after..]
            .find(';')
            .map_or(code.len(), |index| after + index);
        let listed = &code[after..statement_end];
        let names: Vec<String> = if listed.trim_start().starts_with('*') {
            variants.iter().map(|name| (*name).to_owned()).collect()
        } else {
            listed
                .split(|byte: char| !(byte.is_ascii_alphanumeric() || byte == '_'))
                .filter(|name| variants.contains(name))
                .map(str::to_owned)
                .collect()
        };
        // The scope is the innermost block that contains the import, or the
        // rest of the file for a module-level import.
        let mut depth = 0_usize;
        let mut cursor = use_start;
        let mut scope_end = code.len();
        while cursor > 0 {
            cursor -= 1;
            match bytes[cursor] {
                b'}' => depth += 1,
                b'{' if depth > 0 => depth -= 1,
                b'{' => {
                    scope_end = matching_close(code, cursor).unwrap_or(code.len());
                    break;
                }
                _ => {}
            }
        }
        out.push((names, (statement_end.min(scope_end), scope_end)));
    }
    out
}

/// `VMError` variants that `code` constructs.
///
/// `code` must be non-test and comment-free. A variant counts when it is
/// built through `VMError::`, an alias of the type, `Self::` inside an
/// `impl` of the type, a bare name brought in by a `use` of its variants, or
/// one of the helper constructors. Match arms, `matches!` patterns,
/// comparisons and conversions of an existing error do not count. An unknown
/// lowercase associated function is reported as `helper:<name>` so a new
/// constructor cannot go unreviewed.
pub(super) fn constructed_vm_errors(code: &str, variants: &[&str]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut record = |prefix_start: usize, name_start: usize, trusted_prefix: bool| {
        let name = identifier_at(code, name_start);
        let Some(first) = name.bytes().next() else {
            return;
        };
        if first.is_ascii_lowercase() || first == b'_' {
            if let Some((_, built)) = HELPER_CONSTRUCTORS
                .iter()
                .find(|(helper, _)| *helper == name)
            {
                out.extend(built.iter().map(|variant| (*variant).to_owned()));
            } else if trusted_prefix && !CONVERSIONS.contains(&name) {
                out.insert(format!("helper:{name}"));
            }
            return;
        }
        if !trusted_prefix && !variants.contains(&name) {
            return;
        }
        if !is_matched_not_constructed(code, prefix_start, name_start + name.len()) {
            out.insert(name.to_owned());
        }
    };
    for start in boundary_matches(code, "VMError::") {
        if import_use_start(code, start).is_none() {
            record(start, start + "VMError::".len(), true);
        }
    }
    let mut aliases = BTreeSet::new();
    for start in boundary_matches(code, "VMError as ") {
        aliases.insert(identifier_at(code, start + "VMError as ".len()).to_owned());
    }
    for start in boundary_matches(code, "type ") {
        let alias = identifier_at(code, start + 5);
        let rest = code[start + 5 + alias.len()..].trim_start();
        let aliases_the_type = rest.strip_prefix('=').is_some_and(|target| {
            let target = target.split(';').next().unwrap_or_default().trim();
            target.rsplit("::").next() == Some("VMError")
        });
        if aliases_the_type {
            aliases.insert(alias.to_owned());
        }
    }
    for alias in aliases.iter().filter(|alias| !alias.is_empty()) {
        let prefix = format!("{alias}::");
        for start in boundary_matches(code, &prefix) {
            record(start, start + prefix.len(), false);
        }
    }
    for (open, close) in vm_error_impl_ranges(code) {
        for start in boundary_matches(&code[open..close], "Self::") {
            record(open + start, open + start + "Self::".len(), false);
        }
    }
    for (names, (from, to)) in variant_imports(code, variants) {
        for name in names {
            for start in boundary_matches(&code[from..to], &name) {
                let start = from + start;
                let end = start + name.len();
                let qualified = code[..start].ends_with("::") || code[..start].ends_with('.');
                let whole = !code
                    .as_bytes()
                    .get(end)
                    .copied()
                    .is_some_and(is_identifier_byte);
                if !qualified && whole && !is_matched_not_constructed(code, start, end) {
                    out.insert(name.clone());
                }
            }
        }
    }
    out
}

/// Variant identifiers of the enum introduced by `header`, in declaration order.
pub(super) fn enum_variants(text: &str, header: &str) -> Vec<String> {
    let start = text
        .find(&format!("{header} {{"))
        .unwrap_or_else(|| panic!("enum header `{header}` not found"));
    let mut depth = 0_i64;
    let mut variants = Vec::new();
    for line in text[start..].lines() {
        let trimmed = line.trim();
        if depth == 1
            && trimmed
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_uppercase())
        {
            variants.push(identifier_at(trimmed, 0).to_owned());
        }
        if !trimmed.starts_with("//") {
            depth += line.matches('{').count() as i64 - line.matches('}').count() as i64;
            if depth == 0 {
                break;
            }
        }
    }
    variants
}

/// Value of the integer literal constant `name` declared in `text`.
pub(super) fn const_literal(text: &str, name: &str) -> Option<u64> {
    let needle = format!("const {name}:");
    let start = text.find(&needle)? + needle.len();
    let rest = &text[start..];
    let value = &rest[rest.find('=')? + 1..rest.find(';')?];
    value.trim().replace('_', "").parse().ok()
}

/// `(module, NAME, value)` of every hexadecimal `u8` constant in the nested
/// modules of `ivm_abi::instruction::wide`.
pub(super) fn opcode_constants(text: &str) -> Vec<(String, String, u8)> {
    let mut module = String::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("pub mod ") {
            module = identifier_at(rest, 0).to_owned();
        } else if let Some(rest) = line.strip_prefix("pub const ") {
            let name = identifier_at(rest, 0);
            let Some(hex) = rest[name.len()..]
                .strip_prefix(": u8 = 0x")
                .and_then(|value| value.strip_suffix(';'))
            else {
                continue;
            };
            let value = u8::from_str_radix(hex, 16)
                .unwrap_or_else(|error| panic!("opcode constant {name}: {error}"));
            out.push((module.clone(), name.to_owned(), value));
        }
    }
    out
}

/// `(NAME, value)` of every `pub const SYSCALL_*: u32` constant.
pub(super) fn syscall_constants(text: &str) -> Vec<(String, u32)> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("pub const SYSCALL_")?;
            let name = identifier_at(rest, 0);
            let literal = rest[name.len()..]
                .strip_prefix(": u32 = ")?
                .strip_suffix(';')?
                .replace('_', "");
            let value = match literal.strip_prefix("0x") {
                Some(hex) => u32::from_str_radix(hex, 16),
                None => literal.parse(),
            }
            .unwrap_or_else(|error| panic!("syscall constant {name}: {error}"));
            Some((name.to_owned(), value))
        })
        .collect()
}

/// Collapse whitespace and join method chains split across lines.
fn flatten(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut skip_space = false;
    for character in body.chars() {
        if character.is_whitespace() {
            if !skip_space && !out.ends_with(' ') && !out.is_empty() {
                out.push(' ');
            }
            continue;
        }
        if character == '.' && out.ends_with(' ') {
            out.pop();
        }
        skip_space = character == '.';
        out.push(character);
    }
    out
}

/// Callee paths of every call whose result is propagated with `?`.
///
/// A leading `self.` is dropped and plain result adapters are ignored: their
/// error argument is a direct `VMError` token, which is tracked separately.
pub(super) fn fallible_calls(body: &str) -> BTreeSet<String> {
    let flat = flatten(body);
    let bytes = flat.as_bytes();
    let mut out = BTreeSet::new();
    for open in 0..bytes.len() {
        if bytes[open] != b'(' {
            continue;
        }
        let mut start = open;
        while start > 0
            && (is_identifier_byte(bytes[start - 1]) || matches!(bytes[start - 1], b'.' | b':'))
        {
            start -= 1;
        }
        let callee = &flat[start..open];
        let mut cursor = open + 1;
        let mut depth = 1;
        while cursor < bytes.len() && depth > 0 {
            match bytes[cursor] {
                b'"' => {
                    cursor += 1;
                    while cursor < bytes.len() && bytes[cursor] != b'"' {
                        if bytes[cursor] == b'\\' {
                            cursor += 1;
                        }
                        cursor += 1;
                    }
                }
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            cursor += 1;
        }
        while cursor < bytes.len() && bytes[cursor] == b' ' {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b'?' || callee.is_empty() {
            continue;
        }
        let last = callee.rsplit(['.', ':']).next().unwrap_or_default();
        let snake = last
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte == b'_')
            && last
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        if !snake || ADAPTERS.contains(&last) {
            continue;
        }
        let name = callee.strip_prefix("self.").unwrap_or(callee);
        out.insert(name.trim_start_matches('.').to_owned());
    }
    out
}

/// Fault surface of one contiguous region of interpreter source.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct RegionSurface {
    /// `VMError` variants named directly in the region.
    pub(super) direct_traps: BTreeSet<String>,
    /// Fallible helpers whose error the region propagates with `?`.
    pub(super) fallible_helpers: BTreeSet<String>,
    /// Snake-case names of every function or method the region calls.
    pub(super) calls: BTreeSet<String>,
    /// Non-`VMError` arguments the region gives to `Err(`.
    pub(super) err_arguments: BTreeSet<String>,
    /// The region's comment-free source text.
    pub(super) code: String,
}

/// Collect the fault surface of one region of comment-free source.
pub(super) fn region_surface(code: &str) -> RegionSurface {
    RegionSurface {
        direct_traps: tokens_after(code, "VMError::"),
        fallible_helpers: fallible_calls(code),
        calls: called_names(code),
        err_arguments: err_arguments(code),
        code: code.to_owned(),
    }
}

/// One arm of the interpreter's `match wide_op` dispatch.
pub(super) struct InterpreterArm {
    /// Opcode constant names selected by the arm; empty for the default arm.
    pub(super) names: Vec<String>,
    /// `VMError` variants constructed directly in the arm.
    pub(super) direct_traps: BTreeSet<String>,
    /// Fallible helpers whose error the arm propagates.
    pub(super) fallible_helpers: BTreeSet<String>,
    /// Privacy-tag accessors and privacy helpers the arm calls.
    pub(super) tag_surface: BTreeSet<String>,
    /// Snake-case names of every function or method the arm calls.
    pub(super) calls: BTreeSet<String>,
}

/// `IVM::run_with_host_ref` split into the regions before the loop, between
/// loop entry and dispatch, one record per dispatch arm, and after the loop.
pub(super) struct InterpreterDispatch {
    /// From function entry to the fetch-decode-execute loop.
    pub(super) entry: RegionSurface,
    /// Between loop entry and dispatch, executed before every step.
    pub(super) preamble: RegionSurface,
    /// Dispatch arms in source order, including the default arm.
    pub(super) arms: Vec<InterpreterArm>,
    /// From the end of the dispatch to the end of the function.
    pub(super) terminal: RegionSurface,
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Privacy-tag accessors and helpers of `helpers` that `code` calls.
pub(super) fn tag_surface(code: &str, helpers: &[&str]) -> BTreeSet<String> {
    let calls = called_names(code);
    let mut out: BTreeSet<String> = helpers
        .iter()
        .filter(|helper| calls.contains(**helper))
        .map(|helper| (*helper).to_owned())
        .collect();
    for (name, needle) in TAG_ACCESSORS {
        if code.contains(needle) {
            out.insert(name.to_owned());
        }
    }
    out
}

/// Names of the functions in `code` whose body touches a privacy marker.
pub(super) fn privacy_functions(code: &str) -> BTreeSet<String> {
    functions(code)
        .into_iter()
        .filter(|(_, body)| PRIVACY_MARKERS.iter().any(|marker| body.contains(marker)))
        .map(|(name, _)| name)
        .collect()
}

/// Parse `IVM::run_with_host_ref` from the comment-bearing, non-test text of
/// `crates/ivm/src/ivm.rs`. `helpers` names the privacy helpers recorded in
/// each arm's tag surface.
pub(super) fn interpreter_dispatch(text: &str, helpers: &[&str]) -> InterpreterDispatch {
    const RUN: &str = "fn run_with_host_ref(";
    let lines: Vec<&str> = text.lines().collect();
    let position = |needle: &str, exact: bool| {
        let found: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| {
                if exact {
                    line.trim() == needle
                } else {
                    line.contains(needle)
                }
            })
            .map(|(index, _)| index)
            .collect();
        assert_eq!(found.len(), 1, "exactly one `{needle}` line is expected");
        found[0]
    };
    let run_start = position(RUN, false);
    let loop_start = position(LOOP_MARKER, false);
    let dispatch = position(DISPATCH, true);
    assert!(
        run_start < loop_start && loop_start < dispatch,
        "the run function contains the loop marker and then the dispatch"
    );
    let run_indent = indent_of(lines[run_start]);
    let run_end = lines
        .iter()
        .enumerate()
        .skip(dispatch)
        .find(|(_, line)| indent_of(line) == run_indent && line.trim() == "}")
        .map(|(index, _)| index)
        .expect("end of the run function");
    let match_indent = indent_of(lines[dispatch]);
    let arm_indent = match_indent + 4;
    let mut arms: Vec<(String, String)> = Vec::new();
    let mut in_head = false;
    let mut dispatch_end = dispatch;
    for (offset, line) in lines[dispatch + 1..run_end].iter().enumerate() {
        if indent_of(line) == match_indent && line.trim_start().starts_with('}') {
            dispatch_end = dispatch + 1 + offset;
            break;
        }
        let trimmed = line.trim_start();
        let starts_arm = indent_of(line) == arm_indent
            && (trimmed.starts_with("instruction::wide::") || trimmed.starts_with("_ "));
        if starts_arm {
            arms.push((String::new(), String::new()));
            in_head = true;
        }
        let Some((head, body)) = arms.last_mut() else {
            continue;
        };
        if in_head {
            head.push_str(line);
            head.push('\n');
            in_head = !line.contains("=>");
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }
    assert!(dispatch_end > dispatch, "the dispatch match is closed");
    let region =
        |from: usize, to: usize| region_surface(&strip_line_comments(&lines[from..to].join("\n")));
    let arms = arms
        .into_iter()
        .map(|(head, body)| {
            let body = strip_line_comments(&body);
            let mut direct_traps = tokens_after(&head, "VMError::");
            direct_traps.extend(tokens_after(&body, "VMError::"));
            InterpreterArm {
                names: opcode_tokens(&head)
                    .into_iter()
                    .map(|(_, name)| name)
                    .collect(),
                direct_traps,
                fallible_helpers: fallible_calls(&body),
                tag_surface: tag_surface(&body, helpers),
                calls: called_names(&body),
            }
        })
        .collect();
    InterpreterDispatch {
        entry: region(run_start, loop_start),
        preamble: region(loop_start, dispatch),
        arms,
        terminal: region(dispatch_end + 1, run_end),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_test_source_drops_gated_declarations_functions_and_modules() {
        let text = "\
use a::b;
#[cfg(test)]
use super::{Role, wide};
fn kept() {}
#[cfg(test)]
fn dropped() -> u8 {
    wide::control::JAL
}
#[cfg(test)]
const DROPPED: usize = 3;
#[cfg(test)]
#[allow(dead_code)]
mod gated;
mod child;
#[cfg(test)]
mod tests {
    fn inner() { wide::memory::LOAD64; }
}
struct Holder {
    #[cfg(test)]
    counter: u64,
    kept: u8,
}
fn tail() {
    #[cfg(test)]
    COUNTER.with(|count| count.set(count.get() + 1));
    #[cfg(test)]
    {
        self.counter += 1;
    }
    #[cfg(test)]
    if REFUSE.with(|refuse| refuse.replace(false)) {
        return;
    }
    let holder = Holder {
        #[cfg(test)]
        counter: 0,
        kept: 1,
    };
}
";
        let kept = non_test_source(text);
        assert_eq!(
            kept,
            "use a::b;\nfn kept() {}\nmod child;\nstruct Holder {\n    kept: u8,\n}\n\
             fn tail() {\n    let holder = Holder {\n        kept: 1,\n    };\n}\n"
        );
        assert_eq!(child_modules(&kept), ["child"]);
    }

    #[test]
    fn token_scans_respect_identifier_boundaries() {
        let text = "wide::arithmetic::ADD | instruction::wide::control::JAL if x \
                    narrow_wide::zk::FADD VMError::OutOfGas MyVMError::Hidden wide::crypto::tests";
        assert_eq!(
            opcode_tokens(text).into_iter().collect::<Vec<_>>(),
            [
                ("arithmetic".to_owned(), "ADD".to_owned()),
                ("control".to_owned(), "JAL".to_owned()),
            ]
        );
        let errors = tokens_after(text, "VMError::");
        assert!(errors.contains("OutOfGas"));
        assert!(!errors.contains("Hidden"));
        assert!(!errors.contains("OutOf"));
        assert_eq!(boundary_matches(text, "VMError::").len(), 1);
    }

    #[test]
    fn enum_variants_skip_fields_docs_and_attributes() {
        let text = "\
/// Docs.
pub enum Sample {
    /// First.
    Unit,
    Tuple(u8),
    Struct {
        /// Field docs Start with uppercase.
        Field: u8,
    },
    #[allow(dead_code)]
    Tagged = 4,
}
pub enum Other { Hidden }
";
        assert_eq!(
            enum_variants(text, "pub enum Sample"),
            ["Unit", "Tuple", "Struct", "Tagged"]
        );
    }

    #[test]
    fn constants_parse_decimal_hex_and_underscores() {
        let text = "\
pub mod wide {
    pub mod arithmetic {
        pub const ADD: u8 = 0x01;
        pub const WIDTH: usize = 6;
        pub const LIMIT: u8 = u8::MAX - 1;
    }
}
pub const SYSCALL_EXIT: u32 = 0x01;
pub const SYSCALL_JSON_BUILD: u32 = 0x01_004E;
pub(super) const PACKET_SLOTS: usize = 16_384;
";
        assert_eq!(
            opcode_constants(text),
            [("arithmetic".to_owned(), "ADD".to_owned(), 1)]
        );
        assert_eq!(
            syscall_constants(text),
            [("EXIT".to_owned(), 1), ("JSON_BUILD".to_owned(), 0x01_004E)]
        );
        assert_eq!(const_literal(text, "PACKET_SLOTS"), Some(16_384));
        assert_eq!(const_literal(text, "WIDTH"), Some(6));
        assert_eq!(const_literal(text, "LIMIT"), None);
        assert_eq!(const_literal(text, "MISSING"), None);
    }

    #[test]
    fn fallible_calls_report_propagated_helpers_and_skip_adapters() {
        let body = "\
let tag = self.zk_match_tags(rs1, rs2)?;
let value = self
    .memory
    .load_u64(address)?;
let literal = table.get(index).copied().ok_or(VMError::InvalidMetadata)?;
let count = u64::try_from(len).map_err(|_| VMError::GasCostOverflow)?;
let quotient = checked_div_i64(num, denom)?;
self.registers.set(rd, value);
eprintln!(\"unbalanced ( in a string\");
self.finish_call()?;
";
        assert_eq!(
            fallible_calls(body).into_iter().collect::<Vec<_>>(),
            [
                "checked_div_i64",
                "finish_call",
                "memory.load_u64",
                "zk_match_tags"
            ]
        );
    }

    #[test]
    fn interpreter_dispatch_splits_entry_preamble_arms_and_terminal() {
        let text = "\
impl IVM {
    fn run_with_host_ref(&mut self) -> Result<(), VMError> {
        self.prepare_log()?;
        if stale { return Err(VMError::PrivacyViolation); }
        self.begin_root_call(host)?;
        // Fetch-Decode-Execute loop
        loop {
            if done { return Err(VMError::MissingHalt); }
            let fetched = self.fetch_instruction()?;
            match wide_op {
                instruction::wide::arithmetic::ADD => {
                    // VMError::OutOfMemory in prose is not a trap.
                    let tag = self.zk_match_tags(a, b)?;
                    self.zk_apply_tag(rd, tag);
                    continue;
                }
                instruction::wide::control::BEQ => {
                    if self.registers.tag(rs1) { return Err(VMError::PrivacyViolation); }
                    continue;
                }
                instruction::wide::crypto::PARBEGIN | instruction::wide::crypto::PAREND => {
                    continue;
                }
                _ => {
                    return Err(VMError::InvalidOpcode(0));
                }
            }
        }
        if short { return Err(VMError::OutOfGas); }
        if let Some(error) = self.contract_abort_error.clone() {
            Err(error.into_vm_error())
        } else {
            self.call_result_word_count()?;
            budget.ensure_healthy()
        }
    }
    fn later(&self) {
        let _ = VMError::DecodeError;
    }
}
";
        let helpers = ["zk_match_tags", "zk_apply_tag"];
        let dispatch = interpreter_dispatch(text, &helpers);
        let set = |values: &[&str]| -> BTreeSet<String> {
            values.iter().map(|value| (*value).to_owned()).collect()
        };
        assert_eq!(dispatch.entry.direct_traps, set(&["PrivacyViolation"]));
        assert_eq!(
            dispatch.entry.fallible_helpers,
            set(&["begin_root_call", "prepare_log"])
        );
        assert_eq!(dispatch.preamble.direct_traps, set(&["MissingHalt"]));
        assert_eq!(
            dispatch.preamble.fallible_helpers,
            set(&["fetch_instruction"])
        );
        assert_eq!(dispatch.arms.len(), 4);
        assert_eq!(dispatch.arms[0].names, ["ADD"]);
        assert!(dispatch.arms[0].direct_traps.is_empty());
        assert_eq!(dispatch.arms[0].fallible_helpers, set(&["zk_match_tags"]));
        assert_eq!(
            dispatch.arms[0].tag_surface,
            set(&["zk_apply_tag", "zk_match_tags"])
        );
        assert!(dispatch.arms[0].calls.contains("zk_apply_tag"));
        assert_eq!(dispatch.arms[1].tag_surface, set(&["tag"]));
        assert_eq!(dispatch.arms[2].names, ["PARBEGIN", "PAREND"]);
        assert!(dispatch.arms[2].tag_surface.is_empty());
        assert!(dispatch.arms[3].names.is_empty());
        assert_eq!(dispatch.arms[3].direct_traps, set(&["InvalidOpcode"]));
        assert_eq!(dispatch.terminal.direct_traps, set(&["OutOfGas"]));
        assert_eq!(
            dispatch.terminal.fallible_helpers,
            set(&["call_result_word_count"])
        );
        assert_eq!(
            dispatch.terminal.calls,
            set(&[
                "call_result_word_count",
                "clone",
                "ensure_healthy",
                "into_vm_error"
            ])
        );
        assert_eq!(
            dispatch.terminal.err_arguments,
            set(&["error.into_vm_error()"])
        );
    }

    #[test]
    fn comment_stripping_keeps_code_and_string_slashes() {
        let text = "\
let a = 1; // VMError::OutOfGas
/// Returns [`VMError::DecodeError`].
let url = \"http://example\"; // trailing
let quote = '\"'; // after a quote character
";
        assert_eq!(
            strip_line_comments(text),
            "let a = 1; \n\nlet url = \"http://example\"; \nlet quote = '\"'; \n"
        );
    }

    #[test]
    fn functions_and_calls_are_extracted_with_balanced_bodies() {
        let code = "\
trait Host { fn declared(&self) -> u8; }
impl Vm {
    fn first(&self, close: char) -> bool {
        let text = \"} not a brace\";
        close == '}' && self.second(text)
    }
    fn second<T: Into<u64>>(&self, value: [u8; 2]) -> Result<(), VMError>
    where
        T: Copy,
    {
        if (value[0]) > 0 { helper(value)?; }
        Some(1).map(wrap);
        log!(\"skipped\");
        Ok(())
    }
}
";
        let found = functions(code);
        assert_eq!(
            found
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert!(found[0].1.starts_with('{') && found[0].1.ends_with('}'));
        assert!(found[0].1.contains("self.second(text)"));
        assert!(!found[0].1.contains("helper"));
        assert_eq!(function_body(code, "second"), found[1].1);
        assert_eq!(
            called_names(&found[1].1).into_iter().collect::<Vec<_>>(),
            ["helper", "map"]
        );
        assert_eq!(matching_close("(a[b]{c})d", 0), Some(9));
        assert_eq!(matching_close("(unclosed", 0), None);
        assert_eq!(matching_close(")", 0), None);
    }

    #[test]
    #[should_panic(expected = "exactly one function `missing`")]
    fn function_body_requires_a_single_definition() {
        let _ = function_body("fn present() {}", "missing");
    }

    #[test]
    fn err_arguments_report_stored_and_bound_errors() {
        let code = "\
if short { return Err(VMError::OutOfGas); }
match outcome { Err(payload) => resume(payload), Ok(value) => value }
Err(self.stored.clone())
";
        assert_eq!(
            err_arguments(code).into_iter().collect::<Vec<_>>(),
            ["payload", "self.stored.clone()"]
        );
    }

    #[test]
    fn constructions_exclude_patterns_comparisons_and_conversions() {
        const VARIANTS: [&str; 8] = [
            "OutOfGas",
            "OutOfMemory",
            "DecodeError",
            "Metered",
            "NotImplemented",
            "NoritoInvalid",
            "PermissionDenied",
            "InvalidOpcode",
        ];
        let constructed = |code: &str| -> Vec<String> {
            constructed_vm_errors(code, &VARIANTS).into_iter().collect()
        };
        // Constructions in every expression position.
        assert_eq!(
            constructed(
                "return Err(VMError::OutOfGas);\n\
                 let e = x.ok_or(VMError::DecodeError)?;\n\
                 y.map_err(|_| crate::VMError::NoritoInvalid)?;\n\
                 z.map_err(VMError::InvalidOpcode);\n\
                 if c { VMError::PermissionDenied } else { other }\n"
            ),
            [
                "DecodeError",
                "InvalidOpcode",
                "NoritoInvalid",
                "OutOfGas",
                "PermissionDenied"
            ]
        );
        // Match arms, or-patterns, guards, bindings and `matches!` patterns.
        assert!(
            constructed(
                "match e {\n\
                     VMError::OutOfGas | VMError::OutOfMemory => 1,\n\
                     Err(VMError::Metered { gas, source }) if gas > 0 => 2,\n\
                     VMError::InvalidOpcode(op) => 3,\n\
                 }\n\
                 if let Err(VMError::DecodeError) = result {}\n\
                 let ok = matches!(result, Err(VMError::NoritoInvalid));\n\
                 let VMError::Metered { gas, .. } = wrapped else { return };\n"
            )
            .is_empty()
        );
        // Comparisons and equality assertions.
        assert!(
            constructed(
                "if result == Err(VMError::OutOfGas) {}\n\
                 if error != &VMError::DecodeError {}\n\
                 if error == ivm::VMError::NoritoInvalid { return; }\n\
                 assert_eq!(run(), Err(VMError::PermissionDenied));\n"
            )
            .is_empty()
        );
        // A construction in the scrutinee of `matches!` or after a boolean
        // operator is still a construction.
        assert_eq!(
            constructed(
                "let a = matches!(wrap(VMError::OutOfGas), Wrapped(_));\n\
                 let b = left == right && check(VMError::DecodeError);\n\
                 Err(VMError::NoritoInvalid) => return Err(VMError::PermissionDenied),\n"
            ),
            ["DecodeError", "OutOfGas", "PermissionDenied"]
        );
        // Helper constructors, conversions and unknown helpers.
        assert_eq!(
            constructed(
                "return Err(VMError::metered(gas, error));\n\
                 return Err(VMError::metered_not_implemented(gas, number));\n\
                 let converted = VMError::from(fault);\n\
                 let unknown = VMError::brand_new(1);\n"
            ),
            ["Metered", "NotImplemented", "helper:brand_new"]
        );
        // An unknown variant behind the type's own path is still reported.
        assert_eq!(constructed("Err(VMError::BrandNew)"), ["BrandNew"]);
    }

    #[test]
    fn constructions_follow_aliases_self_and_imported_variants() {
        const VARIANTS: [&str; 4] = ["OutOfGas", "DecodeError", "Metered", "NotImplemented"];
        let constructed = |code: &str| -> Vec<String> {
            constructed_vm_errors(code, &VARIANTS).into_iter().collect()
        };
        assert_eq!(
            constructed(
                "use ivm::{VMError as IvmError, Other};\n\
                 fn f() -> IvmError { IvmError::OutOfGas }\n\
                 fn g(e: &IvmError) -> bool { matches!(e, IvmError::DecodeError) }\n"
            ),
            ["OutOfGas"]
        );
        assert_eq!(
            constructed(
                "impl TryFrom<u8> for Kind {\n\
                     type Error = VMError;\n\
                     fn try_from(v: u8) -> Result<Self, Self::Error> { Err(Error::DecodeError) }\n\
                 }\n"
            ),
            ["DecodeError"]
        );
        assert_eq!(
            constructed(
                "impl VMError {\n\
                     pub fn not_implemented(gas: u64) -> Self {\n\
                         Self::metered(gas, Self::NotImplemented { syscall: 0 })\n\
                     }\n\
                     pub fn deferral(&self) -> bool {\n\
                         match self { Self::OutOfGas => false, _ => true }\n\
                     }\n\
                 }\n\
                 impl Other { fn f() -> Self { Self::DecodeError } }\n\
                 fn g(x: impl Into<u8>) -> VMError { Kind::OutOfGas.into() }\n"
            ),
            ["Metered", "NotImplemented"]
        );
        // A glob import makes bare names constructions inside its scope only.
        assert_eq!(
            constructed(
                "fn reason(error: &VMError) -> u8 {\n\
                     use ivm::VMError::*;\n\
                     match error { OutOfGas => 1, Metered { .. } | DecodeError => 2, _ => 3 }\n\
                 }\n\
                 fn build() -> Kind { Kind::DecodeError }\n\
                 fn bare() -> u8 { let DecodeError = 1; DecodeError }\n"
            ),
            Vec::<String>::new()
        );
        assert!(constructed("use ivm::VMError::DecodeError;\nfn f() {}\n").is_empty());
        assert_eq!(
            constructed(
                "use ivm::VMError::{DecodeError, OutOfGas};\n\
                 fn build(short: bool) -> VMError {\n\
                     if short { OutOfGas } else { DecodeError }\n\
                 }\n\
                 fn other() -> Trap { VmTrapKind::OutOfGas }\n"
            ),
            ["DecodeError", "OutOfGas"]
        );
    }

    #[test]
    fn tag_surface_names_accessors_and_listed_helpers() {
        let helpers = ["zk_match_tags", "ensure_public_memory"];
        let body = "\
if self.registers.tag(rs) { return Err(VMError::PrivacyViolation); }
self.registers.set_tag(rd, false);
self.ensure_public_memory(addr, 8)?;
self.unlisted_helper();
";
        assert_eq!(
            tag_surface(body, &helpers).into_iter().collect::<Vec<_>>(),
            ["ensure_public_memory", "set_tag", "tag"]
        );
        assert!(tag_surface("self.pc = self.pc.wrapping_add(4);", &helpers).is_empty());
        let code = "\
fn reads(&self) -> bool { self.registers.tag(1) }
fn traps() -> VMError { VMError::PrivacyViolation }
fn plain(&self) -> u64 { self.pc }
";
        assert_eq!(
            privacy_functions(code).into_iter().collect::<Vec<_>>(),
            ["reads", "traps"]
        );
        let surface = region_surface("let x = self.load(a)?; return Err(VMError::OutOfGas);");
        assert_eq!(surface.direct_traps.len(), 1);
        assert!(surface.fallible_helpers.contains("load"));
        assert!(surface.calls.contains("load"));
        assert!(surface.err_arguments.is_empty());
        assert!(surface.code.contains("self.load(a)"));
    }

    #[test]
    fn module_walk_finds_this_module_tree() {
        let files = module_files("crates/ivm/src/proof_coverage.rs");
        assert!(files.contains(&"crates/ivm/src/proof_coverage/opcodes.rs".to_owned()));
        assert!(!files.contains(&"crates/ivm/src/proof_coverage/tests.rs".to_owned()));
        assert!(!files.contains(&"crates/ivm/src/proof_coverage/source_scan.rs".to_owned()));
        let all = rust_files("crates/ivm/src/proof_coverage");
        assert!(all.contains(&"crates/ivm/src/proof_coverage/tests.rs".to_owned()));
    }
}
