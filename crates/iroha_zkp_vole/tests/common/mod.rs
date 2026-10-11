//! Loader for the line-oriented FAEST reference-vector fixtures.
//!
//! Each fixture line is `name = value`, where the value is lowercase hex (a byte
//! array), a bracketed list of decimals (a `u16` array) or a decimal integer. Lines
//! starting with `#` are comments. See `tests/fixtures/faest_v3_0_2/README.md`.

// Each integration test binary uses its own subset of these helpers.
#![allow(dead_code)]

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

/// Names of all fixture files, without the `.txt` extension.
pub const FIXTURE_FILES: [&str; 8] = [
    "bavc_tvs",
    "crt_vole_commit_tvs",
    "faest_tvs",
    "field_tvs",
    "owf_tvs",
    "prg_tvs",
    "universal_hashing_tvs",
    "vole_tvs",
];

/// One parsed fixture file.
pub struct Fixture {
    file: String,
    entries: BTreeMap<String, String>,
    order: Vec<String>,
    consumed: RefCell<BTreeSet<String>>,
}

impl Fixture {
    /// Load `tests/fixtures/faest_v3_0_2/<file>.txt`.
    ///
    /// # Panics
    /// Panics if the file is missing or a line is malformed or repeats a name.
    pub fn load(file: &str) -> Self {
        Self::load_from("faest_v3_0_2", file)
    }

    /// Load the known-answer values read from the upstream test sources,
    /// `tests/fixtures/faest_v3_0_2_extracted/upstream_test_kats.txt`.
    ///
    /// # Panics
    /// As [`Self::load`].
    pub fn load_extracted() -> Self {
        Self::load_from("faest_v3_0_2_extracted", "upstream_test_kats")
    }

    /// Load `tests/fixtures/<directory>/<file>.txt`.
    ///
    /// # Panics
    /// Panics if the file is missing or a line is malformed or repeats a name.
    pub fn load_from(directory: &str, file: &str) -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(directory)
            .join(format!("{file}.txt"));
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read fixture {}: {error}", path.display()));
        let mut entries = BTreeMap::new();
        let mut order = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = line
                .split_once(" =")
                .unwrap_or_else(|| panic!("{file}.txt:{}: expected `name = value`", index + 1));
            let value = value.trim_start_matches(' ');
            assert!(
                entries.insert(name.to_owned(), value.to_owned()).is_none(),
                "{file}.txt:{}: duplicate name `{name}`",
                index + 1
            );
            order.push(name.to_owned());
        }
        Self {
            file: file.to_owned(),
            entries,
            order,
            consumed: RefCell::new(BTreeSet::new()),
        }
    }

    /// Entry names in upstream declaration order.
    pub fn names(&self) -> &[String] {
        &self.order
    }

    fn raw(&self, name: &str) -> &str {
        let value = self
            .entries
            .get(name)
            .unwrap_or_else(|| panic!("fixture {}.txt has no entry named `{name}`", self.file));
        self.consumed.borrow_mut().insert(name.to_owned());
        value
    }

    /// Assert that every entry whose name starts with `prefix` has been read through
    /// [`Self::bytes`], [`Self::integer`] or [`Self::u16_list`].
    ///
    /// # Panics
    /// Panics naming the entries that were never read.
    pub fn assert_consumed(&self, prefix: &str) {
        let consumed = self.consumed.borrow();
        let unread: Vec<&String> = self
            .order
            .iter()
            .filter(|name| name.starts_with(prefix) && !consumed.contains(*name))
            .collect();
        assert!(
            unread.is_empty(),
            "fixture {}.txt entries never read: {unread:?}",
            self.file
        );
    }

    /// The byte array stored under `name`.
    ///
    /// # Panics
    /// Panics if the name is missing or the value is not an even-length hex string.
    pub fn bytes(&self, name: &str) -> Vec<u8> {
        let raw = self.raw(name);
        assert!(
            raw.len().is_multiple_of(2)
                && raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "fixture {}.txt entry `{name}` is not a lowercase hex byte string",
            self.file
        );
        raw.as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_digit(pair[0]) << 4) | hex_digit(pair[1]))
            .collect()
    }

    /// The decimal integer stored under `name`.
    ///
    /// # Panics
    /// Panics if the name is missing or the value is not a decimal integer.
    pub fn integer(&self, name: &str) -> u64 {
        let raw = self.raw(name);
        assert!(
            !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()),
            "fixture {}.txt entry `{name}` is not a decimal integer",
            self.file
        );
        raw.parse().unwrap_or_else(|error| {
            panic!(
                "fixture {}.txt entry `{name}` is out of range: {error}",
                self.file
            )
        })
    }

    /// The `u16` array stored under `name` as `[d,d,...]`.
    ///
    /// # Panics
    /// Panics if the name is missing or the value is not a bracketed decimal list.
    pub fn u16_list(&self, name: &str) -> Vec<u16> {
        let raw = self.raw(name);
        let inner = raw
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or_else(|| {
                panic!(
                    "fixture {}.txt entry `{name}` is not a bracketed list",
                    self.file
                )
            });
        if inner.is_empty() {
            return Vec::new();
        }
        inner
            .split(',')
            .map(|item| {
                item.parse().unwrap_or_else(|error| {
                    panic!(
                        "fixture {}.txt entry `{name}` has a bad element `{item}`: {error}",
                        self.file
                    )
                })
            })
            .collect()
    }
}

fn hex_digit(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => unreachable!("validated by the caller"),
    }
}

/// SHAKE256 of `data` squeezed to 64 bytes: the digest the upstream generators
/// (`hash_array` in `tests/test_utils.cpp`) publish in place of large buffers, used
/// by every `hashed_*` fixture entry.
pub fn hash_array(data: &[u8]) -> [u8; 64] {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut sponge = sha3::Shake256::default();
    sponge.update(data);
    let mut digest = [0u8; 64];
    sponge.finalize_xof().read(&mut digest);
    digest
}
