//! Reader of the generated vector files under `tests/vectors/`.
//!
//! A file is `key = value` lines grouped under `[section]` headers. Word
//! lists are concatenated 16-digit hexadecimal words, most significant digit
//! first; lists of numbers are comma-separated decimals. [`Kat::load`] reads
//! `bgv_kat_v1.txt`, the output of the Python reference; [`Kat::parse`] reads
//! any file of the same grammar.
use num_bigint::BigInt;
use std::collections::BTreeMap;

/// The generated file, embedded at compile time.
const KAT_TEXT: &str = include_str!("../vectors/bgv_kat_v1.txt");

/// All sections of the known-answer file.
pub struct Kat {
    sections: BTreeMap<String, BTreeMap<String, String>>,
}

/// One section of the known-answer file.
pub struct Section<'kat> {
    name: &'kat str,
    values: &'kat BTreeMap<String, String>,
}

impl Kat {
    /// Parse the embedded known-answer file of the Python reference.
    pub fn load() -> Self {
        Self::parse(KAT_TEXT)
    }

    /// Parse a file of `[section]` headers and `key = value` lines.
    pub fn parse(text: &str) -> Self {
        let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut current = String::new();
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            {
                name.clone_into(&mut current);
                assert!(
                    sections.insert(current.clone(), BTreeMap::new()).is_none(),
                    "duplicate section {current}"
                );
                continue;
            }
            let (key, value) = line.split_once(" = ").expect("key = value");
            let previous = sections
                .get_mut(&current)
                .expect("a section header precedes every value")
                .insert(key.to_owned(), value.to_owned());
            assert!(previous.is_none(), "duplicate key {key} in {current}");
        }
        Self { sections }
    }

    /// The names of every section, sorted.
    pub fn section_names(&self) -> Vec<&str> {
        self.sections.keys().map(String::as_str).collect()
    }

    /// The section called `name`.
    pub fn section<'kat>(&'kat self, name: &'kat str) -> Section<'kat> {
        Section {
            name,
            values: self
                .sections
                .get(name)
                .unwrap_or_else(|| panic!("missing section {name}")),
        }
    }
}

impl Section<'_> {
    /// The keys of the section, sorted.
    pub fn keys(&self) -> Vec<&str> {
        self.values.keys().map(String::as_str).collect()
    }

    /// The raw value of `key`.
    pub fn text(&self, key: &str) -> &str {
        self.values
            .get(key)
            .unwrap_or_else(|| panic!("missing {key} in {}", self.name))
    }

    /// A list of 64-bit words.
    pub fn words(&self, key: &str) -> Vec<u64> {
        let text = self.text(key);
        assert!(text.len().is_multiple_of(16), "{key}: partial word");
        (0..text.len() / 16)
            .map(|index| {
                u64::from_str_radix(&text[16 * index..16 * index + 16], 16).expect("hexadecimal")
            })
            .collect()
    }

    /// Bytes written as hexadecimal.
    pub fn bytes(&self, key: &str) -> Vec<u8> {
        let text = self.text(key);
        assert!(text.len().is_multiple_of(2), "{key}: partial byte");
        (0..text.len() / 2)
            .map(|index| u8::from_str_radix(&text[2 * index..2 * index + 2], 16).expect("hex"))
            .collect()
    }

    /// One unsigned number.
    pub fn number(&self, key: &str) -> u64 {
        self.text(key).parse().expect("decimal")
    }

    /// A list of unsigned numbers.
    pub fn numbers(&self, key: &str) -> Vec<u64> {
        self.text(key)
            .split(',')
            .map(|item| item.parse().expect("decimal"))
            .collect()
    }

    /// A list of signed numbers.
    pub fn signed(&self, key: &str) -> Vec<i64> {
        self.text(key)
            .split(',')
            .map(|item| item.parse().expect("decimal"))
            .collect()
    }

    /// One integer of any size.
    pub fn integer(&self, key: &str) -> BigInt {
        self.text(key).parse().expect("decimal integer")
    }

    /// A list of integers of any size.
    pub fn integers(&self, key: &str) -> Vec<BigInt> {
        self.text(key)
            .split(',')
            .map(|item| item.parse().expect("decimal integer"))
            .collect()
    }
}
