//! Test-only refusal oracle over the sole ordinary writer and original borrowed graph.

use norito::json::{BoundedJsonError, JsonSerialize, JsonWriteSink};

pub const ORIGINAL_DEPTH: usize = 7;
pub struct OriginalSink {
    pub text: String,
    pub depth: usize,
    cap: usize,
    deny_entry: Option<usize>,
    entries: usize,
}
impl OriginalSink {
    pub fn new(cap: usize) -> Self {
        Self {
            text: String::new(),
            depth: ORIGINAL_DEPTH,
            cap,
            deny_entry: None,
            entries: 0,
        }
    }
}
impl JsonWriteSink for OriginalSink {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        self.push_str(value.encode_utf8(&mut [0; 4]))
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        if self
            .text
            .len()
            .checked_add(value.len())
            .is_none_or(|len| len > self.cap)
        {
            return Err(BoundedJsonError::BodyTooLarge);
        }
        self.text.push_str(value);
        Ok(())
    }
    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        self.entries += 1;
        if self.deny_entry == Some(self.entries) {
            return Err(BoundedJsonError::Unsupported);
        }
        self.depth += 1;
        Ok(())
    }
    fn end_container(&mut self) {
        assert!(
            self.depth > ORIGINAL_DEPTH,
            "writer cannot release inherited caller depth"
        );
        self.depth -= 1;
    }
}
/// Retain exact bytes/errors/depth on every byte cap and every actual entry refusal.
pub fn audit_write(
    ordinary: &str,
    write: impl Fn(&mut dyn JsonWriteSink) -> Result<(), BoundedJsonError>,
) {
    for cap in 0..ordinary.len() {
        let mut sink = OriginalSink::new(cap);
        assert_eq!(
            write(&mut sink),
            Err(BoundedJsonError::BodyTooLarge),
            "exact byte refusal at {cap}"
        );
        assert_eq!(
            sink.depth, ORIGINAL_DEPTH,
            "original inherited depth at byte cap {cap}"
        );
        assert!(
            ordinary.starts_with(&sink.text),
            "unchanged canonical prefix at {cap}"
        );
    }
    let mut sink = OriginalSink::new(ordinary.len());
    assert_eq!(write(&mut sink), Ok(()));
    assert_eq!(sink.text, ordinary);
    assert_eq!(sink.depth, ORIGINAL_DEPTH);
    for denied in 1..=sink.entries {
        let mut refused = OriginalSink::new(usize::MAX);
        refused.deny_entry = Some(denied);
        assert_eq!(
            write(&mut refused),
            Err(BoundedJsonError::Unsupported),
            "actual entry {denied}"
        );
        assert_eq!(
            refused.depth, ORIGINAL_DEPTH,
            "every entered level must release on child admission refusal {denied}"
        );
        assert!(ordinary.starts_with(&refused.text));
    }
    // Retry the same borrowed graph with a fresh test sink; no decode or copied source.
    let mut retry = OriginalSink::new(ordinary.len());
    assert_eq!(write(&mut retry), Ok(()));
    assert_eq!(retry.text, ordinary);
    assert_eq!(retry.depth, ORIGINAL_DEPTH);
}
/// Observe the same owning object via ordinary and checked canonical writers.
pub fn audit<T: JsonSerialize + ?Sized>(value: &T) {
    let original = std::ptr::from_ref(value);
    let mut ordinary = String::new();
    value.json_serialize(&mut ordinary);
    audit_write(&ordinary, |out| value.json_serialize_to(out));
    assert!(std::ptr::eq(std::ptr::from_ref(value), original));
}
/// Fixture authority seeded before any alias or domain context.
pub fn account(seed: u8) -> crate::account::AccountId {
    let key = iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519);
    crate::account::AccountId::new(key.public_key().clone())
}
/// Canonical inline definition used only to construct original test objects.
pub fn definition() -> crate::asset::AssetDefinitionId {
    crate::asset::AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::try_new("cleanup", "test").unwrap(),
        "xor".parse().unwrap(),
    )
}
/// Original authority asset for instruction writer controls.
pub fn asset() -> crate::asset::AssetId {
    crate::asset::AssetId::new(definition(), account(61))
}

/// Manual leaf has neither `FastJsonWrite` nor `Clone`; its exact refusal must propagate.
#[derive(Debug)]
pub struct RefusingLeaf(pub std::cell::Cell<usize>);
impl JsonSerialize for RefusingLeaf {
    fn json_serialize(&self, out: &mut String) {
        out.push_str("null");
    }
    fn json_serialize_to(&self, _out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        self.0.set(self.0.get() + 1);
        Err(BoundedJsonError::Unsupported)
    }
}
/// Inspect the original inherited depth after the exact manual leaf error.
pub fn audit_leaf_refusal(
    expected_prefix: &str,
    write: impl FnOnce(&mut dyn JsonWriteSink) -> Result<(), BoundedJsonError>,
) {
    let mut sink = OriginalSink::new(usize::MAX);
    assert_eq!(write(&mut sink), Err(BoundedJsonError::Unsupported));
    assert_eq!(sink.depth, ORIGINAL_DEPTH);
    assert_eq!(sink.text, expected_prefix);
}
