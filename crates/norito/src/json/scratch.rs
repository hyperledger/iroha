//! Allocation destinations for one shared typed JSON grammar.
//!
//! These helpers own only temporary decoded string/key bytes. They do not admit
//! source documents, records, retained graphs or authenticated State authority.

use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};

use super::{Error, KeyRef, MapVisitor, Parser};

/// An original parser/decoder refusal or exact original-pool scratch refusal.
#[derive(Debug, thiserror::Error)]
pub enum ScratchAdmissionError {
    /// Original JSON error, including any live cumulative-decoder observer.
    #[error(transparent)]
    Json(#[from] Error),
    /// Original finite-pool or native allocator refusal.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
}

/// Temporary string/key storage selected by a typed record's caller.
///
/// The parser owns all lexical work and logical allocation accounting. A
/// destination only chooses the physical text backing; typed owners retain one
/// record relation for ordinary and original-pool reads.
pub trait ScratchDestination {
    /// Original syntax/resource error together with destination refusal.
    type Error: From<Error>;
    /// Decoded UTF-8 temporary backing.
    type Text: AsRef<str>;
    /// Read one key using the same map delimiter and escape state.
    /// # Errors
    /// Preserves the original parser and destination refusal.
    fn key<'a>(
        &self,
        object: &mut MapVisitor<'a, '_>,
    ) -> Result<Option<KeyRef<'a, Self::Text>>, Self::Error>;
    /// Read one string into temporary storage.
    /// # Errors
    /// Preserves the original parser and destination refusal.
    fn string(&self, parser: &mut Parser<'_>) -> Result<Self::Text, Self::Error>;
}

/// Ordinary authoring/input destination, retaining cumulative decoder limits.
pub struct OrdinaryScratch;
impl ScratchDestination for OrdinaryScratch {
    type Error = Error;
    type Text = String;
    fn key<'a>(&self, object: &mut MapVisitor<'a, '_>) -> Result<Option<KeyRef<'a>>, Error> {
        object.next_key()
    }
    fn string(&self, parser: &mut Parser<'_>) -> Result<String, Error> {
        parser.parse_string()
    }
}

/// Exact temporary UTF-8 backing whose physical storage outlives its charge.
pub struct AdmittedText(ChargedBuffer<u8>);
impl AsMut<[u8]> for AdmittedText {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}
impl AsRef<str> for AdmittedText {
    fn as_ref(&self) -> &str {
        std::str::from_utf8(self.0.as_slice()).expect("the shared parser emits UTF-8")
    }
}

/// Temporary strings/escaped keys funded by the caller's exact original pool.
pub struct AdmittedScratch<'a> {
    budget: &'a AllocationBudget,
}
impl<'a> AdmittedScratch<'a> {
    /// Select the original pool without reserving or allocating a control shell.
    pub const fn new(budget: &'a AllocationBudget) -> Self {
        Self { budget }
    }
    fn text(&self, length: usize) -> Result<AdmittedText, ScratchAdmissionError> {
        let mut bytes = ChargedBuffer::new(length, self.budget)?;
        for _ in 0..length {
            bytes.push_reserved(0);
        }
        Ok(AdmittedText(bytes))
    }
}
impl ScratchDestination for AdmittedScratch<'_> {
    type Error = ScratchAdmissionError;
    type Text = AdmittedText;
    fn key<'a>(
        &self,
        object: &mut MapVisitor<'a, '_>,
    ) -> Result<Option<KeyRef<'a, AdmittedText>>, Self::Error> {
        object.next_key_with_buffer(|length| self.text(length))
    }
    fn string(&self, parser: &mut Parser<'_>) -> Result<AdmittedText, Self::Error> {
        parser.parse_string_with_buffer(|length| self.text(length))
    }
}

/// Borrow key text independently of its ordinary or charged backing.
pub fn key_text<'a, T: AsRef<str>>(key: &'a KeyRef<'_, T>) -> &'a str {
    match key {
        KeyRef::Borrowed(text) => text,
        KeyRef::Owned(text) => text.as_ref(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destinations_share_string_and_escaped_key_bytes() {
        let pool = AllocationBudget::new(128);
        let admitted = AdmittedScratch::new(&pool);
        for source in [r#""plain""#, r#""a\u0062\n""#, r#""\ud83c\udf0d""#] {
            let expected = OrdinaryScratch.string(&mut Parser::new(source)).unwrap();
            let text = admitted.string(&mut Parser::new(source)).unwrap();
            assert_eq!(text.as_ref(), expected);
            assert_eq!(pool.reserved_bytes(), expected.len());
            drop(text);
            assert_eq!(pool.reserved_bytes(), 0);
        }
        let mut parser = Parser::new(r#"{"a\u0062":null}"#);
        let mut object = MapVisitor::new(&mut parser).unwrap();
        let key = admitted.key(&mut object).unwrap().unwrap();
        assert_eq!(key_text(&key), "ab");
        assert_eq!(pool.reserved_bytes(), 2);
        object.parse_value::<()>().unwrap();
        drop(key);
        assert_eq!(pool.reserved_bytes(), 0);
        assert!(admitted.key(&mut object).unwrap().is_none());
        object.finish().unwrap();
    }

    #[test]
    fn zero_pool_refuses_string_but_borrows_unescaped_key() {
        let pool = AllocationBudget::new(0);
        let admitted = AdmittedScratch::new(&pool);
        assert!(matches!(
            admitted.string(&mut Parser::new(r#""x""#)),
            Err(ScratchAdmissionError::Allocation(
                ChargedBufferError::Admission(_)
            ))
        ));
        let mut parser = Parser::new(r#"{"x":null}"#);
        let mut object = MapVisitor::new(&mut parser).unwrap();
        let key = admitted.key(&mut object).unwrap().unwrap();
        assert!(matches!(key, KeyRef::Borrowed("x")));
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
