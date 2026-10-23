//! Original-pool custody carried by every immutable JSON reference.

use std::{alloc::Layout, cmp::Ordering, fmt, ops::Deref};

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer, ChargedBufferError,
    ChargedBufferFromChargeError,
    shared::{ReservationError, Reserved, Shared},
};

use super::Json;

// Fields retire in declaration order: text storage is freed before its charge.
pub(super) struct JsonText {
    pub(super) value: String,
    text_charge: Option<AllocationCharge>,
}

impl JsonText {
    pub(super) fn untracked(value: String) -> Self {
        Self {
            value,
            text_charge: None,
        }
    }
}

impl Deref for JsonText {
    type Target = String;

    fn deref(&self) -> &String {
        &self.value
    }
}

pub(super) type SharedJsonText = Shared<JsonText, Option<AllocationCharge>>;

/// Original refusal to retain canonical JSON in a finite allocation pool.
#[derive(Debug)]
pub enum JsonRetentionError {
    /// The caller's original pool refused the complete allocation demand.
    Admission(AllocationRefusal),
    /// The allocator refused the original prepaid shared control layout.
    Shared(ReservationError),
    /// The allocator refused the original prepaid text backing.
    Text(ChargedBufferFromChargeError),
    /// Original parser/resource refusal from the unchanged JSON observer.
    Decode(norito::json::Error),
    /// Original finite-pool or physical refusal for transient validation text.
    Scratch(ChargedBufferError),
}

impl fmt::Display for JsonRetentionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => error.fmt(formatter),
            Self::Shared(error) => error.fmt(formatter),
            Self::Text(error) => error.fmt(formatter),
            Self::Decode(error) => error.fmt(formatter),
            Self::Scratch(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for JsonRetentionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Shared(error) => Some(error),
            Self::Text(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::Scratch(error) => Some(error),
        }
    }
}

impl From<norito::json::Error> for JsonRetentionError {
    fn from(error: norito::json::Error) -> Self {
        Self::Decode(error)
    }
}

struct Scratch(ChargedBuffer<u8>);
impl AsRef<[u8]> for Scratch {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}
impl AsMut<[u8]> for Scratch {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl Json {
    /// Whether every original text and control allocation belongs to this pool.
    ///
    /// Ordinary authoring values have no finite-pool custody and return false.
    /// The private admitted constructor installs both charges from one original
    /// reservation; no API can detach either charge or mutate its text.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.0
            .text_charge
            .as_ref()
            .is_some_and(|charge| charge.belongs_to(budget))
    }

    /// Retain validated text with its original physical allocation custody.
    ///
    /// A same-pool reference shares its already funded backing without allocation.
    /// An authoring or foreign-pool value is copied into exact new backing only
    /// after the complete text and control demand has been reserved. Every plain
    /// [`Clone`] of the result retains that same custody, even after its enclosing
    /// State owner has retired. This does not reparse or normalize the text.
    ///
    /// # Errors
    /// Returns the unchanged pool refusal or original physical allocator error.
    /// Partial construction releases backing before refunding its charge.
    #[allow(unsafe_code)]
    pub fn try_retain_in(&self, budget: &AllocationBudget) -> Result<Self, JsonRetentionError> {
        if self.belongs_to(budget) {
            return Ok(self.clone());
        }
        Self::retain_text(self.get(), budget, || Ok(()))
    }

    /// Decode one original canonical JSON fragment directly into funded custody.
    ///
    /// Text, shared control and transient validation strings use the supplied
    /// original pool. Existing grammar/writer kernels establish canonical bytes
    /// without a Value tree or rewritten document. The caller retains the source
    /// and enclosing decoder/State control and checks its document boundary.
    ///
    /// # Errors
    /// Preserves original syntax, observer-bound decoder, pool and allocator errors.
    pub fn try_decode_json(
        parser: &mut norito::json::Parser<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, JsonRetentionError> {
        parser.skip_ws();
        let value_start = parser.position();
        let raw = parser.raw_value_slice()?;
        let input = parser.input();
        let first = input
            .bytes()
            .position(|byte| !matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
            .unwrap_or(input.len());
        if value_start == first && input != raw {
            return Err(norito::json::Error::WithPos {
                msg: "Json payload is valid but not in canonical lexical form",
                byte: 0,
                line: 1,
                col: 1,
            }
            .into());
        }
        if raw.len() > super::MAX_JSON_BYTES {
            return Err(norito::json::Error::WithPos {
                msg: "Json payload exceeds the 1048576-byte UTF-8 limit",
                byte: 0,
                line: 1,
                col: 1,
            }
            .into());
        }
        let retained_bytes = raw
            .len()
            .checked_add(SharedJsonText::layout().size())
            .ok_or(JsonRetentionError::Admission(
                AllocationRefusal::DemandOverflow,
            ))?;
        norito::core::reserve_decode_allocation(retained_bytes)
            .map_err(norito::json::Error::from_decode_resource)?;
        Self::retain_text(raw, budget, || {
            norito::json::validate_canonical_json_with_buffer(raw, |length| {
                let mut buffer =
                    ChargedBuffer::new(length, budget).map_err(JsonRetentionError::Scratch)?;
                for _ in 0..length {
                    buffer.push_reserved(0);
                }
                Ok(Scratch(buffer))
            })
        })
    }

    #[allow(unsafe_code)]
    fn retain_text(
        raw: &str,
        budget: &AllocationBudget,
        validate: impl FnOnce() -> Result<(), JsonRetentionError>,
    ) -> Result<Self, JsonRetentionError> {
        let text_layout = Layout::array::<u8>(raw.len())
            .map_err(|_| JsonRetentionError::Admission(AllocationRefusal::DemandOverflow))?;
        let shell_layout = SharedJsonText::layout();
        let mut reservation = budget
            .try_reserve_layouts([text_layout, shell_layout])
            .map_err(JsonRetentionError::Admission)?;
        validate()?;
        let shell_charge = reservation
            .try_split(shell_layout)
            .expect("the complete original layouts were reserved before construction");
        let shell = Reserved::<JsonText, Option<AllocationCharge>>::try_new(Some(shell_charge))
            .map_err(|(_original_charge, error)| JsonRetentionError::Shared(error))?;
        let text_charge = reservation
            .try_split(text_layout)
            .expect("the exact original text layout remains prepaid");
        let mut text = ChargedBuffer::<u8>::try_from_charge(raw.len(), text_charge)
            .map_err(|(_original_charge, error)| JsonRetentionError::Text(error))?;
        for byte in raw.bytes() {
            text.push_reserved(byte);
        }
        // SAFETY: the initialized buffer moves unchanged into String. Its exact
        // charge follows the same allocation into JsonText and drops after it.
        // There is no fallible operation between extraction and shared placement.
        let (bytes, text_charge) = unsafe { text.into_allocation_parts() };
        // SAFETY: these are the unchanged bytes of an existing canonical String.
        let value = unsafe { String::from_utf8_unchecked(bytes) };
        Ok(Self(shell.initialize(JsonText {
            value,
            text_charge: Some(text_charge),
        })))
    }
}

impl fmt::Debug for Json {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Json").field(self.get()).finish()
    }
}

impl fmt::Display for Json {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.get(), formatter)
    }
}

impl PartialEq for Json {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl Eq for Json {}

impl PartialOrd for Json {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Json {
    fn cmp(&self, other: &Self) -> Ordering {
        self.get().cmp(other.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authoring_value_cannot_claim_pool_custody() {
        let pool = AllocationBudget::new(4096);
        let value = Json::new("canonical source");
        assert!(!value.belongs_to(&pool));
        assert!(!value.clone().belongs_to(&pool));
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn complete_demand_precedes_any_retained_owner_and_retry_preserves_source() {
        let source = Json::new("canonical source");
        let demand = source.get().len() + SharedJsonText::layout().size();
        for limit in [0, demand - 1] {
            let pool = AllocationBudget::new(limit);
            assert!(matches!(
                source.try_retain_in(&pool),
                Err(JsonRetentionError::Admission(_))
            ));
            assert_eq!(pool.reserved_bytes(), 0);
            assert!(!source.belongs_to(&pool));
            pool.set_limit_bytes(demand);
            let retained = source.try_retain_in(&pool).unwrap();
            assert_eq!(retained, source);
            assert!(!retained.ptr_eq(&source));
            assert_eq!(pool.reserved_bytes(), demand);
            drop(retained);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }

    #[test]
    fn raw_clones_keep_original_custody_until_the_last_reader() {
        let pool = AllocationBudget::new(4096);
        let retained = Json::new("canonical source").try_retain_in(&pool).unwrap();
        let demand = pool.reserved_bytes();
        let escaped = retained.clone();
        assert!(escaped.ptr_eq(&retained));
        drop(retained);
        assert_eq!(pool.reserved_bytes(), demand);
        assert!(escaped.belongs_to(&pool));
        pool.set_limit_bytes(0);
        let same = escaped.try_retain_in(&pool).unwrap();
        assert!(same.ptr_eq(&escaped));
        assert_eq!(pool.reserved_bytes(), demand);
        drop(escaped);
        assert_eq!(pool.reserved_bytes(), demand);
        drop(same);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn equal_foreign_pool_never_adopts_another_pools_backing() {
        let first = AllocationBudget::new(4096);
        let second = AllocationBudget::new(4096);
        let original = Json::new("canonical source").try_retain_in(&first).unwrap();
        assert!(!original.belongs_to(&second));
        let copied = original.try_retain_in(&second).unwrap();
        assert!(!copied.ptr_eq(&original));
        assert_eq!(copied, original);
        assert!(copied.belongs_to(&second));
        drop(original);
        assert_eq!(first.reserved_bytes(), 0);
        assert!(second.reserved_bytes() > 0);
        drop(copied);
        assert_eq!(second.reserved_bytes(), 0);
    }

    #[test]
    fn retained_and_authoring_values_have_identical_wire_and_order() {
        let pool = AllocationBudget::new(4096);
        let first = Json::new("a");
        let second = Json::new("b");
        let retained = first.try_retain_in(&pool).unwrap();
        assert_eq!(
            norito::to_bytes(&retained).unwrap(),
            norito::to_bytes(&first).unwrap()
        );
        assert_eq!(
            norito::json::to_json(&retained).unwrap(),
            norito::json::to_json(&first).unwrap()
        );
        assert_eq!(retained.cmp(&second), first.cmp(&second));
        assert_eq!(retained.partial_cmp(&second), first.partial_cmp(&second));
        assert_eq!(format!("{retained}"), format!("{first}"));
        assert_eq!(format!("{retained:?}"), format!("{first:?}"));
    }
}
