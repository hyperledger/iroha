//! One sorted custom-parameter backing with explicit original-pool custody.
//!
//! Ordinary codecs produce authoring values, never retained State authority.
//! TODO: connect the owner's admitted cold-restore and atomic replacement paths
//! before claiming complete State parameter allocation closure.

use std::{alloc::Layout, cmp::Ordering, fmt, ops::Index};

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer, PrepaidBufferError,
};
use iroha_primitives::json::JsonRetentionError;
use norito::{
    core::{self, Archived, DecodeFromSlice, DeserializePayload, Encoder, SerializePayload},
    json::{self, JsonDeserialize, JsonSerialize},
};

use super::{CustomParameter, CustomParameterId};

mod json_decode;
pub use json_decode::CustomParametersJsonAdmissionError;
pub(super) use json_decode::decode_parameter;

/// Custom parameters stored once, in strictly increasing parameter identity order.
///
/// Keys are borrowed from the immutable entries, never stored in a second tree.
/// Authoring values are mutable and have no finite-pool publication authority.
/// Retained values own their exact array and identifier charges; each JSON leaf
/// retains its own shared backing custody, including through escaping clones.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parameter::CustomParameters")]
pub struct CustomParameters {
    // Entries, including their allocation, retire before the custody ledger.
    entries: Vec<CustomParameter>,
    custody: Option<Custody>,
}

struct Custody {
    array: AllocationCharge,
    ids: ChargedBuffer<AllocationCharge>,
}

/// Original refusal to prepare or retain a custom-parameter collection.
#[derive(Debug, thiserror::Error)]
pub enum CustomParametersAdmissionError {
    /// The original finite pool refused a concrete allocation demand.
    #[error(transparent)]
    Admission(AllocationRefusal),
    /// A prepaid backing allocation failed, preserving its original cause.
    #[error(transparent)]
    Buffer(PrepaidBufferError),
    /// An existing fallible identifier or authoring allocation refused.
    #[error(transparent)]
    Codec(norito::Error),
    /// A shared JSON owner could not retain its original-pool custody.
    #[error(transparent)]
    Json(JsonRetentionError),
    /// Retained values are immutable; build a separate authoring replacement.
    #[error("retained custom parameters cannot be mutated")]
    RetainedMutation,
    /// The offered replacement has a different identity than its selected key.
    #[error("custom parameter replacement identity differs from its selected key")]
    KeyValueMismatch,
}

impl CustomParameters {
    /// Create an empty unadmitted authoring collection without allocating.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            custody: None,
        }
    }

    /// Number of distinct parameter identities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether this collection has no parameters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Borrow a parameter by its exact identity without allocation.
    #[must_use]
    pub fn get(&self, id: &CustomParameterId) -> Option<&CustomParameter> {
        self.position(id).ok().map(|index| &self.entries[index])
    }

    /// Test whether an exact identity is present.
    #[must_use]
    pub fn contains_key(&self, id: &CustomParameterId) -> bool {
        self.position(id).is_ok()
    }

    /// Borrow key/value pairs in canonical identity order.
    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = (&CustomParameterId, &CustomParameter)> + DoubleEndedIterator
    {
        self.entries
            .iter()
            .map(|parameter| (&parameter.id, parameter))
    }

    /// Borrow identities in canonical order.
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &CustomParameterId> + DoubleEndedIterator {
        self.entries.iter().map(|parameter| &parameter.id)
    }

    /// Borrow immutable parameter values in canonical identity order.
    pub fn values(&self) -> std::slice::Iter<'_, CustomParameter> {
        self.entries.iter()
    }

    fn position(&self, id: &CustomParameterId) -> Result<usize, usize> {
        self.entries
            .binary_search_by(|parameter| parameter.id.cmp(id))
    }

    fn require_authoring(&self) -> Result<(), CustomParametersAdmissionError> {
        if self.custody.is_some() {
            return Err(CustomParametersAdmissionError::RetainedMutation);
        }
        Ok(())
    }

    /// Insert or replace an authored parameter using the value's own identity.
    ///
    /// # Errors
    /// Refuses retained mutation before touching bytes. Preserves the original
    /// decoder budget or allocator error if an authoring array must grow.
    pub fn try_insert(
        &mut self,
        parameter: CustomParameter,
    ) -> Result<Option<CustomParameter>, CustomParametersAdmissionError> {
        self.require_authoring()?;
        match self.position(&parameter.id) {
            Ok(index) => Ok(Some(std::mem::replace(&mut self.entries[index], parameter))),
            Err(index) => {
                if self.entries.len() == self.entries.capacity() {
                    let next =
                        self.len()
                            .checked_add(1)
                            .ok_or(CustomParametersAdmissionError::Codec(
                                norito::Error::LengthMismatch,
                            ))?;
                    reserve_authoring(&mut self.entries, next)
                        .map_err(CustomParametersAdmissionError::Codec)?;
                }
                self.entries.insert(index, parameter);
                Ok(None)
            }
        }
    }

    /// Convenience insertion for an explicitly unadmitted authoring instance.
    ///
    /// # Panics
    /// Panics on retained mutation or local allocation refusal. State preparation
    /// must use [`Self::try_insert`] and preserve its original error.
    pub fn insert(&mut self, parameter: CustomParameter) -> Option<CustomParameter> {
        self.try_insert(parameter)
            .expect("unadmitted custom parameter authoring insertion")
    }

    /// Remove an authored parameter without allocating.
    ///
    /// # Errors
    /// Refuses retained mutation before inspecting or changing the destination.
    pub fn try_remove(
        &mut self,
        id: &CustomParameterId,
    ) -> Result<Option<CustomParameter>, CustomParametersAdmissionError> {
        self.require_authoring()?;
        Ok(self
            .position(id)
            .ok()
            .map(|index| self.entries.remove(index)))
    }

    /// Convenience removal for an explicitly unadmitted authoring instance.
    ///
    /// # Panics
    /// Panics on retained mutation. State preparation uses [`Self::try_remove`].
    pub fn remove(&mut self, id: &CustomParameterId) -> Option<CustomParameter> {
        self.try_remove(id)
            .expect("unadmitted custom parameter authoring removal")
    }

    /// Build an authoring collection, applying later values of the same identity.
    ///
    /// # Errors
    /// Preserves the first original allocation error without exposing a partial collection.
    pub fn try_from_iter(
        parameters: impl IntoIterator<Item = CustomParameter>,
    ) -> Result<Self, CustomParametersAdmissionError> {
        let mut result = Self::new();
        for parameter in parameters {
            result.try_insert(parameter)?;
        }
        Ok(result)
    }

    /// Fallibly copy a separate authoring draft without publication authority.
    ///
    /// JSON references keep their original shared custody; identifier and array
    /// copies are ordinary authoring storage. Publication requires retention.
    ///
    /// # Errors
    /// Preserves the original decoder allowance or physical allocator refusal.
    pub fn try_clone_for_authoring(&self) -> Result<Self, CustomParametersAdmissionError> {
        let mut entries = Vec::new();
        reserve_authoring(&mut entries, self.len())
            .map_err(CustomParametersAdmissionError::Codec)?;
        for parameter in &self.entries {
            let id = parameter
                .id
                .name()
                .try_clone_for_admission()
                .map_err(CustomParametersAdmissionError::Codec)?;
            entries.push(CustomParameter::new(
                CustomParameterId::new(id),
                parameter.payload.clone(),
            ));
        }
        Ok(Self {
            entries,
            custody: None,
        })
    }

    /// Whether the complete retained collection belongs to this original pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.custody.as_ref().is_some_and(|custody| {
            custody.array.belongs_to(budget)
                && custody.ids.belongs_to(budget)
                && custody
                    .ids
                    .as_slice()
                    .iter()
                    .all(|charge| charge.belongs_to(budget))
                && self
                    .entries
                    .iter()
                    .all(|parameter| parameter.payload.belongs_to(budget))
        })
    }

    /// Retain a complete immutable copy with exact original-pool custody.
    ///
    /// Array, identifier ledger and identifier text are reserved before copying.
    /// JSON leaves separately retain their own text and shared-control charges;
    /// already admitted same-pool leaves are shared without double charging.
    /// Any later failure drops the partial graph before refunding its charges.
    /// An enclosing immutable State handle can share this result across versions.
    ///
    /// # Errors
    /// Returns the original allocation or nested JSON refusal. No partial owner escapes.
    pub fn try_retain_in(
        &self,
        budget: &AllocationBudget,
    ) -> Result<Self, CustomParametersAdmissionError> {
        Self::retain_entries(self.entries.iter(), budget)
    }

    /// Prepare one borrowed insertion, replacement or removal into a new owner.
    ///
    /// The source remains immutable and retains every original charge. The
    /// replacement's own identity must match `id`. Sorted borrowed segments feed
    /// the same exact array/ID/JSON retention kernel as [`Self::try_retain_in`];
    /// no ordinary authoring map, cloned update or intermediate payload is built.
    /// Removing an absent key makes a separately retained equal collection.
    ///
    /// # Errors
    /// An identity mismatch rejects before any allocation. Other errors retain
    /// their original causes and retire the partial destination without changing
    /// the predecessor or refunding any of its still-owned backing.
    pub fn try_with_update(
        &self,
        id: &CustomParameterId,
        value: Option<&CustomParameter>,
        budget: &AllocationBudget,
    ) -> Result<Self, CustomParametersAdmissionError> {
        if value.is_some_and(|value| &value.id != id) {
            return Err(CustomParametersAdmissionError::KeyValueMismatch);
        }
        let (index, after) = match self.position(id) {
            Ok(index) => (index, index + 1),
            Err(index) => (index, index),
        };
        let parameters = self.entries[..index]
            .iter()
            .chain(value)
            .chain(self.entries[after..].iter());
        Self::retain_entries(parameters, budget)
    }

    #[allow(unsafe_code)]
    fn retain_entries<'a>(
        parameters: impl Iterator<Item = &'a CustomParameter> + Clone,
        budget: &AllocationBudget,
    ) -> Result<Self, CustomParametersAdmissionError> {
        let count = parameters.clone().count();
        let id_count = parameters
            .clone()
            .filter(|parameter| parameter.id.name().admission_clone_layout().is_some())
            .count();
        let array_layout = Layout::array::<CustomParameter>(count).map_err(|_| {
            CustomParametersAdmissionError::Admission(AllocationRefusal::DemandOverflow)
        })?;
        let ledger_layout = Layout::array::<AllocationCharge>(id_count).map_err(|_| {
            CustomParametersAdmissionError::Admission(AllocationRefusal::DemandOverflow)
        })?;
        let layouts = [array_layout, ledger_layout].into_iter().chain(
            parameters
                .clone()
                .filter_map(|parameter| parameter.id.name().admission_clone_layout()),
        );
        let mut reservation = budget
            .try_reserve_layouts(layouts)
            .map_err(CustomParametersAdmissionError::Admission)?;
        // Declared first so all copied entries retire before their identifier ledger.
        let mut ids =
            ChargedBuffer::<AllocationCharge>::from_reservation(id_count, &mut reservation)
                .map_err(CustomParametersAdmissionError::Buffer)?;
        let mut entries =
            ChargedBuffer::<CustomParameter>::from_reservation(count, &mut reservation)
                .map_err(CustomParametersAdmissionError::Buffer)?;
        for parameter in parameters {
            if let Some(layout) = parameter.id.name().admission_clone_layout() {
                ids.push_reserved(
                    reservation
                        .try_split(layout)
                        .expect("complete identifier demand was reserved"),
                );
            }
            let id = parameter
                .id
                .name()
                .try_clone_for_admission()
                .map_err(CustomParametersAdmissionError::Codec)?;
            let payload = parameter
                .payload
                .try_retain_in(budget)
                .map_err(CustomParametersAdmissionError::Json)?;
            entries.push_reserved(CustomParameter::new(CustomParameterId::new(id), payload));
        }
        // SAFETY: entries keep the exact backing and identifier allocations. The
        // private custody fields retain their original charges until after all
        // entries retire. No fallible operation occurs after extraction.
        let (entries, array) = unsafe { entries.into_allocation_parts() };
        Ok(Self {
            entries,
            custody: Some(Custody { array, ids }),
        })
    }
}

fn reserve_authoring(
    entries: &mut Vec<CustomParameter>,
    count: usize,
) -> Result<(), norito::Error> {
    if count <= entries.capacity() {
        return Ok(());
    }
    let layout =
        Layout::array::<CustomParameter>(count).map_err(|_| norito::Error::LengthMismatch)?;
    core::reserve_decode_allocation(layout.size())?;
    entries
        .try_reserve_exact(count - entries.len())
        .map_err(|_| norito::Error::AllocationFailed {
            bytes: layout.size() as u64,
        })?;
    if entries.capacity() != count {
        return Err(norito::Error::AllocationFailed {
            bytes: layout.size() as u64,
        });
    }
    Ok(())
}

impl Default for CustomParameters {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for CustomParameters {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            custody: None,
        }
    }
}

impl fmt::Debug for CustomParameters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_map().entries(self.iter()).finish()
    }
}

impl PartialEq for CustomParameters {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}
impl Eq for CustomParameters {}
impl PartialOrd for CustomParameters {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for CustomParameters {
    fn cmp(&self, other: &Self) -> Ordering {
        self.entries.cmp(&other.entries)
    }
}

impl Index<&CustomParameterId> for CustomParameters {
    type Output = CustomParameter;
    fn index(&self, id: &CustomParameterId) -> &CustomParameter {
        self.get(id).expect("custom parameter identity exists")
    }
}

impl FromIterator<CustomParameter> for CustomParameters {
    fn from_iter<T: IntoIterator<Item = CustomParameter>>(parameters: T) -> Self {
        Self::try_from_iter(parameters).expect("unadmitted custom parameter authoring collection")
    }
}

impl<'a> IntoIterator for &'a CustomParameters {
    type Item = (&'a CustomParameterId, &'a CustomParameter);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, CustomParameter>,
        fn(&'a CustomParameter) -> Self::Item,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.entries
            .iter()
            .map(|parameter| (&parameter.id, parameter))
    }
}

impl SerializePayload for CustomParameters {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        core::write_ordered_map_entries(writer, self.len(), self.iter())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        core::map_encoded_len_hint(self.iter())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        core::map_encoded_len_exact(self.iter())
    }
}

impl<'a> DecodeFromSlice<'a> for CustomParameters {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::Error> {
        let (count, _) = core::inspect_seq_len_slice(bytes)?;
        core::validate_current_map_reservation(bytes, count)?;
        let mut entries = Vec::new();
        reserve_authoring(&mut entries, count)?;
        let (_, used) = core::decode_map_entries::<CustomParameterId, CustomParameter, _>(
            bytes,
            |key, value| {
                if key != value.id
                    || entries
                        .last()
                        .is_some_and(|previous: &CustomParameter| previous.id >= key)
                    || entries.len() == count
                {
                    return Err(norito::Error::LengthMismatch);
                }
                entries.push(value);
                Ok(())
            },
        )?;
        Ok((
            Self {
                entries,
                custody: None,
            },
            used,
        ))
    }
}

impl<'a> DeserializePayload<'a> for CustomParameters {
    fn deserialize(archived: &'a Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("valid canonical custom parameters")
    }
    fn try_deserialize(archived: &'a Archived<Self>) -> Result<Self, norito::Error> {
        let bytes = core::payload_slice_from_ptr(::core::ptr::from_ref(archived).cast::<u8>())?;
        Self::decode_from_slice(bytes).map(|(parameters, _)| parameters)
    }
}

impl JsonSerialize for CustomParameters {
    fn json_serialize(&self, output: &mut String) {
        super::json_helpers::serialize(self, output);
    }
    fn json_serialize_to(
        &self,
        output: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        super::json_helpers::serialize_bounded(self, output)
    }
}

impl JsonDeserialize for CustomParameters {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        json_decode::decode_collection(parser)
    }
}

impl iroha_schema::TypeId for CustomParameters {
    fn id() -> String {
        "CustomParameters".into()
    }
}

impl iroha_schema::IntoSchema for CustomParameters {
    fn type_name() -> String {
        "CustomParameters".into()
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(iroha_schema::Metadata::Map(iroha_schema::MapMeta {
                key: std::any::TypeId::of::<CustomParameterId>(),
                value: std::any::TypeId::of::<CustomParameter>(),
            }));
            <CustomParameterId as iroha_schema::IntoSchema>::update_schema_map(map);
            <CustomParameter as iroha_schema::IntoSchema>::update_schema_map(map);
        }
    }
}

#[cfg(test)]
mod tests;
