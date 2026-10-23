//! One strict custom map/record walk with ordinary and original-budget destinations.

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer, ChargedBufferError,
};
use iroha_model_base::name::{MAX_NAME_BYTES, Name};
use iroha_primitives::json::{Json, JsonRetentionError};
use norito::json::{self, JsonDeserialize, JsonObjectKeyOwned};

use super::{Custody, CustomParameter, CustomParameterId, CustomParameters, reserve_authoring};

/// Original JSON or allocation refusal from a directly admitted custom collection.
#[derive(Debug, thiserror::Error)]
pub enum CustomParametersJsonAdmissionError {
    /// Exact original JSON error, including its opaque decoder observer identity.
    #[error(transparent)]
    Json(#[from] json::Error),
    /// Original finite-pool refusal before backing or validation scratch is used.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// Original physical buffer or allocation refusal.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
    /// Original shared JSON text/control or validation scratch refusal.
    #[error(transparent)]
    RetainedJson(JsonRetentionError),
}

impl From<JsonRetentionError> for CustomParametersJsonAdmissionError {
    fn from(error: JsonRetentionError) -> Self {
        match error {
            JsonRetentionError::Decode(error) => Self::Json(error),
            error => Self::RetainedJson(error),
        }
    }
}

impl CustomParameters {
    /// Decode the original map directly into immutable same-pool custody.
    ///
    /// Map/record fields use the same strict walk as ordinary decoding. The exact
    /// entry array and ID-charge ledger precede any retained field. Escaped keys,
    /// ID text, canonical-name validation scratch and JSON validation text use
    /// the same pool. No Value tree, reserialized document or postcharged clone
    /// is created. The caller owns source bytes, enclosing State/control and the
    /// original complete-document boundary; this does not authenticate genesis.
    ///
    /// # Errors
    /// Preserves native JSON observer errors and original pool/allocator refusals.
    /// The complete partial destination retires on failure; no progress escapes.
    pub fn try_decode_json(
        parser: &mut json::Parser<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, CustomParametersJsonAdmissionError> {
        decode_map(parser, &mut Admitted { budget })
    }
}

pub(super) fn decode_collection(
    parser: &mut json::Parser<'_>,
) -> Result<CustomParameters, json::Error> {
    decode_map(parser, &mut Ordinary)
}

pub(in crate::parameter::custom) fn decode_parameter(
    parser: &mut json::Parser<'_>,
) -> Result<CustomParameter, json::Error> {
    let record = decode_record(parser, &mut Ordinary)?;
    Ok(CustomParameter::new(record.id, record.payload))
}

fn invalid(message: &'static str) -> json::Error {
    json::Error::WithPos {
        msg: message,
        byte: 0,
        line: 1,
        col: 1,
    }
}

fn key_text<'a, T: AsRef<str>>(key: &'a json::KeyRef<'_, T>) -> &'a str {
    match key {
        json::KeyRef::Borrowed(text) => text,
        json::KeyRef::Owned(text) => text.as_ref(),
    }
}

struct Record<I> {
    id: I,
    payload: Json,
}

trait Destination {
    type Error: From<json::Error>;
    type Text: AsRef<str>;
    type Id;
    type Map;
    fn key<'a>(
        &mut self,
        object: &mut json::MapVisitor<'a, '_>,
    ) -> Result<Option<json::KeyRef<'a, Self::Text>>, Self::Error>;
    fn id(&mut self, parser: &mut json::Parser<'_>) -> Result<Self::Id, Self::Error>;
    fn payload(&mut self, parser: &mut json::Parser<'_>) -> Result<Json, Self::Error>;
    fn identity(id: &Self::Id) -> &CustomParameterId;
    fn begin(&mut self, count: usize) -> Result<Self::Map, Self::Error>;
    fn len(map: &Self::Map) -> usize;
    fn last(map: &Self::Map) -> Option<&CustomParameterId>;
    fn append(map: &mut Self::Map, record: Record<Self::Id>);
    fn finish(map: Self::Map) -> CustomParameters;
}

fn decode_record<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &mut D,
) -> Result<Record<D::Id>, D::Error> {
    let mut object = json::MapVisitor::new(parser)?;
    let mut id = None;
    let mut payload = None;
    while let Some(key) = destination.key(&mut object)? {
        match key_text(&key) {
            "id" => {
                if id.is_some() {
                    return Err(invalid("duplicate custom parameter id field").into());
                }
                id = Some(object.parse_value_with_parser_typed(|parser| destination.id(parser))?);
            }
            "payload" => {
                if payload.is_some() {
                    return Err(invalid("duplicate custom parameter payload field").into());
                }
                payload = Some(
                    object.parse_value_with_parser_typed(|parser| destination.payload(parser))?,
                );
            }
            _ => return Err(invalid("unknown custom parameter field").into()),
        }
    }
    object.finish()?;
    Ok(Record {
        id: id.ok_or_else(|| invalid("missing custom parameter id field"))?,
        payload: payload.ok_or_else(|| invalid("missing custom parameter payload field"))?,
    })
}

fn decode_map<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &mut D,
) -> Result<CustomParameters, D::Error> {
    let mut object = json::MapVisitor::new(parser)?;
    let count = object.total_entries();
    let mut map = destination.begin(count)?;
    while let Some(key) = destination.key(&mut object)? {
        let record =
            object.parse_value_with_parser_typed(|parser| decode_record(parser, destination))?;
        let id = D::identity(&record.id);
        if key_text(&key) != id.name().as_ref()
            || D::last(&map).is_some_and(|previous| previous >= id)
            || D::len(&map) == count
        {
            return Err(invalid("custom parameters require strictly increasing unique keys matching each value identity").into());
        }
        D::append(&mut map, record);
    }
    object.finish()?;
    Ok(D::finish(map))
}

struct Ordinary;
impl Destination for Ordinary {
    type Error = json::Error;
    type Text = String;
    type Id = CustomParameterId;
    type Map = Vec<CustomParameter>;
    fn key<'a>(
        &mut self,
        object: &mut json::MapVisitor<'a, '_>,
    ) -> Result<Option<json::KeyRef<'a>>, json::Error> {
        object.next_key()
    }
    fn id(&mut self, parser: &mut json::Parser<'_>) -> Result<Self::Id, json::Error> {
        CustomParameterId::json_deserialize(parser)
    }
    fn payload(&mut self, parser: &mut json::Parser<'_>) -> Result<Json, json::Error> {
        Json::json_deserialize(parser)
    }
    fn identity(id: &Self::Id) -> &CustomParameterId {
        id
    }
    fn begin(&mut self, count: usize) -> Result<Self::Map, json::Error> {
        let mut entries = Vec::new();
        reserve_authoring(&mut entries, count).map_err(json::Error::from_decode_resource)?;
        Ok(entries)
    }
    fn len(map: &Self::Map) -> usize {
        map.len()
    }
    fn last(map: &Self::Map) -> Option<&CustomParameterId> {
        map.last().map(|entry| &entry.id)
    }
    fn append(map: &mut Self::Map, record: Record<Self::Id>) {
        map.push(CustomParameter::new(record.id, record.payload));
    }
    fn finish(entries: Self::Map) -> CustomParameters {
        CustomParameters {
            entries,
            custody: None,
        }
    }
}

struct Text(ChargedBuffer<u8>);
impl AsMut<[u8]> for Text {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}
impl AsRef<str> for Text {
    fn as_ref(&self) -> &str {
        std::str::from_utf8(self.0.as_slice()).expect("the original string kernel writes UTF-8")
    }
}
fn text(
    length: usize,
    budget: &AllocationBudget,
) -> Result<Text, CustomParametersJsonAdmissionError> {
    let mut bytes = ChargedBuffer::new(length, budget)?;
    for _ in 0..length {
        bytes.push_reserved(0);
    }
    Ok(Text(bytes))
}

// Physical Name storage retires before its original persistent charge.
struct Id {
    value: CustomParameterId,
    charge: AllocationCharge,
}
// Every partial entry retires before any corresponding identifier credit.
struct Map {
    entries: ChargedBuffer<CustomParameter>,
    ids: ChargedBuffer<AllocationCharge>,
}
struct Admitted<'a> {
    budget: &'a AllocationBudget,
}
impl Destination for Admitted<'_> {
    type Error = CustomParametersJsonAdmissionError;
    type Text = Text;
    type Id = Id;
    type Map = Map;
    fn key<'a>(
        &mut self,
        object: &mut json::MapVisitor<'a, '_>,
    ) -> Result<Option<json::KeyRef<'a, Text>>, Self::Error> {
        object.next_key_with_buffer(|length| text(length, self.budget))
    }
    fn id(&mut self, parser: &mut json::Parser<'_>) -> Result<Id, Self::Error> {
        let source = parser.parse_string_with_buffer(|length| {
            if length > MAX_NAME_BYTES {
                return Err(
                    invalid("custom parameter id exceeds canonical Name byte bound").into(),
                );
            }
            text(length, self.budget)
        })?;
        let source = source.as_ref();
        let layout = Name::json_decode_allocation_layout(source)
            .unwrap_or_else(|| std::alloc::Layout::array::<u8>(0).expect("zero layout"));
        let mut reservation = self.budget.try_reserve(layout)?;
        let charge = reservation
            .try_split(layout)
            .expect("the exact Name backing was reserved");
        let _scratch = self
            .budget
            .try_reserve_bytes(Name::canonical_validation_scratch_bytes(source))?;
        let value = CustomParameterId::from_json_key_text(source)?;
        Ok(Id { value, charge })
    }
    fn payload(&mut self, parser: &mut json::Parser<'_>) -> Result<Json, Self::Error> {
        Json::try_decode_json(parser, self.budget).map_err(Into::into)
    }
    fn identity(id: &Id) -> &CustomParameterId {
        &id.value
    }
    fn begin(&mut self, count: usize) -> Result<Map, Self::Error> {
        // Both physical destinations precede any decoded record. On second
        // allocation refusal the first owner refunds itself without retained fields.
        let entry_layout = std::alloc::Layout::array::<CustomParameter>(count)
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        let ledger_layout = std::alloc::Layout::array::<AllocationCharge>(count)
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        norito::core::reserve_decode_allocation(entry_layout.size())
            .map_err(json::Error::from_decode_resource)?;
        norito::core::reserve_decode_allocation(ledger_layout.size())
            .map_err(json::Error::from_decode_resource)?;
        let entries = ChargedBuffer::new(count, self.budget)?;
        let ids = ChargedBuffer::new(count, self.budget)?;
        Ok(Map { entries, ids })
    }
    fn len(map: &Map) -> usize {
        map.entries.as_slice().len()
    }
    fn last(map: &Map) -> Option<&CustomParameterId> {
        map.entries.as_slice().last().map(|entry| &entry.id)
    }
    fn append(map: &mut Map, record: Record<Id>) {
        let Id { value, charge } = record.id;
        map.ids.push_reserved(charge);
        map.entries
            .push_reserved(CustomParameter::new(value, record.payload));
    }
    #[allow(unsafe_code)]
    fn finish(map: Map) -> CustomParameters {
        // SAFETY: the exact unchanged entries allocation and all ID charges move
        // into the private immutable owner. No fallible operation intervenes;
        // final field order frees entries before the array and identifier credits.
        let (entries, array) = unsafe { map.entries.into_allocation_parts() };
        CustomParameters {
            entries,
            custody: Some(Custody {
                array,
                ids: map.ids,
            }),
        }
    }
}

#[cfg(test)]
mod tests;
