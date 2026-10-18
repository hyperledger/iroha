//! Sole bounded operation metadata image, independent of native authority and wallet custody.
//!
//! The envelope is authenticated once; its canonical child frames are decoded lazily in
//! the original semantic order. Publication is an exact expected-to-next durable rename
//! under the existing purpose lock, never an operating-system compare-and-swap.

use super::*;
use iroha_allocation::AllocationBudget;
use norito::core::{
    self as nc, CanonicalField, DecodeField, DecodeIntoError, DecodeRecordFields, FieldDestination,
    PreparedDecodeWorkspace, PreparedRecordDestination, SequenceSpan, SerializePayload,
};

pub(in crate::managed) const FILE: &str = "operation.nrt";
// Three root frames and four frames per row. Each frame keeps its original 16 KiB cap;
// the additional fixed allowance covers only bounded canonical envelope framing.
pub(in crate::managed) const MAX_IMAGE_BYTES: usize =
    (3 + 4 * MAX_ATTEMPTS) * (MAX_RECORD_BYTES + 32) + 1024;
use crate::managed::stream_token_custody::body_history::MAX_BODY_BYTES as MAX_RESERVATION_BYTES;
const EMPTY: SequenceSpan = SequenceSpan { start: 0, end: 0 };

#[derive(Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::MetadataPhase")]
enum Phase {
    Unselected,
    ReservedBody,
    PublishingOriginal,
    Pristine,
    Reserved,
    Published,
    Closing,
    Closed,
}

// These owned types declare the sole wire shape. Production reading uses the derived
// field walk with fixed span storage, never their allocating owning decoder.
#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::MetadataRow")]
#[norito(decode_fields)]
struct Row {
    authorization: Vec<u8>,
    observation: Vec<u8>,
    commit: Vec<u8>,
    retirement: Vec<u8>,
}
#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::OperationMetadata")]
#[norito(decode_fields)]
struct Wire {
    phase: Phase,
    original: [u8; 32],
    reservation: Option<[u8; 32]>,
    pending_original: Vec<u8>,
    dispatch: Vec<u8>,
    closing: Vec<u8>,
    closed: Vec<u8>,
    rows: Vec<Row>,
}
#[derive(Clone)]
struct Index {
    phase: Option<Phase>,
    original: [u8; 32],
    reservation: Option<[u8; 32]>,
    pending: SequenceSpan,
    root: [SequenceSpan; 3],
    rows: [[SequenceSpan; 4]; MAX_ATTEMPTS],
    count: usize,
}
impl Default for Index {
    fn default() -> Self {
        Self {
            phase: None,
            original: [0; 32],
            reservation: None,
            pending: EMPTY,
            root: [EMPTY; 3],
            rows: [[EMPTY; 4]; MAX_ATTEMPTS],
            count: 0,
        }
    }
}
struct Destination<'a> {
    source: &'a [u8],
    index: Index,
    pending_maximum: usize,
}
impl FieldDestination for Destination<'_> {
    type Error = std::convert::Infallible;
}
type DecodeResult<T> = std::result::Result<T, DecodeIntoError<std::convert::Infallible>>;
fn bad() -> nc::Error {
    nc::Error::InvalidValue {
        context: "invalid bounded operation metadata image",
    }
}
fn span(
    source: &[u8],
    bytes: &[u8],
    maximum: usize,
) -> std::result::Result<SequenceSpan, nc::Error> {
    let (length, prefix) = nc::inspect_seq_len_slice(bytes)?;
    let end = prefix.checked_add(length).ok_or_else(bad)?;
    let value = bytes.get(prefix..end).ok_or_else(bad)?;
    if value.len() > maximum || end != bytes.len() {
        return Err(bad());
    }
    // This is borrowed envelope geometry, not allocation or logical child decoding.
    // The original component decoder owns its resource debit at its semantic position.
    let start = value
        .as_ptr()
        .addr()
        .checked_sub(source.as_ptr().addr())
        .ok_or_else(bad)?;
    let end = start.checked_add(value.len()).ok_or_else(bad)?;
    if source
        .get(start..end)
        .is_none_or(|v| v.as_ptr() != value.as_ptr())
    {
        return Err(bad());
    }
    Ok(SequenceSpan { start, end })
}
impl DecodeField<0, Phase> for Destination<'_> {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, Phase>) -> DecodeResult<()> {
        self.index.phase = Some(field.decode_owned()?);
        Ok(())
    }
}
impl DecodeField<1, [u8; 32]> for Destination<'_> {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, [u8; 32]>) -> DecodeResult<()> {
        self.index.original = field.decode_owned()?;
        Ok(())
    }
}
impl DecodeField<2, Option<[u8; 32]>> for Destination<'_> {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, Option<[u8; 32]>>) -> DecodeResult<()> {
        self.index.reservation = field.decode_owned()?;
        Ok(())
    }
}
macro_rules! byte_field {
    ($index:literal, $target:expr, $maximum:expr) => {
        impl DecodeField<$index, Vec<u8>> for Destination<'_> {
            type Value = ();
            fn decode_field(&mut self, field: CanonicalField<'_, Vec<u8>>) -> DecodeResult<()> {
                let value =
                    field.with_payload(|bytes| Ok(span(self.source, bytes, ($maximum)(self))?))?;
                ($target)(self, value);
                Ok(())
            }
        }
    };
}
byte_field!(
    3,
    |d: &mut Destination<'_>, s| d.index.pending = s,
    |d: &Destination<'_>| d.pending_maximum
);
byte_field!(
    4,
    |d: &mut Destination<'_>, s| d.index.root[0] = s,
    |_: &Destination<'_>| MAX_IMAGE_BYTES
);
byte_field!(
    5,
    |d: &mut Destination<'_>, s| d.index.root[1] = s,
    |_: &Destination<'_>| MAX_IMAGE_BYTES
);
byte_field!(
    6,
    |d: &mut Destination<'_>, s| d.index.root[2] = s,
    |_: &Destination<'_>| MAX_IMAGE_BYTES
);
struct RowDestination<'a> {
    source: &'a [u8],
    spans: [SequenceSpan; 4],
}
impl FieldDestination for RowDestination<'_> {
    type Error = std::convert::Infallible;
}
impl<const N: usize> DecodeField<N, Vec<u8>> for RowDestination<'_> {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, Vec<u8>>) -> DecodeResult<()> {
        self.spans[N] =
            field.with_payload(|bytes| Ok(span(self.source, bytes, MAX_IMAGE_BYTES)?))?;
        Ok(())
    }
}
impl DecodeField<7, Vec<Row>> for Destination<'_> {
    type Value = ();
    fn decode_field(&mut self, field: CanonicalField<'_, Vec<Row>>) -> DecodeResult<()> {
        field.with_payload(|bytes| {
            let mut scratch = [EMPTY; MAX_ATTEMPTS];
            let plan =
                nc::prepare_element_sequence(bytes, &mut scratch).map_err(|error| match error {
                    nc::SequenceDestinationError::Codec(error) => error,
                    nc::SequenceDestinationError::Storage { .. } => bad(),
                })?;
            if plan.used() != bytes.len() {
                return Err(bad().into());
            }
            plan.decode_elements::<Row, std::convert::Infallible>(|index, field| {
                let mut row = RowDestination {
                    source: self.source,
                    spans: [EMPTY; 4],
                };
                field.with_payload(|bytes| {
                    let (_, used) = Row::decode_fields(bytes, &mut row)?;
                    if used != bytes.len() {
                        return Err(bad().into());
                    }
                    Ok(())
                })?;
                self.index.rows[index] = row.spans;
                Ok(())
            })?;
            self.index.count = plan.len();
            Ok(())
        })
    }
}
#[derive(norito::NoritoSerialize)]
struct RowView<'a> {
    authorization: &'a [u8],
    observation: &'a [u8],
    commit: &'a [u8],
    retirement: &'a [u8],
}
struct RowsView<'a> {
    source: &'a [u8],
    rows: &'a [[SequenceSpan; 4]],
}
fn bytes(source: &[u8], span: SequenceSpan) -> &[u8] {
    &source[span.start..span.end]
}
impl SerializePayload for RowsView<'_> {
    fn serialize(&self, writer: &mut nc::Encoder<'_>) -> std::result::Result<(), nc::Error> {
        nc::write_element_sequence::<RowView<'_>, _>(
            writer,
            self.rows.iter().map(|row| RowView {
                authorization: bytes(self.source, row[0]),
                observation: bytes(self.source, row[1]),
                commit: bytes(self.source, row[2]),
                retirement: bytes(self.source, row[3]),
            }),
        )
    }
}
impl SerializePayload for Destination<'_> {
    fn serialize(&self, writer: &mut nc::Encoder<'_>) -> std::result::Result<(), nc::Error> {
        #[derive(norito::NoritoSerialize)]
        struct View<'a> {
            phase: Phase,
            original: [u8; 32],
            reservation: Option<[u8; 32]>,
            pending_original: &'a [u8],
            dispatch: &'a [u8],
            closing: &'a [u8],
            closed: &'a [u8],
            rows: nc::PayloadRef<'a, RowsView<'a>>,
        }
        let rows = RowsView {
            source: self.source,
            rows: &self.index.rows[..self.index.count],
        };
        View {
            phase: self.index.phase.ok_or_else(bad)?,
            original: self.index.original,
            reservation: self.index.reservation,
            pending_original: bytes(self.source, self.index.pending),
            dispatch: bytes(self.source, self.index.root[0]),
            closing: bytes(self.source, self.index.root[1]),
            closed: bytes(self.source, self.index.root[2]),
            rows: nc::PayloadRef(&rows),
        }
        .serialize(writer)
    }
}
impl PreparedRecordDestination<Wire> for Destination<'_> {
    fn reset(&mut self) {
        self.index = Index::default();
    }
}

/// One authenticated image and its bounded, lazy canonical child-frame locations.
pub(super) struct Image {
    bytes: Vec<u8>,
    index: Index,
}
impl Image {
    fn decode(bytes: Vec<u8>, pending_maximum: usize) -> Result<Self> {
        let image = Self::decode_envelope(bytes, pending_maximum)?;
        image.validate_shape()?;
        Ok(image)
    }
    fn decode_envelope(bytes: Vec<u8>, pending_maximum: usize) -> Result<Self> {
        let maximum = MAX_IMAGE_BYTES.max(pending_maximum.saturating_add(1024));
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(invalid("operation metadata image exceeds its bound"));
        }
        let layouts = PreparedDecodeWorkspace::allocation_layouts();
        let budget = AllocationBudget::new(layouts.iter().map(std::alloc::Layout::size).sum());
        let mut reservation = budget
            .try_reserve_layouts(layouts)
            .map_err(|_| invalid("operation metadata decode control allocation refused"))?;
        let mut decoder = PreparedDecodeWorkspace::from_reservation(&budget, &mut reservation)
            .map_err(|_| invalid("operation metadata decode controls unavailable"))?;
        let mut destination = Destination {
            source: &bytes,
            index: Index::default(),
            pending_maximum,
        };
        decoder
            .decode_canonical_into::<Wire, _>(
                &bytes,
                norito::DecodeLimits::new(maximum, maximum, maximum, maximum.saturating_mul(2), 32),
                &mut destination,
            )
            .map_err(|_| invalid("invalid canonical operation metadata image"))?;
        let index = destination.index;
        let image = Self { bytes, index };
        Ok(image)
    }
    fn validate_shape(&self) -> Result<()> {
        let phase = self
            .index
            .phase
            .ok_or_else(|| invalid("operation metadata phase missing"))?;
        let root = self.index.root.map(|s| s.start != s.end);
        let pending = self.index.pending.start != self.index.pending.end;
        let initialization = matches!(
            phase,
            Phase::Unselected | Phase::ReservedBody | Phase::PublishingOriginal | Phase::Pristine
        );
        if (phase != Phase::PublishingOriginal && self.bytes.len() > MAX_IMAGE_BYTES)
            || (phase == Phase::Unselected
                && (self.index.original != [0; 32] || self.index.reservation.is_some()))
            || (initialization && (root != [false; 3] || self.index.count != 0))
            || (pending != (phase == Phase::PublishingOriginal))
            || (phase == Phase::ReservedBody
                && (self.index.original != [0; 32] || self.index.reservation.is_none()))
            || (!matches!(phase, Phase::Unselected | Phase::ReservedBody)
                && self.index.original == [0; 32])
            || (matches!(phase, Phase::Reserved | Phase::Published) && root != [true, false, false])
            || (phase == Phase::Closing && (!root[1] || root[2]))
            || (phase == Phase::Closed && (!root[1] || !root[2]))
        {
            return Err(invalid("operation metadata phase and fields disagree"));
        }
        Ok(())
    }
    pub(super) fn require_original(&self, semantic: [u8; 32]) -> Result<()> {
        if matches!(
            self.index.phase,
            Some(Phase::Unselected | Phase::ReservedBody | Phase::PublishingOriginal)
        ) || self.index.original != semantic
        {
            return Err(invalid(
                "operation metadata differs from its published Original",
            ));
        }
        Ok(())
    }
    pub(super) fn require_phase(
        &self,
        dispatch: Option<&Dispatch>,
        closing: bool,
        closed: bool,
    ) -> Result<()> {
        let phase = if closed {
            Phase::Closed
        } else if closing {
            Phase::Closing
        } else {
            match dispatch.map(|d| d.state) {
                None => Phase::Pristine,
                Some(ReservationState::Reserved) => Phase::Reserved,
                Some(ReservationState::Published) => Phase::Published,
            }
        };
        if self.index.phase != Some(phase) {
            return Err(invalid("operation phase differs from its dispatch state"));
        }
        Ok(())
    }
    pub(super) fn same_bytes(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
    pub(super) fn row_count(&self) -> usize {
        self.index.count
    }
    fn component(&self, ordinal: Option<u8>, component: usize) -> Result<&[u8]> {
        let span = match ordinal {
            None => *self
                .index
                .root
                .get(component)
                .ok_or_else(|| invalid("unknown operation metadata component"))?,
            Some(ordinal) => {
                let index = usize::from(ordinal)
                    .checked_sub(1)
                    .filter(|i| *i < MAX_ATTEMPTS)
                    .ok_or_else(|| invalid("operation metadata ordinal exceeds its bound"))?;
                if index >= self.index.count {
                    return Ok(&[]);
                }
                *self.index.rows[index]
                    .get(component)
                    .ok_or_else(|| invalid("unknown attempt metadata component"))?
            }
        };
        Ok(bytes(&self.bytes, span))
    }
    pub(super) fn read<T: norito::NoritoSerialize + for<'a> norito::NoritoDeserialize<'a>>(
        &self,
        ordinal: Option<u8>,
        component: usize,
    ) -> Result<Option<T>> {
        let bytes = self.component(ordinal, component)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("dispatch custody record exceeds its bound"));
        }
        #[cfg(test)]
        let _timing = finish_timing::phase(finish_timing::Phase::AttemptScopedRecordDecode);
        let value = decode_record(bytes)?;
        #[cfg(test)]
        tests::parse_digest_tests::record_decoded();
        Ok(Some(value))
    }
    fn owned(&self) -> Wire {
        Wire {
            phase: self.index.phase.expect("authenticated image phase"),
            original: self.index.original,
            reservation: self.index.reservation,
            pending_original: bytes(&self.bytes, self.index.pending).to_vec(),
            dispatch: bytes(&self.bytes, self.index.root[0]).to_vec(),
            closing: bytes(&self.bytes, self.index.root[1]).to_vec(),
            closed: bytes(&self.bytes, self.index.root[2]).to_vec(),
            rows: self.index.rows[..self.index.count]
                .iter()
                .map(|r| Row {
                    authorization: bytes(&self.bytes, r[0]).to_vec(),
                    observation: bytes(&self.bytes, r[1]).to_vec(),
                    commit: bytes(&self.bytes, r[2]).to_vec(),
                    retirement: bytes(&self.bytes, r[3]).to_vec(),
                })
                .collect(),
        }
    }
}
fn wire(
    phase: Phase,
    original: [u8; 32],
    reservation: Option<[u8; 32]>,
    pending_original: Vec<u8>,
) -> Wire {
    Wire {
        phase,
        original,
        reservation,
        pending_original,
        dispatch: Vec::new(),
        closing: Vec::new(),
        closed: Vec::new(),
        rows: Vec::new(),
    }
}
fn encode_image(image: &Wire, maximum: usize) -> Result<Vec<u8>> {
    encode(image, maximum)
}
pub(super) fn load(operation: &PrivateDirectory) -> Result<Image> {
    operation.read_scope(load_in_scope)
}
pub(super) fn load_in_scope(reader: &mut iroha_fs::PrivateReadScope<'_>) -> Result<Image> {
    #[cfg(test)]
    let _timing = finish_timing::phase(finish_timing::Phase::AttemptScopedRecordRead);
    #[cfg(test)]
    tests::parse_digest_tests::record_read();
    let bytes = reader
        .read_admitted(
            FILE,
            MAX_IMAGE_BYTES,
            (
                |length| {
                    usize::try_from(length).map_err(|_| invalid("operation image length overflow"))
                },
                |length| {
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(length)
                        .map_err(|_| invalid("operation image allocation refused"))?;
                    bytes.resize(length, 0);
                    Ok::<_, crate::managed::Error>(bytes)
                },
            ),
            |_| Ok(()),
            (crate::managed::Error::from, |_| {
                invalid("operation image changed during native read")
            }),
        )?
        .ok_or_else(|| invalid("operation metadata image is absent"))?;
    Image::decode(bytes, 0)
}
fn replace(
    operation: &PrivateDirectory,
    expected: &Image,
    next: &Wire,
    maximum: usize,
) -> Result<()> {
    operation.revalidate()?;
    let identity = operation.identity()?;
    let bytes = encode_image(next, maximum)?;
    if operation.read(FILE, maximum)?.as_slice() != expected.bytes {
        return Err(invalid("operation metadata changed before publication"));
    }
    operation.write_atomic(FILE, &bytes, PublishMode::Replace)?;
    if operation.identity()? != identity || operation.read(FILE, maximum)?.as_slice() != bytes {
        return Err(invalid("operation metadata changed during publication"));
    }
    operation.revalidate()?;
    Ok(())
}
pub(super) fn update_dispatch(
    operation: &PrivateDirectory,
    expected: Option<&Dispatch>,
    next: &Dispatch,
) -> Result<()> {
    let image = load(operation)?;
    image.require_original(next.semantic)?;
    if image.read::<Dispatch>(None, 0)?.as_ref() != expected
        || !image.component(None, 1)?.is_empty()
        || !image.component(None, 2)?.is_empty()
    {
        return Err(invalid("dispatch high-water changed before publication"));
    }
    let mut value = image.owned();
    value.dispatch = encode(next, MAX_RECORD_BYTES)?;
    value.phase = match next.state {
        ReservationState::Reserved => Phase::Reserved,
        ReservationState::Published => Phase::Published,
    };
    if next.state == ReservationState::Published {
        let ordinal = usize::from(next.highest.ordinal);
        let authorization = encode(&next.highest, MAX_RECORD_BYTES)?;
        if value.rows.len() + 1 == ordinal {
            value.rows.push(Row {
                authorization,
                observation: Vec::new(),
                commit: Vec::new(),
                retirement: Vec::new(),
            });
        } else if value.rows.len() != ordinal
            || value
                .rows
                .last()
                .is_none_or(|r| r.authorization != authorization)
        {
            return Err(invalid(
                "published attempt metadata differs from its reservation",
            ));
        }
    }
    replace(operation, &image, &value, MAX_IMAGE_BYTES)
}
pub(super) fn retain<T: norito::NoritoSerialize>(
    operation: &PrivateDirectory,
    row: Option<&PrivateDirectory>,
    ordinal: Option<u8>,
    component: usize,
    value: &T,
    validate: impl FnOnce(&Image) -> Result<()>,
) -> Result<()> {
    if let Some(row) = row {
        row.revalidate()?;
    }
    let result = retain_inner(operation, ordinal, component, value, validate);
    if let Some(row) = row {
        row.revalidate()?;
    }
    result
}
fn retain_inner<T: norito::NoritoSerialize>(
    operation: &PrivateDirectory,
    ordinal: Option<u8>,
    component: usize,
    value: &T,
    validate: impl FnOnce(&Image) -> Result<()>,
) -> Result<()> {
    let image = load(operation)?;
    validate(&image)?;
    if matches!(
        image.index.phase,
        Some(
            Phase::Unselected
                | Phase::ReservedBody
                | Phase::PublishingOriginal
                | Phase::Pristine
                | Phase::Closed
        )
    ) && ordinal.is_some()
    {
        return Err(invalid(
            "attempt metadata is not writable in this operation phase",
        ));
    }
    let bytes = encode(value, MAX_RECORD_BYTES)?;
    let old = image.component(ordinal, component)?;
    if !old.is_empty() {
        return if old == bytes {
            Ok(())
        } else {
            Err(invalid("immutable dispatch custody record changed"))
        };
    }
    let mut next = image.owned();
    match ordinal {
        Some(ordinal) => {
            let row = next
                .rows
                .get_mut(usize::from(ordinal) - 1)
                .ok_or_else(|| invalid("attempt metadata is not published"))?;
            match component {
                1 => row.observation = bytes,
                2 => row.commit = bytes,
                3 => row.retirement = bytes,
                _ => {
                    return Err(invalid(
                        "attempt authorization is owned by reservation publication",
                    ));
                }
            }
        }
        None => match component {
            1 if next.phase != Phase::Closed => {
                next.closing = bytes;
                next.phase = Phase::Closing;
            }
            2 if next.phase == Phase::Closing => {
                next.closed = bytes;
                next.phase = Phase::Closed;
            }
            _ => return Err(invalid("illegal operation closure transition")),
        },
    }
    replace(operation, &image, &next, MAX_IMAGE_BYTES)
}

/// Atomically create the metadata owner with a new fixed operation directory.
/// An existing directory never synthesizes a lost image, even when every leaf was deleted.
pub(in crate::managed) fn ensure_operation(
    parent: &PrivateDirectory,
    name: &str,
) -> Result<PrivateDirectory> {
    if let Some(operation) = parent.open_child_optional(name)? {
        if !operation.entries(4)?.iter().any(|entry| entry == FILE) {
            return Err(invalid("retained operation lost its metadata image"));
        }
        return Ok(operation);
    }
    let image = encode_image(
        &wire(Phase::Unselected, [0; 32], None, Vec::new()),
        MAX_IMAGE_BYTES,
    )?;
    Ok(parent.publish_private_child(name, &[(FILE, image.as_slice())])?)
}
/// The exact no-intent state; ordinary readers do not repair any other phase.
pub(in crate::managed) fn require_unselected(operation: &PrivateDirectory) -> Result<()> {
    let image = load(operation)?;
    if image.index.phase != Some(Phase::Unselected)
        || operation.entries(1)?.as_slice() != [std::ffi::OsString::from(FILE)]
    {
        return Err(invalid("operation is not its retained unselected state"));
    }
    Ok(())
}

/// Exact initial reserved-body image, published atomically with its reservation by the body owner.
pub(in crate::managed) fn reserved_body(reservation: &[u8]) -> Result<Vec<u8>> {
    encode_image(
        &wire(
            Phase::ReservedBody,
            [0; 32],
            Some(Hash::new(reservation).into()),
            Vec::new(),
        ),
        MAX_IMAGE_BYTES,
    )
}
/// Read-only Original admission. Neither missing metadata nor a pending publication is repaired.
pub(in crate::managed) fn require_published(
    operation: &PrivateDirectory,
    original: &[u8],
) -> Result<()> {
    load(operation)?.require_original(Hash::new(original).into())
}
/// Start an exact retained publication, then materialize those same bytes. The concrete publisher
/// validates its canonical Original before entering; recovery validates the retained bytes again.
pub(in crate::managed) fn publish_original(
    operation: &PrivateDirectory,
    original: &[u8],
    maximum: usize,
    conflict: &'static str,
) -> Result<bool> {
    if original.is_empty() || original.len() > maximum {
        return Err(invalid("Original exceeds its purpose bound"));
    }
    let semantic = Hash::new(original).into();
    let image = Image::decode(operation.read(FILE, MAX_IMAGE_BYTES)?.to_vec(), 0)?;
    match image.index.phase {
        Some(Phase::Unselected) => require_unselected(operation)?,
        Some(Phase::ReservedBody) => require_reserved_image(operation, &image)?,
        _ => {
            let retained = operation.read("original.nrt", maximum)?;
            image.require_original(Hash::new(&retained).into())?;
            if retained.as_slice() != original {
                return Err(invalid(conflict));
            }
            return Ok(false);
        }
    }
    let pending = wire(
        Phase::PublishingOriginal,
        semantic,
        image.index.reservation,
        original.to_vec(),
    );
    let pending_maximum = maximum
        .checked_add(1024)
        .ok_or_else(|| invalid("Original publication bound overflow"))?;
    replace(operation, &image, &pending, pending_maximum)?;
    recover_original(operation, maximum, |bytes| {
        if bytes == original {
            Ok(())
        } else {
            Err(invalid(conflict))
        }
    })?;
    Ok(true)
}
/// Explicit producer recovery only. It runs before selecting fresh terms/checkpoints and promotes
/// only the already retained exact Original. This supplies no current authority or expiry waiver.
pub(in crate::managed) fn recover_original(
    operation: &PrivateDirectory,
    maximum: usize,
    validate: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<()> {
    let bound = maximum
        .checked_add(1024)
        .ok_or_else(|| invalid("Original publication bound overflow"))?
        .max(MAX_IMAGE_BYTES);
    let raw = operation.read(FILE, bound)?;
    let image = Image::decode(raw.to_vec(), maximum)?;
    if image.index.phase != Some(Phase::PublishingOriginal) {
        if image.index.phase == Some(Phase::Unselected) {
            require_unselected(operation)?;
        } else if image.index.phase == Some(Phase::ReservedBody) {
            require_reserved_image(operation, &image)?;
        } else {
            let original = operation.read("original.nrt", maximum)?;
            image.require_original(Hash::new(&original).into())?;
        }
        return Ok(());
    }
    if operation.entries(3)?.iter().any(|name| {
        name != FILE
            && name != "original.nrt"
            && !(image.index.reservation.is_some() && name == "reserved.nrt")
    }) {
        return Err(invalid(
            "pending Original publication contains later material",
        ));
    }
    let original = bytes(&image.bytes, image.index.pending);
    if *Hash::new(original).as_ref() != image.index.original {
        return Err(invalid("pending Original commitment changed"));
    }
    validate(original)?;
    if operation.entries(3)?.iter().any(|name| {
        name != FILE
            && name != "original.nrt"
            && !(image.index.reservation.is_some() && name == "reserved.nrt")
    }) || operation.read(FILE, bound)?.as_slice() != image.bytes
    {
        return Err(invalid(
            "pending Original custody changed during validation",
        ));
    }
    if let Some(reservation) = image.index.reservation
        && *Hash::new(&operation.read("reserved.nrt", MAX_RESERVATION_BYTES)?).as_ref()
            != reservation
    {
        return Err(invalid("pending Original reservation changed"));
    }
    if let Some(retained) = operation.read_optional("original.nrt", maximum)? {
        if retained.as_slice() != original {
            return Err(invalid("pending Original differs from retained Original"));
        }
    } else {
        operation.write_atomic("original.nrt", original, PublishMode::CreateNew)?;
    }
    if operation.read("original.nrt", maximum)?.as_slice() != original {
        return Err(invalid("pending Original changed during materialization"));
    }
    let next = wire(
        Phase::Pristine,
        image.index.original,
        image.index.reservation,
        Vec::new(),
    );
    replace(operation, &image, &next, bound)?;
    if operation.entries(3)?.iter().any(|name| {
        name != FILE
            && name != "original.nrt"
            && !(image.index.reservation.is_some() && name == "reserved.nrt")
    }) {
        return Err(invalid("Original publication acquired unexpected material"));
    }
    Ok(())
}

fn require_reserved_image(operation: &PrivateDirectory, image: &Image) -> Result<()> {
    if image.index.phase != Some(Phase::ReservedBody)
        || operation
            .entries(2)?
            .iter()
            .any(|name| name != FILE && name != "reserved.nrt")
        || image.index.reservation
            != Some(Hash::new(&operation.read("reserved.nrt", MAX_RESERVATION_BYTES)?).into())
    {
        return Err(invalid("reserved body operation metadata changed"));
    }
    Ok(())
}
/// Admit only the explicitly created no-Original body phase; this never initializes metadata.
pub(in crate::managed) fn require_reserved(operation: &PrivateDirectory) -> Result<()> {
    require_reserved_image(operation, &load(operation)?)
}

#[cfg(test)]
fn test_component_index(ordinal: Option<u8>, name: &str) -> Result<usize> {
    match (ordinal, name) {
        (None, "dispatch" | "dispatch.nrt") | (Some(_), "authorization" | "authorization.nrt") => {
            Ok(0)
        }
        (None, "closing" | "closing.nrt") | (Some(_), "observation" | "observation.nrt") => Ok(1),
        (None, "closed" | "closed.nrt") | (Some(_), "committed" | "committed.nrt") => Ok(2),
        (Some(_), "retired" | "retired.nrt") => Ok(3),
        _ => Err(invalid("unknown test metadata component")),
    }
}
/// Explicit test fixture producer for an already written exact Original. No reader uses it.
#[cfg(test)]
pub(in crate::managed) fn test_initialize(
    operation: &PrivateDirectory,
    original: &[u8],
) -> Result<()> {
    if operation.read("original.nrt", original.len())?.as_slice() != original {
        return Err(invalid("test Original mismatch"));
    }
    operation.write_atomic(
        FILE,
        &encode_image(
            &wire(
                Phase::Pristine,
                Hash::new(original).into(),
                None,
                Vec::new(),
            ),
            MAX_IMAGE_BYTES,
        )?,
        PublishMode::CreateNew,
    )?;
    Ok(())
}
/// Inspect raw child bytes without incrementing production physical or logical counters.
#[cfg(test)]
pub(in crate::managed) fn test_read_component(
    operation: &PrivateDirectory,
    ordinal: Option<u8>,
    name: &str,
) -> Result<Option<Vec<u8>>> {
    let image = Image::decode_envelope(operation.read(FILE, MAX_IMAGE_BYTES)?.to_vec(), 0)?;
    let value = image.component(ordinal, test_component_index(ordinal, name)?)?;
    Ok((!value.is_empty()).then(|| value.to_vec()))
}
/// Inspect through the actual retained operation owner, never an inferred parent path.
#[cfg(test)]
pub(in crate::managed) fn test_read_attempt_component(
    attempt: &Attempt,
    name: &str,
) -> Result<Option<Vec<u8>>> {
    test_read_component(&attempt.operation, Some(attempt.ordinal()), name)
}
/// Prepare a canonical envelope containing deliberately corrupted/missing logical child bytes.
/// Prepare outside an inherited decoder hook; the actual hook need only publish these bytes.
#[cfg(test)]
pub(in crate::managed) fn test_changed_image(
    image_bytes: &[u8],
    ordinal: Option<u8>,
    name: &str,
    replacement: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let image = Image::decode_envelope(image_bytes.to_vec(), 0)?;
    let component = test_component_index(ordinal, name)?;
    let mut next = image.owned();
    let replacement = replacement.unwrap_or_default().to_vec();
    if let Some(ordinal) = ordinal {
        let row = next
            .rows
            .get_mut(
                usize::from(ordinal)
                    .checked_sub(1)
                    .ok_or_else(|| invalid("test row absent"))?,
            )
            .ok_or_else(|| invalid("test row absent"))?;
        match component {
            0 => row.authorization = replacement,
            1 => row.observation = replacement,
            2 => row.commit = replacement,
            3 => row.retirement = replacement,
            _ => unreachable!(),
        }
    } else {
        match component {
            0 => next.dispatch = replacement,
            1 => next.closing = replacement,
            2 => next.closed = replacement,
            _ => unreachable!(),
        }
    }
    encode_image(&next, MAX_IMAGE_BYTES)
}
/// Publish one deliberately changed logical test component, retaining every sibling byte.
#[cfg(test)]
pub(in crate::managed) fn test_replace_component(
    operation: &PrivateDirectory,
    ordinal: Option<u8>,
    name: &str,
    replacement: Option<&[u8]>,
) -> Result<()> {
    let changed = test_changed_image(
        &operation.read(FILE, MAX_IMAGE_BYTES)?,
        ordinal,
        name,
        replacement,
    )?;
    operation.write_atomic(FILE, &changed, PublishMode::Replace)?;
    Ok(())
}

/// Stage exact interrupted publisher bytes for real coordinator recovery tests.
#[cfg(test)]
pub(in crate::managed) fn test_pending_original(
    operation: &PrivateDirectory,
    original: &[u8],
    maximum: usize,
) -> Result<()> {
    if original.is_empty() || original.len() > maximum {
        return Err(invalid("test pending Original exceeds bound"));
    }
    let old = operation.read_optional(FILE, MAX_IMAGE_BYTES)?;
    let reservation = old
        .as_ref()
        .map(|bytes| Image::decode_envelope(bytes.to_vec(), 0))
        .transpose()?
        .and_then(|image| image.index.reservation);
    let bytes = encode_image(
        &wire(
            Phase::PublishingOriginal,
            Hash::new(original).into(),
            reservation,
            original.to_vec(),
        ),
        maximum + 1024,
    )?;
    operation.write_atomic(
        FILE,
        &bytes,
        if old.is_some() {
            PublishMode::Replace
        } else {
            PublishMode::CreateNew
        },
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod bounds_tests;
