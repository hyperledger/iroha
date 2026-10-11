//! One canonical ordered signature sequence and its exact original physical custody.
//!
//! Runtime admission has no wire tag. Prepared values own fixed collection backing,
//! every exact signature allocation and one immutable shared control. A shared clone
//! retains those same owners; no mutable or allocation extraction API is exposed.

use super::{
    BlockHeader, BlockSignature,
    header::{BlockSignatureRecord, validate_block_signature_payload},
};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer, ChargedBufferError,
    ChargedShared, PrepaidSharedError,
};
use iroha_crypto::{ChargedSignature, Hash, SignatureOf};
use iroha_schema::{IntoSchema, MetaMap, Metadata, TypeId, VecMeta};
use norito::core::{
    CanonicalField, DecodeField, DecodeFromSlice, DecodeIntoError, DecodeRecordFields, Encoder,
    FieldDestination, PreparedElementSequence, SequenceDestinationError, SequenceSpan,
    prepare_element_sequence,
};
use std::{alloc::Layout, cmp::Ordering, fmt};

const CAP: usize = crate::sumeragi::epoch::MAX_VALIDATORS;

/// The sole ordered, duplicate-free block-signature collection.
///
/// Offchain construction/ordinary decoding is untrusted. A production prepared
/// owner retains exact original pool custody, including every signature byte.
/// Cloning an admitted collection shares its immutable owners without allocation.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::block::BlockSignatures")]
pub struct BlockSignatures {
    storage: Storage,
}
enum Storage {
    Untrusted(Vec<BlockSignature>),
    Admitted(ChargedShared<Funded>),
}
struct Funded {
    // Destroy all canonical signature allocations before refunding their ledger.
    values: ChargedBuffer<BlockSignature>,
    charges: ChargedBuffer<AllocationCharge>,
    budget: AllocationBudget,
}
impl Funded {
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.budget.same_pool(budget)
            && self.values.belongs_to(budget)
            && self.charges.belongs_to(budget)
            && self
                .charges
                .as_slice()
                .iter()
                .all(|charge| charge.belongs_to(budget))
    }
}
impl BlockSignatures {
    /// Construct an untrusted collection in canonical order from ordinary inputs.
    ///
    /// Equal signatures are deduplicated. At most the global validator bound of
    /// distinct signatures is retained, regardless of the iterator's size hint;
    /// the first additional distinct signature stops iteration and is rejected.
    /// This establishes neither signature authority nor physical pool custody.
    ///
    /// # Errors
    /// Rejects more than 31 distinct signatures or failure to reserve the one
    /// bounded collection backing. The input iterator is not consumed further
    /// after either refusal.
    pub fn try_from_iter<I>(signatures: I) -> Result<Self, norito::Error>
    where
        I: IntoIterator<Item = BlockSignature>,
    {
        let mut values = Vec::<BlockSignature>::new();
        for signature in signatures {
            let Err(index) = values.binary_search(&signature) else {
                continue;
            };
            if values.len() >= CAP {
                return Err(norito::Error::NonCanonicalEncoding);
            }
            if values.capacity() == 0 {
                let layout = Layout::array::<BlockSignature>(CAP)
                    .map_err(|_| norito::Error::LengthMismatch)?;
                values
                    .try_reserve_exact(CAP)
                    .map_err(|_| norito::Error::AllocationFailed {
                        bytes: u64::try_from(layout.size()).unwrap_or(u64::MAX),
                    })?;
            }
            values.insert(index, signature);
        }
        Self::from_ordered(values)
    }
    /// Borrow the exact ordered original values, without granting mutation.
    pub fn as_slice(&self) -> &[BlockSignature] {
        match &self.storage {
            Storage::Untrusted(values) => values,
            Storage::Admitted(owner) => owner.values.as_slice(),
        }
    }
    /// Iterate the same immutable ordered signature values.
    pub fn iter(&self) -> std::slice::Iter<'_, BlockSignature> {
        self.as_slice().iter()
    }
    /// Exact initialized count.
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }
    /// Whether no validator supplied a block signature.
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
    /// Whether collection/control/every signature charge retain this exact pool.
    pub fn admitted_to(&self, budget: &AllocationBudget) -> bool {
        match &self.storage {
            Storage::Untrusted(_) => false,
            Storage::Admitted(owner) => {
                owner.belongs_to(budget) && Funded::belongs_to(owner, budget)
            }
        }
    }
    /// Whether two admitted collections retain the same immutable physical owner.
    /// Untrusted values never gain custody identity by having equal bytes.
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        match (&left.storage, &right.storage) {
            (Storage::Admitted(left), Storage::Admitted(right)) => {
                ChargedShared::ptr_eq(left, right)
            }
            _ => false,
        }
    }
    /// Exact immutable collection control layout, separate from all child backings.
    pub fn allocation_layout() -> Layout {
        ChargedShared::<Funded>::allocation_layout()
    }
    /// Exact original typed collection and signature-ledger backing layouts.
    ///
    /// # Errors
    /// Rejects an unrepresentable count before any capacity acquisition.
    pub fn backing_layouts(count: usize) -> Result<[Layout; 2], AllocationRefusal> {
        Ok([
            Layout::array::<BlockSignature>(count)
                .map_err(|_| AllocationRefusal::DemandOverflow)?,
            Layout::array::<AllocationCharge>(count)
                .map_err(|_| AllocationRefusal::DemandOverflow)?,
        ])
    }
    /// Insert during untrusted proposal construction only.
    ///
    /// # Errors
    /// Admitted immutable custody cannot be edited or downgraded to an uncharged clone.
    pub fn try_insert(&mut self, signature: BlockSignature) -> Result<bool, iroha_crypto::Error> {
        let Storage::Untrusted(values) = &mut self.storage else {
            return Err(iroha_crypto::Error::Signing(
                "admitted block signatures are immutable".into(),
            ));
        };
        match values.binary_search(&signature) {
            Ok(_) => Ok(false),
            Err(index) => {
                if values.len() >= CAP {
                    return Err(iroha_crypto::Error::Signing(
                        "block signatures exceed the global validator bound".into(),
                    ));
                }
                values.insert(index, signature);
                Ok(true)
            }
        }
    }
    /// Admit only the empty local-construction leaf from its original finite pool.
    /// This grants no signature or block authority and never decodes a second graph.
    #[cfg(feature = "transparent_api")]
    pub(super) fn prepare_local_unsigned(
        &mut self,
        budget: &AllocationBudget,
    ) -> Result<(), BlockSignatureCustodyError> {
        if !self.is_empty() {
            return Err(BlockSignatureCustodyError::UnsignedProfile);
        }
        if matches!(&self.storage, Storage::Admitted(_)) {
            return if self.admitted_to(budget) {
                Ok(())
            } else {
                Err(BlockSignatureCustodyError::ForeignPool)
            };
        }
        // Admit and allocate the sole exact immutable control before touching the source.
        // Zero-capacity typed backings allocate nothing and keep this same pool identity.
        let mut reservation = budget
            .try_reserve(Self::allocation_layout())
            .map_err(BlockSignatureCustodyError::ControlAdmission)?;
        let shell = ChargedShared::<Funded>::reserve_from(&mut reservation)
            .map_err(BlockSignatureCustodyError::ControlAllocation)?;
        let values = ChargedBuffer::<BlockSignature>::new(0, budget)?;
        let charges = ChargedBuffer::<AllocationCharge>::new(0, budget)?;
        let owner = shell.initialize(Funded {
            values,
            charges,
            budget: budget.clone(),
        });
        self.storage = Storage::Admitted(owner);
        Ok(())
    }

    #[cfg(any(test, feature = "transparent_api"))]
    pub(super) fn permits_replacement(&self, replacement: &Self) -> bool {
        match &self.storage {
            Storage::Untrusted(_) => true,
            Storage::Admitted(owner) => replacement.admitted_to(&owner.budget),
        }
    }
    fn from_ordered(values: Vec<BlockSignature>) -> Result<Self, norito::Error> {
        if values.len() > CAP || values.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(norito::Error::NonCanonicalEncoding);
        }
        Ok(Self {
            storage: Storage::Untrusted(values),
        })
    }
}
impl Default for BlockSignatures {
    fn default() -> Self {
        Self {
            storage: Storage::Untrusted(Vec::new()),
        }
    }
}
impl<'a> IntoIterator for &'a BlockSignatures {
    type Item = &'a BlockSignature;
    type IntoIter = std::slice::Iter<'a, BlockSignature>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl Clone for BlockSignatures {
    fn clone(&self) -> Self {
        Self {
            storage: match &self.storage {
                Storage::Untrusted(values) => Storage::Untrusted(values.clone()),
                Storage::Admitted(owner) => Storage::Admitted(owner.clone()),
            },
        }
    }
}
impl fmt::Debug for BlockSignatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}
impl PartialEq for BlockSignatures {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for BlockSignatures {}
impl PartialOrd for BlockSignatures {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for BlockSignatures {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}
impl norito::core::SerializePayload for BlockSignatures {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        if self.len() > CAP {
            return Err(norito::Error::NonCanonicalEncoding);
        }
        norito::core::write_element_sequence::<BlockSignature, _>(writer, self.iter())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        if self.len() > CAP {
            return None;
        }
        norito::core::sequence_encoded_len_hint(self.iter())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        if self.len() > CAP {
            return None;
        }
        norito::core::sequence_encoded_len_exact(self.iter())
    }
}
fn signature_plan<'input, 'scratch>(
    bytes: &'input [u8],
    scratch: &'scratch mut [SequenceSpan; CAP],
) -> Result<PreparedElementSequence<'input, 'scratch>, norito::Error> {
    prepare_element_sequence(bytes, scratch).map_err(|error| match error {
        SequenceDestinationError::Codec(original) => original,
        // The sole canonical global signature collection is bounded by 31 seats.
        // Count/format/minimum-framing admission precedes this intrinsic size check.
        SequenceDestinationError::Storage { .. } => norito::Error::NonCanonicalEncoding,
    })
}
impl<'de> DecodeFromSlice<'de> for BlockSignatures {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::Error> {
        let mut spans = [SequenceSpan { start: 0, end: 0 }; CAP];
        let plan = signature_plan(bytes, &mut spans)?;
        let count = plan.len();
        let mut values: Vec<BlockSignature> = Vec::new();
        let mut allocated = false;
        plan.decode_elements::<BlockSignature, std::convert::Infallible>(|_, field| {
            if !allocated {
                values
                    .try_reserve_exact(count)
                    .map_err(|_| norito::Error::AllocationFailed {
                        bytes: u64::try_from(
                            std::mem::size_of::<BlockSignature>().saturating_mul(count),
                        )
                        .unwrap_or(u64::MAX),
                    })?;
                allocated = true;
            }
            let value = field.decode_owned()?;
            if values.last().is_some_and(|previous| previous >= &value) {
                return Err(norito::Error::NonCanonicalEncoding.into());
            }
            values.push(value);
            Ok(())
        })
        .map_err(DecodeIntoError::into_codec)?;
        Ok((Self::from_ordered(values)?, plan.used()))
    }
}
impl<'de> norito::core::DeserializePayload<'de> for BlockSignatures {
    fn deserialize(archive: &'de norito::Archived<Self>) -> Self {
        Self::try_deserialize(archive).expect("canonical ordered block signatures")
    }
    fn try_deserialize(archive: &'de norito::Archived<Self>) -> Result<Self, norito::Error> {
        norito::core::with_context_fields(std::ptr::from_ref(archive).cast::<u8>(), |bytes| {
            Self::decode_from_slice(bytes).map(|(value, _)| value)
        })?
    }
}
impl TypeId for BlockSignatures {
    fn id() -> String {
        "BlockSignatures".into()
    }
}
impl IntoSchema for BlockSignatures {
    fn type_name() -> String {
        "BlockSignatures".into()
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Vec(VecMeta {
                ty: std::any::TypeId::of::<BlockSignature>(),
            }));
            BlockSignature::update_schema_map(map);
        }
    }
}
impl norito::json::JsonSerialize for BlockSignatures {
    fn json_serialize(&self, out: &mut String) {
        out.push('[');
        for (index, signature) in self.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            norito::json::JsonSerialize::json_serialize(signature, out);
        }
        out.push(']');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        out.push('[')?;
        for (index, signature) in self.iter().enumerate() {
            if index != 0 {
                out.push(',')?;
            }
            norito::json::JsonSerialize::json_serialize_to(signature, out)?;
        }
        out.push(']')?;
        out.end_container();
        Ok(())
    }
}
impl norito::json::JsonDeserialize for BlockSignatures {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        Self::from_ordered(
            <Vec<BlockSignature> as norito::json::JsonDeserialize>::json_deserialize(parser)?,
        )
        .map_err(|error| norito::json::Error::Message(error.to_string()))
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        Self::from_ordered(
            <Vec<BlockSignature> as norito::json::JsonDeserialize>::json_from_value(value)?,
        )
        .map_err(|error| norito::json::Error::Message(error.to_string()))
    }
}

/// Original-source, canonical-wire or exact physical signature-custody refusal.
#[derive(Debug, thiserror::Error)]
pub enum BlockSignatureCustodyError {
    /// Local construction admits only empty signatures on a resultless proposal.
    #[error("local signature custody requires an unsigned resultless proposal")]
    UnsignedProfile,
    /// Original charged input or budget changed.
    #[error("block signature source belongs to another original pool")]
    ForeignPool,
    /// Address, initialized length or complete original frame hash changed.
    #[error("block signature retry changed the original source")]
    SourceChanged,
    /// The selected canonical collection is outside the initialized source.
    #[error("block signature collection is outside its original source")]
    SourceRange,
    /// The enclosing frame has not installed its advertised layout.
    #[error("block signature preparation requires the advertised original layout")]
    MissingLayout,
    /// Original canonical/refusal cause, captured before caller scope retirement.
    #[error(transparent)]
    Decode(#[from] norito::core::DecodeAttemptError),
    /// Original pool/allocator refused actual collection, ledger or leaf backing.
    #[error(transparent)]
    Buffer(#[from] ChargedBufferError),
    /// Original pool refused the exact immutable collection control.
    #[error(transparent)]
    ControlAdmission(#[from] AllocationRefusal),
    /// Actual immutable control allocation failed.
    #[error(transparent)]
    ControlAllocation(#[from] PrepaidSharedError),
    /// Not all exact original signature leaves have completed physical custody.
    #[error("block signature preparation is incomplete")]
    Incomplete,
}
struct Identity {
    address: usize,
    length: usize,
    hash: Hash,
}
impl Identity {
    fn new(bytes: &[u8]) -> Self {
        Self {
            address: bytes.as_ptr().addr(),
            length: bytes.len(),
            hash: Hash::new(bytes),
        }
    }
    fn matches(&self, bytes: &[u8]) -> bool {
        self.address == bytes.as_ptr().addr()
            && self.length == bytes.len()
            && self.hash == Hash::new(bytes)
    }
}
/// Source-bound exact collection/ledger/leaf owners retained through every refusal.
///
/// The enclosing owner must keep the original `ChargedBuffer` alive through this
/// attempt. Prepared spans are inline and all byte leaves use the sole signature
/// record walk. This funds signatures only; other block/result children remain
/// separate preparation obligations.
pub struct PreparedBlockSignatures {
    source: Identity,
    count: usize,
    indices: [u64; CAP],
    leaves: [SequenceSpan; CAP],
    values: Option<ChargedBuffer<BlockSignature>>,
    charges: Option<ChargedBuffer<AllocationCharge>>,
    budget: AllocationBudget,
}
impl PreparedBlockSignatures {
    /// Plan all canonical ordered signature children in one original funded source.
    ///
    /// # Errors
    /// Rejects original-pool/layout/range changes or the original canonical failure.
    pub fn from_source(
        source: &ChargedBuffer<u8>,
        span: SequenceSpan,
        budget: &AllocationBudget,
    ) -> Result<Self, BlockSignatureCustodyError> {
        if !source.belongs_to(budget) {
            return Err(BlockSignatureCustodyError::ForeignPool);
        }
        let bytes = span
            .get(source.as_slice())
            .map_err(|_| BlockSignatureCustodyError::SourceRange)?;
        if norito::core::effective_decode_flags().is_none() {
            return Err(BlockSignatureCustodyError::MissingLayout);
        }
        let (count, indices, leaves) = norito::core::classify_decode_attempt(|| {
            let mut spans = [SequenceSpan { start: 0, end: 0 }; CAP];
            let plan = signature_plan(bytes, &mut spans)?;
            let mut indices = [0; CAP];
            let mut leaves = [SequenceSpan { start: 0, end: 0 }; CAP];
            plan.decode_elements::<BlockSignature, std::convert::Infallible>(|position, field| {
                field.with_payload(|bytes| {
                    let mut leaf = Leaf {
                        source: source.as_slice(),
                        index: None,
                        payload: None,
                    };
                    let (_, used) = BlockSignatureRecord::decode_fields(bytes, &mut leaf)?;
                    if used != bytes.len() {
                        return Err(norito::Error::LengthMismatch.into());
                    }
                    let index = leaf.index.ok_or(norito::Error::LengthMismatch)?;
                    let payload = leaf.payload.ok_or(norito::Error::LengthMismatch)?;
                    if position > 0 {
                        let previous = leaves[position - 1].get(source.as_slice())?;
                        let current = payload.get(source.as_slice())?;
                        if indices[position - 1]
                            .cmp(&index)
                            .then_with(|| previous.cmp(current))
                            != Ordering::Less
                        {
                            return Err(norito::Error::NonCanonicalEncoding.into());
                        }
                    }
                    indices[position] = index;
                    leaves[position] = payload;
                    Ok(())
                })
            })
            .map_err(DecodeIntoError::into_codec)?;
            if plan.used() != bytes.len() {
                return Err(norito::Error::LengthMismatch);
            }
            Ok((plan.len(), indices, leaves))
        })?;
        Ok(Self {
            source: Identity::new(source.as_slice()),
            count,
            indices,
            leaves,
            values: None,
            charges: None,
            budget: budget.clone(),
        })
    }
    fn check(&self, source: &ChargedBuffer<u8>) -> Result<(), BlockSignatureCustodyError> {
        if !source.belongs_to(&self.budget) {
            return Err(BlockSignatureCustodyError::ForeignPool);
        }
        if !self.source.matches(source.as_slice()) {
            return Err(BlockSignatureCustodyError::SourceChanged);
        }
        Ok(())
    }
    /// Exact original collection, ledger and signature charges all use this pool.
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.budget.same_pool(budget)
            && self
                .values
                .as_ref()
                .is_none_or(|values| values.belongs_to(budget))
            && self.charges.as_ref().is_none_or(|charges| {
                charges.belongs_to(budget)
                    && charges
                        .as_slice()
                        .iter()
                        .all(|charge| charge.belongs_to(budget))
            })
    }
    /// Borrow the completed original prefix without escaping its charges.
    ///
    /// # Errors
    /// Rejects any change to the complete original source.
    pub fn initialized<'a>(
        &'a self,
        source: &ChargedBuffer<u8>,
    ) -> Result<&'a [BlockSignature], BlockSignatureCustodyError> {
        self.check(source)?;
        Ok(self.values.as_ref().map_or(&[], ChargedBuffer::as_slice))
    }
    /// Allocate exact typed/ledger backing and only missing original signature bytes.
    ///
    /// # Errors
    /// Preserves completed owners and returns exact original pool/allocator refusal.
    #[allow(unsafe_code)]
    pub fn prepare(
        &mut self,
        source: &ChargedBuffer<u8>,
    ) -> Result<(), BlockSignatureCustodyError> {
        self.check(source)?;
        if self.values.is_none() {
            self.values = Some(ChargedBuffer::new(self.count, &self.budget)?)
        }
        if self.charges.is_none() {
            self.charges = Some(ChargedBuffer::new(self.count, &self.budget)?)
        }
        let values = self.values.as_mut().expect("original collection backing");
        let charges = self
            .charges
            .as_mut()
            .expect("original signature ledger backing");
        while values.as_slice().len() < self.count {
            let index = values.as_slice().len();
            let payload = self.leaves[index]
                .get(source.as_slice())
                .map_err(|_| BlockSignatureCustodyError::SourceRange)?;
            let mut bytes = ChargedBuffer::new(payload.len(), &self.budget)?;
            bytes
                .append(payload)
                .expect("exact original signature backing");
            let original = ChargedSignature::try_from_preallocated(&self.budget, bytes)
                .unwrap_or_else(|_| {
                    unreachable!("source and exact initialization checked before allocation")
                });
            // SAFETY: both original owners move immediately into fixed values/ledger
            // backing. Values are immutable after publication, cannot escape, and
            // Funded field order destroys every signature before refunding charges.
            let (signature, charge) = unsafe { original.into_allocation_parts() };
            values.push_reserved(BlockSignature::new(
                self.indices[index],
                SignatureOf::<BlockHeader>::from_signature(signature),
            ));
            charges.push_reserved(charge);
        }
        Ok(())
    }
    /// Move all original collection/leaf owners into their exact immutable control.
    ///
    /// # Errors
    /// Returns the identical complete attempt on every source, capacity or allocator refusal.
    #[expect(
        clippy::result_large_err,
        reason = "refusal preserves every original prepared owner"
    )]
    pub fn finish(
        mut self,
        source: &ChargedBuffer<u8>,
    ) -> Result<BlockSignatures, (Self, BlockSignatureCustodyError)> {
        if let Err(error) = self.check(source) {
            return Err((self, error));
        }
        if self
            .values
            .as_ref()
            .is_none_or(|values| values.as_slice().len() != self.count)
            || self
                .charges
                .as_ref()
                .is_none_or(|charges| charges.as_slice().len() != self.count)
        {
            return Err((self, BlockSignatureCustodyError::Incomplete));
        }
        let mut reservation = match self
            .budget
            .try_reserve(BlockSignatures::allocation_layout())
        {
            Ok(value) => value,
            Err(error) => return Err((self, BlockSignatureCustodyError::ControlAdmission(error))),
        };
        let funded = Funded {
            values: self.values.take().expect("complete original values"),
            charges: self.charges.take().expect("complete original ledger"),
            budget: self.budget.clone(),
        };
        match ChargedShared::from_reservation(funded, &mut reservation) {
            Ok(owner) => Ok(BlockSignatures {
                storage: Storage::Admitted(owner),
            }),
            Err((funded, error)) => {
                self.values = Some(funded.values);
                self.charges = Some(funded.charges);
                Err((self, BlockSignatureCustodyError::ControlAllocation(error)))
            }
        }
    }
}
struct Leaf<'a> {
    source: &'a [u8],
    index: Option<u64>,
    payload: Option<SequenceSpan>,
}
impl FieldDestination for Leaf<'_> {
    type Error = std::convert::Infallible;
}
impl DecodeField<0, u64> for Leaf<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, u64>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        self.index = Some(field.decode_owned()?);
        Ok(())
    }
}
impl DecodeField<1, Vec<u8>> for Leaf<'_> {
    type Value = ();
    fn decode_field(
        &mut self,
        field: CanonicalField<'_, Vec<u8>>,
    ) -> Result<(), DecodeIntoError<Self::Error>> {
        field.with_payload(|bytes| {
            let (payload, used) = <&[u8] as DecodeFromSlice>::decode_from_slice(bytes)?;
            norito::core::reserve_decode_allocation(payload.len())?;
            if used != bytes.len() {
                return Err(norito::Error::LengthMismatch.into());
            }
            validate_block_signature_payload(payload)?;
            norito::core::reserve_decode_allocation(payload.len())?;
            let start = payload
                .as_ptr()
                .addr()
                .checked_sub(self.source.as_ptr().addr())
                .ok_or(norito::Error::LengthMismatch)?;
            let end = start
                .checked_add(payload.len())
                .ok_or(norito::Error::LengthMismatch)?;
            if self
                .source
                .get(start..end)
                .is_none_or(|original| original.as_ptr() != payload.as_ptr())
            {
                return Err(norito::Error::LengthMismatch.into());
            }
            self.payload = Some(SequenceSpan { start, end });
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
