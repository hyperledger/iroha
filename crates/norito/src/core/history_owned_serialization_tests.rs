//! Real canonical serialization scratch must join the original cumulative owner.

use super::*;
use std::{
    alloc::Layout,
    collections::{BinaryHeap, HashMap, HashSet},
};

fn context(bytes: usize) -> DecodeBudgetContext {
    DecodeBudgetContext::new(DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        bytes,
        64,
    ))
}

#[test]
fn canonical_map_set_heap_refuse_before_unowned_sorting_allocation() {
    let map: HashMap<u64, u64> = (0..64).map(|key| (key, key + 1)).collect();
    let set: HashSet<u64> = (0..64).collect();
    let heap: BinaryHeap<u64> = (0..64).collect();
    let map_bytes = Layout::array::<(&u64, &u64)>(map.len()).unwrap().size();
    let set_bytes = Layout::array::<&u64>(set.len()).unwrap().size();
    for (value, bytes) in [
        (&map as &dyn SerializePayload, map_bytes),
        (&set as &dyn SerializePayload, set_bytes),
        (&heap as &dyn SerializePayload, set_bytes),
    ] {
        let owner = context(bytes - 1);
        let error = owner
            .with(|| encoded_payload_len(value))
            .expect_err("sorting references require native custody");
        assert!(
            matches!(error, Error::TotalAllocationExceeded { attempted, limit }
            if attempted == bytes as u64 && limit == (bytes-1) as u64)
        );
        assert_eq!(owner.consumed_allocated_bytes(), 0);
    }
}

#[test]
fn streamed_map_frame_preserves_wire_and_charges_both_real_sort_passes() {
    let value: HashMap<u64, u64> = (0..64).map(|key| (key, 128 - key)).collect();
    let bytes = Layout::array::<(&u64, &u64)>(value.len()).unwrap().size();
    let mut expected = Vec::new();
    write_canonical_to_writer(&value, &mut expected).unwrap();
    let owner = context(2 * bytes);
    let mut actual = Vec::new();
    owner
        .with(|| write_canonical_to_writer(&value, &mut actual))
        .unwrap();
    assert_eq!(
        actual, expected,
        "native sorted order and canonical frame stay exact"
    );
    assert_eq!(owner.consumed_allocated_bytes(), (2 * bytes) as u64);
    assert!(
        owner.with(|| encoded_payload_len(&value)).is_err(),
        "a later encoder phase must not reset the original cumulative credit"
    );
}

#[test]
fn a_completed_measurement_cannot_authorize_the_second_pass_allocation() {
    let value: HashSet<u64> = (0..64).collect();
    let bytes = Layout::array::<&u64>(value.len()).unwrap().size();
    let owner = context(bytes);
    let mut discarded_partial = Vec::new();
    let error = owner
        .with(|| write_canonical_to_writer(&value, &mut discarded_partial))
        .expect_err("second physical sorting allocation requires independent remaining credit");
    assert!(matches!(error, Error::TotalAllocationExceeded { .. }));
    assert_eq!(owner.consumed_allocated_bytes(), bytes as u64);
}

// Equal priority is lawful equality, while a separate carried tag still has
// distinct wire bytes. Keep PartialEq, PartialOrd and Ord consistent so this
// oracle does not depend on violating Rust's ordering contract.
#[derive(
    Clone, Copy, Debug, crate::NoritoSerialize, crate::NoritoDeserialize, crate::NoritoSchema,
)]
#[norito(decode_fields)]
#[norito_schema(name = "norito.test.heap.PriorityTaggedItem")]
struct PriorityTaggedHeapItem {
    priority: u8,
    tag: u8,
}

impl PartialEq for PriorityTaggedHeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for PriorityTaggedHeapItem {}

impl PartialOrd for PriorityTaggedHeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityTaggedHeapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

const HEAP_TIE_ITEMS: usize = 128;
const HEAP_TIE_PAYLOAD_BYTES: usize = 8 + HEAP_TIE_ITEMS * 5;

fn heap_tie_item(tag: u8) -> PriorityTaggedHeapItem {
    PriorityTaggedHeapItem {
        priority: ((u16::from(tag) * 37 + 11) % 7) as u8,
        tag,
    }
}

fn heap_tie_pairs() -> [(u8, u8); HEAP_TIE_ITEMS] {
    let mut pairs = std::array::from_fn(|tag| {
        let item = heap_tie_item(u8::try_from(tag).unwrap());
        (item.priority, item.tag)
    });
    // This oracle compares both physical fields, unlike the priority-only Eq.
    pairs.sort_unstable();
    pairs
}

fn mixed_tie_heap(mode: usize) -> BinaryHeap<PriorityTaggedHeapItem> {
    let items = std::array::from_fn::<_, HEAP_TIE_ITEMS, _>(|index| {
        let tag = match mode {
            0 | 2 => index,
            1 => HEAP_TIE_ITEMS - index - 1,
            3 => (index * 37 + 11) % HEAP_TIE_ITEMS,
            _ => panic!("closed heap fixture construction mode"),
        };
        heap_tie_item(u8::try_from(tag).unwrap())
    });
    if mode < 2 {
        BinaryHeap::from(items)
    } else {
        let mut heap = BinaryHeap::with_capacity(HEAP_TIE_ITEMS);
        for item in items {
            heap.push(item);
        }
        heap
    }
}

struct HeapTieFixtureOwner {
    context: DecodeBudgetContext,
    scratch: iroha_allocation::AllocationReservation,
    fixture: iroha_allocation::AllocationReservation,
    pool: iroha_allocation::AllocationBudget,
    frame_bytes: usize,
}

impl HeapTieFixtureOwner {
    fn new() -> Self {
        Self::new_for_payload(HEAP_TIE_PAYLOAD_BYTES)
    }

    fn new_for_payload(payload_bytes: usize) -> Self {
        let frame_bytes = Header::SIZE
            + payload_alignment_padding_for::<BinaryHeap<PriorityTaggedHeapItem>>()
            + payload_bytes;
        Self::new_with_payload_and_limit(
            payload_bytes,
            crate::canonical_decode_limits(frame_bytes).max_total_allocated_bytes(),
        )
    }

    fn new_with_allocation_limit(scratch_bytes: usize) -> Self {
        Self::new_with_payload_and_limit(HEAP_TIE_PAYLOAD_BYTES, scratch_bytes)
    }

    fn new_with_payload_and_limit(payload_bytes: usize, scratch_bytes: usize) -> Self {
        let frame_bytes = Header::SIZE
            + payload_alignment_padding_for::<BinaryHeap<PriorityTaggedHeapItem>>()
            + payload_bytes;
        let canonical = crate::canonical_decode_limits(frame_bytes);
        let limits = DecodeLimits::new(
            canonical.max_sequence_elements(),
            canonical.max_field_bytes(),
            canonical.max_total_elements(),
            scratch_bytes,
            canonical.max_nesting_depth(),
        );
        // Original and decoded heaps plus both bounded output frames remain
        // within this fixture's prepaid grant through their actual consumption.
        let fixture_bytes = 2 * frame_bytes
            + 2 * Layout::array::<PriorityTaggedHeapItem>(HEAP_TIE_ITEMS)
                .unwrap()
                .size();
        let counter_bytes = DecodeBudgetContext::allocation_layout().size();
        let pool = iroha_allocation::AllocationBudget::new(
            scratch_bytes
                .checked_add(fixture_bytes)
                .and_then(|bytes| bytes.checked_add(counter_bytes))
                .expect("finite heap oracle grant fits usize"),
        );
        let scratch = pool
            .try_reserve_bytes(scratch_bytes)
            .expect("fund original heap codec scratch");
        let fixture = pool
            .try_reserve_bytes(fixture_bytes)
            .expect("fund bounded heap oracle fixtures");
        let context = DecodeBudgetContext::try_new_owned(limits, &pool)
            .expect("fund original heap codec counter");
        Self {
            context,
            scratch,
            fixture,
            pool,
            frame_bytes,
        }
    }

    fn finish(self) {
        let Self {
            context,
            scratch,
            fixture,
            pool,
            frame_bytes: _,
        } = self;
        drop(context);
        let held = pool.reserved_bytes();
        assert!(held > 0, "original scratch and fixtures remain owned");
        drop(scratch);
        assert!(pool.reserved_bytes() < held);
        drop(fixture);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn heap_with_mixed_priority_ties_accepts_its_own_canonical_frames() {
    for mode in 0..4 {
        let owner = HeapTieFixtureOwner::new();
        let heap = mixed_tie_heap(mode);
        let mut frame = Vec::with_capacity(owner.frame_bytes);
        owner
            .context
            .with(|| write_canonical_to_writer(&heap, &mut frame))
            .expect("encode original mixed-priority heap");
        assert_eq!(frame.len(), owner.frame_bytes);
        let decoded = owner
            .context
            .with(|| crate::decode_canonical::<BinaryHeap<PriorityTaggedHeapItem>>(&frame))
            .expect("a canonical heap encoder must produce a decodable frame");
        assert_eq!(decoded.len(), HEAP_TIE_ITEMS);
        let mut physical_pairs = [(0_u8, 0_u8); HEAP_TIE_ITEMS];
        for (slot, item) in physical_pairs.iter_mut().zip(decoded.iter()) {
            *slot = (item.priority, item.tag);
        }
        physical_pairs.sort_unstable();
        assert_eq!(
            physical_pairs,
            heap_tie_pairs(),
            "every physical tag and its multiplicity survive, including Ord ties",
        );
        let mut repeated = Vec::with_capacity(owner.frame_bytes);
        owner
            .context
            .with(|| write_canonical_to_writer(&decoded, &mut repeated))
            .unwrap();
        assert_eq!(repeated, frame, "canonical reconstruction is byte-exact");
        drop(repeated);
        drop(decoded);
        drop(frame);
        drop(heap);
        owner.finish();
    }
}

#[test]
fn heap_ties_use_canonical_payload_order_independent_of_insertion() {
    // First-release tie contract: preserve ascending Ord and break
    // ties by the lexicographic canonical element payload, never heap layout.
    // Under COMPACT_LEN each item is [1, priority, 1, tag], so this literal
    // oracle specifies the complete count and all 128 element payloads.
    let first = heap_tie_item(0);
    let tied = heap_tie_item(7);
    assert_eq!(first, tied, "priority equality obeys Ord");
    assert_eq!(first.cmp(&tied), std::cmp::Ordering::Equal);
    assert_ne!(first.tag, tied.tag, "equal priorities carry distinct bytes");
    let mut expected = [0_u8; HEAP_TIE_PAYLOAD_BYTES];
    expected[..8].copy_from_slice(&(HEAP_TIE_ITEMS as u64).to_le_bytes());
    for (chunk, (priority, tag)) in expected[8..].chunks_exact_mut(5).zip(heap_tie_pairs()) {
        chunk.copy_from_slice(&[4, 1, priority, 1, tag]);
    }
    for mode in 0..4 {
        let owner = HeapTieFixtureOwner::new();
        let heap = mixed_tie_heap(mode);
        let _flags = DecodeFlagsGuard::enter(default_encode_flags());
        let mut payload = Vec::with_capacity(HEAP_TIE_PAYLOAD_BYTES);
        owner
            .context
            .with(|| serialize_to_writer(&heap, &mut payload))
            .unwrap();
        assert_eq!(
            payload, expected,
            "mixed Ord ties must use the same complete canonical payload in mode {mode}",
        );
        drop(payload);
        drop(heap);
        owner.finish();
    }
}

fn heap_tie_reference_bytes() -> usize {
    Layout::array::<&PriorityTaggedHeapItem>(HEAP_TIE_ITEMS)
        .unwrap()
        .size()
}

fn heap_tie_metadata_bytes() -> usize {
    // Exactly three native usize fields: output index, start and length.
    Layout::array::<[usize; 3]>(HEAP_TIE_ITEMS).unwrap().size()
}

fn heap_tie_key_bytes() -> usize {
    HEAP_TIE_ITEMS * 4
}

fn heap_tie_pass_bytes() -> usize {
    heap_tie_reference_bytes() + heap_tie_metadata_bytes() + heap_tie_key_bytes()
}

#[test]
fn heap_tie_metadata_and_key_arena_refuse_before_each_unowned_allocation() {
    let references = heap_tie_reference_bytes();
    let metadata = heap_tie_metadata_bytes();
    let keys = heap_tie_key_bytes();
    for (limit, attempted, consumed) in [
        (references + metadata - 1, references + metadata, references),
        (
            references + metadata + keys - 1,
            references + metadata + keys,
            references + metadata,
        ),
    ] {
        let owner = HeapTieFixtureOwner::new_with_allocation_limit(limit);
        let heap = mixed_tie_heap(0);
        let held = owner.pool.reserved_bytes();
        let error = owner
            .context
            .with(|| encoded_payload_len(&heap))
            .expect_err("each exact native heap scratch allocation needs original credit");
        assert!(matches!(
            error,
            Error::TotalAllocationExceeded { attempted: actual, limit: actual_limit }
            if actual == attempted as u64 && actual_limit == limit as u64
        ));
        assert_eq!(owner.context.consumed_allocated_bytes(), consumed as u64);
        assert_eq!(
            owner.pool.reserved_bytes(),
            held,
            "failed work cannot release its retained original source/counter grants",
        );
        drop(heap);
        owner.finish();
    }
}

#[test]
fn heap_tie_scratch_refund_does_not_renew_cumulative_codec_credit() {
    let per_pass = heap_tie_pass_bytes();
    let owner = HeapTieFixtureOwner::new_with_allocation_limit(per_pass);
    let heap = mixed_tie_heap(2);
    let held = owner.pool.reserved_bytes();
    assert_eq!(
        owner.context.with(|| encoded_payload_len(&heap)).unwrap(),
        HEAP_TIE_PAYLOAD_BYTES,
    );
    assert_eq!(owner.context.consumed_allocated_bytes(), per_pass as u64);
    assert_eq!(owner.pool.reserved_bytes(), held);
    // The local reference/metadata/arena Vecs have all dropped, while the
    // original context still retains their cumulative allocation history.
    let error = owner
        .context
        .with(|| encoded_payload_len(&heap))
        .expect_err("a later phase cannot replace the original consumed history");
    assert!(matches!(
        error,
        Error::TotalAllocationExceeded { attempted, limit }
        if attempted == (per_pass + heap_tie_reference_bytes()) as u64
            && limit == per_pass as u64
    ));
    assert_eq!(owner.context.consumed_allocated_bytes(), per_pass as u64);
    drop(heap);
    owner.finish();
}

#[test]
fn heap_canonical_frame_charges_both_real_tie_sort_passes_exactly() {
    let per_pass = heap_tie_pass_bytes();
    let owner = HeapTieFixtureOwner::new_with_allocation_limit(2 * per_pass);
    let heap = mixed_tie_heap(3);
    let mut frame = Vec::with_capacity(owner.frame_bytes);
    owner
        .context
        .with(|| write_canonical_to_writer(&heap, &mut frame))
        .unwrap();
    assert_eq!(frame.len(), owner.frame_bytes);
    assert_eq!(
        owner.context.consumed_allocated_bytes(),
        (2 * per_pass) as u64
    );
    let mut expected = [0_u8; HEAP_TIE_PAYLOAD_BYTES];
    expected[..8].copy_from_slice(&(HEAP_TIE_ITEMS as u64).to_le_bytes());
    for (chunk, (priority, tag)) in expected[8..].chunks_exact_mut(5).zip(heap_tie_pairs()) {
        chunk.copy_from_slice(&[4, 1, priority, 1, tag]);
    }
    assert_eq!(
        &frame[owner.frame_bytes - HEAP_TIE_PAYLOAD_BYTES..],
        expected
    );
    assert!(owner.context.with(|| encoded_payload_len(&heap)).is_err());
    assert_eq!(
        owner.context.consumed_allocated_bytes(),
        (2 * per_pass) as u64
    );
    drop(frame);
    drop(heap);
    owner.finish();
}

#[test]
fn heap_unique_order_retains_reference_only_budget_and_numeric_order() {
    let references = Layout::array::<&u64>(2).unwrap().size();
    let owner = HeapTieFixtureOwner::new_with_allocation_limit(references);
    let heap = BinaryHeap::from([256_u64, 255_u64]);
    let mut bytes = [0_u8; 26];
    owner
        .context
        .with(|| serialize_to_writer(&heap, &mut std::io::Cursor::new(&mut bytes[..])))
        .unwrap();
    let mut expected = [0_u8; 26];
    expected[..8].copy_from_slice(&2_u64.to_le_bytes());
    expected[8] = 8;
    expected[9..17].copy_from_slice(&255_u64.to_le_bytes());
    expected[17] = 8;
    expected[18..].copy_from_slice(&256_u64.to_le_bytes());
    assert_eq!(
        bytes, expected,
        "ordinary numeric order precedes payload byte order"
    );
    assert_eq!(owner.context.consumed_allocated_bytes(), references as u64);
    drop(heap);
    owner.finish();
}

#[test]
fn heap_equal_payload_ties_preserve_physical_multiplicity() {
    let owner = HeapTieFixtureOwner::new();
    let heap = BinaryHeap::from(std::array::from_fn::<_, HEAP_TIE_ITEMS, _>(|index| {
        heap_tie_item(if index % 2 == 0 { 0 } else { 7 })
    }));
    let mut frame = Vec::with_capacity(owner.frame_bytes);
    owner
        .context
        .with(|| write_canonical_to_writer(&heap, &mut frame))
        .unwrap();
    let decoded = owner
        .context
        .with(|| crate::decode_canonical::<BinaryHeap<PriorityTaggedHeapItem>>(&frame))
        .unwrap();
    let mut physical = [(0_u8, 0_u8); HEAP_TIE_ITEMS];
    for (slot, item) in physical.iter_mut().zip(decoded.iter()) {
        *slot = (item.priority, item.tag);
    }
    physical.sort_unstable();
    let expected = std::array::from_fn::<_, HEAP_TIE_ITEMS, _>(|index| {
        let item = heap_tie_item(if index < HEAP_TIE_ITEMS / 2 { 0 } else { 7 });
        (item.priority, item.tag)
    });
    assert_eq!(physical, expected);
    assert_eq!(decoded.len(), HEAP_TIE_ITEMS);
    drop(decoded);
    drop(frame);
    drop(heap);
    owner.finish();
}

struct NestedHeapKey(BinaryHeap<u8>);

impl PartialEq for NestedHeapKey {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for NestedHeapKey {}

impl PartialOrd for NestedHeapKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NestedHeapKey {
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        std::cmp::Ordering::Equal
    }
}

impl SerializePayload for NestedHeapKey {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        self.0.serialize(writer)
    }
}

#[test]
fn heap_tie_nested_key_allocations_share_the_original_cumulative_context() {
    let references = Layout::array::<&NestedHeapKey>(2).unwrap().size();
    let metadata = Layout::array::<[usize; 3]>(2).unwrap().size();
    let inner_references = Layout::array::<&u8>(2).unwrap().size();
    let arena = 2 * (8 + 2 * (1 + 1));
    let exact = references + metadata + 4 * inner_references + arena;
    for limit in [exact - 1, exact] {
        let owner = HeapTieFixtureOwner::new_with_allocation_limit(limit);
        let heap = BinaryHeap::from([
            NestedHeapKey(BinaryHeap::from([1, 2])),
            NestedHeapKey(BinaryHeap::from([2, 3])),
        ]);
        let result = owner.context.with(|| encoded_payload_len(&heap));
        if limit == exact {
            assert_eq!(result.unwrap(), 8 + 2 * (1 + 12));
            assert_eq!(owner.context.consumed_allocated_bytes(), exact as u64);
        } else {
            assert!(matches!(
                result,
                Err(Error::TotalAllocationExceeded { attempted, limit: refused_limit })
                if attempted == exact as u64 && refused_limit == limit as u64
            ));
            assert_eq!(
                owner.context.consumed_allocated_bytes(),
                (exact - inner_references) as u64,
            );
        }
        drop(heap);
        owner.finish();
    }
}

struct GrowingHeapKey {
    tag: u8,
    calls: Cell<usize>,
}

impl PartialEq for GrowingHeapKey {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for GrowingHeapKey {}

impl PartialOrd for GrowingHeapKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GrowingHeapKey {
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        std::cmp::Ordering::Equal
    }
}

impl SerializePayload for GrowingHeapKey {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let call = self.calls.get();
        self.calls.set(call + 1);
        if call == 0 {
            writer.write_all(&[self.tag])?;
        } else {
            // A hostile serializer cannot clear the bounded destination's
            // sticky overrun by ignoring this error.
            let _ignored = writer.write_all(&[self.tag, 0xEE]);
        }
        Ok(())
    }
}

#[test]
fn heap_tie_key_arena_rejects_ignored_second_pass_growth_and_refunds() {
    let exact = Layout::array::<&GrowingHeapKey>(2).unwrap().size()
        + Layout::array::<[usize; 3]>(2).unwrap().size()
        + 2;
    let owner = HeapTieFixtureOwner::new_with_allocation_limit(exact);
    let heap = BinaryHeap::from([
        GrowingHeapKey {
            tag: 1,
            calls: Cell::new(0),
        },
        GrowingHeapKey {
            tag: 2,
            calls: Cell::new(0),
        },
    ]);
    let mut bytes = [0_u8; 32];
    let mut destination = std::io::Cursor::new(&mut bytes[..]);
    let error = owner
        .context
        .with(|| serialize_to_writer(&heap, &mut destination))
        .expect_err("bounded tie keys cannot overrun measured exact capacity");
    assert!(matches!(error, Error::LengthMismatch));
    assert_eq!(
        destination.position(),
        0,
        "no sequence frame precedes admitted valid keys"
    );
    assert_eq!(owner.context.consumed_allocated_bytes(), exact as u64);
    assert_eq!(heap.iter().map(|item| item.calls.get()).sum::<usize>(), 3);
    drop(heap);
    owner.finish();
}

#[test]
fn heap_tie_real_nested_count_work_remains_finitely_bounded() {
    // Key measurement visits each four-byte payload once. Constructing each
    // real key also measures its two one-byte child fields. Incorporating the
    // measured arena into the sequence adds no second payload count charge.
    let counted_work = HEAP_TIE_PAYLOAD_BYTES + HEAP_TIE_ITEMS * 2;
    for maximum in [counted_work - 1, counted_work] {
        let owner = HeapTieFixtureOwner::new_with_allocation_limit(heap_tie_pass_bytes());
        let heap = mixed_tie_heap(0);
        let result = owner
            .context
            .with(|| encoded_payload_len_bounded(&heap, maximum));
        if maximum == counted_work {
            assert_eq!(result.unwrap(), HEAP_TIE_PAYLOAD_BYTES);
        } else {
            assert!(matches!(
                result,
                Err(Error::Io(error))
                if error.kind() == std::io::ErrorKind::Other
                    && error.get_ref().is_none()
                    && error.raw_os_error().is_none()
            ));
        }
        assert_eq!(
            owner.context.consumed_allocated_bytes(),
            heap_tie_pass_bytes() as u64,
        );
        drop(heap);
        owner.finish();
    }
}

#[test]
fn heap_singletons_and_tie_groups_preserve_sequence_positions() {
    let input = [
        PriorityTaggedHeapItem {
            priority: 2,
            tag: 255,
        },
        PriorityTaggedHeapItem {
            priority: 0,
            tag: 7,
        },
        PriorityTaggedHeapItem {
            priority: 3,
            tag: 0,
        },
        PriorityTaggedHeapItem {
            priority: 2,
            tag: 8,
        },
        PriorityTaggedHeapItem {
            priority: 1,
            tag: 9,
        },
        PriorityTaggedHeapItem {
            priority: 0,
            tag: 2,
        },
    ];
    let references = Layout::array::<&PriorityTaggedHeapItem>(input.len())
        .unwrap()
        .size();
    let metadata = Layout::array::<[usize; 3]>(4).unwrap().size();
    let owner = HeapTieFixtureOwner::new_with_allocation_limit(references + metadata + 4 * 4);
    let heap = BinaryHeap::from(input);
    let mut bytes = [0_u8; 38];
    owner
        .context
        .with(|| serialize_to_writer(&heap, &mut std::io::Cursor::new(&mut bytes[..])))
        .unwrap();
    let mut expected = [0_u8; 38];
    expected[..8].copy_from_slice(&6_u64.to_le_bytes());
    for (chunk, (priority, tag)) in
        expected[8..]
            .chunks_exact_mut(5)
            .zip([(0, 2), (0, 7), (1, 9), (2, 8), (2, 255), (3, 0)])
    {
        chunk.copy_from_slice(&[4, 1, priority, 1, tag]);
    }
    assert_eq!(bytes, expected);
    assert_eq!(
        owner.context.consumed_allocated_bytes(),
        (references + metadata + 16) as u64
    );
    drop(heap);
    owner.finish();
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct EmptyHeapKey;

impl SerializePayload for EmptyHeapKey {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        writer.write_all(&[])?;
        Ok(())
    }
}

#[test]
fn heap_empty_tie_payloads_need_no_key_arena_allocation() {
    let exact = Layout::array::<&EmptyHeapKey>(HEAP_TIE_ITEMS)
        .unwrap()
        .size()
        + Layout::array::<[usize; 3]>(HEAP_TIE_ITEMS).unwrap().size();
    let owner = HeapTieFixtureOwner::new_with_allocation_limit(exact);
    let heap = BinaryHeap::from([EmptyHeapKey; HEAP_TIE_ITEMS]);
    let mut bytes = [0_u8; 8 + HEAP_TIE_ITEMS];
    owner
        .context
        .with(|| serialize_to_writer(&heap, &mut std::io::Cursor::new(&mut bytes[..])))
        .unwrap();
    assert_eq!(&bytes[..8], (HEAP_TIE_ITEMS as u64).to_le_bytes());
    assert!(bytes[8..].iter().all(|byte| *byte == 0));
    assert_eq!(owner.context.consumed_allocated_bytes(), exact as u64);
    drop(heap);
    owner.finish();
}

#[test]
fn heap_tie_keys_use_the_advertised_active_element_layout() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let prefix = if flags == 0 { 8 } else { 1 };
        let item_bytes = 2 * (prefix + 1);
        let payload_bytes = 8 + HEAP_TIE_ITEMS * (prefix + item_bytes);
        let owner = HeapTieFixtureOwner::new_for_payload(payload_bytes);
        let heap = mixed_tie_heap(1);
        let _flags = DecodeFlagsGuard::enter(flags);
        let mut bytes = [0_u8; 8 + HEAP_TIE_ITEMS * (8 + 18)];
        let mut destination = std::io::Cursor::new(&mut bytes[..payload_bytes]);
        owner
            .context
            .with(|| serialize_to_writer(&heap, &mut destination))
            .unwrap();
        assert_eq!(destination.position(), payload_bytes as u64);
        let (decoded, used) = owner
            .context
            .with(|| {
                <BinaryHeap<PriorityTaggedHeapItem> as DecodeFromSlice>::decode_from_slice(
                    &bytes[..payload_bytes],
                )
            })
            .unwrap();
        assert_eq!(used, payload_bytes);
        let mut physical = [(0_u8, 0_u8); HEAP_TIE_ITEMS];
        for (slot, item) in physical.iter_mut().zip(decoded.iter()) {
            *slot = (item.priority, item.tag);
        }
        physical.sort_unstable();
        assert_eq!(physical, heap_tie_pairs());
        let mut expected = [0_u8; 8 + HEAP_TIE_ITEMS * (8 + 18)];
        let mut cursor = std::io::Cursor::new(&mut expected[..payload_bytes]);
        cursor
            .write_all(&(HEAP_TIE_ITEMS as u64).to_le_bytes())
            .unwrap();
        for (priority, tag) in heap_tie_pairs() {
            if flags == 0 {
                cursor
                    .write_all(&(item_bytes as u64).to_le_bytes())
                    .unwrap();
                cursor.write_all(&1_u64.to_le_bytes()).unwrap();
                cursor.write_all(&[priority]).unwrap();
                cursor.write_all(&1_u64.to_le_bytes()).unwrap();
                cursor.write_all(&[tag]).unwrap();
            } else {
                cursor.write_all(&[4, 1, priority, 1, tag]).unwrap();
            }
        }
        assert_eq!(cursor.position(), payload_bytes as u64);
        assert_eq!(&bytes[..payload_bytes], &expected[..payload_bytes]);
        let mut repeated = [0_u8; 8 + HEAP_TIE_ITEMS * (8 + 18)];
        owner
            .context
            .with(|| {
                serialize_to_writer(
                    &decoded,
                    &mut std::io::Cursor::new(&mut repeated[..payload_bytes]),
                )
            })
            .unwrap();
        assert_eq!(&repeated[..payload_bytes], &bytes[..payload_bytes]);
        drop(decoded);
        drop(heap);
        owner.finish();
    }
}
