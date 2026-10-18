//! Actual Box rollback, original finite-pool refusal, and owning drop parity.
//!
//! These controls exercise the sole native generated materializer and real
//! owning Box decoder. They do not implement the still-missing production Box
//! prepared kernel, complete graph scope, or production Evidence owner.
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer, ChargedShared,
    ReservedChargedShared, RetainedPayload,
};
use norito::core::{
    CanonicalField, DecodeFlagsGuard, DecodeIntoError, DecodeValueDestination, DecodeValueFields,
    DecodeVariantField, EnumFieldDestination, FieldDestination, OwnedFields, default_encode_flags,
};
use norito::{DeserializePayload, NoritoSchema, NoritoSerialize};
use std::{alloc::Layout, cell::Cell, ops::Range, ptr};

#[derive(Debug, PartialEq, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "rollback.Atom")]
#[norito(decode_from_slice)]
struct Atom {
    bytes: [u8; 128],
}
#[derive(Debug, PartialEq, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "rollback.Pair")]
#[norito(decode_fields, decode_from_slice)]
enum Pair {
    Only(Box<Atom>, Box<Atom>, u8),
}
#[derive(Debug, PartialEq, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "rollback.Pair")]
#[norito(decode_from_slice)]
enum OriginalPair {
    Only(Box<Atom>, Box<Atom>, u8),
}
fn fixture() -> Pair {
    Pair::Only(
        Box::new(Atom { bytes: [0xa5; 128] }),
        Box::new(Atom { bytes: [0x5a; 128] }),
        9,
    )
}
fn charged_source(pool: &AllocationBudget, bytes: &[u8]) -> ChargedBuffer<u8> {
    let mut source = ChargedBuffer::new(bytes.len(), pool).unwrap();
    source.append(bytes).unwrap();
    source
}
#[derive(Debug)]
enum Refusal {
    Pool(AllocationRefusal),
    Source,
}
struct Complete<'source> {
    payload: RetainedPayload<Pair>,
    source: &'source ChargedBuffer<u8>,
}
// Every actual child precedes the exact charge ledger and root shell. The
// original source is borrowed and cannot retire or mutate while this owner lives.
struct Destination<'source> {
    complete: Option<Pair>,
    cached: [Option<Box<Atom>>; 2],
    pending: [Option<AllocationCharge>; 2],
    ledger: ChargedBuffer<AllocationCharge>,
    shell: Option<ReservedChargedShared<Complete<'source>>>,
    source: &'source ChargedBuffer<u8>,
    range: Range<usize>,
    pool: AllocationBudget,
    pointers: [usize; 2],
    restored: [usize; 4],
    restore_count: usize,
}
impl<'source> Destination<'source> {
    fn new(
        source: &'source ChargedBuffer<u8>,
        range: Range<usize>,
        pool: &AllocationBudget,
    ) -> Self {
        assert!(source.belongs_to(pool));
        assert!(source.as_slice().get(range.clone()).is_some());
        let ledger = ChargedBuffer::new(2, pool).unwrap();
        let layout = ChargedShared::<Complete<'source>>::allocation_layout();
        let mut reservation = pool.try_reserve(layout).unwrap();
        let charge = reservation.try_split(layout).unwrap();
        let shell = ChargedShared::reserve_from_charge(charge).ok().unwrap();
        Self {
            complete: None,
            cached: [None, None],
            pending: [None, None],
            ledger,
            shell: Some(shell),
            source,
            range,
            pool: pool.clone(),
            pointers: [0; 2],
            restored: [0; 4],
            restore_count: 0,
        }
    }
    fn decode(&mut self, source: &ChargedBuffer<u8>) -> Result<Pair, DecodeIntoError<Refusal>> {
        if !ptr::eq(source, self.source) || !source.belongs_to(&self.pool) {
            return Err(DecodeIntoError::Destination(Refusal::Source));
        }
        if let Some(Pair::Only(first, second, _)) = self.complete.take() {
            // A private same-source retry may move the original no-hook enum's
            // actual fields back into its own existing slots. The ledger and
            // every original Box backing remain unchanged; nothing escapes.
            assert!(self.cached.iter().all(Option::is_none));
            self.cached = [Some(first), Some(second)];
        }
        self.restore_count = 0;
        let original = self.source;
        let bytes = &original.as_slice()[self.range.clone()];
        let _flags = DecodeFlagsGuard::enter(default_encode_flags());
        let (value, used) = Pair::decode_value_fields(bytes, self)?;
        assert_eq!(used, bytes.len());
        Ok(value)
    }
    fn hold_complete(&mut self, value: Pair) {
        assert!(self.complete.is_none());
        self.complete = Some(value);
    }
    fn verify_complete(&self) -> Result<(), norito::Error> {
        norito::verify_exact_frame(self.complete.as_ref().unwrap(), self.source.as_slice())
    }
    fn finish(mut self) -> ChargedShared<Complete<'source>> {
        self.verify_complete().unwrap();
        assert!(self.cached.iter().all(Option::is_none));
        assert!(self.pending.iter().all(Option::is_none));
        assert_eq!(self.ledger.as_slice().len(), 2);
        let payload = self.complete.take().unwrap();
        // SAFETY: Pair has exactly two actual Box<Atom> allocations and no other
        // heap. Each ledger entry is the original exact Layout::new::<Atom>()
        // admitted before that original owning allocation; source and shell are
        // separately charged. Immutable RetainedPayload exposes no extraction.
        let retained = unsafe { RetainedPayload::try_new(payload, self.ledger, &self.pool) }
            .ok()
            .unwrap();
        self.shell.take().unwrap().initialize(Complete {
            payload: retained,
            source: self.source,
        })
    }
}
impl FieldDestination for Destination<'_> {
    type Error = Refusal;
}
impl DecodeValueDestination<Pair> for Destination<'_> {
    fn restore_value(&mut self, value: Pair) {
        assert!(self.complete.is_none());
        let Pair::Only(first, second, _) = &value;
        assert_eq!((&**first as *const Atom) as usize, self.pointers[0]);
        assert_eq!((&**second as *const Atom) as usize, self.pointers[1]);
        self.complete = Some(value);
    }
}
impl EnumFieldDestination for Destination<'_> {
    fn begin_variant(&mut self, variant: u32) -> Result<(), Self::Error> {
        assert_eq!(variant, 0);
        Ok(())
    }
}
impl<const I: usize> DecodeVariantField<0, I, Box<Atom>> for Destination<'_> {
    fn decode_variant_field(
        &mut self,
        field: CanonicalField<'_, Box<Atom>>,
    ) -> Result<Box<Atom>, DecodeIntoError<Self::Error>> {
        if let Some(value) = self.cached[I].take() {
            // The exact immutable source is unchanged. Re-check the complete
            // original Box payload against its actual retained value without
            // another owning decode, allocation, replacement, or fake frame.
            if let Err(error) = field.with_payload(|bytes| {
                norito::codec::verify_exact_payload(&value, bytes).map_err(DecodeIntoError::Codec)
            }) {
                self.cached[I] = Some(value);
                return Err(error);
            }
            assert_eq!((&*value as *const Atom) as usize, self.pointers[I]);
            return Ok(value);
        }
        if self.pending[I].is_none() {
            let layout = Layout::new::<Atom>();
            let mut reservation = self
                .pool
                .try_reserve(layout)
                .map_err(|cause| DecodeIntoError::Destination(Refusal::Pool(cause)))?;
            self.pending[I] = Some(reservation.try_split(layout).unwrap());
        }
        // This is the actual original successful owning Box decoder. Refusal
        // injection is only the real finite-pool admission above, because the
        // production fallible prepared Box construction is still a TODO.
        let value = field.decode_owned()?;
        self.pointers[I] = (&*value as *const Atom) as usize;
        self.ledger.push_reserved(self.pending[I].take().unwrap());
        Ok(value)
    }
    fn restore_variant_field(&mut self, value: Box<Atom>) {
        assert!(self.cached[I].is_none());
        assert_eq!((&*value as *const Atom) as usize, self.pointers[I]);
        self.cached[I] = Some(value);
        self.restored[self.restore_count] = I;
        self.restore_count += 1;
    }
}
impl DecodeVariantField<0, 2, u8> for Destination<'_> {
    fn decode_variant_field(
        &mut self,
        field: CanonicalField<'_, u8>,
    ) -> Result<u8, DecodeIntoError<Self::Error>> {
        Ok(field.decode_owned()?)
    }
    fn restore_variant_field(&mut self, value: u8) {
        let _ = value;
    }
}

#[test]
fn enum_rollback_retains_actual_earlier_box_on_real_pool_refusal_and_same_source_retry() {
    let pool = AllocationBudget::new(1 << 20);
    let frame = norito::encode_canonical(&fixture()).unwrap();
    let source = charged_source(&pool, &frame);
    let view = norito::core::from_bytes_view(source.as_slice()).unwrap();
    assert_eq!(view.flags(), default_encode_flags());
    let start = view.as_bytes().as_ptr() as usize - source.as_slice().as_ptr() as usize;
    let mut destination = Destination::new(&source, start..start + view.as_bytes().len(), &pool);
    let blocked = pool.try_reserve(Layout::new::<Atom>()).unwrap();
    let baseline = pool.reserved_bytes();
    pool.set_limit_bytes(baseline + Layout::new::<Atom>().size());
    let cause = destination.decode(&source).unwrap_err();
    let original = match cause {
        DecodeIntoError::Destination(Refusal::Pool(cause)) => cause,
        other => panic!("lost actual second Box admission cause: {other:?}"),
    };
    assert!(
        matches!(original,AllocationRefusal::Capacity{requested_bytes,reserved_bytes,limit_bytes,..}
        if requested_bytes==Layout::new::<Atom>().size() && reserved_bytes==baseline+requested_bytes && limit_bytes==reserved_bytes)
    );
    assert_eq!(destination.restore_count, 1);
    assert_eq!(destination.restored[0], 0);
    let first = destination.cached[0].as_deref().unwrap() as *const Atom;
    assert_eq!(first as usize, destination.pointers[0]);
    assert_eq!(destination.ledger.as_slice().len(), 1);
    assert!(destination.ledger.as_slice()[0].belongs_to(&pool));
    assert_eq!(
        destination.ledger.as_slice()[0].layout(),
        Layout::new::<Atom>()
    );
    assert_eq!(
        source.as_slice().as_ptr(),
        view.as_bytes().as_ptr().wrapping_sub(start)
    );
    drop(blocked);
    let value = destination.decode(&source).unwrap();
    let Pair::Only(ref earlier, _, _) = value;
    assert_eq!((&**earlier) as *const Atom, first);
    assert_eq!(destination.ledger.as_slice().len(), 2);
    destination.hold_complete(value);
    destination.verify_complete().unwrap();
    let complete = destination.finish();
    let occupied = pool.reserved_bytes();
    pool.set_limit_bytes(0);
    let mut last = None;
    let allocations = super::allocations_during(|| last = Some(complete.clone()));
    assert_eq!(allocations, 0);
    drop(complete);
    assert_eq!(pool.reserved_bytes(), occupied);
    let last = last.unwrap();
    assert!(last.payload.belongs_to(&pool));
    assert!(ptr::eq(last.source, &source));
    let Pair::Only(earlier, _, _) = last.payload.get();
    assert_eq!((&**earlier) as *const Atom, first);
    drop(last);
    assert_eq!(pool.reserved_bytes(), source.as_slice().len());
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn enum_rollback_returns_actual_boxes_in_reverse_order_after_late_sibling_framing() {
    let flags = default_encode_flags();
    let mut bytes = super::bare_bytes(&fixture(), flags);
    bytes.pop().unwrap();
    let _flags = DecodeFlagsGuard::enter(flags);
    let original = norito::core::decode_field_canonical::<OriginalPair>(&bytes).unwrap_err();
    let pool = AllocationBudget::new(1 << 20);
    let source = charged_source(&pool, &bytes);
    let mut destination = Destination::new(&source, 0..bytes.len(), &pool);
    let cause = destination.decode(&source).unwrap_err();
    assert!(
        matches!(cause,DecodeIntoError::Codec(ref error) if error.to_string()==original.to_string())
    );
    assert_eq!(&destination.restored[..destination.restore_count], &[1, 0]);
    let pointers = destination.pointers;
    let occupied = pool.reserved_bytes();
    let mut retry = None;
    let allocations = super::allocations_during(|| retry = Some(destination.decode(&source)));
    assert_eq!(allocations, 0);
    assert!(
        matches!(retry.unwrap(),Err(DecodeIntoError::Codec(ref error)) if error.to_string()==original.to_string())
    );
    assert_eq!(destination.pointers, pointers);
    assert_eq!(pool.reserved_bytes(), occupied);
    drop(destination);
    assert_eq!(pool.reserved_bytes(), source.as_slice().len());
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn enum_rollback_retains_both_actual_boxes_on_final_framing_and_rejects_foreign_source() {
    let flags = default_encode_flags();
    let mut bytes = super::bare_bytes(&fixture(), flags);
    bytes.push(0xa5);
    let _flags = DecodeFlagsGuard::enter(flags);
    let original = norito::core::decode_field_canonical::<OriginalPair>(&bytes).unwrap_err();
    let pool = AllocationBudget::new(1 << 20);
    let source = charged_source(&pool, &bytes);
    let foreign = charged_source(&pool, &bytes);
    let mut destination = Destination::new(&source, 0..bytes.len(), &pool);
    let cause = destination.decode(&source).unwrap_err();
    assert!(
        matches!(cause,DecodeIntoError::Codec(ref error) if error.to_string()==original.to_string())
    );
    assert_eq!(destination.restore_count, 0);
    assert!(destination.complete.is_some());
    let pointers = destination.pointers;
    let occupied = pool.reserved_bytes();
    assert!(matches!(
        destination.decode(&foreign),
        Err(DecodeIntoError::Destination(Refusal::Source))
    ));
    assert_eq!(destination.pointers, pointers);
    assert_eq!(pool.reserved_bytes(), occupied);
    assert!(destination.complete.is_some());
    let mut retry = None;
    let allocations = super::allocations_during(|| retry = Some(destination.decode(&source)));
    assert_eq!(allocations, 0);
    assert!(
        matches!(retry.unwrap(),Err(DecodeIntoError::Codec(ref error)) if error.to_string()==original.to_string())
    );
    assert_eq!(destination.pointers, pointers);
    assert_eq!(pool.reserved_bytes(), occupied);
    drop(destination);
    assert_eq!(
        pool.reserved_bytes(),
        source.as_slice().len() + foreign.as_slice().len()
    );
    drop(foreign);
    drop(source);
    assert_eq!(pool.reserved_bytes(), 0);
}

thread_local! {
    static DROPS: Cell<([u8; 8], usize)> = const { Cell::new(([0; 8], 0)) };
}
#[derive(Debug, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "rollback.DropToken")]
#[norito(decode_from_slice)]
struct DropToken {
    ordinal: u8,
}
impl Drop for DropToken {
    fn drop(&mut self) {
        DROPS.with(|cell| {
            let (mut values, count) = cell.get();
            values[count] = self.ordinal;
            cell.set((values, count + 1));
        });
    }
}
#[derive(Debug, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "rollback.DropChoice")]
#[norito(decode_fields, decode_from_slice)]
enum DropChoice {
    Only(DropToken, DropToken, u8),
}
#[derive(Debug, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "rollback.DropChoice")]
#[norito(decode_from_slice)]
enum OriginalDropChoice {
    Only(DropToken, DropToken, u8),
}
fn drop_enum() {
    DROPS.with(|cell| {
        let (mut values, count) = cell.get();
        values[count] = 7;
        cell.set((values, count + 1));
    });
}
impl Drop for DropChoice {
    fn drop(&mut self) {
        drop_enum();
    }
}
impl Drop for OriginalDropChoice {
    fn drop(&mut self) {
        drop_enum();
    }
}
fn drop_order(operation: impl FnOnce()) -> ([u8; 8], usize) {
    DROPS.set(([0; 8], 0));
    operation();
    DROPS.get()
}
#[test]
fn enum_rollback_owned_fields_preserves_original_drop_order_on_both_result_paths() {
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let value = DropChoice::Only(DropToken { ordinal: 1 }, DropToken { ordinal: 2 }, 9);
        let bytes = super::bare_bytes(&value, flags);
        drop(value);
        let _flags = DecodeFlagsGuard::enter(flags);
        let cases: [(Vec<u8>, &[u8]); 2] = [
            (bytes[..bytes.len() - 1].to_vec(), &[2, 1]),
            (
                {
                    let mut b = bytes.clone();
                    b.push(0xa5);
                    b
                },
                &[7, 1, 2],
            ),
        ];
        for (changed, expected) in cases {
            let mut prior = None;
            let ordinary = drop_order(|| {
                prior = Some(
                    norito::core::decode_field_canonical::<OriginalDropChoice>(&changed)
                        .unwrap_err(),
                );
            });
            assert_eq!(&ordinary.0[..ordinary.1], expected);
            let mut actual = None;
            let current = drop_order(|| {
                actual =
                    Some(DropChoice::decode_value_fields(&changed, &mut OwnedFields).unwrap_err());
            });
            assert_eq!(current, ordinary);
            assert!(
                matches!(actual.unwrap(),DecodeIntoError::Codec(ref error) if error.to_string()==prior.unwrap().to_string())
            );
        }
    }
}

thread_local! {
    static CONSUMING_HOOK_CALLS: Cell<usize> = const { Cell::new(0) };
}
#[derive(Debug, NoritoSerialize, DeserializePayload, NoritoSchema)]
#[norito_schema(name = "rollback.HookChoice")]
#[norito(decode_fields, decode_from_slice, validate = "Self::reject")]
enum HookChoice {
    Only(DropToken, DropToken),
}
impl HookChoice {
    fn reject(self) -> Result<Self, norito::Error> {
        CONSUMING_HOOK_CALLS.set(CONSUMING_HOOK_CALLS.get() + 1);
        Err(norito::Error::Message("original consuming hook".into()))
    }
}
#[derive(Default)]
struct HookDestination {
    restores: usize,
}
impl FieldDestination for HookDestination {
    type Error = std::convert::Infallible;
}
impl DecodeValueDestination<HookChoice> for HookDestination {
    fn restore_value(&mut self, value: HookChoice) {
        self.restores += 1;
        drop(value);
    }
}
impl EnumFieldDestination for HookDestination {
    fn begin_variant(&mut self, _variant: u32) -> Result<(), Self::Error> {
        Ok(())
    }
}
impl<const I: usize> DecodeVariantField<0, I, DropToken> for HookDestination {
    fn decode_variant_field(
        &mut self,
        field: CanonicalField<'_, DropToken>,
    ) -> Result<DropToken, DecodeIntoError<Self::Error>> {
        Ok(field.decode_owned()?)
    }
    fn restore_variant_field(&mut self, value: DropToken) {
        self.restores += 1;
        drop(value);
    }
}
#[test]
fn enum_rollback_consuming_hook_error_preserves_cause_and_cannot_restore_consumed_children() {
    let flags = default_encode_flags();
    let value = HookChoice::Only(DropToken { ordinal: 1 }, DropToken { ordinal: 2 });
    let bytes = super::bare_bytes(&value, flags);
    drop(value);
    CONSUMING_HOOK_CALLS.set(0);
    let _flags = DecodeFlagsGuard::enter(flags);
    let mut destination = HookDestination::default();
    let mut cause = None;
    let consumed = drop_order(|| {
        cause = Some(HookChoice::decode_value_fields(&bytes, &mut destination).unwrap_err());
    });
    assert_eq!(&consumed.0[..consumed.1], &[1, 2]);
    assert_eq!(destination.restores, 0);
    assert_eq!(CONSUMING_HOOK_CALLS.get(), 1);
    assert!(
        matches!(cause.unwrap(),DecodeIntoError::Codec(norito::Error::Message(message)) if message=="original consuming hook")
    );
    let mut trailing = bytes;
    trailing.push(0xa5);
    CONSUMING_HOOK_CALLS.set(0);
    let framed = drop_order(|| {
        assert!(matches!(
            HookChoice::decode_value_fields(&trailing, &mut destination),
            Err(DecodeIntoError::Codec(norito::Error::LengthMismatch))
        ));
    });
    assert_eq!(&framed.0[..framed.1], &[1, 2]);
    assert_eq!(destination.restores, 1);
    assert_eq!(CONSUMING_HOOK_CALLS.get(), 0);
}
