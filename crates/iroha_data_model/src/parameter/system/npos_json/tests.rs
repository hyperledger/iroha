//! Captured derive parity and exact original-pool `NPoS` record destination controls.

use std::{
    error::Error as _,
    future::Future as _,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
use norito::core::{DecodeBudgetContext, DecodeLimits, serialize_to_buffer};
use norito::json::JsonDeserialize;

use crate::amx_prepare_streaming_allocations::PhysicalObservation;

use super::*;

// Captured original ten-field derive is a test oracle only. Shipping ordinary
// and admitted decoding both run decode_record; this oracle is never a fallback.
#[derive(norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct CapturedNposJson {
    xor_asset_definition_id: AssetDefinitionId,
    epoch_seed: [u8; 32],
    max_validators: u32,
    min_self_bond: Quantity,
    min_nomination_bond: Quantity,
    finality_margin_blocks: u64,
    evidence_horizon_blocks: u64,
    activation_lag_blocks: u64,
    slashing_delay_blocks: u64,
    epoch_length_blocks: NonZeroU64,
}
struct CapturedNpos(SumeragiNposParameters);
impl JsonDeserialize for CapturedNpos {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = CapturedNposJson::json_deserialize(parser)?;
        let value = SumeragiNposParameters {
            xor_asset_definition_id: value.xor_asset_definition_id,
            epoch_seed: value.epoch_seed,
            max_validators: value.max_validators,
            min_self_bond: value.min_self_bond,
            min_nomination_bond: value.min_nomination_bond,
            finality_margin_blocks: value.finality_margin_blocks,
            evidence_horizon_blocks: value.evidence_horizon_blocks,
            activation_lag_blocks: value.activation_lag_blocks,
            slashing_delay_blocks: value.slashing_delay_blocks,
            epoch_length_blocks: value.epoch_length_blocks,
        };
        value
            .validate()
            .map_err(|message| json::Error::InvalidField {
                field: "SumeragiNposParameters".to_owned(),
                message: message.to_owned(),
            })?;
        Ok(Self(value))
    }
}
fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}
fn source() -> String {
    let value = SumeragiNposParameters {
        max_validators: 4,
        min_self_bond: "123456789012345678901234567890".parse().unwrap(),
        min_nomination_bond: "234567890123456789012345678901".parse().unwrap(),
        ..SumeragiNposParameters::default()
    };
    json::to_json(&value).unwrap()
}
fn observed_demand(source: &str) -> (SumeragiNposParameters, usize) {
    let context = DecodeBudgetContext::new(limits(usize::MAX));
    let value = context
        .with(|| json::from_str::<CapturedNpos>(source))
        .unwrap()
        .0;
    let demand = usize::try_from(context.consumed_allocated_bytes()).unwrap();
    (value, demand)
}
fn decode(
    source: &str,
    budget: &AllocationBudget,
    context: &DecodeBudgetContext,
) -> Result<AdmittedSumeragiNposParameters, SumeragiNposJsonAdmissionError> {
    context.with(|| {
        let mut parser = json::Parser::new(source);
        parser.preflight_document()?;
        parser.skip_ws();
        let value = AdmittedSumeragiNposParameters::try_decode_json(&mut parser, budget)?;
        parser.finish_document()?;
        Ok(value)
    })
}

#[test]
fn ordinary_and_admitted_npos_keep_captured_field_error_order_and_outer_validation_label() {
    let source = source();
    let body = &source[..source.len() - 1];
    let quantity = json::to_json(
        &"123456789012345678901234567890"
            .parse::<Quantity>()
            .unwrap(),
    )
    .unwrap();
    let cases = [
        "{}".to_owned(),
        "{\"epoch_seed\":\"00\"}".to_owned(),
        format!("{body},\"max_validators\":\"not-a-number\"}}"),
        format!("{body},\"unknown\":\"not-a-policy\"}}"),
        format!("{body},}}"),
        "{\"\\uD800\":1}".to_owned(),
        source.replace("\"max_validators\":4", "\"max_validators\":5"),
        source.replacen(&quantity, "\"0\"", 1),
        source.replacen(&quantity, "\"1.0\"", 1),
        source.replacen(&quantity, "\"\\uD800\"", 1),
        source.replace("A5A5", "ZZZZ"),
    ];
    for input in cases {
        assert_ne!(
            input, source,
            "each captured-error fixture changes the genuine valid source"
        );
        let original = json::from_str::<CapturedNpos>(&input)
            .err()
            .expect("invalid captured fixture");
        let ordinary = json::from_str::<SumeragiNposParameters>(&input).unwrap_err();
        let budget = AllocationBudget::new(
            AdmittedSumeragiNposParameters::allocation_layout().size()
                + input.len()
                + 2 * core::mem::size_of::<Quantity>(),
        );
        let context = DecodeBudgetContext::new(limits(usize::MAX));
        let admitted = decode(&input, &budget, &context).unwrap_err();
        assert_eq!(
            format!("{ordinary:?}"),
            format!("{original:?}"),
            "original derive-era order: {input}"
        );
        let SumeragiNposJsonAdmissionError::Json(admitted) = admitted else {
            panic!("ample original pool must not mask syntax: {admitted:?}")
        };
        assert_eq!(
            format!("{admitted:?}"),
            format!("{original:?}"),
            "admitted field order: {input}"
        );
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "all partial physical leaves retire before refund"
        );
    }
}

struct ObservedDestination<'a> {
    inner: AdmittedDestination<'a>,
    observation: &'a PhysicalObservation,
    pointers: [Option<usize>; 2],
    original_checkpoints: [usize; 2],
    bonds: usize,
}
impl Destination for ObservedDestination<'_> {
    type Error = SumeragiNposJsonAdmissionError;
    type Text = AdmittedText;
    type Bond = ChargedQuantity;
    type Record = ChargedBuffer<AdmittedRecord>;
    type Output = AdmittedSumeragiNposParameters;
    fn admit_record(&mut self) -> Result<Self::Record, Self::Error> {
        self.inner.admit_record()
    }
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a, AdmittedText>, Self::Error> {
        self.inner.parse_key(parser)
    }
    fn parse_text(&mut self, parser: &mut json::Parser<'_>) -> Result<AdmittedText, Self::Error> {
        self.inner.parse_text(parser)
    }
    fn parse_bond(
        &mut self,
        parser: &mut json::Parser<'_>,
    ) -> Result<ChargedQuantity, Self::Error> {
        let before = self.observation.checkpoint();
        let bond = self.inner.parse_bond(parser)?;
        self.original_checkpoints[self.bonds] = before;
        // This is the actual canonical leaf's native allocation, selected by its
        // source-derived exact native-digit layout, after temporary text retires.
        let layout = bond.get().admission_clone_layout().unwrap();
        self.pointers[self.bonds] = Some(
            self.observation
                .since(before)
                .single_live_pointer(layout)
                .expect("one exact original native-digit allocation remains live"),
        );
        self.bonds += 1;
        Ok(bond)
    }
    fn finish(
        &mut self,
        record: Self::Record,
        fields: RecordFields<ChargedQuantity>,
    ) -> Result<Self::Output, Self::Error> {
        let before = self.observation.checkpoint();
        let owner = self.inner.finish(record, fields)?;
        let transfer = self.observation.since(before);
        assert_eq!(
            transfer.requests(),
            [0; 3],
            "record transfer allocates/reallocates no replacement digit graph"
        );
        for pointer in self.pointers.into_iter().flatten() {
            assert_eq!(
                transfer.retirements(pointer),
                0,
                "record transfer retains the actual original digit backing"
            );
        }
        Ok(owner)
    }
}

#[test]
fn admitted_npos_record_moves_exact_original_quantity_backing_and_funded_charge_ledger() {
    let source = source();
    let (expected, demand) = observed_demand(&source);
    assert_eq!(
        json::from_str::<SumeragiNposParameters>(&source).unwrap(),
        expected
    );
    let record = AdmittedSumeragiNposParameters::allocation_layout().size();
    let control = DecodeBudgetContext::allocation_layout().size();
    let self_digits = expected
        .min_self_bond
        .admission_clone_layout()
        .unwrap()
        .size();
    let nomination_digits = expected
        .min_nomination_bond
        .admission_clone_layout()
        .unwrap()
        .size();
    let budget =
        AllocationBudget::new(control + record + source.len() + self_digits + nomination_digits);
    let foreign = AllocationBudget::new(budget.limit_bytes());
    let context = DecodeBudgetContext::try_new_owned(limits(demand * 2), &budget).unwrap();
    let observation = PhysicalObservation::start();
    let mut observed = ObservedDestination {
        inner: AdmittedDestination { budget: &budget },
        observation: &observation,
        pointers: [None; 2],
        original_checkpoints: [0; 2],
        bonds: 0,
    };
    let owner = context
        .with(|| {
            let mut parser = json::Parser::new(&source);
            parser.preflight_document()?;
            let value = decode_record(&mut parser, &mut observed)?;
            parser.finish_document()?;
            Ok::<_, SumeragiNposJsonAdmissionError>(value)
        })
        .unwrap();
    assert_eq!(owner.get(), &expected);
    assert_ne!(observed.pointers[0], observed.pointers[1]);
    for (index, pointer) in observed.pointers.into_iter().enumerate() {
        assert_eq!(
            observation
                .since(observed.original_checkpoints[index])
                .retirements(pointer.unwrap()),
            0
        );
    }
    assert!(owner.belongs_to(&budget));
    assert!(!owner.belongs_to(&foreign));
    assert_eq!(
        budget.reserved_bytes(),
        control + record + self_digits + nomination_digits
    );
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(demand).unwrap()
    );
    let mut expected_wire = Vec::new();
    let mut actual_wire = Vec::new();
    serialize_to_buffer(&expected, &mut expected_wire).unwrap();
    serialize_to_buffer(owner.get(), &mut actual_wire).unwrap();
    assert_eq!(actual_wire, expected_wire);
    budget.set_limit_bytes(0);
    for (index, pointer) in observed.pointers.into_iter().enumerate() {
        assert_eq!(
            observation
                .since(observed.original_checkpoints[index])
                .retirements(pointer.unwrap()),
            0,
            "actual original native digits remain live after reducing pool limit"
        );
    }
    drop(owner);
    for (index, pointer) in observed.pointers.into_iter().enumerate() {
        assert_eq!(
            observation
                .since(observed.original_checkpoints[index])
                .retirements(pointer.unwrap()),
            1,
            "each original native-digit allocation retires exactly with its admitted record"
        );
    }
    drop(observation);
    assert_eq!(budget.reserved_bytes(), control);
    budget.set_limit_bytes(control + record + source.len() + self_digits + nomination_digits);
    let retry = decode(&source, &budget, &context).unwrap();
    assert_eq!(retry.get(), &expected);
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(demand * 2).unwrap()
    );
    drop(retry);
    let refused = decode(&source, &budget, &context).unwrap_err();
    assert!(
        matches!(refused, SumeragiNposJsonAdmissionError::Json(ref error) if error.is_decode_resource_limit())
    );
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(demand * 2).unwrap()
    );
    assert_eq!(budget.reserved_bytes(), control);
    drop(context);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}

#[test]
fn admitted_npos_record_refuses_original_capacity_before_field_work_then_retries_same_context() {
    let source = source();
    let (expected, demand) = observed_demand(&source);
    // The unchanged kernel charges object-entry planning before admitting the
    // record. Measure that exact prefix independently, without decoding a field.
    let preflight_demand = {
        let prefix = DecodeBudgetContext::new(limits(usize::MAX));
        prefix.with(|| {
            let mut parser = json::Parser::new(&source);
            parser.preflight_document().unwrap();
            assert_eq!(prefix.consumed_allocated_bytes(), 0);
            let position = parser.position();
            assert_eq!(parser.preflight_object_entries().unwrap(), 10);
            assert_eq!(parser.position(), position);
        });
        let consumed = usize::try_from(prefix.consumed_allocated_bytes()).unwrap();
        assert_eq!(consumed, 10);
        consumed
    };
    assert!(preflight_demand < demand);
    let cumulative_demand = preflight_demand.checked_add(demand).unwrap();
    let record = AdmittedSumeragiNposParameters::allocation_layout().size();
    let control = DecodeBudgetContext::allocation_layout().size();
    let registration_layout = ReleaseRegistration::allocation_layout();
    let baseline = control + registration_layout.size();
    let budget = AllocationBudget::new(baseline + record + source.len());
    let context = DecodeBudgetContext::try_new_owned(limits(cumulative_demand), &budget).unwrap();
    let mut reservation = budget.try_reserve(registration_layout).unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut reservation).unwrap();
    drop(reservation);
    assert!(registration.belongs_to(&budget));
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - baseline)
        .unwrap();
    let before = budget.reserved_bytes();
    let error = decode(&source, &budget, &context).unwrap_err();
    assert!(
        matches!(error.source().unwrap().downcast_ref::<ChargedBufferError>().unwrap().source().unwrap().downcast_ref::<AllocationRefusal>(),
        Some(AllocationRefusal::Capacity { requested_bytes, .. }) if *requested_bytes == record)
    );
    let SumeragiNposJsonAdmissionError::Allocation(ChargedBufferError::Admission(
        AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        },
    )) = error
    else {
        panic!("record refusal must retain the exact original pool release observation")
    };
    assert_eq!(requested_bytes, record);
    assert_eq!(reserved_bytes, before);
    assert_eq!(limit_bytes, budget.limit_bytes());
    assert_eq!(budget.reserved_bytes(), before);
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(preflight_demand).unwrap(),
        "record refusal consumes only the original preflight, without field charges"
    );
    let mut waiting = release.wait_for_release(&mut registration);
    let mut task = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut waiting).poll(&mut task),
        Poll::Pending
    ));
    drop(occupied);
    assert!(matches!(
        Pin::new(&mut waiting).poll(&mut task),
        Poll::Ready(())
    ));
    drop(waiting);
    assert_eq!(budget.reserved_bytes(), baseline);
    let owner = decode(&source, &budget, &context).unwrap();
    assert!(owner.belongs_to(&budget));
    assert_eq!(owner.get(), &expected);
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(cumulative_demand).unwrap()
    );
    drop(owner);
    assert_eq!(budget.reserved_bytes(), baseline);
    let exhausted = decode(&source, &budget, &context).unwrap_err();
    assert!(
        matches!(exhausted, SumeragiNposJsonAdmissionError::Json(ref error) if error.is_decode_resource_limit())
    );
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(cumulative_demand).unwrap()
    );
    assert_eq!(budget.reserved_bytes(), baseline);
    drop(registration);
    drop(context);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_npos_escaped_leaves_keep_exact_simultaneous_text_digits_and_record_peak() {
    let value = SumeragiNposParameters::default();
    let original_source = source();
    let escaped_key = original_source.replacen("\"min_self_bond\"", "\"\\u006Din_self_bond\"", 1);
    assert_ne!(
        escaped_key, original_source,
        "the exact original key is escaped"
    );
    let escaped_seed = escaped_key.replacen("A5A5", "\\u00415A5", 1);
    assert_ne!(
        escaped_seed, escaped_key,
        "the exact original seed string is escaped"
    );
    let identity = value.xor_asset_definition_id.to_string();
    let identity_token = format!("\"{identity}\"");
    let escaped_identity_token = format!("\"\\u{:04x}{}\"", identity.as_bytes()[0], &identity[1..]);
    let escaped_identity = escaped_seed.replacen(&identity_token, &escaped_identity_token, 1);
    assert_ne!(
        escaped_identity, escaped_seed,
        "the exact original identity string is escaped"
    );
    let source = escaped_identity.replacen(
        "\"123456789012345678901234567890\"",
        "\"\\u003123456789012345678901234567890\"",
        1,
    );
    assert_ne!(
        source, escaped_identity,
        "the exact original quantity string is escaped"
    );
    let (expected, demand) = observed_demand(&source);
    let self_text = expected.min_self_bond.to_string().len();
    let nomination_text = expected.min_nomination_bond.to_string().len();
    let self_digits = expected
        .min_self_bond
        .admission_clone_layout()
        .unwrap()
        .size();
    let nomination_digits = expected
        .min_nomination_bond
        .admission_clone_layout()
        .unwrap()
        .size();
    let record = AdmittedSumeragiNposParameters::allocation_layout().size();
    let control = DecodeBudgetContext::allocation_layout().size();
    let temporary_peak = value
        .xor_asset_definition_id
        .to_string()
        .len()
        .max(64)
        .max("min_self_bond".len() + self_text + self_digits)
        .max(self_digits + nomination_text + nomination_digits);
    let peak = control + record + temporary_peak;
    let budget = AllocationBudget::new(peak);
    let context = DecodeBudgetContext::try_new_owned(limits(demand), &budget).unwrap();
    let owner = decode(&source, &budget, &context).unwrap();
    assert_eq!(owner.get(), &expected);
    assert_eq!(budget.peak_reserved_bytes(), peak);
    assert_eq!(
        budget.reserved_bytes(),
        control + record + self_digits + nomination_digits
    );
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(demand).unwrap()
    );
    drop(owner);
    drop(context);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_npos_custom_parameter_keeps_exact_source_completion_and_original_validation() {
    let source = source();
    let (expected, demand) = observed_demand(&source);
    let budget = AllocationBudget::new(
        AdmittedSumeragiNposParameters::allocation_layout().size() + source.len(),
    );
    let context = DecodeBudgetContext::new(limits(demand));
    let custom = expected.clone().into_custom_parameter();
    let owner = context
        .with(|| AdmittedSumeragiNposParameters::from_custom_parameter(&custom, &budget))
        .unwrap()
        .unwrap();
    assert_eq!(owner.get(), &expected);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(demand).unwrap()
    );
    let invalid = CustomParameter::new(
        SumeragiNposParameters::parameter_id(),
        iroha_primitives::json::Json::new("not a record"),
    );
    let ordinary = SumeragiNposParameters::from_custom_parameter(&invalid).unwrap_err();
    let admitted =
        AdmittedSumeragiNposParameters::from_custom_parameter(&invalid, &budget).unwrap_err();
    assert!(
        matches!(admitted, SumeragiNposJsonAdmissionError::Json(ref error) if format!("{error:?}")==format!("{ordinary:?}"))
    );
    let unrelated = CustomParameter::new(
        "other_parameter".parse().unwrap(),
        iroha_primitives::json::Json::new(0_u32),
    );
    let before = budget.reserved_bytes();
    assert!(
        AdmittedSumeragiNposParameters::from_custom_parameter(&unrelated, &budget)
            .unwrap()
            .is_none()
    );
    assert_eq!(budget.reserved_bytes(), before);
}
