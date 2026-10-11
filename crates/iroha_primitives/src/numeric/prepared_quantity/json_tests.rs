//! Actual shared JSON leaf, original-pool admission and cumulative refusal controls.

use std::{
    error::Error as _,
    future::Future as _,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
use norito::core::{DecodeBudgetContext, DecodeLimits, serialize_to_buffer};

use super::*;

fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}
fn bytes_u64(bytes: usize) -> u64 {
    u64::try_from(bytes).expect("fixture demand fits u64")
}
fn source_geometry(source: &str) -> (Quantity, usize, Layout) {
    // Independent ordinary decode supplies semantic parity and actual native
    // geometry, outside the admitted leaf's original cumulative operation.
    let ordinary = json::from_str::<Quantity>(source).expect("canonical fixture");
    let text = json::from_str::<String>(source).expect("original string fixture");
    let digits = ordinary
        .admission_clone_layout()
        .expect("actual native digits");
    (ordinary, text.len(), digits)
}
fn decode(
    source: &str,
    budget: &AllocationBudget,
    context: &DecodeBudgetContext,
) -> Result<ChargedQuantity, QuantityJsonAdmissionError> {
    context.with(|| {
        let mut parser = json::Parser::new(source);
        let result = ChargedQuantity::try_decode_json(&mut parser, budget)?;
        parser.skip_ws();
        assert!(
            parser.eof(),
            "the genuine leaf consumes the complete fixture"
        );
        Ok(result)
    })
}

#[test]
fn admitted_quantity_json_matches_ordinary_escaped_values_and_exact_original_digits() {
    let maximum = Quantity::from_canonical_numeric(Numeric::new(
        BigInt::from_inner((UnboundedBigInt::one() << 511_usize) - 1_u8).unwrap(),
        MAX_DECIMAL_SCALE,
    ))
    .unwrap();
    let maximum_source = json::to_json(&maximum).unwrap();
    for source in [
        r#""0""#,
        r#""1""#,
        r#""1.23""#,
        r#""\u0031.\u0032\u0033""#,
        r#""1\u002e23""#,
        maximum_source.as_str(),
    ] {
        let (ordinary, text_bytes, digit_layout) = source_geometry(source);
        let one_pass = text_bytes + digit_layout.size();
        let control = DecodeBudgetContext::allocation_layout().size();
        let peak = control + one_pass;
        let budget = AllocationBudget::new(peak);
        let foreign = AllocationBudget::new(peak);
        let context = DecodeBudgetContext::try_new_owned(limits(one_pass * 2), &budget).unwrap();
        let owner = decode(source, &budget, &context).expect("exact admitted source");
        assert_eq!(owner.get(), &ordinary);
        assert_eq!(owner.charge.layout(), digit_layout);
        assert!(owner.belongs_to(&budget));
        assert!(!owner.belongs_to(&foreign));
        assert_eq!(budget.reserved_bytes(), control + digit_layout.size());
        assert_eq!(budget.peak_reserved_bytes(), peak);
        assert_eq!(context.consumed_allocated_bytes(), bytes_u64(one_pass));
        let original_digits = owner
            .get()
            .mantissa()
            .inner()
            .magnitude()
            .native_digits()
            .as_ptr();
        budget.set_limit_bytes(0);
        assert_eq!(
            owner.get(),
            &ordinary,
            "borrowing never reacquires original backing"
        );
        assert_eq!(
            owner
                .get()
                .mantissa()
                .inner()
                .magnitude()
                .native_digits()
                .as_ptr(),
            original_digits
        );
        let mut expected_wire = Vec::new();
        let mut actual_wire = Vec::new();
        serialize_to_buffer(&ordinary, &mut expected_wire).unwrap();
        serialize_to_buffer(owner.get(), &mut actual_wire).unwrap();
        assert_eq!(
            actual_wire, expected_wire,
            "the leaf changes no canonical wire bytes"
        );
        drop(owner);
        assert_eq!(budget.reserved_bytes(), control);
        budget.set_limit_bytes(peak);
        let retry = decode(source, &budget, &context).expect("same original cumulative context");
        assert_eq!(retry.get(), &ordinary);
        assert_eq!(context.consumed_allocated_bytes(), bytes_u64(one_pass * 2));
        drop(retry);
        let exhausted = decode(source, &budget, &context)
            .err()
            .expect("no fresh decoder budget");
        assert!(
            matches!(exhausted, QuantityJsonAdmissionError::Json(ref error)
            if error.is_decode_resource_limit())
        );
        assert_eq!(context.consumed_allocated_bytes(), bytes_u64(one_pass * 2));
        assert_eq!(budget.reserved_bytes(), control);
        assert_eq!(foreign.reserved_bytes(), 0);
        drop(context);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn admitted_quantity_json_text_capacity_retains_typed_original_release_and_cumulative_work() {
    let source = r#""\u0031.23""#;
    let (ordinary, text_bytes, digit_layout) = source_geometry(source);
    let one_pass = text_bytes + digit_layout.size();
    let decoder_bytes = DecodeBudgetContext::allocation_layout().size();
    let registration_layout = ReleaseRegistration::allocation_layout();
    let baseline = decoder_bytes + registration_layout.size();
    let peak = baseline + one_pass;
    let budget = AllocationBudget::new(peak);
    let context = DecodeBudgetContext::try_new_owned(limits(one_pass * 2), &budget).unwrap();
    let mut reservation = budget.try_reserve(registration_layout).unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut reservation).unwrap();
    drop(reservation);
    assert!(registration.belongs_to(&budget));
    let blocker = budget.try_reserve_bytes(one_pass).unwrap();
    let error = decode(source, &budget, &context)
        .err()
        .expect("actual text capacity refusal");
    let backing_error = error
        .source()
        .unwrap()
        .downcast_ref::<ChargedBufferError>()
        .unwrap();
    assert!(
        matches!(backing_error.source().unwrap().downcast_ref::<AllocationRefusal>(),
        Some(AllocationRefusal::Capacity { requested_bytes, .. }) if *requested_bytes == text_bytes)
    );
    let QuantityJsonAdmissionError::Allocation(ChargedBufferError::Admission(
        AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        },
    )) = error
    else {
        panic!("text admission must preserve its original typed capacity refusal")
    };
    assert_eq!(requested_bytes, text_bytes);
    assert_eq!(reserved_bytes, peak);
    assert_eq!(limit_bytes, peak);
    assert_eq!(budget.reserved_bytes(), peak);
    assert_eq!(context.consumed_allocated_bytes(), bytes_u64(text_bytes));
    let mut waiting = release.wait_for_release(&mut registration);
    let mut task = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut waiting).poll(&mut task),
        Poll::Pending
    ));
    drop(blocker);
    assert!(matches!(
        Pin::new(&mut waiting).poll(&mut task),
        Poll::Ready(())
    ));
    drop(waiting);
    assert_eq!(budget.reserved_bytes(), baseline);
    let owner = decode(source, &budget, &context).expect("release permits same-source retry");
    assert_eq!(owner.get(), &ordinary);
    assert!(owner.belongs_to(&budget));
    assert_eq!(owner.charge.layout(), digit_layout);
    assert_eq!(
        context.consumed_allocated_bytes(),
        bytes_u64(text_bytes + one_pass)
    );
    drop(owner);
    assert_eq!(budget.reserved_bytes(), baseline);
    drop(registration);
    drop(context);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_quantity_json_digit_capacity_keeps_text_debit_and_exact_original_pool() {
    let source = r#""1""#;
    let (ordinary, text_bytes, digit_layout) = source_geometry(source);
    let one_pass = text_bytes + digit_layout.size();
    let control = DecodeBudgetContext::allocation_layout().size();
    let peak = control + one_pass;
    let budget = AllocationBudget::new(peak);
    let context = DecodeBudgetContext::try_new_owned(limits(one_pass * 2), &budget).unwrap();
    // Occupy one genuine original byte: text still fits, but exact native digits do not.
    let blocker = budget.try_reserve_bytes(1).unwrap();
    let error = decode(source, &budget, &context)
        .err()
        .expect("actual digit capacity refusal");
    let QuantityJsonAdmissionError::Allocation(ChargedBufferError::Admission(
        AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            ..
        },
    )) = error
    else {
        panic!("native digits must preserve their exact original capacity refusal")
    };
    assert_eq!(requested_bytes, digit_layout.size());
    assert_eq!(reserved_bytes, control + text_bytes + 1);
    assert_eq!(limit_bytes, peak);
    assert_eq!(
        budget.reserved_bytes(),
        control + 1,
        "refused temporary text retires"
    );
    assert_eq!(context.consumed_allocated_bytes(), bytes_u64(one_pass));
    drop(blocker);
    let owner = decode(source, &budget, &context).expect("same pool and original decoder retry");
    assert_eq!(owner.get(), &ordinary);
    assert!(owner.belongs_to(&budget));
    assert_eq!(owner.charge.layout(), digit_layout);
    assert_eq!(context.consumed_allocated_bytes(), bytes_u64(one_pass * 2));
    drop(owner);
    assert_eq!(budget.reserved_bytes(), control);
    drop(context);
    assert_eq!(budget.reserved_bytes(), 0);

    let permanent = AllocationBudget::new(text_bytes);
    let mut parser = json::Parser::new(source);
    let error = ChargedQuantity::try_decode_json(&mut parser, &permanent)
        .err()
        .unwrap();
    assert!(
        matches!(error, QuantityJsonAdmissionError::Allocation(ChargedBufferError::Admission(
        AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes }
    )) if requested_bytes == digit_layout.size() && limit_bytes == text_bytes)
    );
    assert_eq!(permanent.reserved_bytes(), 0);
}

#[test]
fn admitted_quantity_json_preserves_syntax_and_pre_allocation_logical_refusal_order() {
    let overlong = format!("\"{}\"", "1".repeat(MAX_CANONICAL_QUANTITY_TEXT_BYTES + 1));
    for source in [
        r#""01""#,
        r#""1.0""#,
        r#""-1""#,
        r#""1e2""#,
        r#""\u00e9""#,
        r#""\uD83D\uDE80""#,
        r#""\uD800""#,
        r#""\uDFFF""#,
        r#""\uD800\u0000""#,
        r#""\q""#,
        "\"unterminated",
    ]
    .into_iter()
    .chain([overlong.as_str()])
    {
        let expected = json::from_str::<Quantity>(source).unwrap_err();
        let budget = AllocationBudget::new(
            DecodeBudgetContext::allocation_layout().size() + MAX_CANONICAL_QUANTITY_TEXT_BYTES,
        );
        let context = DecodeBudgetContext::try_new_owned(limits(usize::MAX), &budget).unwrap();
        let before = budget.reserved_bytes();
        let error = decode(source, &budget, &context)
            .err()
            .expect("same canonical syntax refusal");
        let QuantityJsonAdmissionError::Json(error) = error else {
            panic!("invalid syntax must keep the ordinary JSON category")
        };
        assert_eq!(
            error.to_string(),
            expected.to_string(),
            "original source {source}"
        );
        assert_eq!(budget.reserved_bytes(), before);
        drop(context);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let source = r#""\u0031.23""#;
    let (_, text_bytes, digit_layout) = source_geometry(source);
    let control = DecodeBudgetContext::allocation_layout().size();
    let peak = control + text_bytes + digit_layout.size();
    for (bound, expected_consumed) in [
        (text_bytes - 1, 0),
        (text_bytes + digit_layout.size() - 1, text_bytes),
    ] {
        let budget = AllocationBudget::new(peak);
        let context = DecodeBudgetContext::try_new_owned(limits(bound), &budget).unwrap();
        let error = decode(source, &budget, &context)
            .err()
            .expect("actual logical refusal");
        assert!(matches!(error, QuantityJsonAdmissionError::Json(ref error)
            if error.is_decode_resource_limit()));
        assert_eq!(
            context.consumed_allocated_bytes(),
            bytes_u64(expected_consumed)
        );
        assert_eq!(budget.reserved_bytes(), control);
        let expected_peak = control + expected_consumed;
        assert_eq!(
            budget.peak_reserved_bytes(),
            expected_peak,
            "logical refusal precedes the corresponding physical owner callback"
        );
        drop(context);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn admitted_quantity_json_seeded_value_uses_original_visitor_and_typed_leaf_refusal() {
    let source = r#"{"bond":"\u0031.23"}"#;
    let (_, text_bytes, digit_layout) = source_geometry(r#""\u0031.23""#);
    let budget = AllocationBudget::new(text_bytes + digit_layout.size());
    let mut parser = json::Parser::new(source);
    let mut map = json::MapVisitor::new(&mut parser).unwrap();
    assert_eq!(map.next_key().unwrap().unwrap().as_str(), "bond");
    let owner = map
        .parse_value_with_parser_typed(|parser| ChargedQuantity::try_decode_json(parser, &budget))
        .unwrap();
    map.finish().unwrap();
    assert!(parser.eof());
    assert_eq!(
        owner.get(),
        &json::from_str::<Quantity>(r#""1.23""#).unwrap()
    );
    assert!(owner.belongs_to(&budget));
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
    // This uses an ordinary borrowed key. It does not claim admission for
    // escaped key storage, NPoS records, their controls or partial record retry.
    let empty = AllocationBudget::new(0);
    let mut parser = json::Parser::new(source);
    let mut map = json::MapVisitor::new(&mut parser).unwrap();
    map.next_key().unwrap();
    let error = map
        .parse_value_with_parser_typed(|parser| ChargedQuantity::try_decode_json(parser, &empty))
        .err()
        .expect("same typed seeded-value failure");
    assert!(
        matches!(error, QuantityJsonAdmissionError::Allocation(ChargedBufferError::Admission(
        AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes: 0 }
    )) if requested_bytes == "1.23".len())
    );
    assert_eq!(empty.reserved_bytes(), 0);
}
