#[test]
fn rounded_decimal_division_supports_every_v1_rounding_mode() {
    use ivm_abi::numeric::RoundingModeV1 as AbiMode;
    for (dividend, mode, expected, abi_mode) in [
        ("1.0", "toward_zero", "0.12", AbiMode::TowardZero),
        ("1.0", "away_from_zero", "0.13", AbiMode::AwayFromZero),
        ("-1.0", "floor", "-0.13", AbiMode::Floor),
        ("-1.0", "ceil", "-0.12", AbiMode::Ceil),
        ("1.0", "nearest_even", "0.12", AbiMode::NearestEven),
        ("1.0", "nearest_away", "0.13", AbiMode::NearestAway),
        (
            "1.0",
            "nearest_toward_zero",
            "0.12",
            AbiMode::NearestTowardZero,
        ),
    ] {
        let expression = returned_expr(&format!(
            "fn value() -> decimal {{ return {dividend}.div_round(\
                    divisor: 8.0, scale: 2, mode: Rounding::{mode}); }}"
        ));
        let ExprKind::DecimalLiteral { value, .. } = expression.expr else {
            panic!("constant rounded division must fold");
        };
        assert_eq!(value.to_string(), expected, "mode={mode}");
        let expression = returned_expr(&format!(
            "fn rounded(decimal value) -> decimal {{ return value.div_round(\
                    divisor: 8.0, scale: 2, mode: Rounding::{mode}); }}"
        ));
        let ExprKind::NamedCall { target: name, args, .. } = expression.expr else {
            panic!("dynamic rounded division must remain an intrinsic for mode={mode}");
        };
        assert_eq!(name, CallTarget::Intrinsic(CompilerIntrinsic::DecimalDivRound), "mode={mode}");
        assert!(
            matches!(
                args[3].expr,
                ExprKind::IntLiteral(ref value)
                    if value.try_to_u64() == Some(abi_mode.tag())
            ),
            "mode={mode} did not lower to ABI tag {}",
            abi_mode.tag(),
        );
    }
    let expression = returned_expr(
        "fn rounded(quantity value, decimal divisor, int scale) -> quantity { \
                return value.div_round( \
                    mode: Rounding::nearest_even, divisor: divisor, scale: scale); }",
    );
    let ExprKind::NamedCall {
        target: name,
        args,
        evaluation_order,
    } = expression.expr
    else {
        panic!("dynamic rounded division must remain a typed intrinsic");
    };
    assert_eq!(name, CallTarget::Intrinsic(CompilerIntrinsic::QuantityDivRound));
    assert_eq!(args.len(), 4);
    assert_eq!(args[0].ty, Type::Quantity);
    assert_eq!(args[1].ty, Type::Decimal);
    assert_eq!(args[2].ty, Type::Int);
    assert!(matches!(
        args[3].expr,
        ExprKind::IntLiteral(ref value)
            if value.try_to_u64()
                == Some(ivm_abi::numeric::RoundingModeV1::NearestEven.tag())
    ));
    assert_eq!(evaluation_order, [0, 3, 1, 2]);
    let ratio = returned_expr(
        "fn rounded(quantity value, quantity divisor, int scale) -> decimal { \
                return value.ratio_round( \
                    divisor: divisor, scale: scale, mode: Rounding::floor); }",
    );
    let ExprKind::NamedCall { target: name, args, .. } = ratio.expr else {
        panic!("dynamic rounded ratio must remain a typed intrinsic");
    };
    assert_eq!(name, CallTarget::Intrinsic(CompilerIntrinsic::QuantityRatioRound));
    assert_eq!(args[0].ty, Type::Quantity);
    assert_eq!(args[1].ty, Type::Quantity);
    assert_eq!(args[2].ty, Type::Int);
    assert_eq!(ratio.ty, Type::Decimal);
}
