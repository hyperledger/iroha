//! The gates of the Pasta ECC chip (layout in the module documentation).
//!
//! Every gate is a simple selector times polynomials in the chip's ten
//! advice columns `a0..a9` at rotations `-1, 0, 1` (and, for the fixed-base
//! gates, sixteen coefficient columns at rotation 0). Degrees, selector
//! included, are at most [`crate::MAX_GATE_DEGREE`].

use ff::Field;
use iroha_pasta::{PastaCurve, PastaField};
use iroha_plonk::cs::{
    Advice, Column, ConstraintSystem, Expression, Fixed, Rotation, Selector, VirtualCells,
};

use crate::phase::{Enable, PhaseColumns};

use super::{
    ECC_ADVICE_COLUMNS,
    native::{SplitConstants, beta, coordinates, two_pow, two_pow_128},
};

/// The chip's advice columns.
pub(super) type Advices = [Column<Advice>; ECC_ADVICE_COLUMNS];

/// A named polynomial.
type Named<F> = (&'static str, Expression<F>);

/// The query of advice column `column` at `rotation`.
fn adv<F: PastaField>(
    cells: &mut VirtualCells<'_, F>,
    advice: &Advices,
    column: usize,
    rotation: i32,
) -> Expression<F> {
    cells.query_advice(advice[column], Rotation(rotation))
}

/// A constant expression.
const fn constant<F>(value: F) -> Expression<F> {
    Expression::Constant(value)
}

/// `b (b - 1)`.
fn boolean<F: PastaField>(b: &Expression<F>) -> Expression<F> {
    b.clone() * (b.clone() - constant(F::ONE))
}

/// Multiplies every polynomial by the selector.
fn gated<F: PastaField>(q: &Expression<F>, polys: Vec<Named<F>>) -> Vec<Named<F>> {
    polys
        .into_iter()
        .map(|(name, poly)| (name, q.clone() * poly))
        .collect()
}

/// The joint digit point `T = (2 b1 - 1) P + (2 b2 - 1) phi(P)` as
/// expressions in the digit bits and the carried base data
/// `(x_P, y_P, x_-, y_-)`: `S+ = (beta^2 x_P, -y_P)`, `S- = (x_-, y_-)`,
/// `c = b1 xor b2`, `x_T = x_+ + c (x_- - x_+)`,
/// `y_T = (2 b1 - 1) (y_+ + c (y_- - y_+))` (degrees 3 and 4).
fn joint_point<F: PastaField>(
    bits: [&Expression<F>; 2],
    base: [&Expression<F>; 4],
    beta_squared: F,
) -> (Expression<F>, Expression<F>) {
    let [b1, b2] = bits;
    let [x_p, y_p, x_m, y_m] = base;
    let two = F::from(2);
    let c = b1.clone() + b2.clone() - b1.clone() * b2.clone() * two;
    let x_plus = x_p.clone() * beta_squared;
    let y_plus = -y_p.clone();
    let x_t = x_plus.clone() + c.clone() * (x_m.clone() - x_plus);
    let y_t = (b1.clone() * two - constant(F::ONE)) * (y_plus.clone() + c * (y_m.clone() - y_plus));
    (x_t, y_t)
}

/// The constraints carrying the base data `(x_P, y_P, x_-, y_-)` from the
/// current row to the next.
fn carry<F: PastaField>(base: &[Expression<F>; 4], next: [Expression<F>; 4]) -> Vec<Named<F>> {
    ["carry x_P", "carry y_P", "carry x_-", "carry y_-"]
        .into_iter()
        .zip(next.into_iter().zip(base))
        .map(|(name, (next, base))| (name, next - base.clone()))
        .collect()
}

/// The constraints of the chain's initial row: the tangent slope of `2P`
/// gives `acc_0 = 2 S+ = (beta^2 x_2P, -y_2P)`, the slope of `P - phi(P)`
/// gives `S-`, and the running sums start at zero.
fn init_constraints<F: PastaField>(
    base: [&Expression<F>; 2],
    slopes: [&Expression<F>; 2],
    next: [&Expression<F>; 6],
    beta: F,
) -> Vec<Named<F>> {
    let [x, y] = base;
    let [lambda_d, lambda_s] = slopes;
    let [acc_x, acc_y, run_1, run_2, minus_x, minus_y] = next;
    let two = F::from(2);
    let three = F::from(3);
    let x_2 = lambda_d.clone() * lambda_d.clone() - x.clone() * two;
    let y_2 = lambda_d.clone() * (x.clone() - x_2.clone()) - y.clone();
    vec![
        (
            "tangent slope",
            lambda_d.clone() * y.clone() * two - x.clone() * x.clone() * three,
        ),
        ("acc x = beta^2 x_2P", acc_x.clone() - x_2 * beta.square()),
        ("acc y = -y_2P", acc_y.clone() + y_2),
        (
            "minus slope",
            lambda_s.clone() * x.clone() * (F::ONE - beta) - y.clone() * two,
        ),
        (
            "minus x",
            minus_x.clone() - (lambda_s.clone() * lambda_s.clone() - x.clone() * (F::ONE + beta)),
        ),
        (
            "minus y",
            minus_y.clone() - (lambda_s.clone() * (x.clone() - minus_x.clone()) - y.clone()),
        ),
        ("running 1 starts at 0", run_1.clone()),
        ("running 2 starts at 0", run_2.clone()),
    ]
}

/// The selectors of the variable-base gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Selectors {
    /// On-curve-or-identity of `(a0, a1)` and of `(a2, a3)`.
    pub point: [Enable; 2],
    /// On-curve (never the identity) of `(a0, a1)` and of `(a2, a3)`.
    pub curve: [Enable; 2],
    /// The chain's initial row (non-identity base).
    pub init: Enable,
    /// The chain's initial row with the identity guard.
    pub init_guarded: Enable,
    /// One incomplete double-and-add iteration.
    pub incomplete: Enable,
    /// The digit point of one complete iteration.
    pub select: Enable,
    /// The even-digit correction `-E`.
    pub tail: Enable,
    /// One complete addition.
    pub add: Enable,
    /// The guarded output.
    pub guard_out: Enable,
    /// The GLV split check.
    pub split: Enable,
}

/// The fixed-base columns and selectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedBaseColumns {
    /// Multilinear coefficients of the window points' `x`.
    pub(super) x: [Column<Fixed>; 8],
    /// Multilinear coefficients of the window points' `y`.
    pub(super) y: [Column<Fixed>; 8],
    /// Window 0: `A_1 = T_0`.
    pub(super) first: Selector,
    /// Windows `1..=83`: `A_{i+1} = A_i + T_i` (incomplete).
    pub(super) incomplete: Selector,
    /// Window 84: `T_84` and the carried `A_84` for the complete addition.
    pub(super) last: Selector,
    /// The link of the window running sum to the scalar limbs.
    pub(super) link: Selector,
}

/// Configures the variable-base gates on `advice` for the curve `C`.
pub(super) fn configure_variable_base<C: PastaCurve>(
    meta: &mut ConstraintSystem<C::Base>,
    advice: Advices,
) -> Selectors {
    let selectors = Selectors {
        point: [meta.selector().into(), meta.selector().into()],
        curve: [meta.selector().into(), meta.selector().into()],
        init: meta.selector().into(),
        init_guarded: meta.selector().into(),
        incomplete: meta.selector().into(),
        select: meta.selector().into(),
        tail: meta.selector().into(),
        add: meta.selector().into(),
        guard_out: meta.selector().into(),
        split: meta.selector().into(),
    };
    configure_variable_base_with::<C>(meta, advice, &selectors)
}

/// Compact ECC phase; paired codes are mutually exclusive in the fixed layout.
pub(super) fn configure_variable_base_phased<C: PastaCurve>(
    meta: &mut ConstraintSystem<C::Base>,
    advice: Advices,
    phases: PhaseColumns,
) -> Selectors {
    let code = |column, code, largest| phases.enable(1, Some((column, code, largest)));
    let selectors = Selectors {
        point: [code(0, 1, 3), code(1, 1, 3)],
        curve: [code(0, 2, 3), code(1, 2, 3)],
        init: code(2, 1, 4),
        init_guarded: code(2, 2, 4),
        incomplete: code(3, 1, 3),
        select: code(3, 2, 3),
        tail: code(4, 1, 2),
        add: code(4, 2, 2),
        guard_out: code(5, 1, 5),
        split: code(5, 2, 5),
    };
    configure_variable_base_with::<C>(meta, advice, &selectors)
}

fn configure_variable_base_with<C: PastaCurve>(
    meta: &mut ConstraintSystem<C::Base>,
    advice: Advices,
    selectors: &Selectors,
) -> Selectors {
    configure_points::<C>(meta, advice, selectors);
    configure_init::<C>(meta, advice, selectors);
    configure_iterations::<C>(meta, advice, selectors);
    configure_complete_add(meta, advice, selectors.add);
    configure_guard_out(meta, advice, selectors.guard_out);
    configure_split::<C>(meta, advice, selectors.split);
    *selectors
}

/// The on-curve gates.
fn configure_points<C: PastaCurve>(
    meta: &mut ConstraintSystem<C::Base>,
    advice: Advices,
    selectors: &Selectors,
) {
    let b = C::b();
    for (half, (point, curve)) in selectors.point.into_iter().zip(selectors.curve).enumerate() {
        let (x_column, y_column) = (2 * half, 2 * half + 1);
        meta.create_gate("ecc on curve or identity", |cells| {
            let q = point.query(cells);
            let x = adv(cells, &advice, x_column, 0);
            let y = adv(cells, &advice, y_column, 0);
            let residue = y.clone() * y.clone() - x.clone() * x.clone() * x.clone() - constant(b);
            gated(
                &q,
                vec![
                    ("(y^2 - x^3 - b) x", residue.clone() * x),
                    ("(y^2 - x^3 - b) y", residue * y),
                ],
            )
        });
        meta.create_gate("ecc on curve", |cells| {
            let q = curve.query(cells);
            let x = adv(cells, &advice, x_column, 0);
            let y = adv(cells, &advice, y_column, 0);
            gated(
                &q,
                vec![(
                    "y^2 - x^3 - b",
                    y.clone() * y - x.clone() * x.clone() * x - constant(b),
                )],
            )
        });
    }
}

/// The chain's initial-row gates (plain and guarded).
fn configure_init<C: PastaCurve>(
    meta: &mut ConstraintSystem<C::Base>,
    advice: Advices,
    selectors: &Selectors,
) {
    let beta = beta::<C>();
    let (g_x, g_y) = coordinates(&C::generator());
    meta.create_gate("ecc glv init", |cells| {
        let q = selectors.init.query(cells);
        let x = adv(cells, &advice, 2, 0);
        let y = adv(cells, &advice, 3, 0);
        let lambda_d = adv(cells, &advice, 4, 0);
        let lambda_s = adv(cells, &advice, 5, 0);
        let next = [0, 1, 2, 3, 8, 9].map(|column| adv(cells, &advice, column, 1));
        let base_x = adv(cells, &advice, 6, 1);
        let base_y = adv(cells, &advice, 7, 1);
        let mut polys = vec![
            ("carried base x", base_x - x.clone()),
            ("carried base y", base_y - y.clone()),
        ];
        polys.extend(init_constraints(
            [&x, &y],
            [&lambda_d, &lambda_s],
            [&next[0], &next[1], &next[2], &next[3], &next[4], &next[5]],
            beta,
        ));
        gated(&q, polys)
    });
    meta.create_gate("ecc glv guarded init", |cells| {
        let q = selectors.init_guarded.query(cells);
        let is_identity = adv(cells, &advice, 0, 0);
        let inverse = adv(cells, &advice, 1, 0);
        let x_in = adv(cells, &advice, 2, 0);
        let y_in = adv(cells, &advice, 3, 0);
        let lambda_d = adv(cells, &advice, 4, 0);
        let lambda_s = adv(cells, &advice, 5, 0);
        let next = [0, 1, 2, 3, 8, 9].map(|column| adv(cells, &advice, column, 1));
        let x = adv(cells, &advice, 6, 1);
        let y = adv(cells, &advice, 7, 1);
        let one = constant(C::Base::ONE);
        let mut polys = vec![
            (
                "x inv + is_id - 1",
                x_in.clone() * inverse.clone() + is_identity.clone() - one,
            ),
            ("x is_id", x_in.clone() * is_identity.clone()),
            ("inv is_id", inverse * is_identity.clone()),
            (
                "guarded base x",
                x.clone() - (x_in.clone() + is_identity.clone() * (constant(g_x) - x_in)),
            ),
            (
                "guarded base y",
                y.clone() - (y_in.clone() + is_identity * (constant(g_y) - y_in)),
            ),
        ];
        polys.extend(init_constraints(
            [&x, &y],
            [&lambda_d, &lambda_s],
            [&next[0], &next[1], &next[2], &next[3], &next[4], &next[5]],
            beta,
        ));
        gated(&q, polys)
    });
}

/// The incomplete double-and-add, the complete-iteration digit point and
/// the even-digit correction gates.
fn configure_iterations<C: PastaCurve>(
    meta: &mut ConstraintSystem<C::Base>,
    advice: Advices,
    selectors: &Selectors,
) {
    let beta = beta::<C>();
    let beta_squared = beta.square();
    let two = C::Base::from(2);
    meta.create_gate("ecc glv incomplete double-and-add", |cells| {
        let q = selectors.incomplete.query(cells);
        let cur: [Expression<C::Base>; ECC_ADVICE_COLUMNS] =
            core::array::from_fn(|column| adv(cells, &advice, column, 0));
        let [x_next, y_next, run_1_next, run_2_next] =
            [0, 1, 2, 3].map(|column| adv(cells, &advice, column, 1));
        let carried = [6, 7, 8, 9].map(|column| adv(cells, &advice, column, 1));
        let [
            x_a,
            y_a,
            run_1,
            run_2,
            lambda_1,
            lambda_2,
            x_p,
            y_p,
            x_m,
            y_m,
        ] = cur;
        let base = [x_p, y_p, x_m, y_m];
        let b1 = run_1_next - run_1 * two;
        let b2 = run_2_next - run_2 * two;
        let (x_t, y_t) = joint_point(
            [&b1, &b2],
            [&base[0], &base[1], &base[2], &base[3]],
            beta_squared,
        );
        let x_r = lambda_1.clone() * lambda_1.clone() - x_a.clone() - x_t.clone();
        let mut polys = vec![
            ("bit 1", boolean(&b1)),
            ("bit 2", boolean(&b2)),
            (
                "lambda_1 (x_A - x_T) = y_A - y_T",
                lambda_1.clone() * (x_a.clone() - x_t) - (y_a.clone() - y_t),
            ),
            (
                "(lambda_1 + lambda_2) (x_A - x_R) = 2 y_A",
                (lambda_1 + lambda_2.clone()) * (x_a.clone() - x_r.clone()) - y_a.clone() * two,
            ),
            (
                "x_A' = lambda_2^2 - x_A - x_R",
                x_next.clone() - (lambda_2.clone() * lambda_2.clone() - x_a.clone() - x_r),
            ),
            (
                "y_A' = lambda_2 (x_A - x_A') - y_A",
                y_next - (lambda_2 * (x_a - x_next) - y_a),
            ),
        ];
        polys.extend(carry(&base, carried));
        gated(&q, polys)
    });
    meta.create_gate("ecc glv complete-iteration digit point", |cells| {
        let q = selectors.select.query(cells);
        let run_1 = adv(cells, &advice, 2, 0);
        let run_2 = adv(cells, &advice, 3, 0);
        let base = [6, 7, 8, 9].map(|column| adv(cells, &advice, column, 0));
        let [x_t_next, y_t_next, run_1_next, run_2_next] =
            [0, 1, 2, 3].map(|column| adv(cells, &advice, column, 1));
        let carried = [6, 7, 8, 9].map(|column| adv(cells, &advice, column, 1));
        let b1 = run_1_next - run_1 * two;
        let b2 = run_2_next - run_2 * two;
        let (x_t, y_t) = joint_point(
            [&b1, &b2],
            [&base[0], &base[1], &base[2], &base[3]],
            beta_squared,
        );
        let mut polys = vec![
            ("bit 1", boolean(&b1)),
            ("bit 2", boolean(&b2)),
            ("x_T", x_t_next - x_t),
            ("y_T", y_t_next - y_t),
        ];
        polys.extend(carry(&base, carried));
        gated(&q, polys)
    });
    meta.create_gate("ecc glv even-digit correction", |cells| {
        let q = selectors.tail.query(cells);
        let x_p = adv(cells, &advice, 6, 0);
        let y_p = adv(cells, &advice, 7, 0);
        let x_e = adv(cells, &advice, 0, 1);
        let y_e = adv(cells, &advice, 1, 1);
        let f1 = adv(cells, &advice, 2, 1);
        let f2 = adv(cells, &advice, 3, 1);
        let one = constant(C::Base::ONE);
        let e1 = one.clone() - f1.clone();
        let e2 = one - f2.clone();
        let x_factor = e1.clone()
            + e2.clone() * beta
            + e1.clone() * e2.clone() * (beta_squared - C::Base::ONE - beta);
        let y_factor = e1.clone() + e2.clone() - e1 * e2 * C::Base::from(3);
        gated(
            &q,
            vec![
                ("f1 bit", boolean(&f1)),
                ("f2 bit", boolean(&f2)),
                ("-E x", x_e - x_p * x_factor),
                ("-E y", y_e + y_p * y_factor),
            ],
        )
    });
}

/// The complete addition gate: the halo2 book's complete addition, plus
/// constraints that pin every inverse witness and the slope in every case.
fn configure_complete_add<F: PastaField>(
    meta: &mut ConstraintSystem<F>,
    advice: Advices,
    selector: Enable,
) {
    meta.create_gate("ecc complete addition", |cells| {
        let q = selector.query(cells);
        let cur: [Expression<F>; 9] = core::array::from_fn(|column| adv(cells, &advice, column, 0));
        let x_r = adv(cells, &advice, 2, 1);
        let y_r = adv(cells, &advice, 3, 1);
        let [x_p, y_p, x_q, y_q, lambda, alpha, beta, gamma, delta] = cur;
        let one = constant(F::ONE);
        let d = x_q.clone() - x_p.clone();
        let s = y_q.clone() + y_p.clone();
        let not_d = one.clone() - d.clone() * alpha.clone();
        let not_p = one.clone() - x_p.clone() * beta.clone();
        let not_q = one.clone() - x_q.clone() * gamma.clone();
        let not_s = one - s.clone() * delta.clone();
        let secant_x = lambda.clone() * lambda.clone() - x_p.clone() - x_q.clone() - x_r.clone();
        let secant_y = lambda.clone() * (x_p.clone() - x_r.clone()) - y_p.clone() - y_r.clone();
        let both = x_p.clone() * x_q.clone();
        let neither = not_d.clone() - s.clone() * delta.clone();
        gated(
            &q,
            vec![
                (
                    "d (d lambda - (y_q - y_p))",
                    d.clone() * (d.clone() * lambda.clone() - (y_q.clone() - y_p.clone())),
                ),
                (
                    "(1 - d alpha) (2 y_p lambda - 3 x_p^2)",
                    not_d.clone()
                        * (y_p.clone() * lambda.clone() * F::from(2)
                            - x_p.clone() * x_p.clone() * F::from(3)),
                ),
                (
                    "x_p x_q d secant x",
                    both.clone() * d.clone() * secant_x.clone(),
                ),
                (
                    "x_p x_q d secant y",
                    both.clone() * d.clone() * secant_y.clone(),
                ),
                ("x_p x_q s secant x", both.clone() * s.clone() * secant_x),
                ("x_p x_q s secant y", both * s.clone() * secant_y),
                (
                    "p = O: x_r = x_q",
                    not_p.clone() * (x_r.clone() - x_q.clone()),
                ),
                ("p = O: y_r = y_q", not_p.clone() * (y_r.clone() - y_q)),
                (
                    "q = O: x_r = x_p",
                    not_q.clone() * (x_r.clone() - x_p.clone()),
                ),
                ("q = O: y_r = y_p", not_q.clone() * (y_r.clone() - y_p)),
                ("opposite: x_r = 0", neither.clone() * x_r),
                ("opposite: y_r = 0", neither * y_r),
                ("alpha pinned (d != 0)", d.clone() * not_d.clone()),
                ("alpha pinned (d = 0)", alpha * not_d.clone()),
                ("beta pinned (x_p != 0)", x_p.clone() * not_p.clone()),
                ("beta pinned (x_p = 0)", beta * not_p.clone()),
                ("gamma pinned (x_q != 0)", x_q.clone() * not_q.clone()),
                ("gamma pinned (x_q = 0)", gamma * not_q.clone()),
                ("delta = 0 when d != 0", d * delta.clone()),
                ("delta pinned (d = 0, s != 0)", not_d * s * not_s.clone()),
                ("delta pinned (s = 0)", delta * not_s),
                ("lambda = 0 for O + O", not_p * not_q * lambda),
            ],
        )
    });
}

/// The guarded-output gate: `out = (1 - is_id) R`.
fn configure_guard_out<F: PastaField>(
    meta: &mut ConstraintSystem<F>,
    advice: Advices,
    selector: Enable,
) {
    meta.create_gate("ecc glv guarded output", |cells| {
        let q = selector.query(cells);
        let is_identity = adv(cells, &advice, 0, 0);
        let x = adv(cells, &advice, 2, 0);
        let y = adv(cells, &advice, 3, 0);
        let x_out = adv(cells, &advice, 2, 1);
        let y_out = adv(cells, &advice, 3, 1);
        let keep = constant(F::ONE) - is_identity;
        gated(
            &q,
            vec![
                ("x_out = (1 - is_id) x", x_out - keep.clone() * x),
                ("y_out = (1 - is_id) y", y_out - keep * y),
            ],
        )
    });
}

/// The GLV split check (module documentation, "Scalar split").
///
/// Rows (columns `a0..a3`): `prev = [f1, B1, f2, B2]`,
/// `cur = [B2_hi, lo, hi, h0]`, `next = [h1, u_lo, u_hi, v + 2^67]`.
fn configure_split<C: PastaCurve>(
    meta: &mut ConstraintSystem<C::Base>,
    advice: Advices,
    selector: Enable,
) {
    let k = SplitConstants::<C::Base>::new::<C>();
    let two = C::Base::from(2);
    let two_64 = two_pow::<C::Base>(64);
    let two_128 = two_pow_128::<C::Base>();
    let two_136 = two_pow::<C::Base>(136);
    let two_67 = two_pow::<C::Base>(67);
    meta.create_gate("ecc glv split", |cells| {
        let q = selector.query(cells);
        let [f1, b1, f2, b2] = [0, 1, 2, 3].map(|column| adv(cells, &advice, column, -1));
        let [b2_high, lo, hi, h0] = [0, 1, 2, 3].map(|column| adv(cells, &advice, column, 0));
        let [h1, u_low, u_high, v_shifted] =
            [0, 1, 2, 3].map(|column| adv(cells, &advice, column, 1));
        let k1 = b1 * two + f1.clone();
        let k2 = b2.clone() * two + f2.clone();
        let k2_low = b2 * two - b2_high.clone() * two_64 + f2.clone();
        let native = k1.clone() + k2 * k.lambda + constant(k.c1)
            - lo.clone()
            - hi.clone() * two_128
            - (u_low.clone() + u_high.clone() * two_64) * k.modulus;
        let low =
            k1 + k2_low * k.lambda_136 + b2_high * (two_64 * k.lambda_72) + constant(k.c1_136)
                - lo
                - h0.clone() * two_128
                - u_low * k.modulus_136
                - u_high * (two_64 * k.modulus_72)
                - (v_shifted - constant(two_67)) * two_136;
        gated(
            &q,
            vec![
                ("f1 bit", boolean(&f1)),
                ("f2 bit", boolean(&f2)),
                ("W = K1 + zeta K2 + C0 (mod p_N)", native),
                ("W = K1 + zeta K2 + C0 (mod 2^136)", low),
                ("hi = h0 + 2^8 h1", hi - h0 - h1 * C::Base::from(256)),
            ],
        )
    });
}

/// The multilinear interpolation `sum_S c_S prod_{i in S} b_i` of eight
/// coefficient columns at the bits `b0, b1, b2`.
fn multilinear<F: PastaField>(
    coefficients: &[Expression<F>; 8],
    bits: [&Expression<F>; 3],
) -> Expression<F> {
    let [b0, b1, b2] = bits;
    let mut sum = coefficients[0].clone();
    for (mask, coefficient) in coefficients.iter().enumerate().skip(1) {
        let mut term = coefficient.clone();
        for (bit, value) in [b0, b1, b2].into_iter().enumerate() {
            if mask & (1 << bit) != 0 {
                term = term * value.clone();
            }
        }
        sum = sum + term;
    }
    sum
}

/// Configures the fixed-base gates on `advice`.
pub(super) fn configure_fixed_base<F: PastaField>(
    meta: &mut ConstraintSystem<F>,
    advice: Advices,
) -> FixedBaseColumns {
    let columns = FixedBaseColumns {
        x: core::array::from_fn(|_| meta.fixed_column()),
        y: core::array::from_fn(|_| meta.fixed_column()),
        first: meta.selector(),
        incomplete: meta.selector(),
        last: meta.selector(),
        link: meta.selector(),
    };
    let quarter = F::from(4).invert().unwrap_or(F::ZERO);
    let eight = F::from(8);
    let two = F::from(2);
    // The window bits from the running sum `z`, `z_next` (zero for the last
    // window) and the witnessed `b0, b1`: `b2 = (k - b0 - 2 b1) / 4`.
    let window = move |cells: &mut VirtualCells<'_, F>, last: bool| {
        let z = adv(cells, &advice, 2, 0);
        let k = if last {
            z
        } else {
            z - adv(cells, &advice, 2, 1) * eight
        };
        let b0 = adv(cells, &advice, 3, 0);
        let b1 = adv(cells, &advice, 4, 0);
        let b2 = (k - b0.clone() - b1.clone() * two) * quarter;
        let x_coefficients = columns
            .x
            .map(|column| cells.query_fixed(column, Rotation::cur()));
        let y_coefficients = columns
            .y
            .map(|column| cells.query_fixed(column, Rotation::cur()));
        let x_t = multilinear(&x_coefficients, [&b0, &b1, &b2]);
        let y_t = multilinear(&y_coefficients, [&b0, &b1, &b2]);
        let bits = vec![
            ("b0 bit", boolean(&b0)),
            ("b1 bit", boolean(&b1)),
            ("b2 bit", boolean(&b2)),
        ];
        (bits, x_t, y_t)
    };
    meta.create_gate("ecc fixed-base first window", |cells| {
        let q = cells.query_selector(columns.first);
        let (mut polys, x_t, y_t) = window(cells, false);
        let x_next = adv(cells, &advice, 0, 1);
        let y_next = adv(cells, &advice, 1, 1);
        polys.push(("A_1 x = x_T", x_next - x_t));
        polys.push(("A_1 y = y_T", y_next - y_t));
        gated(&q, polys)
    });
    meta.create_gate("ecc fixed-base incomplete window", |cells| {
        let q = cells.query_selector(columns.incomplete);
        let (mut polys, x_t, y_t) = window(cells, false);
        let x_a = adv(cells, &advice, 0, 0);
        let y_a = adv(cells, &advice, 1, 0);
        let lambda = adv(cells, &advice, 5, 0);
        let x_next = adv(cells, &advice, 0, 1);
        let y_next = adv(cells, &advice, 1, 1);
        polys.push((
            "lambda (x_A - x_T) = y_A - y_T",
            lambda.clone() * (x_a.clone() - x_t.clone()) - (y_a.clone() - y_t),
        ));
        polys.push((
            "x_A' = lambda^2 - x_A - x_T",
            x_next.clone() - (lambda.clone() * lambda.clone() - x_a.clone() - x_t),
        ));
        polys.push((
            "y_A' = lambda (x_A - x_A') - y_A",
            y_next - (lambda * (x_a - x_next) - y_a),
        ));
        gated(&q, polys)
    });
    meta.create_gate("ecc fixed-base last window", |cells| {
        let q = cells.query_selector(columns.last);
        let (mut polys, x_t, y_t) = window(cells, true);
        let x_a = adv(cells, &advice, 0, 0);
        let y_a = adv(cells, &advice, 1, 0);
        let [x_p, y_p, x_q, y_q] = [0, 1, 2, 3].map(|column| adv(cells, &advice, column, 1));
        polys.push(("carry A_84 x", x_p - x_a));
        polys.push(("carry A_84 y", y_p - y_a));
        polys.push(("T_84 x", x_q - x_t));
        polys.push(("T_84 y", y_q - y_t));
        gated(&q, polys)
    });
    meta.create_gate("ecc fixed-base scalar link", |cells| {
        let q = cells.query_selector(columns.link);
        let [z_0, z_43, lo, hi] = [0, 1, 2, 3].map(|column| adv(cells, &advice, column, 0));
        let h0 = adv(cells, &advice, 0, 1);
        gated(
            &q,
            vec![
                ("h0 bit", boolean(&h0)),
                ("hi = 2 z_43 + h0", hi - z_43.clone() * two - h0.clone()),
                (
                    "z_0 = lo + 2^128 h0 + 2^129 z_43",
                    z_0 - lo - h0 * two_pow_128::<F>() - z_43 * two_pow::<F>(129),
                ),
            ],
        )
    });
    columns
}
