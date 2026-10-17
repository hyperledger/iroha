//! Complete P-256 group formulas over the exact nonnative arithmetic chip.
//!
//! The formulas in this module are the exception-free Renes-Costello-Batina
//! formulas for short-Weierstrass curves with `a = -3`.  They deliberately do
//! not branch on equality, inverses, the point at infinity, or secret scalar
//! bits.  Every field operation is emitted through
//! [`P256BaseFieldCircuitV1`], whose production implementation links each
//! value to the exact integer arithmetic trace and its value-copy bus.
/// Exact arithmetic-operation count for one `[u1]G + [u2]Q` execution,
/// including the fourteen-addition variable-base table.
pub const P256_TWO_SCALAR_ARITHMETIC_OPERATIONS_V1: usize = 14 * 43 + 64 * (4 * 34 + 2 * 43);
/// P-256 curve coefficient `b`, in canonical big-endian form.
pub const P256_CURVE_B_BE_V1: [u8; 32] = [
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];
const ZERO_BE_V1: [u8; 32] = [0; 32];
const ONE_BE_V1: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
const THREE_BE_V1: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
];
/// A homogeneous projective point with affine coordinates `(x/z, y/z)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ProjectiveValueV1<V> {
    /// Homogeneous x-coordinate.
    pub(crate) x: V,
    /// Homogeneous y-coordinate.
    pub(crate) y: V,
    /// Homogeneous denominator; zero denotes the identity.
    pub(crate) z: V,
}
/// Exact base-field operations required by the group layer.
///
/// A production implementation must emit a newly written value for every
/// arithmetic result and must algebraically bind `assert_equal` and
/// `inverse_nonzero`; native comparisons are not a valid implementation.
pub trait P256BaseFieldCircuitV1 {
    /// Handle of one canonical P-256 base-field value.
    type Value: Copy;
    /// Bounded circuit-construction failure.
    type Error;
    /// Allocate a verifier-fixed canonical constant.
    fn constant_v1(&mut self, value: [u8; 32]) -> Result<Self::Value, Self::Error>;
    /// Emit `left + right (mod p)`.
    fn add_v1(&mut self, left: Self::Value, right: Self::Value)
    -> Result<Self::Value, Self::Error>;
    /// Emit `left - right (mod p)`.
    fn subtract_v1(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<Self::Value, Self::Error>;
    /// Emit `left * right (mod p)`.
    fn multiply_v1(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<Self::Value, Self::Error>;
    /// Constrain two assigned values to be identical.
    fn assert_equal_v1(&mut self, left: Self::Value, right: Self::Value)
    -> Result<(), Self::Error>;
    /// Allocate `value^-1` and constrain `value * inverse = 1`.
    ///
    /// Construction must fail when `value` is zero.
    fn inverse_nonzero_v1(&mut self, value: Self::Value) -> Result<Self::Value, Self::Error>;
}
/// Fixed four-bit point lookup used by the two-scalar multiplication layer.
///
/// The production implementation is a 16-candidate one-hot AIR with a challenge-separated bit-copy
/// bus. It may not select natively from secret bits.
pub trait P256WindowCircuitV1: P256BaseFieldCircuitV1 {
    /// One algebraically constrained scalar bit.
    type Bit: Copy;
    /// Select exactly one of sixteen projective points from four big-endian nibble bits.
    fn select_window_v1(
        &mut self,
        table: &[P256ProjectiveValueV1<Self::Value>; 16],
        bits_be: [Self::Bit; 4],
    ) -> Result<P256ProjectiveValueV1<Self::Value>, Self::Error>;
}
/// Allocate the canonical projective identity `(0 : 1 : 0)`.
pub fn p256_projective_identity_v1<C: P256BaseFieldCircuitV1>(
    circuit: &mut C,
) -> Result<P256ProjectiveValueV1<C::Value>, C::Error> {
    Ok(P256ProjectiveValueV1 {
        x: circuit.constant_v1(ZERO_BE_V1)?,
        y: circuit.constant_v1(ONE_BE_V1)?,
        z: circuit.constant_v1(ZERO_BE_V1)?,
    })
}
/// Emit complete projective addition for P-256.
///
/// This is Algorithm 4 of Renes-Costello-Batina (2015), specialized to
/// `a = -3`.  It is complete for valid input points, including identities,
/// equal points, and additive inverses.
pub fn p256_complete_add_v1<C: P256BaseFieldCircuitV1>(
    circuit: &mut C,
    left: P256ProjectiveValueV1<C::Value>,
    right: P256ProjectiveValueV1<C::Value>,
) -> Result<P256ProjectiveValueV1<C::Value>, C::Error> {
    let curve_b = circuit.constant_v1(P256_CURVE_B_BE_V1)?;
    let xx = circuit.multiply_v1(left.x, right.x)?;
    let yy = circuit.multiply_v1(left.y, right.y)?;
    let zz = circuit.multiply_v1(left.z, right.z)?;
    let left_xy = circuit.add_v1(left.x, left.y)?;
    let right_xy = circuit.add_v1(right.x, right.y)?;
    let xy_product = circuit.multiply_v1(left_xy, right_xy)?;
    let xx_plus_yy = circuit.add_v1(xx, yy)?;
    let xy_pairs = circuit.subtract_v1(xy_product, xx_plus_yy)?;
    let left_yz = circuit.add_v1(left.y, left.z)?;
    let right_yz = circuit.add_v1(right.y, right.z)?;
    let yz_product = circuit.multiply_v1(left_yz, right_yz)?;
    let yy_plus_zz = circuit.add_v1(yy, zz)?;
    let yz_pairs = circuit.subtract_v1(yz_product, yy_plus_zz)?;
    let left_xz = circuit.add_v1(left.x, left.z)?;
    let right_xz = circuit.add_v1(right.x, right.z)?;
    let xz_product = circuit.multiply_v1(left_xz, right_xz)?;
    let xx_plus_zz = circuit.add_v1(xx, zz)?;
    let xz_pairs = circuit.subtract_v1(xz_product, xx_plus_zz)?;
    let b_times_zz = circuit.multiply_v1(curve_b, zz)?;
    let bzz_part = circuit.subtract_v1(xz_pairs, b_times_zz)?;
    let bzz_twice = circuit.add_v1(bzz_part, bzz_part)?;
    let bzz3_part = circuit.add_v1(bzz_twice, bzz_part)?;
    let yy_minus_bzz3 = circuit.subtract_v1(yy, bzz3_part)?;
    let yy_plus_bzz3 = circuit.add_v1(yy, bzz3_part)?;
    let zz_twice = circuit.add_v1(zz, zz)?;
    let zz3 = circuit.add_v1(zz_twice, zz)?;
    let b_times_xz = circuit.multiply_v1(curve_b, xz_pairs)?;
    let zz3_plus_xx = circuit.add_v1(zz3, xx)?;
    let bxz_part = circuit.subtract_v1(b_times_xz, zz3_plus_xx)?;
    let bxz_twice = circuit.add_v1(bxz_part, bxz_part)?;
    let bxz3_part = circuit.add_v1(bxz_twice, bxz_part)?;
    let xx_twice = circuit.add_v1(xx, xx)?;
    let xx3 = circuit.add_v1(xx_twice, xx)?;
    let xx3_minus_zz3 = circuit.subtract_v1(xx3, zz3)?;
    let x_left = circuit.multiply_v1(yy_plus_bzz3, xy_pairs)?;
    let x_right = circuit.multiply_v1(yz_pairs, bxz3_part)?;
    let x = circuit.subtract_v1(x_left, x_right)?;
    let y_left = circuit.multiply_v1(yy_plus_bzz3, yy_minus_bzz3)?;
    let y_right = circuit.multiply_v1(xx3_minus_zz3, bxz3_part)?;
    let y = circuit.add_v1(y_left, y_right)?;
    let z_left = circuit.multiply_v1(yy_minus_bzz3, yz_pairs)?;
    let z_right = circuit.multiply_v1(xy_pairs, xx3_minus_zz3)?;
    let z = circuit.add_v1(z_left, z_right)?;
    Ok(P256ProjectiveValueV1 { x, y, z })
}
/// Emit exception-free projective doubling for P-256.
///
/// This is Algorithm 6 of Renes-Costello-Batina (2015), specialized to
/// `a = -3`.
pub fn p256_complete_double_v1<C: P256BaseFieldCircuitV1>(
    circuit: &mut C,
    point: P256ProjectiveValueV1<C::Value>,
) -> Result<P256ProjectiveValueV1<C::Value>, C::Error> {
    let curve_b = circuit.constant_v1(P256_CURVE_B_BE_V1)?;
    let xx = circuit.multiply_v1(point.x, point.x)?;
    let yy = circuit.multiply_v1(point.y, point.y)?;
    let zz = circuit.multiply_v1(point.z, point.z)?;
    let xy = circuit.multiply_v1(point.x, point.y)?;
    let xy2 = circuit.add_v1(xy, xy)?;
    let xz = circuit.multiply_v1(point.x, point.z)?;
    let xz2 = circuit.add_v1(xz, xz)?;
    let b_times_zz = circuit.multiply_v1(curve_b, zz)?;
    let bzz_part = circuit.subtract_v1(b_times_zz, xz2)?;
    let bzz_twice = circuit.add_v1(bzz_part, bzz_part)?;
    let bzz3_part = circuit.add_v1(bzz_twice, bzz_part)?;
    let yy_minus_bzz3 = circuit.subtract_v1(yy, bzz3_part)?;
    let yy_plus_bzz3 = circuit.add_v1(yy, bzz3_part)?;
    let y_fragment = circuit.multiply_v1(yy_plus_bzz3, yy_minus_bzz3)?;
    let x_fragment = circuit.multiply_v1(yy_minus_bzz3, xy2)?;
    let zz_twice = circuit.add_v1(zz, zz)?;
    let zz3 = circuit.add_v1(zz_twice, zz)?;
    let b_times_xz2 = circuit.multiply_v1(curve_b, xz2)?;
    let zz3_plus_xx = circuit.add_v1(zz3, xx)?;
    let bxz2_part = circuit.subtract_v1(b_times_xz2, zz3_plus_xx)?;
    let bxz2_twice = circuit.add_v1(bxz2_part, bxz2_part)?;
    let bxz6_part = circuit.add_v1(bxz2_twice, bxz2_part)?;
    let xx_twice = circuit.add_v1(xx, xx)?;
    let xx3 = circuit.add_v1(xx_twice, xx)?;
    let xx3_minus_zz3 = circuit.subtract_v1(xx3, zz3)?;
    let y_right = circuit.multiply_v1(xx3_minus_zz3, bxz6_part)?;
    let y = circuit.add_v1(y_fragment, y_right)?;
    let yz = circuit.multiply_v1(point.y, point.z)?;
    let yz2 = circuit.add_v1(yz, yz)?;
    let x_right = circuit.multiply_v1(bxz6_part, yz2)?;
    let x = circuit.subtract_v1(x_fragment, x_right)?;
    let z_product = circuit.multiply_v1(yz2, yy)?;
    let z_twice = circuit.add_v1(z_product, z_product)?;
    let z = circuit.add_v1(z_twice, z_twice)?;
    Ok(P256ProjectiveValueV1 { x, y, z })
}
/// Build the variable-base table `[0]P, [1]P, ..., [15]P`.
///
/// The topology is fixed at fourteen complete additions. `table[0]` is the
/// canonical identity and `table[1]` aliases the constrained input point.
pub fn p256_variable_window_table_v1<C: P256BaseFieldCircuitV1>(
    circuit: &mut C,
    point: P256ProjectiveValueV1<C::Value>,
) -> Result<[P256ProjectiveValueV1<C::Value>; 16], C::Error> {
    let identity = p256_projective_identity_v1(circuit)?;
    let mut table = [identity; 16];
    table[1] = point;
    for multiple in 2..16 {
        table[multiple] = p256_complete_add_v1(circuit, table[multiple - 1], point)?;
    }
    Ok(table)
}
/// Emit fixed-topology Straus multiplication `[u1]G + [u2]Q`.
///
/// Both scalars are consumed as 256 big-endian bits. Each of 64 rounds emits exactly four
/// exception-free doublings, two fixed 16-way lookups, and two complete additions. The generator
/// table is verifier-fixed; the variable table is constrained by [`p256_variable_window_table_v1`].
pub fn p256_two_scalar_linear_combination_v1<C: P256WindowCircuitV1>(
    circuit: &mut C,
    generator_table: &[P256ProjectiveValueV1<C::Value>; 16],
    public_key: P256ProjectiveValueV1<C::Value>,
    u1_bits_be: &[C::Bit; 256],
    u2_bits_be: &[C::Bit; 256],
) -> Result<P256ProjectiveValueV1<C::Value>, C::Error> {
    let public_key_table = p256_variable_window_table_v1(circuit, public_key)?;
    let mut accumulator = p256_projective_identity_v1(circuit)?;
    for window in 0..64 {
        for _ in 0..4 {
            accumulator = p256_complete_double_v1(circuit, accumulator)?;
        }
        let start = window * 4;
        let generator = circuit.select_window_v1(
            generator_table,
            [
                u1_bits_be[start],
                u1_bits_be[start + 1],
                u1_bits_be[start + 2],
                u1_bits_be[start + 3],
            ],
        )?;
        let public_key_multiple = circuit.select_window_v1(
            &public_key_table,
            [
                u2_bits_be[start],
                u2_bits_be[start + 1],
                u2_bits_be[start + 2],
                u2_bits_be[start + 3],
            ],
        )?;
        accumulator = p256_complete_add_v1(circuit, accumulator, generator)?;
        accumulator = p256_complete_add_v1(circuit, accumulator, public_key_multiple)?;
    }
    Ok(accumulator)
}
/// Constrain a homogeneous point to the P-256 curve.
///
/// For affine coordinates `(X/Z, Y/Z)`, the exact homogeneous equation is
/// `Y²Z = X³ - 3XZ² + bZ³`.  The identity `(0 : 1 : 0)` satisfies it.
pub fn constrain_p256_projective_on_curve_v1<C: P256BaseFieldCircuitV1>(
    circuit: &mut C,
    point: P256ProjectiveValueV1<C::Value>,
) -> Result<(), C::Error> {
    let curve_b = circuit.constant_v1(P256_CURVE_B_BE_V1)?;
    let three = circuit.constant_v1(THREE_BE_V1)?;
    let y_squared = circuit.multiply_v1(point.y, point.y)?;
    let left = circuit.multiply_v1(y_squared, point.z)?;
    let x_squared = circuit.multiply_v1(point.x, point.x)?;
    let x_cubed = circuit.multiply_v1(x_squared, point.x)?;
    let z_squared = circuit.multiply_v1(point.z, point.z)?;
    let x_z_squared = circuit.multiply_v1(point.x, z_squared)?;
    let three_x_z_squared = circuit.multiply_v1(three, x_z_squared)?;
    let z_cubed = circuit.multiply_v1(z_squared, point.z)?;
    let b_z_cubed = circuit.multiply_v1(curve_b, z_cubed)?;
    let x_part = circuit.subtract_v1(x_cubed, three_x_z_squared)?;
    let right = circuit.add_v1(x_part, b_z_cubed)?;
    circuit.assert_equal_v1(left, right)
}
/// Constrain an affine input point `(x : y : 1)` to P-256.
pub fn constrain_p256_affine_on_curve_v1<C: P256BaseFieldCircuitV1>(
    circuit: &mut C,
    x: C::Value,
    y: C::Value,
) -> Result<P256ProjectiveValueV1<C::Value>, C::Error> {
    let point = P256ProjectiveValueV1 {
        x,
        y,
        z: circuit.constant_v1(ONE_BE_V1)?,
    };
    constrain_p256_projective_on_curve_v1(circuit, point)?;
    Ok(point)
}
/// Constrain a projective point to be non-identity and return affine `(x,y)`.
pub fn normalize_p256_nonidentity_v1<C: P256BaseFieldCircuitV1>(
    circuit: &mut C,
    point: P256ProjectiveValueV1<C::Value>,
) -> Result<(C::Value, C::Value), C::Error> {
    let z_inverse = circuit.inverse_nonzero_v1(point.z)?;
    let x = circuit.multiply_v1(point.x, z_inverse)?;
    let y = circuit.multiply_v1(point.y, z_inverse)?;
    Ok((x, y))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::zk_x509::p256_air::{
        P256_BASE_MODULUS_BE_V1, ZkX509P256ArithmeticKindV1, ZkX509P256ArithmeticOperationV1,
        ZkX509P256ModulusV1, build_zk_x509_p256_arithmetic_trace_v1,
    };
    use p256::{
        EncodedPoint, FieldBytes, FieldElement, ProjectivePoint, Scalar,
        elliptic_curve::{group::Group as _, sec1::ToEncodedPoint as _},
    };
    use thiserror::Error;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestValue(usize);
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
    enum TestCircuitError {
        #[error("test circuit received a non-canonical value")]
        NonCanonical,
        #[error("test circuit was asked to invert zero")]
        ZeroInverse,
        #[error("test circuit equality constraint failed")]
        Equality,
    }
    #[derive(Default)]
    struct RecordingCircuit {
        values: Vec<[u8; 32]>,
        operations: Vec<ZkX509P256ArithmeticOperationV1>,
    }
    impl RecordingCircuit {
        fn input(&mut self, value: [u8; 32]) -> Result<TestValue, TestCircuitError> {
            if value >= P256_BASE_MODULUS_BE_V1 {
                return Err(TestCircuitError::NonCanonical);
            }
            let id = TestValue(self.values.len());
            self.values.push(value);
            Ok(id)
        }
        fn bytes(&self, value: TestValue) -> [u8; 32] {
            self.values[value.0]
        }
        fn field(&self, value: TestValue) -> Result<FieldElement, TestCircuitError> {
            Option::<FieldElement>::from(FieldElement::from_bytes(&FieldBytes::from(
                self.bytes(value),
            )))
            .ok_or(TestCircuitError::NonCanonical)
        }
        fn push_operation(
            &mut self,
            kind: ZkX509P256ArithmeticKindV1,
            left: TestValue,
            right: TestValue,
            result: [u8; 32],
        ) -> TestValue {
            self.operations.push(ZkX509P256ArithmeticOperationV1 {
                kind,
                modulus: ZkX509P256ModulusV1::BaseField,
                a: self.bytes(left),
                b: self.bytes(right),
                c: result,
            });
            let value = TestValue(self.values.len());
            self.values.push(result);
            value
        }
    }
    impl P256BaseFieldCircuitV1 for RecordingCircuit {
        type Value = TestValue;
        type Error = TestCircuitError;
        fn constant_v1(&mut self, value: [u8; 32]) -> Result<Self::Value, Self::Error> {
            self.input(value)
        }
        fn add_v1(
            &mut self,
            left: Self::Value,
            right: Self::Value,
        ) -> Result<Self::Value, Self::Error> {
            let result = (self.field(left)? + self.field(right)?).to_bytes().into();
            Ok(self.push_operation(ZkX509P256ArithmeticKindV1::Add, left, right, result))
        }
        fn subtract_v1(
            &mut self,
            left: Self::Value,
            right: Self::Value,
        ) -> Result<Self::Value, Self::Error> {
            let result = (self.field(left)? - self.field(right)?).to_bytes().into();
            Ok(self.push_operation(ZkX509P256ArithmeticKindV1::Subtract, left, right, result))
        }
        fn multiply_v1(
            &mut self,
            left: Self::Value,
            right: Self::Value,
        ) -> Result<Self::Value, Self::Error> {
            let result = (self.field(left)? * self.field(right)?).to_bytes().into();
            Ok(self.push_operation(ZkX509P256ArithmeticKindV1::Multiply, left, right, result))
        }
        fn assert_equal_v1(
            &mut self,
            left: Self::Value,
            right: Self::Value,
        ) -> Result<(), Self::Error> {
            if self.bytes(left) != self.bytes(right) {
                return Err(TestCircuitError::Equality);
            }
            Ok(())
        }
        fn inverse_nonzero_v1(&mut self, value: Self::Value) -> Result<Self::Value, Self::Error> {
            let inverse = Option::<FieldElement>::from(self.field(value)?.invert())
                .ok_or(TestCircuitError::ZeroInverse)?;
            let inverse = self.input(inverse.to_bytes().into())?;
            let product = self.multiply_v1(value, inverse)?;
            let one = self.constant_v1(ONE_BE_V1)?;
            self.assert_equal_v1(product, one)?;
            Ok(inverse)
        }
    }
    impl P256WindowCircuitV1 for RecordingCircuit {
        type Bit = bool;
        fn select_window_v1(
            &mut self,
            table: &[P256ProjectiveValueV1<Self::Value>; 16],
            bits_be: [Self::Bit; 4],
        ) -> Result<P256ProjectiveValueV1<Self::Value>, Self::Error> {
            let index = bits_be
                .into_iter()
                .fold(0_usize, |value, bit| (value << 1) | usize::from(bit));
            Ok(table[index])
        }
    }
    fn assigned_point(
        circuit: &mut RecordingCircuit,
        point: ProjectivePoint,
    ) -> P256ProjectiveValueV1<TestValue> {
        if bool::from(point.is_identity()) {
            return p256_projective_identity_v1(circuit).expect("identity constants");
        }
        let encoded = point.to_affine().to_encoded_point(false);
        let mut x = [0_u8; 32];
        let mut y = [0_u8; 32];
        x.copy_from_slice(encoded.x().expect("nonidentity x"));
        y.copy_from_slice(encoded.y().expect("nonidentity y"));
        P256ProjectiveValueV1 {
            x: circuit.input(x).expect("canonical x"),
            y: circuit.input(y).expect("canonical y"),
            z: circuit.input(ONE_BE_V1).expect("canonical one"),
        }
    }
    fn normalized_encoding(
        circuit: &mut RecordingCircuit,
        point: P256ProjectiveValueV1<TestValue>,
    ) -> EncodedPoint {
        let (x, y) =
            normalize_p256_nonidentity_v1(circuit, point).expect("nonidentity normalization");
        EncodedPoint::from_affine_coordinates(
            &FieldBytes::from(circuit.bytes(x)),
            &FieldBytes::from(circuit.bytes(y)),
            false,
        )
    }
    fn scalar_bits_be(scalar: Scalar) -> [bool; 256] {
        let bytes: [u8; 32] = scalar.to_bytes().into();
        core::array::from_fn(|bit| (bytes[bit / 8] >> (7 - bit % 8)) & 1 == 1)
    }
    fn assigned_generator_table(
        circuit: &mut RecordingCircuit,
    ) -> [P256ProjectiveValueV1<TestValue>; 16] {
        core::array::from_fn(|multiple| {
            assigned_point(
                circuit,
                ProjectivePoint::GENERATOR * Scalar::from(multiple as u64),
            )
        })
    }
    #[test]
    fn complete_formulas_have_fixed_exact_operation_counts() {
        let mut add_circuit = RecordingCircuit::default();
        let generator = assigned_point(&mut add_circuit, ProjectivePoint::GENERATOR);
        let identity = assigned_point(&mut add_circuit, ProjectivePoint::IDENTITY);
        let sum =
            p256_complete_add_v1(&mut add_circuit, generator, identity).expect("complete add");
        assert_eq!(add_circuit.operations.len(), 43);
        assert_eq!(
            normalized_encoding(&mut add_circuit, sum),
            ProjectivePoint::GENERATOR
                .to_affine()
                .to_encoded_point(false)
        );
        let mut double_circuit = RecordingCircuit::default();
        let generator = assigned_point(&mut double_circuit, ProjectivePoint::GENERATOR);
        let doubled =
            p256_complete_double_v1(&mut double_circuit, generator).expect("complete double");
        assert_eq!(double_circuit.operations.len(), 34);
        assert_eq!(
            normalized_encoding(&mut double_circuit, doubled),
            (ProjectivePoint::GENERATOR + ProjectivePoint::GENERATOR)
                .to_affine()
                .to_encoded_point(false)
        );
    }
    #[test]
    fn complete_addition_differential_covers_exceptional_and_random_pairs() {
        let generator = ProjectivePoint::GENERATOR;
        let identity = ProjectivePoint::IDENTITY;
        let mut pairs = vec![
            (identity, identity),
            (identity, generator),
            (generator, identity),
            (generator, generator),
            (generator, -generator),
        ];
        for left in 1_u64..=24 {
            for right in [1_u64, 2, 3, 7, 13, 29, 61, 127] {
                pairs.push((
                    generator * Scalar::from(left),
                    generator * Scalar::from(right + left * 17),
                ));
            }
        }
        for (left, right) in pairs {
            let expected = left + right;
            let mut circuit = RecordingCircuit::default();
            let assigned_left = assigned_point(&mut circuit, left);
            let assigned_right = assigned_point(&mut circuit, right);
            let actual = p256_complete_add_v1(&mut circuit, assigned_left, assigned_right)
                .expect("complete addition");
            constrain_p256_projective_on_curve_v1(&mut circuit, actual)
                .expect("output curve equation");
            if bool::from(expected.is_identity()) {
                assert_eq!(circuit.bytes(actual.z), ZERO_BE_V1);
            } else {
                assert_eq!(
                    normalized_encoding(&mut circuit, actual),
                    expected.to_affine().to_encoded_point(false)
                );
            }
            build_zk_x509_p256_arithmetic_trace_v1(&circuit.operations)
                .expect("all emitted arithmetic is exact")
                .validate()
                .expect("exact arithmetic trace");
        }
    }
    #[test]
    fn complete_doubling_differential_covers_identity_and_random_points() {
        for scalar in 0_u64..=192 {
            let point = ProjectivePoint::GENERATOR * Scalar::from(scalar);
            let expected = point + point;
            let mut circuit = RecordingCircuit::default();
            let assigned = assigned_point(&mut circuit, point);
            let actual =
                p256_complete_double_v1(&mut circuit, assigned).expect("exception-free double");
            constrain_p256_projective_on_curve_v1(&mut circuit, actual)
                .expect("output curve equation");
            if bool::from(expected.is_identity()) {
                assert_eq!(circuit.bytes(actual.z), ZERO_BE_V1);
            } else {
                assert_eq!(
                    normalized_encoding(&mut circuit, actual),
                    expected.to_affine().to_encoded_point(false)
                );
            }
            build_zk_x509_p256_arithmetic_trace_v1(&circuit.operations)
                .expect("all emitted arithmetic is exact")
                .validate()
                .expect("exact arithmetic trace");
        }
    }
    #[test]
    fn fixed_window_two_scalar_multiplication_is_exact_and_budgeted() {
        let cases = [
            (0_u64, 0_u64, 1_u64),
            (1, 0, 1),
            (0, 1, 1),
            (1, 1, 1),
            (17, 31, 7),
            (u64::from(u32::MAX), 0xdead_beef, 19),
            (u64::MAX, u64::MAX - 1, 127),
            (0x9e37_79b9_7f4a_7c15, 0xd1b5_4a32_d192_ed03, 4093),
        ];
        for (u1_raw, u2_raw, key_raw) in cases {
            let u1 = Scalar::from(u1_raw);
            let u2 = Scalar::from(u2_raw);
            let public_key = ProjectivePoint::GENERATOR * Scalar::from(key_raw);
            let expected = ProjectivePoint::GENERATOR * u1 + public_key * u2;
            let mut circuit = RecordingCircuit::default();
            let generator_table = assigned_generator_table(&mut circuit);
            let assigned_public_key = assigned_point(&mut circuit, public_key);
            let actual = p256_two_scalar_linear_combination_v1(
                &mut circuit,
                &generator_table,
                assigned_public_key,
                &scalar_bits_be(u1),
                &scalar_bits_be(u2),
            )
            .expect("fixed-window two-scalar multiplication");
            assert_eq!(
                circuit.operations.len(),
                P256_TWO_SCALAR_ARITHMETIC_OPERATIONS_V1,
                "fixed arithmetic topology"
            );
            if bool::from(expected.is_identity()) {
                assert_eq!(circuit.bytes(actual.z), ZERO_BE_V1);
            } else {
                assert_eq!(
                    normalized_encoding(&mut circuit, actual),
                    expected.to_affine().to_encoded_point(false)
                );
            }
            for operation in circuit.operations.iter().step_by(137) {
                build_zk_x509_p256_arithmetic_trace_v1(&[*operation])
                    .expect("sampled exact window arithmetic")
                    .validate()
                    .expect("sampled arithmetic constraints");
            }
        }
    }
    #[test]
    fn affine_curve_constraint_rejects_every_single_bit_coordinate_mutation() {
        let encoded = ProjectivePoint::GENERATOR
            .to_affine()
            .to_encoded_point(false);
        let mut x = [0_u8; 32];
        let mut y = [0_u8; 32];
        x.copy_from_slice(encoded.x().expect("x"));
        y.copy_from_slice(encoded.y().expect("y"));
        for coordinate in 0..2 {
            for bit in 0..256 {
                let mut changed_x = x;
                let mut changed_y = y;
                let target = if coordinate == 0 {
                    &mut changed_x
                } else {
                    &mut changed_y
                };
                target[bit / 8] ^= 1 << (7 - bit % 8);
                if *target >= P256_BASE_MODULUS_BE_V1 {
                    continue;
                }
                let mut circuit = RecordingCircuit::default();
                let assigned_x = circuit.input(changed_x).expect("canonical changed x");
                let assigned_y = circuit.input(changed_y).expect("canonical changed y");
                assert_eq!(
                    constrain_p256_affine_on_curve_v1(&mut circuit, assigned_x, assigned_y),
                    Err(TestCircuitError::Equality),
                    "coordinate {coordinate}, bit {bit}"
                );
            }
        }
    }
    #[test]
    fn normalization_rejects_identity() {
        let mut circuit = RecordingCircuit::default();
        let identity = p256_projective_identity_v1(&mut circuit).expect("identity");
        assert_eq!(
            normalize_p256_nonidentity_v1(&mut circuit, identity),
            Err(TestCircuitError::ZeroInverse)
        );
    }
}
