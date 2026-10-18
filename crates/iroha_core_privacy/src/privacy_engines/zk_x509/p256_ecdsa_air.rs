//! Fixed-topology P-256 ECDSA verification composition.
//!
//! This module assembles strict scalar arithmetic, canonical digest/x reduction, complete group
//! formulas, public-key curve validation, nonzero checks, and the wallet-only low-s rule. Every
//! primitive is emitted through [`P256EcdsaCircuitV1`]; a production implementation must bind those
//! primitives to the arithmetic, reduction, window, equality, and byte-I/O AIRs. The verifier never
//! calls `RustCrypto` or the native reference relation.
use super::p256_group_air::{
    P256ProjectiveValueV1, P256WindowCircuitV1, constrain_p256_affine_on_curve_v1,
    normalize_p256_nonidentity_v1, p256_two_scalar_linear_combination_v1,
};
use super::p256_window_air::P256WindowScalarV1;
/// Verifier-fixed signature role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256EcdsaRoleV1 {
    /// Certificate or CRL signature: both mathematically valid s halves are admitted by RFC 5280.
    CertificateOrCrl,
    /// Fresh wallet-ownership signature: low-s is mandatory.
    WalletOwnership,
}
/// Private values required for one exact ECDSA equation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct P256EcdsaWitnessV1 {
    /// Affine public-key x-coordinate.
    pub(crate) public_key_x_be: [u8; 32],
    /// Affine public-key y-coordinate.
    pub(crate) public_key_y_be: [u8; 32],
    /// Canonical signature scalar r.
    pub(crate) r_be: [u8; 32],
    /// Canonical signature scalar s.
    pub(crate) s_be: [u8; 32],
    /// Exact SHA-256/prehash digest interpreted as an unsigned 256-bit word.
    pub(crate) digest_be: [u8; 32],
}
impl core::fmt::Debug for P256EcdsaWitnessV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("P256EcdsaWitnessV1 { <private material redacted> }")
    }
}
impl P256EcdsaWitnessV1 {
    /// Overwrite the complete private ECDSA input tuple.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn zeroize_private_v1(&mut self) {
        super::private_table::zeroize_words_v1(&mut self.public_key_x_be[..]);
        super::private_table::zeroize_words_v1(&mut self.public_key_y_be[..]);
        super::private_table::zeroize_words_v1(&mut self.r_be[..]);
        super::private_table::zeroize_words_v1(&mut self.s_be[..]);
        super::private_table::zeroize_words_v1(&mut self.digest_be[..]);
    }
    #[cfg(test)]
    pub(crate) fn private_is_zeroized_v1(&self) -> bool {
        self.public_key_x_be == [0; 32]
            && self.public_key_y_be == [0; 32]
            && self.r_be == [0; 32]
            && self.s_be == [0; 32]
            && self.digest_be == [0; 32]
    }
}
/// Assigned values retained for complete cross-chip composition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256EcdsaAssignedV1<S, B> {
    /// Constrained affine public key `(x : y : 1)`.
    pub(crate) public_key: P256ProjectiveValueV1<B>,
    /// Canonical signature scalar r.
    pub(crate) r: S,
    /// Canonical signature scalar s.
    pub(crate) s: S,
    /// Canonically reduced digest scalar.
    pub(crate) z: S,
    /// `z * s^-1 mod n`.
    pub(crate) u1: S,
    /// `r * s^-1 mod n`.
    pub(crate) u2: S,
    /// Complete projective verification result.
    pub(crate) result: P256ProjectiveValueV1<B>,
    /// Nonidentity-normalized affine x-coordinate of `result`.
    pub(crate) result_x: B,
    /// `result_x mod n`, constrained equal to r.
    pub(crate) reduced_x: S,
}
/// Scalar, reduction, and binding primitives required in addition to the
/// complete base-field/window circuit.
pub trait P256EcdsaCircuitV1: P256WindowCircuitV1 {
    /// Handle of one canonical P-256 scalar-field value.
    type Scalar: Copy;
    /// Allocate a private base-field value bound to DER/P-256 byte I/O.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn base_input_v1(&mut self, value_be: [u8; 32]) -> Result<Self::Value, Self::Error>;
    /// Allocate a private canonical scalar bound to strict DER output.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn scalar_input_v1(&mut self, value_be: [u8; 32]) -> Result<Self::Scalar, Self::Error>;
    /// Allocate an inverse and constrain `value * inverse = 1 mod n`.
    fn scalar_inverse_nonzero_v1(
        &mut self,
        value: Self::Scalar,
    ) -> Result<Self::Scalar, Self::Error>;
    /// Emit scalar multiplication modulo n.
    fn scalar_multiply_v1(
        &mut self,
        left: Self::Scalar,
        right: Self::Scalar,
    ) -> Result<Self::Scalar, Self::Error>;
    /// Constrain two scalar IDs to the same canonical value.
    fn scalar_assert_equal_v1(
        &mut self,
        left: Self::Scalar,
        right: Self::Scalar,
    ) -> Result<(), Self::Error>;
    /// Reduce an exact SHA-256 word with the one-subtraction reduction AIR.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn reduce_digest_v1(&mut self, digest_be: [u8; 32]) -> Result<Self::Scalar, Self::Error>;
    /// Reduce an assigned canonical base-field coordinate modulo n.
    fn reduce_base_coordinate_v1(
        &mut self,
        coordinate: Self::Value,
    ) -> Result<Self::Scalar, Self::Error>;
    /// Return the 256 algebraically bound big-endian bits of a verifier-positioned ECDSA scalar.
    fn scalar_bits_be_v1(
        &mut self,
        scalar: Self::Scalar,
        role: P256WindowScalarV1,
    ) -> Result<[Self::Bit; 256], Self::Error>;
    /// Apply the exact `s <= floor(n/2)` comparison AIR.
    fn constrain_low_s_v1(&mut self, scalar: Self::Scalar) -> Result<(), Self::Error>;
}
/// Typed source for the five external values consumed by one ECDSA equation.
///
/// The relation schedule asks for each value only at its canonical allocation point. Native proving
/// sources bind concrete witness bytes through [`P256EcdsaCircuitV1`], while verifier-topology
/// compilers can allocate typed handles without constructing witness-shaped placeholder values.
pub trait P256EcdsaInputSourceV1<C: P256EcdsaCircuitV1> {
    /// Allocate the affine public-key coordinates.
    fn public_key_v1(&mut self, circuit: &mut C) -> Result<(C::Value, C::Value), C::Error>;
    /// Allocate the canonical signature scalars `(r, s)`.
    fn signature_v1(&mut self, circuit: &mut C) -> Result<(C::Scalar, C::Scalar), C::Error>;
    /// Allocate and constrain the reduced SHA-256 digest.
    fn reduced_digest_v1(&mut self, circuit: &mut C) -> Result<C::Scalar, C::Error>;
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy)]
struct P256EcdsaWitnessInputSourceV1 {
    witness: P256EcdsaWitnessV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<C: P256EcdsaCircuitV1> P256EcdsaInputSourceV1<C> for P256EcdsaWitnessInputSourceV1 {
    fn public_key_v1(&mut self, circuit: &mut C) -> Result<(C::Value, C::Value), C::Error> {
        Ok((
            circuit.base_input_v1(self.witness.public_key_x_be)?,
            circuit.base_input_v1(self.witness.public_key_y_be)?,
        ))
    }
    fn signature_v1(&mut self, circuit: &mut C) -> Result<(C::Scalar, C::Scalar), C::Error> {
        Ok((
            circuit.scalar_input_v1(self.witness.r_be)?,
            circuit.scalar_input_v1(self.witness.s_be)?,
        ))
    }
    fn reduced_digest_v1(&mut self, circuit: &mut C) -> Result<C::Scalar, C::Error> {
        circuit.reduce_digest_v1(self.witness.digest_be)
    }
}
/// Constrain one complete P-256 ECDSA verification equation from a typed external-value source.
///
/// This is the single canonical relation schedule shared by native witness
/// compilation and independent verifier-topology compilation.
pub fn constrain_p256_ecdsa_from_source_v1<C: P256EcdsaCircuitV1, I: P256EcdsaInputSourceV1<C>>(
    circuit: &mut C,
    generator_table: &[P256ProjectiveValueV1<C::Value>; 16],
    role: P256EcdsaRoleV1,
    mut inputs: I,
) -> Result<P256EcdsaAssignedV1<C::Scalar, C::Value>, C::Error> {
    let (public_key_x, public_key_y) = inputs.public_key_v1(circuit)?;
    let public_key = constrain_p256_affine_on_curve_v1(circuit, public_key_x, public_key_y)?;
    let (r, s) = inputs.signature_v1(circuit)?;
    // ECDSA requires both scalars to be strictly positive.
    let _r_inverse = circuit.scalar_inverse_nonzero_v1(r)?;
    let s_inverse = circuit.scalar_inverse_nonzero_v1(s)?;
    if role == P256EcdsaRoleV1::WalletOwnership {
        circuit.constrain_low_s_v1(s)?;
    }
    let z = inputs.reduced_digest_v1(circuit)?;
    let u1 = circuit.scalar_multiply_v1(z, s_inverse)?;
    let u2 = circuit.scalar_multiply_v1(r, s_inverse)?;
    let u1_bits = circuit.scalar_bits_be_v1(u1, P256WindowScalarV1::U1)?;
    let u2_bits = circuit.scalar_bits_be_v1(u2, P256WindowScalarV1::U2)?;
    let result = p256_two_scalar_linear_combination_v1(
        circuit,
        generator_table,
        public_key,
        &u1_bits,
        &u2_bits,
    )?;
    let (result_x, _result_y) = normalize_p256_nonidentity_v1(circuit, result)?;
    let reduced_x = circuit.reduce_base_coordinate_v1(result_x)?;
    circuit.scalar_assert_equal_v1(reduced_x, r)?;
    Ok(P256EcdsaAssignedV1 {
        public_key,
        r,
        s,
        z,
        u1,
        u2,
        result,
        result_x,
        reduced_x,
    })
}
/// Constrain one complete P-256 ECDSA verification equation from native witness bytes.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn constrain_p256_ecdsa_v1<C: P256EcdsaCircuitV1>(
    circuit: &mut C,
    generator_table: &[P256ProjectiveValueV1<C::Value>; 16],
    role: P256EcdsaRoleV1,
    witness: P256EcdsaWitnessV1,
) -> Result<P256EcdsaAssignedV1<C::Scalar, C::Value>, C::Error> {
    constrain_p256_ecdsa_from_source_v1(
        circuit,
        generator_table,
        role,
        P256EcdsaWitnessInputSourceV1 { witness },
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::zk_x509::{
        p256_air::{
            P256_BASE_MODULUS_BE_V1, P256_SCALAR_MODULUS_BE_V1, ZkX509P256ArithmeticKindV1,
            ZkX509P256ArithmeticOperationV1, ZkX509P256ModulusV1,
            build_zk_x509_p256_arithmetic_trace_v1,
        },
        p256_group_air::{P256_TWO_SCALAR_ARITHMETIC_OPERATIONS_V1, P256BaseFieldCircuitV1},
        p256_reduction_air::{
            P256LowSTraceV1, P256ReductionTraceV1, build_p256_low_s_trace_v1,
            build_p256_reduction_trace_v1,
        },
    };
    use p256::{
        EncodedPoint, FieldBytes, FieldElement, ProjectivePoint, Scalar,
        ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _},
        elliptic_curve::{PrimeField as _, group::Group as _, sec1::ToEncodedPoint as _},
    };
    use thiserror::Error;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct BaseValue(usize);
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct ScalarValue(usize);
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
    enum TestError {
        #[error("non-canonical test value")]
        NonCanonical,
        #[error("zero inversion")]
        ZeroInverse,
        #[error("test equality constraint failed")]
        Equality,
        #[error("wallet signature is high-s")]
        HighS,
    }
    #[derive(Debug, Default, PartialEq, Eq)]
    struct TestCircuit {
        base_values: Vec<[u8; 32]>,
        scalar_values: Vec<[u8; 32]>,
        operations: Vec<ZkX509P256ArithmeticOperationV1>,
        reductions: Vec<P256ReductionTraceV1>,
        low_s: Vec<P256LowSTraceV1>,
    }
    #[derive(Clone, Copy)]
    struct ExplicitTestInputSourceV1 {
        witness: P256EcdsaWitnessV1,
    }
    impl P256EcdsaInputSourceV1<TestCircuit> for ExplicitTestInputSourceV1 {
        fn public_key_v1(
            &mut self,
            circuit: &mut TestCircuit,
        ) -> Result<(BaseValue, BaseValue), TestError> {
            Ok((
                circuit.base_input_v1(self.witness.public_key_x_be)?,
                circuit.base_input_v1(self.witness.public_key_y_be)?,
            ))
        }
        fn signature_v1(
            &mut self,
            circuit: &mut TestCircuit,
        ) -> Result<(ScalarValue, ScalarValue), TestError> {
            Ok((
                circuit.scalar_input_v1(self.witness.r_be)?,
                circuit.scalar_input_v1(self.witness.s_be)?,
            ))
        }
        fn reduced_digest_v1(
            &mut self,
            circuit: &mut TestCircuit,
        ) -> Result<ScalarValue, TestError> {
            circuit.reduce_digest_v1(self.witness.digest_be)
        }
    }
    impl TestCircuit {
        fn push_base(&mut self, value: [u8; 32]) -> Result<BaseValue, TestError> {
            if value >= P256_BASE_MODULUS_BE_V1 {
                return Err(TestError::NonCanonical);
            }
            let assigned = BaseValue(self.base_values.len());
            self.base_values.push(value);
            Ok(assigned)
        }
        fn push_scalar(&mut self, value: [u8; 32]) -> Result<ScalarValue, TestError> {
            if value >= P256_SCALAR_MODULUS_BE_V1 {
                return Err(TestError::NonCanonical);
            }
            let assigned = ScalarValue(self.scalar_values.len());
            self.scalar_values.push(value);
            Ok(assigned)
        }
        fn base_field(&self, value: BaseValue) -> Result<FieldElement, TestError> {
            Option::<FieldElement>::from(FieldElement::from_bytes(&FieldBytes::from(
                self.base_values[value.0],
            )))
            .ok_or(TestError::NonCanonical)
        }
        fn scalar_field(&self, value: ScalarValue) -> Result<Scalar, TestError> {
            Option::<Scalar>::from(Scalar::from_repr(self.scalar_values[value.0].into()))
                .ok_or(TestError::NonCanonical)
        }
        fn push_operation(
            &mut self,
            kind: ZkX509P256ArithmeticKindV1,
            modulus: ZkX509P256ModulusV1,
            a: [u8; 32],
            b: [u8; 32],
            c: [u8; 32],
        ) {
            self.operations.push(ZkX509P256ArithmeticOperationV1 {
                kind,
                modulus,
                a,
                b,
                c,
            });
        }
    }
    impl P256BaseFieldCircuitV1 for TestCircuit {
        type Value = BaseValue;
        type Error = TestError;
        fn constant_v1(&mut self, value: [u8; 32]) -> Result<Self::Value, Self::Error> {
            self.push_base(value)
        }
        fn add_v1(
            &mut self,
            left: Self::Value,
            right: Self::Value,
        ) -> Result<Self::Value, Self::Error> {
            let result = (self.base_field(left)? + self.base_field(right)?)
                .to_bytes()
                .into();
            self.push_operation(
                ZkX509P256ArithmeticKindV1::Add,
                ZkX509P256ModulusV1::BaseField,
                self.base_values[left.0],
                self.base_values[right.0],
                result,
            );
            self.push_base(result)
        }
        fn subtract_v1(
            &mut self,
            left: Self::Value,
            right: Self::Value,
        ) -> Result<Self::Value, Self::Error> {
            let result = (self.base_field(left)? - self.base_field(right)?)
                .to_bytes()
                .into();
            self.push_operation(
                ZkX509P256ArithmeticKindV1::Subtract,
                ZkX509P256ModulusV1::BaseField,
                self.base_values[left.0],
                self.base_values[right.0],
                result,
            );
            self.push_base(result)
        }
        fn multiply_v1(
            &mut self,
            left: Self::Value,
            right: Self::Value,
        ) -> Result<Self::Value, Self::Error> {
            let result = (self.base_field(left)? * self.base_field(right)?)
                .to_bytes()
                .into();
            self.push_operation(
                ZkX509P256ArithmeticKindV1::Multiply,
                ZkX509P256ModulusV1::BaseField,
                self.base_values[left.0],
                self.base_values[right.0],
                result,
            );
            self.push_base(result)
        }
        fn assert_equal_v1(
            &mut self,
            left: Self::Value,
            right: Self::Value,
        ) -> Result<(), Self::Error> {
            if self.base_values[left.0] != self.base_values[right.0] {
                return Err(TestError::Equality);
            }
            Ok(())
        }
        fn inverse_nonzero_v1(&mut self, value: Self::Value) -> Result<Self::Value, Self::Error> {
            let inverse = Option::<FieldElement>::from(self.base_field(value)?.invert())
                .ok_or(TestError::ZeroInverse)?;
            let inverse = self.push_base(inverse.to_bytes().into())?;
            let product = self.multiply_v1(value, inverse)?;
            let one = self.constant_v1({
                let mut one = [0_u8; 32];
                one[31] = 1;
                one
            })?;
            self.assert_equal_v1(product, one)?;
            Ok(inverse)
        }
    }
    impl P256WindowCircuitV1 for TestCircuit {
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
    impl P256EcdsaCircuitV1 for TestCircuit {
        type Scalar = ScalarValue;
        fn base_input_v1(&mut self, value_be: [u8; 32]) -> Result<Self::Value, Self::Error> {
            self.push_base(value_be)
        }
        fn scalar_input_v1(&mut self, value_be: [u8; 32]) -> Result<Self::Scalar, Self::Error> {
            self.push_scalar(value_be)
        }
        fn scalar_inverse_nonzero_v1(
            &mut self,
            value: Self::Scalar,
        ) -> Result<Self::Scalar, Self::Error> {
            let inverse = Option::<Scalar>::from(self.scalar_field(value)?.invert())
                .ok_or(TestError::ZeroInverse)?;
            let inverse = self.push_scalar(inverse.to_bytes().into())?;
            let product = self.scalar_multiply_v1(value, inverse)?;
            let mut one = [0_u8; 32];
            one[31] = 1;
            let one = self.push_scalar(one)?;
            self.scalar_assert_equal_v1(product, one)?;
            Ok(inverse)
        }
        fn scalar_multiply_v1(
            &mut self,
            left: Self::Scalar,
            right: Self::Scalar,
        ) -> Result<Self::Scalar, Self::Error> {
            let result = (self.scalar_field(left)? * self.scalar_field(right)?)
                .to_bytes()
                .into();
            self.push_operation(
                ZkX509P256ArithmeticKindV1::Multiply,
                ZkX509P256ModulusV1::ScalarField,
                self.scalar_values[left.0],
                self.scalar_values[right.0],
                result,
            );
            self.push_scalar(result)
        }
        fn scalar_assert_equal_v1(
            &mut self,
            left: Self::Scalar,
            right: Self::Scalar,
        ) -> Result<(), Self::Error> {
            if self.scalar_values[left.0] != self.scalar_values[right.0] {
                return Err(TestError::Equality);
            }
            Ok(())
        }
        fn reduce_digest_v1(&mut self, digest_be: [u8; 32]) -> Result<Self::Scalar, Self::Error> {
            let trace =
                build_p256_reduction_trace_v1(digest_be).map_err(|_| TestError::NonCanonical)?;
            let reduced = trace.reduced_be_v1();
            self.reductions.push(trace);
            self.push_scalar(reduced)
        }
        fn reduce_base_coordinate_v1(
            &mut self,
            coordinate: Self::Value,
        ) -> Result<Self::Scalar, Self::Error> {
            self.reduce_digest_v1(self.base_values[coordinate.0])
        }
        fn scalar_bits_be_v1(
            &mut self,
            scalar: Self::Scalar,
            _role: P256WindowScalarV1,
        ) -> Result<[Self::Bit; 256], Self::Error> {
            let bytes = self.scalar_values[scalar.0];
            Ok(core::array::from_fn(|bit| {
                (bytes[bit / 8] >> (7 - bit % 8)) & 1 == 1
            }))
        }
        fn constrain_low_s_v1(&mut self, scalar: Self::Scalar) -> Result<(), Self::Error> {
            let trace = build_p256_low_s_trace_v1(self.scalar_values[scalar.0])
                .map_err(|_| TestError::HighS)?;
            self.low_s.push(trace);
            Ok(())
        }
    }
    fn assigned_generator_table(
        circuit: &mut TestCircuit,
    ) -> [P256ProjectiveValueV1<BaseValue>; 16] {
        core::array::from_fn(|multiple| {
            let point = ProjectivePoint::GENERATOR * Scalar::from(multiple as u64);
            if bool::from(point.is_identity()) {
                let mut one = [0_u8; 32];
                one[31] = 1;
                return P256ProjectiveValueV1 {
                    x: circuit.push_base([0; 32]).expect("zero"),
                    y: circuit.push_base(one).expect("one"),
                    z: circuit.push_base([0; 32]).expect("zero"),
                };
            }
            let encoded = point.to_affine().to_encoded_point(false);
            let mut x = [0_u8; 32];
            let mut y = [0_u8; 32];
            x.copy_from_slice(encoded.x().expect("x"));
            y.copy_from_slice(encoded.y().expect("y"));
            let mut one = [0_u8; 32];
            one[31] = 1;
            P256ProjectiveValueV1 {
                x: circuit.push_base(x).expect("x"),
                y: circuit.push_base(y).expect("y"),
                z: circuit.push_base(one).expect("one"),
            }
        })
    }
    fn witness_for(key: &SigningKey, digest: [u8; 32], signature: Signature) -> P256EcdsaWitnessV1 {
        let encoded = key.verifying_key().to_encoded_point(false);
        let mut public_key_x_be = [0_u8; 32];
        let mut public_key_y_be = [0_u8; 32];
        public_key_x_be.copy_from_slice(encoded.x().expect("x"));
        public_key_y_be.copy_from_slice(encoded.y().expect("y"));
        P256EcdsaWitnessV1 {
            public_key_x_be,
            public_key_y_be,
            r_be: signature.r().to_bytes().into(),
            s_be: signature.s().to_bytes().into(),
            digest_be: digest,
        }
    }
    fn signing_key(seed: u8) -> SigningKey {
        let mut bytes = [0_u8; 32];
        bytes[31] = seed.max(1);
        SigningKey::from_slice(&bytes).expect("nonzero key")
    }
    fn execute(
        witness: P256EcdsaWitnessV1,
        role: P256EcdsaRoleV1,
    ) -> Result<TestCircuit, TestError> {
        let mut circuit = TestCircuit::default();
        let generator_table = assigned_generator_table(&mut circuit);
        constrain_p256_ecdsa_v1(&mut circuit, &generator_table, role, witness)?;
        Ok(circuit)
    }
    fn execute_from_explicit_source(
        witness: P256EcdsaWitnessV1,
        role: P256EcdsaRoleV1,
    ) -> Result<TestCircuit, TestError> {
        let mut circuit = TestCircuit::default();
        let generator_table = assigned_generator_table(&mut circuit);
        constrain_p256_ecdsa_from_source_v1(
            &mut circuit,
            &generator_table,
            role,
            ExplicitTestInputSourceV1 { witness },
        )?;
        Ok(circuit)
    }
    #[test]
    fn typed_input_source_preserves_the_exact_native_witness_schedule() {
        let key = signing_key(7);
        let digest = core::array::from_fn(|index| (index as u8).wrapping_mul(29).wrapping_add(3));
        let signature: Signature = key.sign_prehash(&digest).expect("signature");
        let signature = signature.normalize_s().unwrap_or(signature);
        let witness = witness_for(&key, digest, signature);
        assert_eq!(
            execute(witness, P256EcdsaRoleV1::WalletOwnership),
            execute_from_explicit_source(witness, P256EcdsaRoleV1::WalletOwnership),
        );
        assert_eq!(
            execute(witness, P256EcdsaRoleV1::CertificateOrCrl),
            execute_from_explicit_source(witness, P256EcdsaRoleV1::CertificateOrCrl),
        );
    }
    #[test]
    fn complete_ecdsa_equation_matches_rustcrypto_and_fixed_budget() {
        for seed in 1_u8..=8 {
            let key = signing_key(seed);
            let mut digest = [0_u8; 32];
            for (index, byte) in digest.iter_mut().enumerate() {
                *byte = seed
                    .wrapping_mul(index as u8 + 17)
                    .rotate_left((index % 8) as u32);
            }
            let signature: Signature = key.sign_prehash(&digest).expect("prehash signature");
            let signature = signature.normalize_s().unwrap_or(signature);
            let circuit = execute(
                witness_for(&key, digest, signature),
                P256EcdsaRoleV1::WalletOwnership,
            )
            .expect("valid ECDSA equation");
            assert_eq!(
                circuit.operations.len(),
                P256_TWO_SCALAR_ARITHMETIC_OPERATIONS_V1 + 18,
                "11 curve checks + 4 scalar ops + 3 normalization ops"
            );
            assert_eq!(circuit.reductions.len(), 2);
            assert_eq!(circuit.low_s.len(), 1);
            for operation in circuit.operations.iter().step_by(131) {
                build_zk_x509_p256_arithmetic_trace_v1(&[*operation])
                    .expect("sampled exact ECDSA arithmetic")
                    .validate()
                    .expect("sampled arithmetic constraints");
            }
        }
    }
    #[test]
    fn certificate_high_s_is_valid_but_wallet_high_s_is_rejected() {
        let key = signing_key(29);
        let digest = [0xa5_u8; 32];
        let low: Signature = key.sign_prehash(&digest).expect("signature");
        let low = low.normalize_s().unwrap_or(low);
        let high = Signature::from_scalars(low.r().to_bytes(), (-*low.s()).to_bytes())
            .expect("high-s representative");
        execute(
            witness_for(&key, digest, high),
            P256EcdsaRoleV1::CertificateOrCrl,
        )
        .expect("RFC 5280 admits high-s");
        assert_eq!(
            execute(
                witness_for(&key, digest, high),
                P256EcdsaRoleV1::WalletOwnership,
            )
            .map(|_| ()),
            Err(TestError::HighS)
        );
    }
    #[test]
    fn wrong_digest_key_r_s_zero_and_offcurve_inputs_fail_closed() {
        let key = signing_key(41);
        let digest = [0x3c_u8; 32];
        let signature: Signature = key.sign_prehash(&digest).expect("signature");
        let signature = signature.normalize_s().unwrap_or(signature);
        let witness = witness_for(&key, digest, signature);
        let mut wrong_digest = witness;
        wrong_digest.digest_be[0] ^= 1;
        assert!(execute(wrong_digest, P256EcdsaRoleV1::WalletOwnership).is_err());
        let other_key = signing_key(43);
        let mut wrong_key = witness;
        let other = other_key.verifying_key().to_encoded_point(false);
        wrong_key
            .public_key_x_be
            .copy_from_slice(other.x().expect("x"));
        wrong_key
            .public_key_y_be
            .copy_from_slice(other.y().expect("y"));
        assert!(execute(wrong_key, P256EcdsaRoleV1::WalletOwnership).is_err());
        let mut wrong_r = witness;
        wrong_r.r_be[31] ^= 1;
        assert!(execute(wrong_r, P256EcdsaRoleV1::WalletOwnership).is_err());
        let mut wrong_s = witness;
        wrong_s.s_be[31] ^= 1;
        assert!(execute(wrong_s, P256EcdsaRoleV1::WalletOwnership).is_err());
        let mut zero_r = witness;
        zero_r.r_be = [0; 32];
        assert_eq!(
            execute(zero_r, P256EcdsaRoleV1::WalletOwnership).map(|_| ()),
            Err(TestError::ZeroInverse)
        );
        let mut zero_s = witness;
        zero_s.s_be = [0; 32];
        assert_eq!(
            execute(zero_s, P256EcdsaRoleV1::WalletOwnership).map(|_| ()),
            Err(TestError::ZeroInverse)
        );
        let mut off_curve = witness;
        off_curve.public_key_y_be[31] ^= 1;
        assert_eq!(
            execute(off_curve, P256EcdsaRoleV1::WalletOwnership).map(|_| ()),
            Err(TestError::Equality)
        );
    }
    #[test]
    fn digest_and_result_x_reduction_cover_above_order_words() {
        let key = signing_key(53);
        let digest = [0xff_u8; 32];
        let signature: Signature = key.sign_prehash(&digest).expect("signature");
        let signature = signature.normalize_s().unwrap_or(signature);
        let circuit = execute(
            witness_for(&key, digest, signature),
            P256EcdsaRoleV1::WalletOwnership,
        )
        .expect("digest above order reduces once");
        assert_eq!(circuit.reductions.len(), 2);
        assert_ne!(circuit.reductions[0].reduced_be_v1(), digest);
    }
    #[test]
    fn generator_table_constants_are_exact_uncompressed_points() {
        let mut circuit = TestCircuit::default();
        let table = assigned_generator_table(&mut circuit);
        for (multiple, point) in table.into_iter().enumerate() {
            if multiple == 0 {
                assert_eq!(circuit.base_values[point.z.0], [0; 32]);
                continue;
            }
            let encoded = EncodedPoint::from_affine_coordinates(
                &FieldBytes::from(circuit.base_values[point.x.0]),
                &FieldBytes::from(circuit.base_values[point.y.0]),
                false,
            );
            assert_eq!(
                encoded,
                (ProjectivePoint::GENERATOR * Scalar::from(multiple as u64))
                    .to_affine()
                    .to_encoded_point(false)
            );
        }
    }
}
