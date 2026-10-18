//! Native witness compiler for one complete P-256 ECDSA AIR instance.
//!
//! The group and ECDSA modules describe the fixed computation generically.
//! This module is their production witness compiler: it assigns symbolic SSA
//! values, records every exact base/scalar operation, emits all 128 fixed
//! window-selector traces, and records reduction/low-s bindings.  Native P-256
//! arithmetic is used only to construct witness values.  Verification is
//! performed by the arithmetic, value-bus, window, reduction, and scalar-bit
//! AIRs; no native verification result is accepted as a proof.
//!
//! Initial values and derived values occupy separate symbolic namespaces while
//! the computation is built.  Finalization then assigns the only canonical
//! value-id layout: all initial writers first, followed by one result writer
//! for each arithmetic operation.  This avoids forward IDs and interleaved
//! allocator state without introducing aliases or legacy layouts.
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::{
    p256_air::{
        P256_BASE_MODULUS_BE_V1, P256_SCALAR_MODULUS_BE_V1, ZkX509P256AirErrorV1,
        ZkX509P256ArithmeticOperationV1, ZkX509P256ArithmeticTraceV1,
        build_zk_x509_p256_arithmetic_trace_v1,
    },
    p256_ecdsa_air::{P256EcdsaWitnessV1, constrain_p256_ecdsa_v1},
    p256_reduction_air::{
        P256LowSTraceV1, P256ReductionTraceV1, build_p256_low_s_trace_v1,
        build_p256_reduction_trace_v1,
    },
    p256_value_bus::{P256InitialValueBindingV1, P256LinkedOperationV1},
    p256_window_air::{P256WindowPointV1, P256WindowTraceV1, build_p256_window_trace_v1},
};
use super::{
    p256_air::{ZkX509P256ArithmeticKindV1, ZkX509P256ModulusV1},
    p256_ecdsa_air::{
        P256EcdsaAssignedV1, P256EcdsaCircuitV1, P256EcdsaInputSourceV1, P256EcdsaRoleV1,
        constrain_p256_ecdsa_from_source_v1,
    },
    p256_group_air::{P256BaseFieldCircuitV1, P256ProjectiveValueV1, P256WindowCircuitV1},
    p256_value_bus::{
        P256BooleanBridgeBindingV1, P256EqualityBindingV1, P256InitialValueKindV1,
        P256InitialValueTopologyV1, P256LinkedOperationTopologyV1, P256ValueIdV1,
    },
    p256_window_air::P256WindowScalarV1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use p256::{
    FieldBytes, FieldElement, ProjectivePoint, Scalar,
    elliptic_curve::{PrimeField as _, sec1::ToEncodedPoint as _},
};
use thiserror::Error;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const ZERO_BE_V1: [u8; 32] = [0; 32];
const ONE_BE_V1: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
/// Canonical value-bus binding for one selected point.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256BoundWindowTraceV1 {
    /// Verifier-positioned U1/U2 selector trace.
    pub(crate) trace: P256WindowTraceV1,
    /// Candidate coordinate IDs, ordered candidate then x/y/z.
    pub(crate) candidates: [[P256ValueIdV1; 3]; 16],
    /// Selected output x/y/z IDs.
    pub(crate) output: [P256ValueIdV1; 3],
    /// Arithmetic operation whose scalar result supplies the 256 bits.
    pub(crate) scalar_source_operation: u32,
}
/// Origin of a word reduced modulo the scalar-field order.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256ReductionSourceV1 {
    /// Exact 32-byte SHA-256 digest; bound by the SHA/byte-I/O lanes.
    Digest {
        /// Exact unreduced word.
        word_be: [u8; 32],
    },
    /// Canonical base-field coordinate produced by arithmetic.
    BaseCoordinate {
        /// Assigned coordinate ID.
        id: P256ValueIdV1,
        /// Exact unreduced coordinate word.
        word_be: [u8; 32],
    },
}
/// One exact reduction and its value-bus endpoints.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256BoundReductionTraceV1 {
    /// Digest word or assigned base coordinate.
    pub(crate) source: P256ReductionSourceV1,
    /// Canonical scalar result ID.
    pub(crate) output: P256ValueIdV1,
    /// Exact one-subtraction reduction trace.
    pub(crate) trace: P256ReductionTraceV1,
}
/// One wallet-only low-s comparison bound to a scalar ID.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256BoundLowSTraceV1 {
    /// Scalar constrained by the comparison.
    pub(crate) scalar: P256ValueIdV1,
    /// Exact comparison trace.
    pub(crate) trace: P256LowSTraceV1,
}
/// Canonical resolved IDs retained from the generic ECDSA composition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ResolvedEcdsaAssignedV1 {
    /// Constrained affine public key.
    pub(crate) public_key: P256ProjectiveValueV1<P256ValueIdV1>,
    /// Canonical signature scalar r.
    pub(crate) r: P256ValueIdV1,
    /// Canonical signature scalar s.
    pub(crate) s: P256ValueIdV1,
    /// Reduced digest.
    pub(crate) z: P256ValueIdV1,
    /// `z * s^-1`.
    pub(crate) u1: P256ValueIdV1,
    /// `r * s^-1`.
    pub(crate) u2: P256ValueIdV1,
    /// Complete projective result x/y/z.
    pub(crate) result: P256ProjectiveValueV1<P256ValueIdV1>,
    /// Normalized affine result x-coordinate.
    pub(crate) result_x: P256ValueIdV1,
    /// Scalar reduction of `result_x`, constrained equal to r.
    pub(crate) reduced_x: P256ValueIdV1,
}
/// Verifier-owned topology for one four-bit selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256BoundWindowTopologyV1 {
    /// Candidate coordinate IDs, ordered candidate then x/y/z.
    pub(crate) candidates: [[P256ValueIdV1; 3]; 16],
    /// Selected output x/y/z IDs.
    pub(crate) output: [P256ValueIdV1; 3],
    /// Arithmetic operation supplying the scalar bits.
    pub(crate) scalar_source_operation: u32,
}
/// Value-free origin of one scalar reduction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256ReductionSourceTopologyV1 {
    /// Exact digest word supplied by the surrounding SHA relation.
    Digest,
    /// Arithmetic-produced base coordinate.
    BaseCoordinate {
        /// Canonical coordinate value ID.
        id: P256ValueIdV1,
    },
}
/// Verifier-owned reduction topology.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256BoundReductionTopologyV1 {
    /// Digest or arithmetic-coordinate source.
    pub(crate) source: P256ReductionSourceTopologyV1,
    /// Canonical scalar output.
    pub(crate) output: P256ValueIdV1,
}
/// Complete value-free topology for one role-separated ECDSA equation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256EcdsaTopologyV1 {
    /// Verifier-selected signature role.
    pub(crate) role: P256EcdsaRoleV1,
    /// Canonical initial writers.
    pub(crate) initial_values: Vec<P256InitialValueTopologyV1>,
    /// Canonical arithmetic SSA instructions.
    pub(crate) linked_operations: Vec<P256LinkedOperationTopologyV1>,
    /// Same-modulus equality edges.
    pub(crate) equalities: Vec<P256EqualityBindingV1>,
    /// Cross-modulus Boolean equality edges.
    pub(crate) boolean_bridges: Vec<P256BooleanBridgeBindingV1>,
    /// Exactly 128 windows, U1 `0..63` then U2 `0..63`.
    pub(crate) windows: Vec<P256BoundWindowTopologyV1>,
    /// Digest then result-x reductions.
    pub(crate) reductions: Vec<P256BoundReductionTopologyV1>,
    /// Wallet-only low-S scalar IDs.
    pub(crate) low_s: Vec<P256ValueIdV1>,
    /// Canonical retained equation outputs.
    pub(crate) assigned: P256ResolvedEcdsaAssignedV1,
}
/// Final one-signature witness material before aggregate column streaming.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub struct P256EcdsaTraceMaterialV1 {
    /// Signature role fixed by the surrounding relation.
    pub(crate) role: P256EcdsaRoleV1,
    /// Canonical initial writers.
    pub(crate) initial_values: Vec<P256InitialValueBindingV1>,
    /// Canonical SSA-linked arithmetic operations.
    pub(crate) linked_operations: Vec<P256LinkedOperationV1>,
    /// Explicit same-modulus equalities.
    pub(crate) equalities: Vec<P256EqualityBindingV1>,
    /// Cross-modulus Boolean bridges, empty for the direct scalar-bit bus.
    pub(crate) boolean_bridges: Vec<P256BooleanBridgeBindingV1>,
    /// Exactly 128 selectors: U1 windows 0..63, then U2 windows 0..63.
    pub(crate) windows: Vec<P256BoundWindowTraceV1>,
    /// Digest and result-x reductions.
    pub(crate) reductions: Vec<P256BoundReductionTraceV1>,
    /// One comparison for wallet ownership and none for certificate/CRL roles.
    pub(crate) low_s: Vec<P256BoundLowSTraceV1>,
    /// Resolved outputs of the complete equation.
    pub(crate) assigned: P256ResolvedEcdsaAssignedV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256EcdsaTraceMaterialV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256EcdsaTraceMaterialV1")
            .field("role", &self.role)
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256EcdsaTraceMaterialV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_initial_values_v1(values: &mut [P256InitialValueBindingV1]) {
    for value in values {
        super::private_table::zeroize_words_v1(&mut value.value);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_linked_operations_v1(operations: &mut [P256LinkedOperationV1]) {
    for linked in operations {
        super::p256_air::zeroize_p256_operations_v1(core::slice::from_mut(&mut linked.operation));
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256EcdsaTraceMaterialV1 {
    /// Recursively overwrite every witness-derived scalar, coordinate, and
    /// committed field row while leaving only public topology metadata.
    pub(crate) fn zeroize_private_v1(&mut self) {
        for initial in &mut self.initial_values {
            super::private_table::zeroize_words_v1(&mut initial.value[..]);
        }
        self.initial_values.clear();
        for linked in &mut self.linked_operations {
            super::private_table::zeroize_words_v1(&mut linked.operation.a[..]);
            super::private_table::zeroize_words_v1(&mut linked.operation.b[..]);
            super::private_table::zeroize_words_v1(&mut linked.operation.c[..]);
        }
        self.linked_operations.clear();
        self.equalities.clear();
        self.boolean_bridges.clear();
        for window in &mut self.windows {
            window.trace.zeroize_private_v1();
        }
        self.windows.clear();
        for reduction in &mut self.reductions {
            match &mut reduction.source {
                P256ReductionSourceV1::Digest { word_be }
                | P256ReductionSourceV1::BaseCoordinate { word_be, .. } => {
                    super::private_table::zeroize_words_v1(&mut word_be[..])
                }
            }
            reduction.trace.zeroize_private_v1();
        }
        self.reductions.clear();
        for low_s in &mut self.low_s {
            low_s.trace.zeroize_private_v1();
        }
        self.low_s.clear();
    }
    #[cfg(test)]
    pub(crate) fn private_is_zeroized_v1(&self) -> bool {
        self.initial_values.is_empty()
            && self.linked_operations.is_empty()
            && self.equalities.is_empty()
            && self.boolean_bridges.is_empty()
            && self.windows.is_empty()
            && self.reductions.is_empty()
            && self.low_s.is_empty()
    }
    /// Materialize the exact wide arithmetic rows.
    ///
    /// Aggregate proving should stream/shard these columns.  This helper is
    /// retained for focused validation and differential tests.
    pub(crate) fn build_arithmetic_trace_v1(
        &self,
    ) -> Result<ZkX509P256ArithmeticTraceV1, ZkX509P256AirErrorV1> {
        let operations = self
            .linked_operations
            .iter()
            .map(|linked| linked.operation)
            .collect::<Vec<_>>();
        let operations = super::private_table::PrivateTableV1::new(
            operations,
            super::p256_air::zeroize_p256_operations_v1,
        );
        build_zk_x509_p256_arithmetic_trace_v1(&operations)
    }
    fn value_free_topology_v1(&self) -> Result<P256EcdsaTopologyV1, P256TraceCompilerErrorV1> {
        let mut windows = Vec::new();
        windows
            .try_reserve_exact(self.windows.len())
            .map_err(|_| P256TraceCompilerErrorV1::Resource)?;
        for (ordinal, window) in self.windows.iter().enumerate() {
            let (scalar, index) = if ordinal < 64 {
                (P256WindowScalarV1::U1, ordinal)
            } else {
                (P256WindowScalarV1::U2, ordinal - 64)
            };
            let index =
                u8::try_from(index).map_err(|_| P256TraceCompilerErrorV1::WindowTopology)?;
            window
                .trace
                .validate_for_v1(scalar, index)
                .map_err(|_| P256TraceCompilerErrorV1::WindowTopology)?;
            windows.push(P256BoundWindowTopologyV1 {
                candidates: window.candidates,
                output: window.output,
                scalar_source_operation: window.scalar_source_operation,
            });
        }
        let mut reductions = Vec::new();
        reductions
            .try_reserve_exact(self.reductions.len())
            .map_err(|_| P256TraceCompilerErrorV1::Resource)?;
        for reduction in &self.reductions {
            reduction
                .trace
                .validate()
                .map_err(|_| P256TraceCompilerErrorV1::Reduction)?;
            reductions.push(P256BoundReductionTopologyV1 {
                source: match reduction.source {
                    P256ReductionSourceV1::Digest { .. } => P256ReductionSourceTopologyV1::Digest,
                    P256ReductionSourceV1::BaseCoordinate { id, .. } => {
                        P256ReductionSourceTopologyV1::BaseCoordinate { id }
                    }
                },
                output: reduction.output,
            });
        }
        for low_s in &self.low_s {
            low_s
                .trace
                .validate()
                .map_err(|_| P256TraceCompilerErrorV1::Reduction)?;
        }
        Ok(P256EcdsaTopologyV1 {
            role: self.role,
            initial_values: self
                .initial_values
                .iter()
                .map(|initial| P256InitialValueTopologyV1 {
                    id: initial.id,
                    modulus: initial.modulus,
                    kind: initial.kind,
                })
                .collect(),
            linked_operations: self
                .linked_operations
                .iter()
                .map(|linked| P256LinkedOperationTopologyV1 {
                    a: linked.a,
                    b: linked.b,
                    c: linked.c,
                    kind: linked.operation.kind,
                    modulus: linked.operation.modulus,
                })
                .collect(),
            equalities: self.equalities.clone(),
            boolean_bridges: self.boolean_bridges.clone(),
            windows,
            reductions,
            low_s: self.low_s.iter().map(|binding| binding.scalar).collect(),
            assigned: self.assigned,
        })
    }
    /// Reject any witness-owned identifier, role, operation, window, reduction, or comparison
    /// schedule that differs from the independently compiled verifier topology.
    pub(crate) fn validate_topology_v1(
        &self,
        expected: &P256EcdsaTopologyV1,
    ) -> Result<(), P256TraceCompilerErrorV1> {
        if &self.value_free_topology_v1()? != expected {
            return Err(P256TraceCompilerErrorV1::BindingTopology);
        }
        Ok(())
    }
}
/// Witness compilation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum P256TraceCompilerErrorV1 {
    /// A base/scalar input or constant is noncanonical.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 trace compiler received a noncanonical value")]
    NonCanonical,
    /// A requested inverse is undefined.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 trace compiler cannot invert zero")]
    ZeroInverse,
    /// An asserted relation is false.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 trace compiler equality is false")]
    Equality,
    /// Scalar bits were assigned to the wrong U1/U2 window position.
    #[error("zk-X509 P-256 trace compiler window topology is invalid")]
    WindowTopology,
    /// SSA origins, writers, or operation dependencies are inconsistent.
    #[error("zk-X509 P-256 trace compiler value topology is invalid")]
    ValueTopology,
    /// Cross-chip owners or role-specific bindings are inconsistent.
    #[error("zk-X509 P-256 trace compiler binding topology is invalid")]
    BindingTopology,
    /// A reduction or low-s witness is invalid.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 trace compiler reduction is invalid")]
    Reduction,
    /// Value IDs or operation indices exceed the first-release envelope.
    #[error("zk-X509 P-256 trace compiler resource bound is exceeded")]
    Resource,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SymbolicOriginV1 {
    Initial {
        index: usize,
        kind: P256InitialValueKindV1,
    },
    Derived {
        operation: usize,
    },
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SymbolicValueRecordV1 {
    modulus: ZkX509P256ModulusV1,
    value_be: [u8; 32],
    origin: SymbolicOriginV1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256BaseValueV1(usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256ScalarValueV1(usize);
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256ScalarBitV1 {
    source: P256ScalarValueV1,
    role: P256WindowScalarV1,
    global_be: u16,
    value: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256TopologyScalarBitV1 {
    source: P256ScalarValueV1,
    role: P256WindowScalarV1,
    global_be: u16,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecordedOperationV1 {
    a: usize,
    b: usize,
    c: usize,
    operation: ZkX509P256ArithmeticOperationV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct SymbolicWindowV1 {
    trace: P256WindowTraceV1,
    candidates: [[usize; 3]; 16],
    output: [usize; 3],
    scalar_source: usize,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
enum SymbolicReductionSourceV1 {
    Digest { word_be: [u8; 32] },
    BaseCoordinate { handle: usize, word_be: [u8; 32] },
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct SymbolicReductionV1 {
    source: SymbolicReductionSourceV1,
    output: usize,
    trace: P256ReductionTraceV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct SymbolicLowSV1 {
    scalar: usize,
    trace: P256LowSTraceV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Default)]
struct P256TraceCompilerV1 {
    values: Vec<SymbolicValueRecordV1>,
    initial_handles: Vec<usize>,
    operations: Vec<RecordedOperationV1>,
    equalities: Vec<(usize, usize)>,
    windows: Vec<SymbolicWindowV1>,
    reductions: Vec<SymbolicReductionV1>,
    low_s: Vec<SymbolicLowSV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256TraceCompilerV1 {
    fn drop(&mut self) {
        for value in &mut self.values {
            super::private_table::zeroize_words_v1(&mut value.value_be);
        }
        for operation in &mut self.operations {
            super::p256_air::zeroize_p256_operations_v1(core::slice::from_mut(
                &mut operation.operation,
            ));
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for SymbolicReductionV1 {
    fn drop(&mut self) {
        match &mut self.source {
            SymbolicReductionSourceV1::Digest { word_be }
            | SymbolicReductionSourceV1::BaseCoordinate { word_be, .. } => {
                super::private_table::zeroize_words_v1(word_be)
            }
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256BoundReductionTraceV1 {
    fn drop(&mut self) {
        match &mut self.source {
            P256ReductionSourceV1::Digest { word_be }
            | P256ReductionSourceV1::BaseCoordinate { word_be, .. } => {
                super::private_table::zeroize_words_v1(word_be)
            }
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TopologyValueRecordV1 {
    modulus: ZkX509P256ModulusV1,
    origin: SymbolicOriginV1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TopologyOperationRecordV1 {
    a: usize,
    b: usize,
    c: usize,
    kind: ZkX509P256ArithmeticKindV1,
    modulus: ZkX509P256ModulusV1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TopologyWindowRecordV1 {
    candidates: [[usize; 3]; 16],
    output: [usize; 3],
    scalar_source: usize,
    scalar: P256WindowScalarV1,
    window: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TopologyReductionSourceV1 {
    Digest,
    BaseCoordinate(usize),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TopologyReductionRecordV1 {
    source: TopologyReductionSourceV1,
    output: usize,
}
/// Value-free second implementation of the fixed ECDSA program.
///
/// This recorder executes the generic equation compiler without performing
/// native field arithmetic.  It allocates only typed handles and records the
/// resulting SSA graph, making the verifier topology independent from all
/// witness values and from the witness compiler's internal schedule.
#[derive(Clone, Default)]
struct P256TopologyCompilerV1 {
    values: Vec<TopologyValueRecordV1>,
    initial_handles: Vec<usize>,
    operations: Vec<TopologyOperationRecordV1>,
    equalities: Vec<(usize, usize)>,
    windows: Vec<TopologyWindowRecordV1>,
    reductions: Vec<TopologyReductionRecordV1>,
    low_s: Vec<usize>,
}
impl P256TopologyCompilerV1 {
    fn record_v1(&self, handle: usize) -> Result<TopologyValueRecordV1, P256TraceCompilerErrorV1> {
        self.values
            .get(handle)
            .copied()
            .ok_or(P256TraceCompilerErrorV1::Resource)
    }
    fn push_initial_v1(
        &mut self,
        modulus: ZkX509P256ModulusV1,
        kind: P256InitialValueKindV1,
    ) -> Result<usize, P256TraceCompilerErrorV1> {
        let index = self.initial_handles.len();
        let handle = self.values.len();
        self.values.push(TopologyValueRecordV1 {
            modulus,
            origin: SymbolicOriginV1::Initial { index, kind },
        });
        self.initial_handles.push(handle);
        Ok(handle)
    }
    fn push_operation_v1(
        &mut self,
        kind: ZkX509P256ArithmeticKindV1,
        modulus: ZkX509P256ModulusV1,
        a: usize,
        b: usize,
    ) -> Result<usize, P256TraceCompilerErrorV1> {
        let a_record = self.record_v1(a)?;
        let b_record = self.record_v1(b)?;
        if a_record.modulus != modulus || b_record.modulus != modulus {
            return Err(P256TraceCompilerErrorV1::ValueTopology);
        }
        let operation = self.operations.len();
        let c = self.values.len();
        self.values.push(TopologyValueRecordV1 {
            modulus,
            origin: SymbolicOriginV1::Derived { operation },
        });
        self.operations.push(TopologyOperationRecordV1 {
            a,
            b,
            c,
            kind,
            modulus,
        });
        Ok(c)
    }
    fn assert_equal_v1(
        &mut self,
        left: usize,
        right: usize,
    ) -> Result<(), P256TraceCompilerErrorV1> {
        if self.record_v1(left)?.modulus != self.record_v1(right)?.modulus {
            return Err(P256TraceCompilerErrorV1::BindingTopology);
        }
        if left != right {
            self.equalities.push((left, right));
        }
        Ok(())
    }
    fn resolve_id_v1(&self, handle: usize) -> Result<P256ValueIdV1, P256TraceCompilerErrorV1> {
        let index = match self.record_v1(handle)?.origin {
            SymbolicOriginV1::Initial { index, .. } => index,
            SymbolicOriginV1::Derived { operation } => self
                .initial_handles
                .len()
                .checked_add(operation)
                .ok_or(P256TraceCompilerErrorV1::Resource)?,
        };
        Ok(P256ValueIdV1(
            u32::try_from(index).map_err(|_| P256TraceCompilerErrorV1::Resource)?,
        ))
    }
    fn generator_table_v1(
        &mut self,
    ) -> Result<[P256ProjectiveValueV1<P256BaseValueV1>; 16], P256TraceCompilerErrorV1> {
        let identity_x = P256BaseValueV1(self.push_initial_v1(
            ZkX509P256ModulusV1::BaseField,
            P256InitialValueKindV1::Constant,
        )?);
        let identity_y = P256BaseValueV1(self.push_initial_v1(
            ZkX509P256ModulusV1::BaseField,
            P256InitialValueKindV1::Constant,
        )?);
        let identity = P256ProjectiveValueV1 {
            x: identity_x,
            y: identity_y,
            z: identity_x,
        };
        let mut table = [identity; 16];
        for point in table.iter_mut().skip(1) {
            *point = P256ProjectiveValueV1 {
                x: P256BaseValueV1(self.push_initial_v1(
                    ZkX509P256ModulusV1::BaseField,
                    P256InitialValueKindV1::Constant,
                )?),
                y: P256BaseValueV1(self.push_initial_v1(
                    ZkX509P256ModulusV1::BaseField,
                    P256InitialValueKindV1::Constant,
                )?),
                z: P256BaseValueV1(self.push_initial_v1(
                    ZkX509P256ModulusV1::BaseField,
                    P256InitialValueKindV1::Constant,
                )?),
            };
        }
        Ok(table)
    }
    fn finalize_v1(
        self,
        role: P256EcdsaRoleV1,
        assigned: P256EcdsaAssignedV1<P256ScalarValueV1, P256BaseValueV1>,
    ) -> Result<P256EcdsaTopologyV1, P256TraceCompilerErrorV1> {
        if self.windows.len() != 128
            || self.reductions.len() != 2
            || self.initial_handles.len() > self.operations.len()
            || self.values.len()
                != self
                    .initial_handles
                    .len()
                    .checked_add(self.operations.len())
                    .ok_or(P256TraceCompilerErrorV1::Resource)?
            || match role {
                P256EcdsaRoleV1::CertificateOrCrl => !self.low_s.is_empty(),
                P256EcdsaRoleV1::WalletOwnership => self.low_s.len() != 1,
            }
        {
            return Err(P256TraceCompilerErrorV1::BindingTopology);
        }
        let mut initial_values = Vec::new();
        initial_values
            .try_reserve_exact(self.initial_handles.len())
            .map_err(|_| P256TraceCompilerErrorV1::Resource)?;
        for (index, handle) in self.initial_handles.iter().copied().enumerate() {
            let record = self.record_v1(handle)?;
            let SymbolicOriginV1::Initial {
                index: origin_index,
                kind,
            } = record.origin
            else {
                return Err(P256TraceCompilerErrorV1::ValueTopology);
            };
            if origin_index != index {
                return Err(P256TraceCompilerErrorV1::ValueTopology);
            }
            initial_values.push(P256InitialValueTopologyV1 {
                id: P256ValueIdV1(
                    u32::try_from(index).map_err(|_| P256TraceCompilerErrorV1::Resource)?,
                ),
                modulus: record.modulus,
                kind,
            });
        }
        let mut linked_operations = Vec::new();
        linked_operations
            .try_reserve_exact(self.operations.len())
            .map_err(|_| P256TraceCompilerErrorV1::Resource)?;
        for (index, operation) in self.operations.iter().copied().enumerate() {
            let expected_c = self
                .initial_handles
                .len()
                .checked_add(index)
                .ok_or(P256TraceCompilerErrorV1::Resource)?;
            let c = self.resolve_id_v1(operation.c)?;
            if usize::try_from(c.0).map_err(|_| P256TraceCompilerErrorV1::Resource)? != expected_c {
                return Err(P256TraceCompilerErrorV1::ValueTopology);
            }
            for input in [operation.a, operation.b] {
                if matches!(
                    self.record_v1(input)?.origin,
                    SymbolicOriginV1::Derived {
                        operation: dependency
                    } if dependency >= index
                ) {
                    return Err(P256TraceCompilerErrorV1::ValueTopology);
                }
            }
            linked_operations.push(P256LinkedOperationTopologyV1 {
                a: self.resolve_id_v1(operation.a)?,
                b: self.resolve_id_v1(operation.b)?,
                c,
                kind: operation.kind,
                modulus: operation.modulus,
            });
        }
        let equalities = self
            .equalities
            .iter()
            .map(|(left, right)| {
                Ok(P256EqualityBindingV1 {
                    left: self.resolve_id_v1(*left)?,
                    right: self.resolve_id_v1(*right)?,
                })
            })
            .collect::<Result<Vec<_>, P256TraceCompilerErrorV1>>()?;
        let mut windows = Vec::new();
        windows
            .try_reserve_exact(self.windows.len())
            .map_err(|_| P256TraceCompilerErrorV1::Resource)?;
        for ordinal in 0..128 {
            let internal = if ordinal < 64 {
                ordinal * 2
            } else {
                (ordinal - 64) * 2 + 1
            };
            let window = *self
                .windows
                .get(internal)
                .ok_or(P256TraceCompilerErrorV1::WindowTopology)?;
            let expected_scalar = if ordinal < 64 {
                P256WindowScalarV1::U1
            } else {
                P256WindowScalarV1::U2
            };
            let expected_window =
                u8::try_from(ordinal % 64).map_err(|_| P256TraceCompilerErrorV1::Resource)?;
            if window.scalar != expected_scalar || window.window != expected_window {
                return Err(P256TraceCompilerErrorV1::WindowTopology);
            }
            let scalar_source_operation = match self.record_v1(window.scalar_source)?.origin {
                SymbolicOriginV1::Derived { operation } => {
                    u32::try_from(operation).map_err(|_| P256TraceCompilerErrorV1::Resource)?
                }
                SymbolicOriginV1::Initial { .. } => {
                    return Err(P256TraceCompilerErrorV1::WindowTopology);
                }
            };
            let mut candidates = [[P256ValueIdV1(0); 3]; 16];
            for (resolved, symbolic) in candidates.iter_mut().zip(window.candidates) {
                for (resolved, symbolic) in resolved.iter_mut().zip(symbolic) {
                    *resolved = self.resolve_id_v1(symbolic)?;
                }
            }
            let mut output = [P256ValueIdV1(0); 3];
            for (resolved, symbolic) in output.iter_mut().zip(window.output) {
                *resolved = self.resolve_id_v1(symbolic)?;
            }
            windows.push(P256BoundWindowTopologyV1 {
                candidates,
                output,
                scalar_source_operation,
            });
        }
        let reductions = self
            .reductions
            .iter()
            .map(|reduction| {
                Ok(P256BoundReductionTopologyV1 {
                    source: match reduction.source {
                        TopologyReductionSourceV1::Digest => P256ReductionSourceTopologyV1::Digest,
                        TopologyReductionSourceV1::BaseCoordinate(handle) => {
                            P256ReductionSourceTopologyV1::BaseCoordinate {
                                id: self.resolve_id_v1(handle)?,
                            }
                        }
                    },
                    output: self.resolve_id_v1(reduction.output)?,
                })
            })
            .collect::<Result<Vec<_>, P256TraceCompilerErrorV1>>()?;
        let low_s = self
            .low_s
            .iter()
            .map(|handle| self.resolve_id_v1(*handle))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(P256EcdsaTopologyV1 {
            role,
            initial_values,
            linked_operations,
            equalities,
            boolean_bridges: Vec::new(),
            windows,
            reductions,
            low_s,
            assigned: P256ResolvedEcdsaAssignedV1 {
                public_key: P256ProjectiveValueV1 {
                    x: self.resolve_id_v1(assigned.public_key.x.0)?,
                    y: self.resolve_id_v1(assigned.public_key.y.0)?,
                    z: self.resolve_id_v1(assigned.public_key.z.0)?,
                },
                r: self.resolve_id_v1(assigned.r.0)?,
                s: self.resolve_id_v1(assigned.s.0)?,
                z: self.resolve_id_v1(assigned.z.0)?,
                u1: self.resolve_id_v1(assigned.u1.0)?,
                u2: self.resolve_id_v1(assigned.u2.0)?,
                result: P256ProjectiveValueV1 {
                    x: self.resolve_id_v1(assigned.result.x.0)?,
                    y: self.resolve_id_v1(assigned.result.y.0)?,
                    z: self.resolve_id_v1(assigned.result.z.0)?,
                },
                result_x: self.resolve_id_v1(assigned.result_x.0)?,
                reduced_x: self.resolve_id_v1(assigned.reduced_x.0)?,
            },
        })
    }
}
impl P256BaseFieldCircuitV1 for P256TopologyCompilerV1 {
    type Value = P256BaseValueV1;
    type Error = P256TraceCompilerErrorV1;
    fn constant_v1(&mut self, _value: [u8; 32]) -> Result<Self::Value, Self::Error> {
        self.push_initial_v1(
            ZkX509P256ModulusV1::BaseField,
            P256InitialValueKindV1::Constant,
        )
        .map(P256BaseValueV1)
    }
    fn add_v1(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<Self::Value, Self::Error> {
        self.push_operation_v1(
            ZkX509P256ArithmeticKindV1::Add,
            ZkX509P256ModulusV1::BaseField,
            left.0,
            right.0,
        )
        .map(P256BaseValueV1)
    }
    fn subtract_v1(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<Self::Value, Self::Error> {
        self.push_operation_v1(
            ZkX509P256ArithmeticKindV1::Subtract,
            ZkX509P256ModulusV1::BaseField,
            left.0,
            right.0,
        )
        .map(P256BaseValueV1)
    }
    fn multiply_v1(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<Self::Value, Self::Error> {
        self.push_operation_v1(
            ZkX509P256ArithmeticKindV1::Multiply,
            ZkX509P256ModulusV1::BaseField,
            left.0,
            right.0,
        )
        .map(P256BaseValueV1)
    }
    fn assert_equal_v1(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<(), Self::Error> {
        P256TopologyCompilerV1::assert_equal_v1(self, left.0, right.0)
    }
    fn inverse_nonzero_v1(&mut self, value: Self::Value) -> Result<Self::Value, Self::Error> {
        if self.record_v1(value.0)?.modulus != ZkX509P256ModulusV1::BaseField {
            return Err(P256TraceCompilerErrorV1::ValueTopology);
        }
        let inverse = P256BaseValueV1(self.push_initial_v1(
            ZkX509P256ModulusV1::BaseField,
            P256InitialValueKindV1::Input,
        )?);
        let product = self.multiply_v1(value, inverse)?;
        let one = self.constant_v1(ONE_BE_V1)?;
        P256BaseFieldCircuitV1::assert_equal_v1(self, product, one)?;
        Ok(inverse)
    }
}
impl P256WindowCircuitV1 for P256TopologyCompilerV1 {
    type Bit = P256TopologyScalarBitV1;
    fn select_window_v1(
        &mut self,
        table: &[P256ProjectiveValueV1<Self::Value>; 16],
        bits_be: [Self::Bit; 4],
    ) -> Result<P256ProjectiveValueV1<Self::Value>, Self::Error> {
        let scalar = bits_be[0].role;
        let source = bits_be[0].source;
        let start = usize::from(bits_be[0].global_be);
        if start % 4 != 0
            || start >= 256
            || bits_be.iter().enumerate().any(|(offset, bit)| {
                bit.role != scalar
                    || bit.source != source
                    || usize::from(bit.global_be) != start + offset
            })
        {
            return Err(P256TraceCompilerErrorV1::WindowTopology);
        }
        let window =
            u8::try_from(start / 4).map_err(|_| P256TraceCompilerErrorV1::WindowTopology)?;
        let expected_ordinal = self.windows.len();
        let expected_scalar = if expected_ordinal.is_multiple_of(2) {
            P256WindowScalarV1::U1
        } else {
            P256WindowScalarV1::U2
        };
        if scalar != expected_scalar || usize::from(window) != expected_ordinal / 2 {
            return Err(P256TraceCompilerErrorV1::WindowTopology);
        }
        if self.record_v1(source.0)?.modulus != ZkX509P256ModulusV1::ScalarField {
            return Err(P256TraceCompilerErrorV1::WindowTopology);
        }
        let candidates = core::array::from_fn(|candidate| {
            [
                table[candidate].x.0,
                table[candidate].y.0,
                table[candidate].z.0,
            ]
        });
        for handle in candidates.iter().flatten().copied() {
            if self.record_v1(handle)?.modulus != ZkX509P256ModulusV1::BaseField {
                return Err(P256TraceCompilerErrorV1::WindowTopology);
            }
        }
        let output = [
            self.push_initial_v1(
                ZkX509P256ModulusV1::BaseField,
                P256InitialValueKindV1::Input,
            )?,
            self.push_initial_v1(
                ZkX509P256ModulusV1::BaseField,
                P256InitialValueKindV1::Input,
            )?,
            self.push_initial_v1(
                ZkX509P256ModulusV1::BaseField,
                P256InitialValueKindV1::Input,
            )?,
        ];
        self.windows.push(TopologyWindowRecordV1 {
            candidates,
            output,
            scalar_source: source.0,
            scalar,
            window,
        });
        Ok(P256ProjectiveValueV1 {
            x: P256BaseValueV1(output[0]),
            y: P256BaseValueV1(output[1]),
            z: P256BaseValueV1(output[2]),
        })
    }
}
impl P256EcdsaCircuitV1 for P256TopologyCompilerV1 {
    type Scalar = P256ScalarValueV1;
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn base_input_v1(&mut self, _value_be: [u8; 32]) -> Result<Self::Value, Self::Error> {
        self.push_initial_v1(
            ZkX509P256ModulusV1::BaseField,
            P256InitialValueKindV1::Input,
        )
        .map(P256BaseValueV1)
    }
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn scalar_input_v1(&mut self, _value_be: [u8; 32]) -> Result<Self::Scalar, Self::Error> {
        self.push_initial_v1(
            ZkX509P256ModulusV1::ScalarField,
            P256InitialValueKindV1::Input,
        )
        .map(P256ScalarValueV1)
    }
    fn scalar_inverse_nonzero_v1(
        &mut self,
        value: Self::Scalar,
    ) -> Result<Self::Scalar, Self::Error> {
        if self.record_v1(value.0)?.modulus != ZkX509P256ModulusV1::ScalarField {
            return Err(P256TraceCompilerErrorV1::ValueTopology);
        }
        let inverse = P256ScalarValueV1(self.push_initial_v1(
            ZkX509P256ModulusV1::ScalarField,
            P256InitialValueKindV1::Input,
        )?);
        let product = self.scalar_multiply_v1(value, inverse)?;
        let one = P256ScalarValueV1(self.push_initial_v1(
            ZkX509P256ModulusV1::ScalarField,
            P256InitialValueKindV1::Constant,
        )?);
        self.scalar_assert_equal_v1(product, one)?;
        Ok(inverse)
    }
    fn scalar_multiply_v1(
        &mut self,
        left: Self::Scalar,
        right: Self::Scalar,
    ) -> Result<Self::Scalar, Self::Error> {
        self.push_operation_v1(
            ZkX509P256ArithmeticKindV1::Multiply,
            ZkX509P256ModulusV1::ScalarField,
            left.0,
            right.0,
        )
        .map(P256ScalarValueV1)
    }
    fn scalar_assert_equal_v1(
        &mut self,
        left: Self::Scalar,
        right: Self::Scalar,
    ) -> Result<(), Self::Error> {
        P256TopologyCompilerV1::assert_equal_v1(self, left.0, right.0)
    }
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn reduce_digest_v1(&mut self, _digest_be: [u8; 32]) -> Result<Self::Scalar, Self::Error> {
        let output = self.push_initial_v1(
            ZkX509P256ModulusV1::ScalarField,
            P256InitialValueKindV1::Input,
        )?;
        self.reductions.push(TopologyReductionRecordV1 {
            source: TopologyReductionSourceV1::Digest,
            output,
        });
        Ok(P256ScalarValueV1(output))
    }
    fn reduce_base_coordinate_v1(
        &mut self,
        coordinate: Self::Value,
    ) -> Result<Self::Scalar, Self::Error> {
        if self.record_v1(coordinate.0)?.modulus != ZkX509P256ModulusV1::BaseField {
            return Err(P256TraceCompilerErrorV1::ValueTopology);
        }
        let output = self.push_initial_v1(
            ZkX509P256ModulusV1::ScalarField,
            P256InitialValueKindV1::Input,
        )?;
        self.reductions.push(TopologyReductionRecordV1 {
            source: TopologyReductionSourceV1::BaseCoordinate(coordinate.0),
            output,
        });
        Ok(P256ScalarValueV1(output))
    }
    fn scalar_bits_be_v1(
        &mut self,
        scalar: Self::Scalar,
        role: P256WindowScalarV1,
    ) -> Result<[Self::Bit; 256], Self::Error> {
        if self.record_v1(scalar.0)?.modulus != ZkX509P256ModulusV1::ScalarField
            || !matches!(
                self.record_v1(scalar.0)?.origin,
                SymbolicOriginV1::Derived { .. }
            )
        {
            return Err(P256TraceCompilerErrorV1::WindowTopology);
        }
        Ok(core::array::from_fn(|global_be| P256TopologyScalarBitV1 {
            source: scalar,
            role,
            global_be: global_be as u16,
        }))
    }
    fn constrain_low_s_v1(&mut self, scalar: Self::Scalar) -> Result<(), Self::Error> {
        if self.record_v1(scalar.0)?.modulus != ZkX509P256ModulusV1::ScalarField {
            return Err(P256TraceCompilerErrorV1::BindingTopology);
        }
        self.low_s.push(scalar.0);
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Default)]
struct P256TopologyInputSourceV1;
impl P256EcdsaInputSourceV1<P256TopologyCompilerV1> for P256TopologyInputSourceV1 {
    fn public_key_v1(
        &mut self,
        circuit: &mut P256TopologyCompilerV1,
    ) -> Result<(P256BaseValueV1, P256BaseValueV1), P256TraceCompilerErrorV1> {
        Ok((
            P256BaseValueV1(circuit.push_initial_v1(
                ZkX509P256ModulusV1::BaseField,
                P256InitialValueKindV1::Input,
            )?),
            P256BaseValueV1(circuit.push_initial_v1(
                ZkX509P256ModulusV1::BaseField,
                P256InitialValueKindV1::Input,
            )?),
        ))
    }
    fn signature_v1(
        &mut self,
        circuit: &mut P256TopologyCompilerV1,
    ) -> Result<(P256ScalarValueV1, P256ScalarValueV1), P256TraceCompilerErrorV1> {
        Ok((
            P256ScalarValueV1(circuit.push_initial_v1(
                ZkX509P256ModulusV1::ScalarField,
                P256InitialValueKindV1::Input,
            )?),
            P256ScalarValueV1(circuit.push_initial_v1(
                ZkX509P256ModulusV1::ScalarField,
                P256InitialValueKindV1::Input,
            )?),
        ))
    }
    fn reduced_digest_v1(
        &mut self,
        circuit: &mut P256TopologyCompilerV1,
    ) -> Result<P256ScalarValueV1, P256TraceCompilerErrorV1> {
        let output = circuit.push_initial_v1(
            ZkX509P256ModulusV1::ScalarField,
            P256InitialValueKindV1::Input,
        )?;
        circuit.reductions.push(TopologyReductionRecordV1 {
            source: TopologyReductionSourceV1::Digest,
            output,
        });
        Ok(P256ScalarValueV1(output))
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256TraceCompilerV1 {
    fn with_topology_capacity_v1(
        topology: &P256EcdsaTopologyV1,
    ) -> Result<Self, P256TraceCompilerErrorV1> {
        let mut compiler = Self::default();
        let values = topology
            .initial_values
            .len()
            .checked_add(topology.linked_operations.len())
            .ok_or(P256TraceCompilerErrorV1::Resource)?;
        compiler
            .values
            .try_reserve_exact(values)
            .map_err(|_| P256TraceCompilerErrorV1::Resource)?;
        compiler
            .operations
            .try_reserve_exact(topology.linked_operations.len())
            .map_err(|_| P256TraceCompilerErrorV1::Resource)?;
        compiler
            .windows
            .try_reserve_exact(topology.windows.len())
            .map_err(|_| P256TraceCompilerErrorV1::Resource)?;
        compiler
            .reductions
            .try_reserve_exact(topology.reductions.len())
            .map_err(|_| P256TraceCompilerErrorV1::Resource)?;
        compiler
            .low_s
            .try_reserve_exact(topology.low_s.len())
            .map_err(|_| P256TraceCompilerErrorV1::Resource)?;
        Ok(compiler)
    }

    fn record(&self, handle: usize) -> Result<SymbolicValueRecordV1, P256TraceCompilerErrorV1> {
        self.values
            .get(handle)
            .copied()
            .ok_or(P256TraceCompilerErrorV1::Resource)
    }
    fn push_initial_v1(
        &mut self,
        modulus: ZkX509P256ModulusV1,
        value_be: [u8; 32],
        kind: P256InitialValueKindV1,
    ) -> Result<usize, P256TraceCompilerErrorV1> {
        let bound = match modulus {
            ZkX509P256ModulusV1::BaseField => P256_BASE_MODULUS_BE_V1,
            ZkX509P256ModulusV1::ScalarField => P256_SCALAR_MODULUS_BE_V1,
        };
        if value_be >= bound {
            return Err(P256TraceCompilerErrorV1::NonCanonical);
        }
        let initial = self.initial_handles.len();
        let handle = self.values.len();
        if self.values.len() == self.values.capacity() {
            return Err(P256TraceCompilerErrorV1::Resource);
        }
        self.values.push(SymbolicValueRecordV1 {
            modulus,
            value_be,
            origin: SymbolicOriginV1::Initial {
                index: initial,
                kind,
            },
        });
        self.initial_handles.push(handle);
        Ok(handle)
    }
    fn record_operation_v1(
        &mut self,
        kind: ZkX509P256ArithmeticKindV1,
        modulus: ZkX509P256ModulusV1,
        a: usize,
        b: usize,
        c_be: [u8; 32],
    ) -> Result<usize, P256TraceCompilerErrorV1> {
        let a_record = self.record(a)?;
        let b_record = self.record(b)?;
        if a_record.modulus != modulus || b_record.modulus != modulus {
            return Err(P256TraceCompilerErrorV1::NonCanonical);
        }
        let bound = match modulus {
            ZkX509P256ModulusV1::BaseField => P256_BASE_MODULUS_BE_V1,
            ZkX509P256ModulusV1::ScalarField => P256_SCALAR_MODULUS_BE_V1,
        };
        if c_be >= bound {
            return Err(P256TraceCompilerErrorV1::NonCanonical);
        }
        let operation = self.operations.len();
        let c = self.values.len();
        if self.values.len() == self.values.capacity() {
            return Err(P256TraceCompilerErrorV1::Resource);
        }
        self.values.push(SymbolicValueRecordV1 {
            modulus,
            value_be: c_be,
            origin: SymbolicOriginV1::Derived { operation },
        });
        if self.operations.len() == self.operations.capacity() {
            return Err(P256TraceCompilerErrorV1::Resource);
        }
        self.operations.push(RecordedOperationV1 {
            a,
            b,
            c,
            operation: ZkX509P256ArithmeticOperationV1 {
                kind,
                modulus,
                a: a_record.value_be,
                b: b_record.value_be,
                c: c_be,
            },
        });
        Ok(c)
    }
    fn base_field_v1(
        &self,
        value: P256BaseValueV1,
    ) -> Result<FieldElement, P256TraceCompilerErrorV1> {
        let record = self.record(value.0)?;
        if record.modulus != ZkX509P256ModulusV1::BaseField {
            return Err(P256TraceCompilerErrorV1::NonCanonical);
        }
        Option::<FieldElement>::from(FieldElement::from_bytes(&FieldBytes::from(record.value_be)))
            .ok_or(P256TraceCompilerErrorV1::NonCanonical)
    }
    fn scalar_field_v1(
        &self,
        value: P256ScalarValueV1,
    ) -> Result<Scalar, P256TraceCompilerErrorV1> {
        let record = self.record(value.0)?;
        if record.modulus != ZkX509P256ModulusV1::ScalarField {
            return Err(P256TraceCompilerErrorV1::NonCanonical);
        }
        Option::<Scalar>::from(Scalar::from_repr(record.value_be.into()))
            .ok_or(P256TraceCompilerErrorV1::NonCanonical)
    }
    fn assert_equal_handles_v1(
        &mut self,
        left: usize,
        right: usize,
    ) -> Result<(), P256TraceCompilerErrorV1> {
        let left_record = self.record(left)?;
        let right_record = self.record(right)?;
        if left_record.modulus != right_record.modulus
            || left_record.value_be != right_record.value_be
        {
            return Err(P256TraceCompilerErrorV1::Equality);
        }
        if left != right {
            self.equalities.push((left, right));
        }
        Ok(())
    }
    fn generator_table_v1(
        &mut self,
    ) -> Result<[P256ProjectiveValueV1<P256BaseValueV1>; 16], P256TraceCompilerErrorV1> {
        let zero = P256BaseValueV1(self.push_initial_v1(
            ZkX509P256ModulusV1::BaseField,
            ZERO_BE_V1,
            P256InitialValueKindV1::Constant,
        )?);
        let one = P256BaseValueV1(self.push_initial_v1(
            ZkX509P256ModulusV1::BaseField,
            ONE_BE_V1,
            P256InitialValueKindV1::Constant,
        )?);
        let identity = P256ProjectiveValueV1 {
            x: zero,
            y: one,
            z: zero,
        };
        let mut table = [identity; 16];
        for (multiple, assigned) in table.iter_mut().enumerate().skip(1) {
            let point = ProjectivePoint::GENERATOR * Scalar::from(multiple as u64);
            let encoded = point.to_affine().to_encoded_point(false);
            let mut x_be = [0_u8; 32];
            let mut y_be = [0_u8; 32];
            x_be.copy_from_slice(
                encoded
                    .x()
                    .ok_or(P256TraceCompilerErrorV1::WindowTopology)?,
            );
            y_be.copy_from_slice(
                encoded
                    .y()
                    .ok_or(P256TraceCompilerErrorV1::WindowTopology)?,
            );
            *assigned = P256ProjectiveValueV1 {
                x: self.constant_v1(x_be)?,
                y: self.constant_v1(y_be)?,
                z: self.constant_v1(ONE_BE_V1)?,
            };
        }
        Ok(table)
    }
    fn resolve_id_v1(&self, handle: usize) -> Result<P256ValueIdV1, P256TraceCompilerErrorV1> {
        let record = self.record(handle)?;
        let index = match record.origin {
            SymbolicOriginV1::Initial { index, .. } => index,
            SymbolicOriginV1::Derived { operation } => self
                .initial_handles
                .len()
                .checked_add(operation)
                .ok_or(P256TraceCompilerErrorV1::Resource)?,
        };
        Ok(P256ValueIdV1(
            u32::try_from(index).map_err(|_| P256TraceCompilerErrorV1::Resource)?,
        ))
    }
    fn validate_final_topology_v1(
        &self,
        role: P256EcdsaRoleV1,
        assigned: &P256EcdsaAssignedV1<P256ScalarValueV1, P256BaseValueV1>,
    ) -> Result<(), P256TraceCompilerErrorV1> {
        if self.windows.len() != 128 || self.reductions.len() != 2 {
            return Err(P256TraceCompilerErrorV1::BindingTopology);
        }
        if self.initial_handles.len() > self.operations.len()
            || self.values.len()
                != self
                    .initial_handles
                    .len()
                    .checked_add(self.operations.len())
                    .ok_or(P256TraceCompilerErrorV1::Resource)?
        {
            return Err(P256TraceCompilerErrorV1::ValueTopology);
        }
        for (index, handle) in self.initial_handles.iter().copied().enumerate() {
            if !matches!(
                self.record(handle)?.origin,
                SymbolicOriginV1::Initial {
                    index: origin_index,
                    ..
                } if origin_index == index
            ) {
                return Err(P256TraceCompilerErrorV1::ValueTopology);
            }
        }
        for (index, operation) in self.operations.iter().enumerate() {
            let a = self.record(operation.a)?;
            let b = self.record(operation.b)?;
            let c = self.record(operation.c)?;
            if !matches!(
                c.origin,
                SymbolicOriginV1::Derived {
                    operation: origin_operation
                } if origin_operation == index
            ) || [a.modulus, b.modulus, c.modulus]
                .iter()
                .any(|modulus| *modulus != operation.operation.modulus)
                || a.value_be != operation.operation.a
                || b.value_be != operation.operation.b
                || c.value_be != operation.operation.c
            {
                return Err(P256TraceCompilerErrorV1::ValueTopology);
            }
            for input in [a, b] {
                if matches!(
                    input.origin,
                    SymbolicOriginV1::Derived {
                        operation: dependency
                    } if dependency >= index
                ) {
                    return Err(P256TraceCompilerErrorV1::ValueTopology);
                }
            }
            let c_id = self.resolve_id_v1(operation.c)?;
            if self.resolve_id_v1(operation.a)?.0 >= c_id.0
                || self.resolve_id_v1(operation.b)?.0 >= c_id.0
            {
                return Err(P256TraceCompilerErrorV1::ValueTopology);
            }
        }
        for (ordinal, window) in self.windows.iter().enumerate() {
            let expected_role = if ordinal % 2 == 0 {
                P256WindowScalarV1::U1
            } else {
                P256WindowScalarV1::U2
            };
            let expected_window =
                u8::try_from(ordinal / 2).map_err(|_| P256TraceCompilerErrorV1::Resource)?;
            window
                .trace
                .validate_for_v1(expected_role, expected_window)
                .map_err(|_| P256TraceCompilerErrorV1::BindingTopology)?;
            let expected_source = if expected_role == P256WindowScalarV1::U1 {
                assigned.u1.0
            } else {
                assigned.u2.0
            };
            if window.scalar_source != expected_source {
                return Err(P256TraceCompilerErrorV1::BindingTopology);
            }
            for handle in window.candidates.iter().flatten().copied() {
                if self.record(handle)?.modulus != ZkX509P256ModulusV1::BaseField {
                    return Err(P256TraceCompilerErrorV1::BindingTopology);
                }
            }
            for handle in window.output {
                let record = self.record(handle)?;
                if record.modulus != ZkX509P256ModulusV1::BaseField
                    || !matches!(
                        record.origin,
                        SymbolicOriginV1::Initial {
                            kind: P256InitialValueKindV1::Input,
                            ..
                        }
                    )
                {
                    return Err(P256TraceCompilerErrorV1::BindingTopology);
                }
            }
            let selected = window
                .trace
                .selected_point_v1()
                .map_err(|_| P256TraceCompilerErrorV1::BindingTopology)?;
            if [
                self.record(window.output[0])?.value_be,
                self.record(window.output[1])?.value_be,
                self.record(window.output[2])?.value_be,
            ] != [selected.x_be, selected.y_be, selected.z_be]
            {
                return Err(P256TraceCompilerErrorV1::BindingTopology);
            }
        }
        let digest = self
            .reductions
            .first()
            .ok_or(P256TraceCompilerErrorV1::BindingTopology)?;
        let SymbolicReductionSourceV1::Digest { word_be } = digest.source else {
            return Err(P256TraceCompilerErrorV1::BindingTopology);
        };
        if digest.output != assigned.z.0
            || digest.trace
                != build_p256_reduction_trace_v1(word_be)
                    .map_err(|_| P256TraceCompilerErrorV1::Reduction)?
        {
            return Err(P256TraceCompilerErrorV1::BindingTopology);
        }
        let result_x = self
            .reductions
            .get(1)
            .ok_or(P256TraceCompilerErrorV1::BindingTopology)?;
        let SymbolicReductionSourceV1::BaseCoordinate { handle, word_be } = result_x.source else {
            return Err(P256TraceCompilerErrorV1::BindingTopology);
        };
        if handle != assigned.result_x.0
            || result_x.output != assigned.reduced_x.0
            || self.record(handle)?.value_be != word_be
            || result_x.trace
                != build_p256_reduction_trace_v1(word_be)
                    .map_err(|_| P256TraceCompilerErrorV1::Reduction)?
        {
            return Err(P256TraceCompilerErrorV1::BindingTopology);
        }
        match role {
            P256EcdsaRoleV1::WalletOwnership => {
                let [low_s] = self.low_s.as_slice() else {
                    return Err(P256TraceCompilerErrorV1::BindingTopology);
                };
                let scalar = self.record(assigned.s.0)?;
                if low_s.scalar != assigned.s.0
                    || low_s.trace
                        != build_p256_low_s_trace_v1(scalar.value_be)
                            .map_err(|_| P256TraceCompilerErrorV1::Reduction)?
                {
                    return Err(P256TraceCompilerErrorV1::BindingTopology);
                }
            }
            P256EcdsaRoleV1::CertificateOrCrl if !self.low_s.is_empty() => {
                return Err(P256TraceCompilerErrorV1::BindingTopology);
            }
            P256EcdsaRoleV1::CertificateOrCrl => {}
        }
        let required_initials = [
            (
                assigned.public_key.x.0,
                ZkX509P256ModulusV1::BaseField,
                P256InitialValueKindV1::Input,
            ),
            (
                assigned.public_key.y.0,
                ZkX509P256ModulusV1::BaseField,
                P256InitialValueKindV1::Input,
            ),
            (
                assigned.r.0,
                ZkX509P256ModulusV1::ScalarField,
                P256InitialValueKindV1::Input,
            ),
            (
                assigned.s.0,
                ZkX509P256ModulusV1::ScalarField,
                P256InitialValueKindV1::Input,
            ),
            (
                assigned.z.0,
                ZkX509P256ModulusV1::ScalarField,
                P256InitialValueKindV1::Input,
            ),
            (
                assigned.reduced_x.0,
                ZkX509P256ModulusV1::ScalarField,
                P256InitialValueKindV1::Input,
            ),
        ];
        for (handle, modulus, kind) in required_initials {
            let record = self.record(handle)?;
            if record.modulus != modulus
                || !matches!(
                    record.origin,
                    SymbolicOriginV1::Initial {
                        kind: actual_kind,
                        ..
                    } if actual_kind == kind
                )
            {
                return Err(P256TraceCompilerErrorV1::BindingTopology);
            }
        }
        let public_key_z = self.record(assigned.public_key.z.0)?;
        if public_key_z.modulus != ZkX509P256ModulusV1::BaseField
            || public_key_z.value_be != ONE_BE_V1
            || !matches!(
                public_key_z.origin,
                SymbolicOriginV1::Initial {
                    kind: P256InitialValueKindV1::Constant,
                    ..
                }
            )
        {
            return Err(P256TraceCompilerErrorV1::BindingTopology);
        }
        for handle in [
            assigned.u1.0,
            assigned.u2.0,
            assigned.result.x.0,
            assigned.result.y.0,
            assigned.result.z.0,
            assigned.result_x.0,
        ] {
            if !matches!(
                self.record(handle)?.origin,
                SymbolicOriginV1::Derived { .. }
            ) {
                return Err(P256TraceCompilerErrorV1::BindingTopology);
            }
        }
        if !self.equalities.iter().any(|(left, right)| {
            (*left == assigned.reduced_x.0 && *right == assigned.r.0)
                || (*left == assigned.r.0 && *right == assigned.reduced_x.0)
        }) {
            return Err(P256TraceCompilerErrorV1::BindingTopology);
        }
        Ok(())
    }
    fn finalize_v1(
        self,
        role: P256EcdsaRoleV1,
        assigned: P256EcdsaAssignedV1<P256ScalarValueV1, P256BaseValueV1>,
    ) -> Result<P256EcdsaTraceMaterialV1, P256TraceCompilerErrorV1> {
        self.validate_final_topology_v1(role, &assigned)?;
        let mut initial_values =
            super::private_table::PrivateTableV1::new(Vec::new(), zeroize_initial_values_v1);
        initial_values
            .try_reserve_exact(self.initial_handles.len())
            .map_err(|_| P256TraceCompilerErrorV1::Resource)?;
        for value in self
            .initial_handles
            .iter()
            .copied()
            .enumerate()
            .map(|(index, handle)| {
                let record = self.record(handle)?;
                let SymbolicOriginV1::Initial {
                    index: origin_index,
                    kind,
                } = record.origin
                else {
                    return Err(P256TraceCompilerErrorV1::Resource);
                };
                if origin_index != index {
                    return Err(P256TraceCompilerErrorV1::Resource);
                }
                Ok(P256InitialValueBindingV1 {
                    id: P256ValueIdV1(
                        u32::try_from(index).map_err(|_| P256TraceCompilerErrorV1::Resource)?,
                    ),
                    modulus: record.modulus,
                    value: record.value_be,
                    kind,
                })
            })
        {
            initial_values.push(value?);
        }
        let mut linked_operations =
            super::private_table::PrivateTableV1::new(Vec::new(), zeroize_linked_operations_v1);
        linked_operations
            .try_reserve_exact(self.operations.len())
            .map_err(|_| P256TraceCompilerErrorV1::Resource)?;
        for value in self
            .operations
            .iter()
            .enumerate()
            .map(|(index, operation)| {
                let c = self.resolve_id_v1(operation.c)?;
                let expected = self
                    .initial_handles
                    .len()
                    .checked_add(index)
                    .ok_or(P256TraceCompilerErrorV1::Resource)?;
                if c.0 as usize != expected {
                    return Err(P256TraceCompilerErrorV1::Resource);
                }
                Ok(P256LinkedOperationV1 {
                    a: self.resolve_id_v1(operation.a)?,
                    b: self.resolve_id_v1(operation.b)?,
                    c,
                    operation: operation.operation,
                })
            })
        {
            linked_operations.push(value?);
        }
        let equalities = self
            .equalities
            .iter()
            .map(|(left, right)| {
                Ok(P256EqualityBindingV1 {
                    left: self.resolve_id_v1(*left)?,
                    right: self.resolve_id_v1(*right)?,
                })
            })
            .collect::<Result<Vec<_>, P256TraceCompilerErrorV1>>()?;
        let windows = (0..128)
            .map(|ordinal| {
                let internal = if ordinal < 64 {
                    ordinal * 2
                } else {
                    (ordinal - 64) * 2 + 1
                };
                self.windows
                    .get(internal)
                    .ok_or(P256TraceCompilerErrorV1::WindowTopology)
            })
            .map(|window| {
                let window = window?;
                Ok(window)
            })
            .collect::<Result<Vec<_>, P256TraceCompilerErrorV1>>()?
            .into_iter()
            .map(|window| {
                let source = self.record(window.scalar_source)?;
                let SymbolicOriginV1::Derived { operation } = source.origin else {
                    return Err(P256TraceCompilerErrorV1::WindowTopology);
                };
                let mut candidates = [[P256ValueIdV1(0); 3]; 16];
                for (resolved, symbolic) in candidates.iter_mut().zip(window.candidates.iter()) {
                    for (resolved, symbolic) in resolved.iter_mut().zip(symbolic.iter()) {
                        *resolved = self.resolve_id_v1(*symbolic)?;
                    }
                }
                let mut output = [P256ValueIdV1(0); 3];
                for (resolved, symbolic) in output.iter_mut().zip(window.output.iter()) {
                    *resolved = self.resolve_id_v1(*symbolic)?;
                }
                Ok(P256BoundWindowTraceV1 {
                    trace: window.trace.clone(),
                    candidates,
                    output,
                    scalar_source_operation: u32::try_from(operation)
                        .map_err(|_| P256TraceCompilerErrorV1::Resource)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let reductions = self
            .reductions
            .iter()
            .map(|reduction| {
                Ok(P256BoundReductionTraceV1 {
                    source: match reduction.source {
                        SymbolicReductionSourceV1::Digest { word_be } => {
                            P256ReductionSourceV1::Digest { word_be }
                        }
                        SymbolicReductionSourceV1::BaseCoordinate { handle, word_be } => {
                            P256ReductionSourceV1::BaseCoordinate {
                                id: self.resolve_id_v1(handle)?,
                                word_be,
                            }
                        }
                    },
                    output: self.resolve_id_v1(reduction.output)?,
                    trace: reduction.trace.clone(),
                })
            })
            .collect::<Result<Vec<_>, P256TraceCompilerErrorV1>>()?;
        let low_s = self
            .low_s
            .iter()
            .map(|binding| {
                Ok(P256BoundLowSTraceV1 {
                    scalar: self.resolve_id_v1(binding.scalar)?,
                    trace: binding.trace.clone(),
                })
            })
            .collect::<Result<Vec<_>, P256TraceCompilerErrorV1>>()?;
        let assigned = P256ResolvedEcdsaAssignedV1 {
            public_key: P256ProjectiveValueV1 {
                x: self.resolve_id_v1(assigned.public_key.x.0)?,
                y: self.resolve_id_v1(assigned.public_key.y.0)?,
                z: self.resolve_id_v1(assigned.public_key.z.0)?,
            },
            r: self.resolve_id_v1(assigned.r.0)?,
            s: self.resolve_id_v1(assigned.s.0)?,
            z: self.resolve_id_v1(assigned.z.0)?,
            u1: self.resolve_id_v1(assigned.u1.0)?,
            u2: self.resolve_id_v1(assigned.u2.0)?,
            result: P256ProjectiveValueV1 {
                x: self.resolve_id_v1(assigned.result.x.0)?,
                y: self.resolve_id_v1(assigned.result.y.0)?,
                z: self.resolve_id_v1(assigned.result.z.0)?,
            },
            result_x: self.resolve_id_v1(assigned.result_x.0)?,
            reduced_x: self.resolve_id_v1(assigned.reduced_x.0)?,
        };
        Ok(P256EcdsaTraceMaterialV1 {
            role,
            initial_values: initial_values.into_vec(),
            linked_operations: linked_operations.into_vec(),
            equalities,
            boolean_bridges: Vec::new(),
            windows,
            reductions,
            low_s,
            assigned,
        })
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256BaseFieldCircuitV1 for P256TraceCompilerV1 {
    type Value = P256BaseValueV1;
    type Error = P256TraceCompilerErrorV1;
    fn constant_v1(&mut self, value: [u8; 32]) -> Result<Self::Value, Self::Error> {
        self.push_initial_v1(
            ZkX509P256ModulusV1::BaseField,
            value,
            P256InitialValueKindV1::Constant,
        )
        .map(P256BaseValueV1)
    }
    fn add_v1(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<Self::Value, Self::Error> {
        let result = (self.base_field_v1(left)? + self.base_field_v1(right)?)
            .to_bytes()
            .into();
        self.record_operation_v1(
            ZkX509P256ArithmeticKindV1::Add,
            ZkX509P256ModulusV1::BaseField,
            left.0,
            right.0,
            result,
        )
        .map(P256BaseValueV1)
    }
    fn subtract_v1(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<Self::Value, Self::Error> {
        let result = (self.base_field_v1(left)? - self.base_field_v1(right)?)
            .to_bytes()
            .into();
        self.record_operation_v1(
            ZkX509P256ArithmeticKindV1::Subtract,
            ZkX509P256ModulusV1::BaseField,
            left.0,
            right.0,
            result,
        )
        .map(P256BaseValueV1)
    }
    fn multiply_v1(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<Self::Value, Self::Error> {
        let result = (self.base_field_v1(left)? * self.base_field_v1(right)?)
            .to_bytes()
            .into();
        self.record_operation_v1(
            ZkX509P256ArithmeticKindV1::Multiply,
            ZkX509P256ModulusV1::BaseField,
            left.0,
            right.0,
            result,
        )
        .map(P256BaseValueV1)
    }
    fn assert_equal_v1(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<(), Self::Error> {
        self.assert_equal_handles_v1(left.0, right.0)
    }
    fn inverse_nonzero_v1(&mut self, value: Self::Value) -> Result<Self::Value, Self::Error> {
        let inverse = Option::<FieldElement>::from(self.base_field_v1(value)?.invert())
            .ok_or(P256TraceCompilerErrorV1::ZeroInverse)?;
        let inverse = P256BaseValueV1(self.push_initial_v1(
            ZkX509P256ModulusV1::BaseField,
            inverse.to_bytes().into(),
            P256InitialValueKindV1::Input,
        )?);
        let product = self.multiply_v1(value, inverse)?;
        let one = self.constant_v1(ONE_BE_V1)?;
        self.assert_equal_v1(product, one)?;
        Ok(inverse)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256WindowCircuitV1 for P256TraceCompilerV1 {
    type Bit = P256ScalarBitV1;
    fn select_window_v1(
        &mut self,
        table: &[P256ProjectiveValueV1<Self::Value>; 16],
        bits_be: [Self::Bit; 4],
    ) -> Result<P256ProjectiveValueV1<Self::Value>, Self::Error> {
        let role = bits_be[0].role;
        let source = bits_be[0].source;
        let start = usize::from(bits_be[0].global_be);
        if start % 4 != 0
            || start >= 256
            || bits_be.iter().enumerate().any(|(offset, bit)| {
                bit.role != role
                    || bit.source != source
                    || usize::from(bit.global_be) != start + offset
                    || bit.value > 1
            })
        {
            return Err(P256TraceCompilerErrorV1::WindowTopology);
        }
        let window = start / 4;
        let expected_ordinal = self.windows.len();
        let expected_role = if expected_ordinal.is_multiple_of(2) {
            P256WindowScalarV1::U1
        } else {
            P256WindowScalarV1::U2
        };
        if role != expected_role || window != expected_ordinal / 2 {
            return Err(P256TraceCompilerErrorV1::WindowTopology);
        }
        let candidate_handles = core::array::from_fn(|candidate| {
            [
                table[candidate].x.0,
                table[candidate].y.0,
                table[candidate].z.0,
            ]
        });
        let mut candidate_points = [P256WindowPointV1 {
            x_be: ZERO_BE_V1,
            y_be: ZERO_BE_V1,
            z_be: ZERO_BE_V1,
        }; 16];
        for (point, handles) in candidate_points.iter_mut().zip(candidate_handles.iter()) {
            let x = self.record(handles[0])?;
            let y = self.record(handles[1])?;
            let z = self.record(handles[2])?;
            if [x.modulus, y.modulus, z.modulus]
                .iter()
                .any(|modulus| *modulus != ZkX509P256ModulusV1::BaseField)
            {
                return Err(P256TraceCompilerErrorV1::WindowTopology);
            }
            *point = P256WindowPointV1 {
                x_be: x.value_be,
                y_be: y.value_be,
                z_be: z.value_be,
            };
        }
        let bit_values = bits_be.map(|bit| bit.value);
        let selected = bit_values
            .iter()
            .fold(0_usize, |value, bit| (value << 1) | usize::from(*bit));
        let selected_point = candidate_points[selected];
        let output = [
            self.push_initial_v1(
                ZkX509P256ModulusV1::BaseField,
                selected_point.x_be,
                P256InitialValueKindV1::Input,
            )?,
            self.push_initial_v1(
                ZkX509P256ModulusV1::BaseField,
                selected_point.y_be,
                P256InitialValueKindV1::Input,
            )?,
            self.push_initial_v1(
                ZkX509P256ModulusV1::BaseField,
                selected_point.z_be,
                P256InitialValueKindV1::Input,
            )?,
        ];
        let trace = build_p256_window_trace_v1(role, window as u8, candidate_points, bit_values)
            .map_err(|_| P256TraceCompilerErrorV1::WindowTopology)?;
        if self.windows.len() == self.windows.capacity() {
            return Err(P256TraceCompilerErrorV1::Resource);
        }
        self.windows.push(SymbolicWindowV1 {
            trace,
            candidates: candidate_handles,
            output,
            scalar_source: source.0,
        });
        Ok(P256ProjectiveValueV1 {
            x: P256BaseValueV1(output[0]),
            y: P256BaseValueV1(output[1]),
            z: P256BaseValueV1(output[2]),
        })
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256EcdsaCircuitV1 for P256TraceCompilerV1 {
    type Scalar = P256ScalarValueV1;
    fn base_input_v1(&mut self, value_be: [u8; 32]) -> Result<Self::Value, Self::Error> {
        self.push_initial_v1(
            ZkX509P256ModulusV1::BaseField,
            value_be,
            P256InitialValueKindV1::Input,
        )
        .map(P256BaseValueV1)
    }
    fn scalar_input_v1(&mut self, value_be: [u8; 32]) -> Result<Self::Scalar, Self::Error> {
        self.push_initial_v1(
            ZkX509P256ModulusV1::ScalarField,
            value_be,
            P256InitialValueKindV1::Input,
        )
        .map(P256ScalarValueV1)
    }
    fn scalar_inverse_nonzero_v1(
        &mut self,
        value: Self::Scalar,
    ) -> Result<Self::Scalar, Self::Error> {
        let inverse = Option::<Scalar>::from(self.scalar_field_v1(value)?.invert())
            .ok_or(P256TraceCompilerErrorV1::ZeroInverse)?;
        let inverse = P256ScalarValueV1(self.push_initial_v1(
            ZkX509P256ModulusV1::ScalarField,
            inverse.to_bytes().into(),
            P256InitialValueKindV1::Input,
        )?);
        let product = self.scalar_multiply_v1(value, inverse)?;
        let one = P256ScalarValueV1(self.push_initial_v1(
            ZkX509P256ModulusV1::ScalarField,
            ONE_BE_V1,
            P256InitialValueKindV1::Constant,
        )?);
        self.scalar_assert_equal_v1(product, one)?;
        Ok(inverse)
    }
    fn scalar_multiply_v1(
        &mut self,
        left: Self::Scalar,
        right: Self::Scalar,
    ) -> Result<Self::Scalar, Self::Error> {
        let result = (self.scalar_field_v1(left)? * self.scalar_field_v1(right)?)
            .to_bytes()
            .into();
        self.record_operation_v1(
            ZkX509P256ArithmeticKindV1::Multiply,
            ZkX509P256ModulusV1::ScalarField,
            left.0,
            right.0,
            result,
        )
        .map(P256ScalarValueV1)
    }
    fn scalar_assert_equal_v1(
        &mut self,
        left: Self::Scalar,
        right: Self::Scalar,
    ) -> Result<(), Self::Error> {
        self.assert_equal_handles_v1(left.0, right.0)
    }
    fn reduce_digest_v1(&mut self, digest_be: [u8; 32]) -> Result<Self::Scalar, Self::Error> {
        let trace = build_p256_reduction_trace_v1(digest_be)
            .map_err(|_| P256TraceCompilerErrorV1::Reduction)?;
        let output = self.push_initial_v1(
            ZkX509P256ModulusV1::ScalarField,
            trace.reduced_be_v1(),
            P256InitialValueKindV1::Input,
        )?;
        if self.reductions.len() == self.reductions.capacity() {
            return Err(P256TraceCompilerErrorV1::Resource);
        }
        self.reductions.push(SymbolicReductionV1 {
            source: SymbolicReductionSourceV1::Digest { word_be: digest_be },
            output,
            trace,
        });
        Ok(P256ScalarValueV1(output))
    }
    fn reduce_base_coordinate_v1(
        &mut self,
        coordinate: Self::Value,
    ) -> Result<Self::Scalar, Self::Error> {
        let coordinate_record = self.record(coordinate.0)?;
        if coordinate_record.modulus != ZkX509P256ModulusV1::BaseField {
            return Err(P256TraceCompilerErrorV1::NonCanonical);
        }
        let trace = build_p256_reduction_trace_v1(coordinate_record.value_be)
            .map_err(|_| P256TraceCompilerErrorV1::Reduction)?;
        let output = self.push_initial_v1(
            ZkX509P256ModulusV1::ScalarField,
            trace.reduced_be_v1(),
            P256InitialValueKindV1::Input,
        )?;
        if self.reductions.len() == self.reductions.capacity() {
            return Err(P256TraceCompilerErrorV1::Resource);
        }
        self.reductions.push(SymbolicReductionV1 {
            source: SymbolicReductionSourceV1::BaseCoordinate {
                handle: coordinate.0,
                word_be: coordinate_record.value_be,
            },
            output,
            trace,
        });
        Ok(P256ScalarValueV1(output))
    }
    fn scalar_bits_be_v1(
        &mut self,
        scalar: Self::Scalar,
        role: P256WindowScalarV1,
    ) -> Result<[Self::Bit; 256], Self::Error> {
        let record = self.record(scalar.0)?;
        if record.modulus != ZkX509P256ModulusV1::ScalarField
            || !matches!(record.origin, SymbolicOriginV1::Derived { .. })
        {
            return Err(P256TraceCompilerErrorV1::WindowTopology);
        }
        Ok(core::array::from_fn(|global_be| P256ScalarBitV1 {
            source: scalar,
            role,
            global_be: global_be as u16,
            value: (record.value_be[global_be / 8] >> (7 - global_be % 8)) & 1,
        }))
    }
    fn constrain_low_s_v1(&mut self, scalar: Self::Scalar) -> Result<(), Self::Error> {
        let record = self.record(scalar.0)?;
        let trace = build_p256_low_s_trace_v1(record.value_be)
            .map_err(|_| P256TraceCompilerErrorV1::Reduction)?;
        if self.low_s.len() == self.low_s.capacity() {
            return Err(P256TraceCompilerErrorV1::Resource);
        }
        self.low_s.push(SymbolicLowSV1 {
            scalar: scalar.0,
            trace,
        });
        Ok(())
    }
}
/// Independently compile the exact value-free verifier topology for one
/// role-separated ECDSA equation.
pub fn compile_p256_ecdsa_topology_v1(
    role: P256EcdsaRoleV1,
) -> Result<P256EcdsaTopologyV1, P256TraceCompilerErrorV1> {
    let mut compiler = P256TopologyCompilerV1::default();
    let generator_table = compiler.generator_table_v1()?;
    let assigned = constrain_p256_ecdsa_from_source_v1(
        &mut compiler,
        &generator_table,
        role,
        P256TopologyInputSourceV1,
    )?;
    compiler.finalize_v1(role, assigned)
}
/// Compile one complete role-separated ECDSA witness into native AIR material.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn compile_p256_ecdsa_trace_material_v1(
    role: P256EcdsaRoleV1,
    witness: P256EcdsaWitnessV1,
) -> Result<P256EcdsaTraceMaterialV1, P256TraceCompilerErrorV1> {
    let topology = compile_p256_ecdsa_topology_v1(role)?;
    let mut compiler = P256TraceCompilerV1::with_topology_capacity_v1(&topology)?;
    let generator_table = compiler.generator_table_v1()?;
    let assigned = constrain_p256_ecdsa_v1(&mut compiler, &generator_table, role, witness)?;
    let material = compiler.finalize_v1(role, assigned)?;
    material.validate_topology_v1(&topology)?;
    Ok(material)
}
#[cfg(test)]
mod tests {
    #[test]
    fn owned_compiler_erasure_covers_failure_and_preserves_preallocated_addresses() {
        use super::super::private_table::inspection::observe_v1;
        // This fixture checks all five private allocation addresses across compilation.
        let (mut compiler, assigned) = valid_compiler_v1();
        compiler.initial_handles[0] = usize::MAX;
        let (result, observed) =
            observe_v1(|| compiler.finalize_v1(P256EcdsaRoleV1::WalletOwnership, assigned));
        assert!(result.is_err());
        assert!(
            observed
                .iter()
                .any(|item| item.cells == 32 && item.nonzero_before > 0)
        );
        assert!(
            observed
                .iter()
                .any(|item| item.cells > 32 && item.nonzero_before > 0)
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
        let topology = compile_p256_ecdsa_topology_v1(P256EcdsaRoleV1::WalletOwnership).unwrap();
        let mut compiler = P256TraceCompilerV1::with_topology_capacity_v1(&topology).unwrap();
        // Exhaustion rejects before Vec can move a populated private allocation.
        let address = compiler.values.as_ptr();
        compiler.values.resize(
            compiler.values.capacity(),
            SymbolicValueRecordV1 {
                modulus: ZkX509P256ModulusV1::BaseField,
                value_be: [1; 32],
                origin: SymbolicOriginV1::Initial {
                    index: 0,
                    kind: P256InitialValueKindV1::Input,
                },
            },
        );
        assert_eq!(
            compiler.push_initial_v1(
                ZkX509P256ModulusV1::BaseField,
                [2; 32],
                P256InitialValueKindV1::Input
            ),
            Err(P256TraceCompilerErrorV1::Resource)
        );
        assert_eq!(address, compiler.values.as_ptr());
    }

    #[test]
    fn owned_material_erasure_clears_private_words_and_nested_trace_rows() {
        use super::super::private_table::inspection::observe_v1;
        let material = valid_material_v1();
        let ((), observed) = observe_v1(|| drop(material));
        assert!(
            observed
                .iter()
                .any(|item| item.cells == 32 && item.nonzero_before > 0)
        );
        assert!(
            observed
                .iter()
                .any(|item| item.cells > 32 && item.nonzero_before > 0)
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
    }

    use super::*;
    use crate::privacy_engines::zk_x509::p256_group_air::P256_TWO_SCALAR_ARITHMETIC_OPERATIONS_V1;
    use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};
    fn signing_key_v1(seed: u8) -> SigningKey {
        let mut bytes = [0_u8; 32];
        bytes[31] = seed.max(1);
        SigningKey::from_slice(&bytes).expect("valid nonzero key")
    }
    fn witness_v1(
        key: &SigningKey,
        digest_be: [u8; 32],
        signature: Signature,
    ) -> P256EcdsaWitnessV1 {
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
            digest_be,
        }
    }
    fn valid_compiler_v1() -> (
        P256TraceCompilerV1,
        P256EcdsaAssignedV1<P256ScalarValueV1, P256BaseValueV1>,
    ) {
        let key = signing_key_v1(73);
        let digest = core::array::from_fn(|index| (index as u8).wrapping_mul(37).wrapping_add(11));
        let signature: Signature = key.sign_prehash(&digest).expect("sign");
        let signature = signature.normalize_s().unwrap_or(signature);
        let topology = compile_p256_ecdsa_topology_v1(P256EcdsaRoleV1::WalletOwnership).unwrap();
        let mut compiler = P256TraceCompilerV1::with_topology_capacity_v1(&topology).unwrap();
        let addresses = (
            compiler.values.as_ptr(),
            compiler.operations.as_ptr(),
            compiler.windows.as_ptr(),
            compiler.reductions.as_ptr(),
            compiler.low_s.as_ptr(),
        );
        let generator = compiler.generator_table_v1().expect("generator table");
        let assigned = constrain_p256_ecdsa_v1(
            &mut compiler,
            &generator,
            P256EcdsaRoleV1::WalletOwnership,
            witness_v1(&key, digest, signature),
        )
        .expect("compile symbolic equation");
        assert_eq!(
            addresses,
            (
                compiler.values.as_ptr(),
                compiler.operations.as_ptr(),
                compiler.windows.as_ptr(),
                compiler.reductions.as_ptr(),
                compiler.low_s.as_ptr()
            )
        );
        (compiler, assigned)
    }
    fn valid_material_v1() -> P256EcdsaTraceMaterialV1 {
        let (compiler, assigned) = valid_compiler_v1();
        compiler
            .finalize_v1(P256EcdsaRoleV1::WalletOwnership, assigned)
            .expect("finalize exact witness")
    }
    #[test]
    fn complete_compiler_emits_canonical_ssa_windows_and_bindings() {
        let material = valid_material_v1();
        assert_eq!(
            material.linked_operations.len(),
            P256_TWO_SCALAR_ARITHMETIC_OPERATIONS_V1 + 18
        );
        assert!(material.initial_values.len() <= material.linked_operations.len());
        assert_eq!(material.windows.len(), 128);
        assert_eq!(material.reductions.len(), 2);
        assert_eq!(material.low_s.len(), 1);
        assert!(material.boolean_bridges.is_empty());
        for (index, initial) in material.initial_values.iter().enumerate() {
            assert_eq!(initial.id, P256ValueIdV1(index as u32));
        }
        for (index, operation) in material.linked_operations.iter().enumerate() {
            assert_eq!(
                operation.c,
                P256ValueIdV1((material.initial_values.len() + index) as u32)
            );
            assert!(operation.a.0 < operation.c.0);
            assert!(operation.b.0 < operation.c.0);
        }
        for (ordinal, window) in material.windows.iter().enumerate() {
            let role = if ordinal < 64 {
                P256WindowScalarV1::U1
            } else {
                P256WindowScalarV1::U2
            };
            let index = (ordinal % 64) as u8;
            window
                .trace
                .validate_for_v1(role, index)
                .expect("fixed window trace");
            assert_eq!(
                window.scalar_source_operation,
                if role == P256WindowScalarV1::U1 {
                    material.assigned.u1.0 - material.initial_values.len() as u32
                } else {
                    material.assigned.u2.0 - material.initial_values.len() as u32
                }
            );
        }
    }
    #[test]
    fn p256_material_capacity_payload_includes_nested_window_allocations() {
        use super::super::allocation_payload::{p256_material_v1, vector_v1};
        let mut material = valid_material_v1();
        let before = p256_material_v1(&material);
        let old = vector_v1(&material.windows[0].trace.base);
        material.windows[0].trace.base.reserve_exact(23);
        assert_eq!(
            p256_material_v1(&material),
            before - old + vector_v1(&material.windows[0].trace.base)
        );
        material.windows[0].trace.base.clear();
        assert_eq!(
            p256_material_v1(&material),
            before - old + vector_v1(&material.windows[0].trace.base)
        );
    }

    #[test]
    fn independent_verifier_topology_matches_both_roles_and_is_deterministic() {
        let wallet = compile_p256_ecdsa_topology_v1(P256EcdsaRoleV1::WalletOwnership)
            .expect("wallet topology");
        assert_eq!(
            wallet,
            compile_p256_ecdsa_topology_v1(P256EcdsaRoleV1::WalletOwnership)
                .expect("deterministic wallet topology")
        );
        valid_material_v1()
            .validate_topology_v1(&wallet)
            .expect("witness compiler matches independent wallet topology");
        let certificate = compile_p256_ecdsa_topology_v1(P256EcdsaRoleV1::CertificateOrCrl)
            .expect("certificate topology");
        assert_eq!(wallet.initial_values, certificate.initial_values);
        assert_eq!(wallet.linked_operations, certificate.linked_operations);
        assert_eq!(wallet.equalities, certificate.equalities);
        assert_eq!(wallet.boolean_bridges, certificate.boolean_bridges);
        assert_eq!(wallet.windows, certificate.windows);
        assert_eq!(wallet.reductions, certificate.reductions);
        assert_eq!(wallet.assigned, certificate.assigned);
        assert_eq!(wallet.low_s, vec![wallet.assigned.s]);
        assert!(certificate.low_s.is_empty());
        assert_eq!(
            wallet.linked_operations.len(),
            P256_TWO_SCALAR_ARITHMETIC_OPERATIONS_V1 + 18
        );
    }
    #[test]
    fn verifier_topology_rejects_every_witness_owned_schedule_family() {
        let material = valid_material_v1();
        let expected = compile_p256_ecdsa_topology_v1(P256EcdsaRoleV1::WalletOwnership)
            .expect("wallet topology");
        let reject = |changed: &P256EcdsaTraceMaterialV1| {
            assert_eq!(
                changed.validate_topology_v1(&expected),
                Err(P256TraceCompilerErrorV1::BindingTopology)
            );
        };
        let mut changed = material.clone();
        changed.role = P256EcdsaRoleV1::CertificateOrCrl;
        reject(&changed);
        changed = material.clone();
        changed.initial_values[0].id.0 ^= 1;
        reject(&changed);
        changed = material.clone();
        changed.initial_values[0].modulus = ZkX509P256ModulusV1::ScalarField;
        reject(&changed);
        changed = material.clone();
        changed.initial_values[0].kind = match changed.initial_values[0].kind {
            P256InitialValueKindV1::Input => P256InitialValueKindV1::Constant,
            P256InitialValueKindV1::Constant => P256InitialValueKindV1::Input,
        };
        reject(&changed);
        changed = material.clone();
        changed.linked_operations[0].a = changed.linked_operations[0].c;
        reject(&changed);
        changed = material.clone();
        changed.linked_operations[0].operation.kind =
            match changed.linked_operations[0].operation.kind {
                ZkX509P256ArithmeticKindV1::Multiply => ZkX509P256ArithmeticKindV1::Add,
                ZkX509P256ArithmeticKindV1::Add => ZkX509P256ArithmeticKindV1::Subtract,
                ZkX509P256ArithmeticKindV1::Subtract => ZkX509P256ArithmeticKindV1::Multiply,
            };
        reject(&changed);
        changed = material.clone();
        changed.linked_operations[0].operation.modulus = ZkX509P256ModulusV1::ScalarField;
        reject(&changed);
        changed = material.clone();
        changed.equalities[0].left.0 ^= 1;
        reject(&changed);
        changed = material.clone();
        changed.boolean_bridges.push(P256BooleanBridgeBindingV1 {
            scalar_bit: material.assigned.r,
            base_bit: material.assigned.public_key.x,
        });
        reject(&changed);
        changed = material.clone();
        changed.windows[0].candidates[0][0].0 ^= 1;
        reject(&changed);
        changed = material.clone();
        changed.windows[0].output[0].0 ^= 1;
        reject(&changed);
        changed = material.clone();
        changed.windows[0].scalar_source_operation ^= 1;
        reject(&changed);
        changed = material.clone();
        changed.windows[0].trace.fixed[0].scalar = P256WindowScalarV1::U2;
        assert_eq!(
            changed.validate_topology_v1(&expected),
            Err(P256TraceCompilerErrorV1::WindowTopology)
        );
        changed = material.clone();
        changed.reductions.swap(0, 1);
        reject(&changed);
        changed = material.clone();
        changed.reductions[0].output.0 ^= 1;
        reject(&changed);
        changed = material.clone();
        changed.low_s[0].scalar.0 ^= 1;
        reject(&changed);
        changed = material;
        changed.assigned.result_x.0 ^= 1;
        reject(&changed);
    }
    #[test]
    fn sampled_operations_are_exact_native_arithmetic_traces() {
        let material = valid_material_v1();
        for linked in material.linked_operations.iter().step_by(127) {
            let trace = build_zk_x509_p256_arithmetic_trace_v1(&[linked.operation])
                .expect("build sampled operation");
            trace.validate().expect("validate sampled operation");
        }
        for binding in &material.reductions {
            binding.trace.validate().expect("exact reduction");
        }
        for binding in &material.low_s {
            binding.trace.validate().expect("exact low-s");
        }
    }
    #[test]
    fn certificate_role_omits_low_s_but_invalid_equations_fail() {
        let key = signing_key_v1(79);
        let digest = [0xa7; 32];
        let signature: Signature = key.sign_prehash(&digest).expect("sign");
        let signature = signature.normalize_s().unwrap_or(signature);
        let high = Signature::from_scalars(signature.r().to_bytes(), (-*signature.s()).to_bytes())
            .expect("high-s representative");
        let material = compile_p256_ecdsa_trace_material_v1(
            P256EcdsaRoleV1::CertificateOrCrl,
            witness_v1(&key, digest, high),
        )
        .expect("RFC 5280 high-s");
        assert!(material.low_s.is_empty());
        let mut wrong = witness_v1(&key, digest, signature);
        wrong.digest_be[0] ^= 1;
        assert_eq!(
            compile_p256_ecdsa_trace_material_v1(P256EcdsaRoleV1::WalletOwnership, wrong,),
            Err(P256TraceCompilerErrorV1::Equality)
        );
    }
    #[test]
    fn zero_noncanonical_and_high_s_inputs_fail_closed() {
        let key = signing_key_v1(83);
        let digest = [0x5c; 32];
        let signature: Signature = key.sign_prehash(&digest).expect("sign");
        let signature = signature.normalize_s().unwrap_or(signature);
        let witness = witness_v1(&key, digest, signature);
        let mut zero = witness;
        zero.r_be = [0; 32];
        assert_eq!(
            compile_p256_ecdsa_trace_material_v1(P256EcdsaRoleV1::WalletOwnership, zero,),
            Err(P256TraceCompilerErrorV1::ZeroInverse)
        );
        let high = Signature::from_scalars(signature.r().to_bytes(), (-*signature.s()).to_bytes())
            .expect("high-s representative");
        assert_eq!(
            compile_p256_ecdsa_trace_material_v1(
                P256EcdsaRoleV1::WalletOwnership,
                witness_v1(&key, digest, high),
            ),
            Err(P256TraceCompilerErrorV1::Reduction)
        );
        let mut noncanonical = witness;
        noncanonical.s_be = P256_SCALAR_MODULUS_BE_V1;
        assert_eq!(
            compile_p256_ecdsa_trace_material_v1(P256EcdsaRoleV1::CertificateOrCrl, noncanonical,),
            Err(P256TraceCompilerErrorV1::NonCanonical)
        );
    }
    #[test]
    fn finalization_rejects_value_window_reduction_and_low_s_rebinding() {
        let (compiler, assigned) = valid_compiler_v1();
        let mut forward_read = compiler.clone();
        forward_read.operations[0].a = forward_read.operations[0].c;
        assert_eq!(
            forward_read.finalize_v1(P256EcdsaRoleV1::WalletOwnership, assigned),
            Err(P256TraceCompilerErrorV1::ValueTopology)
        );
        let mut wrong_source = compiler.clone();
        wrong_source.windows[0].scalar_source = assigned.u2.0;
        assert_eq!(
            wrong_source.finalize_v1(P256EcdsaRoleV1::WalletOwnership, assigned),
            Err(P256TraceCompilerErrorV1::BindingTopology)
        );
        let mut wrong_position = compiler.clone();
        wrong_position.windows[0].trace.fixed[0].scalar = P256WindowScalarV1::U2;
        assert_eq!(
            wrong_position.finalize_v1(P256EcdsaRoleV1::WalletOwnership, assigned),
            Err(P256TraceCompilerErrorV1::BindingTopology)
        );
        let mut swapped_reductions = compiler.clone();
        swapped_reductions.reductions.swap(0, 1);
        assert_eq!(
            swapped_reductions.finalize_v1(P256EcdsaRoleV1::WalletOwnership, assigned),
            Err(P256TraceCompilerErrorV1::BindingTopology)
        );
        let mut wrong_low_s = compiler.clone();
        wrong_low_s.low_s[0].scalar = assigned.r.0;
        assert_eq!(
            wrong_low_s.finalize_v1(P256EcdsaRoleV1::WalletOwnership, assigned),
            Err(P256TraceCompilerErrorV1::BindingTopology)
        );
        let mut wrong_output = compiler;
        wrong_output.windows[0].output[0] = assigned.public_key.x.0;
        assert_eq!(
            wrong_output.finalize_v1(P256EcdsaRoleV1::WalletOwnership, assigned),
            Err(P256TraceCompilerErrorV1::BindingTopology)
        );
    }
}
