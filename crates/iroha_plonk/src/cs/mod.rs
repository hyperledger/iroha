//! The PIPA-v1 constraint-system IR (spec section 2 and section 4).
//!
//! - [`expression`]: columns, rotations, queries, selectors and expressions;
//! - [`gate`]: gates and constraints;
//! - [`lookup`]: halo2 permuted lookups;
//! - [`permutation`]: the chunked permutation argument and its copy assembly;
//! - [`selector_compression`]: the exact halo2 selector-compression plan;
//! - [`constraint_system`]: the configure-time builder and its finalization;
//! - [`descriptor`]: `CircuitDescriptorV1`, its validation and digest.

pub mod constraint_system;
pub mod descriptor;
pub mod descriptor_v2;
pub mod expression;
pub mod gate;
pub mod lookup;
pub mod permutation;
pub mod selector_compression;

pub use constraint_system::{
    ConstraintSystem, CsError, FinalizedConstraintSystem, SelectorPlan, SelectorPlanEntry,
    VirtualCells, domain_size,
};
pub use descriptor::{
    CircuitDescriptorV1, CurveV1, DescriptorConfig, DescriptorError, DescriptorRule,
    InstanceModeV1, ProofSuffixV1, TranscriptV1, descriptor_digest, transcript_repr,
};
pub use expression::{
    Advice, AdviceQuery, Any, Column, ColumnType, Expression, ExpressionEvaluator, Fixed,
    FixedQuery, Instance, InstanceQuery, Rotation, Selector, TableColumn,
};
pub use gate::{Constraint, Constraints, Gate, VirtualCell};
pub use lookup::LookupArgument;
pub use permutation::{PermutationArgument, PermutationAssembly, PermutationError};

pub use descriptor_v2::{
    CircuitDescriptorV2, DescriptorSource, InstanceType, ProtocolDescriptor, TranscriptV2,
};
