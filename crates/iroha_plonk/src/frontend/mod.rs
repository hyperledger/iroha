//! The circuit frontend: [`Circuit`], [`Layouter`], [`Region`], [`Value`],
//! [`Assigned`], the [`SimpleFloorPlanner`] and the [`Assembly`] backend.
//!
//! The API follows halo2-axiom so chips port mechanically, with two
//! deliberate differences: every fallible operation returns [`Error`] instead
//! of panicking, and instance columns declare their exact length in
//! `configure` (`ConstraintSystem::instance_column(length)`).
//!
//! - [`value`]: [`Value`] and [`Assigned`];
//! - [`assignment`]: the [`Assignment`] backend trait, [`Assembly`] and
//!   [`AssignedTables`];
//! - [`layouter`]: regions, tables, layouters and the floor planner;
//! - [`circuit`]: the [`Circuit`] trait and [`synthesize`].

pub mod assignment;
pub mod circuit;
pub mod layouter;
pub mod value;

pub use assignment::{Assembly, AssignedTables, Assignment, Error, RegionRecord, TableError};
pub use circuit::{Circuit, Synthesized, configure, synthesize, synthesize_cancellable};
pub use layouter::{
    AssignedCell, Cell, FloorPlanner, Layouter, NamespacedLayouter, Region, RegionLayouter,
    SimpleFloorPlanner, SingleChipLayouter, Table, TableLayouter,
};
pub use value::{Assigned, Value};
