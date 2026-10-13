//! This module contains all the internals of how the complex concurrent datastructures
//! are implemented. You should turn back now. Nothing of value is here. This module can
//! only inflict horror upon you.
//!
//! This module exists for one purpose - to allow external composition of structures
//! coordinated by a single locking manager. This makes every element of this module
//! unsafe in every meaning of the word. If you handle this module at all, you will
//! probably cause space time to unravel.
//!
//! ⚠️   ⚠️   ⚠️

pub mod bptree;
pub mod lincowcell;
