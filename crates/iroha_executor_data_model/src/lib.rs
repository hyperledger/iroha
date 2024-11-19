//! Executor data model
#![no_std]

extern crate alloc;
extern crate self as iroha_executor_data_model;

pub mod isi;
pub mod parameter;
pub mod permission;

/// An error that might occur while converting a data model object into a native executor type.
///
/// Such objects are [`iroha_data_model::permission::Permission`] and [`iroha_data_model::parameter::Parameter`].
#[derive(Debug)]
pub enum TryFromDataModelObjectError {
    /// Unexpected object name
    UnknownIdent(iroha_schema::Ident),
    /// Failed to deserialize object payload
    Deserialize(serde_json::Error),
}
