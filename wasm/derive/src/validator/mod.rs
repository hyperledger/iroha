//! Module with validator-related derive macros.

#![allow(clippy::panic)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote, DeriveInput};

pub mod conversion;
pub mod entrypoint;
pub mod token;
pub mod validate;
