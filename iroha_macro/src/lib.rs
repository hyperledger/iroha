pub mod error {
    pub use iroha_error::*;
}

pub trait Io: parity_scale_codec::Encode + parity_scale_codec::Decode {}
pub trait IntoContract {}
pub trait IntoQuery {}
