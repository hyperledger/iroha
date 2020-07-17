pub mod client;
pub mod config;
pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `iroha_client`.

    #[doc(inline)]
    pub use iroha::event::connection::{EntityType, OccurrenceType};
}
