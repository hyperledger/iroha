use impls::impls;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};

#[test]
fn usize_isize_not_into_schema() {
    // The architecture-dependent
    assert!(!impls!(usize: IntoSchema));
    assert!(!impls!(isize: IntoSchema));

    // use serde::Serialize;
    //
    // assert!(!impls!(usize: Serialize));
    // `usize` should be `Serialize`.

    // But not `Encode`/`Decode`.
    assert!(!impls!(usize: Encode | Decode));
    assert!(!impls!(isize: Encode | Decode));

    // There are no other primitive architecture-dependent types, so
    // as long as `IntoSchema` requires all variants and all fields to
    // also be `IntoSchema`, we are guaranteed that all schema types
    // are safe to exchange.
}
