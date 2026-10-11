#[cfg(all(test, feature = "app_api"))]
mod tests {
    // These textual chunks remain inside `tests`, preserving all item namespaces.
    include!("lib_tests/part_1.rs");
    include!("lib_tests/part_2.rs");
    include!("lib_tests/part_3.rs");
    include!("lib_tests/owner_prf_routes.rs");
    include!("lib_tests/part_4.rs");
    include!("lib_tests/part_5.rs");
    include!("lib_tests/iso20022_operator_auth.rs");
    include!("lib_tests/identifier_owner_routes.rs");
    include!("lib_tests/fee_sponsor_enrollment.rs");
}
