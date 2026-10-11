//! Parameter default sanity checks.
use iroha_data_model::parameter::Parameters;
#[test]
fn sumeragi_defaults_have_nonzero_cadence() {
    let params = Parameters::default();
    // §9.3 of `specs/sumeragi.md`: one-second target block time.
    assert_eq!(params.sumeragi().block_cadence_ms().get(), 1_000);
}
