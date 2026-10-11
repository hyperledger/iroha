//! Tests for invalid Kotodama pointer literals.
use kotodama_lang::{compiler::Compiler, i18n::Language};
fn english_compiler() -> Compiler {
    Compiler::new_with_language(Language::English)
}
#[test]
fn invalid_account_id_literal_reports_error() {
    let src = r#"
        seiyaku InvalidAccount { permission RegisterAccount;
          kotoage fn main() authorize(RegisterAccount) {
            ledger::account::register(account: AccountId::parse("invalid-account"));
          }
        }
    "#;
    let err = english_compiler().compile_source(src).unwrap_err();
    assert!(
        err.contains("invalid AccountId literal"),
        "expected invalid AccountId error, got: {err}"
    );
}
#[test]
fn invalid_asset_definition_literal_reports_error() {
    let src = r#"
        seiyaku InvalidAssetDefinition { permission UnregisterAsset;
          kotoage fn main() authorize(UnregisterAsset) {
            ledger::asset::unregister(asset_definition: AssetDefinitionId::parse("invalid"));
          }
        }
    "#;
    let err = english_compiler().compile_source(src).unwrap_err();
    assert!(
        err.contains("invalid AssetDefinitionId literal"),
        "expected invalid AssetDefinitionId error, got: {err}"
    );
}
#[test]
fn invalid_json_literal_reports_error() {
    let src = r#"
        seiyaku InvalidJson { permission SetAccountDetail;
          kotoage fn main() authorize(SetAccountDetail) {
            ledger::account::set_metadata(account: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), key: Name::parse("cursor"), value: Json::parse("{\"unterminated\":}"));
          }
        }
    "#;
    let err = english_compiler().compile_source(src).unwrap_err();
    assert!(
        err.contains("error[E_JSON_LITERAL_INVALID]"),
        "expected stable invalid JSON diagnostic code, got: {err}"
    );
}
#[test]
fn build_submit_ballot_inline_rejects_runtime_bytes() {
    let src = r#"
        seiyaku RuntimeBallotBytes { permission SubmitBallot;
          kotoage fn main(bytes cipher, bytes nullifier, bytes proof, bytes vk) authorize(SubmitBallot) {
            ledger::governance::build_submit_ballot(election_id: "election", ciphertext: cipher, nullifier: nullifier, backend: "ipa", proof: proof, verification_key: vk);
          }
        }
    "#;
    let err = english_compiler().compile_source(src).unwrap_err();
    assert!(
        err.contains("build_submit_ballot_inline requires literal ciphertext"),
        "expected literal ciphertext error, got: {err}"
    );
}
#[test]
fn retired_unshield_builder_is_not_a_source_api() {
    let src = r#"
        seiyaku RetiredUnshieldBuilder { permission Unshield;
          kotoage fn main() authorize(Unshield) {
            crypto::zk::build_unshield();
          }
        }
    "#;
    let err = english_compiler().compile_source(src).unwrap_err();
    assert!(
        err.contains("build_unshield"),
        "the retired builder diagnostic should name the rejected call: {err}"
    );
}
#[test]
fn build_submit_ballot_inline_rejects_wrong_nullifier_length() {
    let src = r#"
        seiyaku ShortNullifier { permission SubmitBallot;
          kotoage fn main() authorize(SubmitBallot) {
            ledger::governance::build_submit_ballot(election_id: "election", ciphertext: b"ciphertext", nullifier: b"short", backend: "ipa", proof: b"proof", verification_key: b"vk");
          }
        }
    "#;
    let err = english_compiler().compile_source(src).unwrap_err();
    assert!(
        err.contains("build_submit_ballot_inline nullifier must be 32 bytes"),
        "expected nullifier length error, got: {err}"
    );
}
