//! Human-written summaries for every source-visible Kotodama builtin.
//!
//! The table is keyed by the builtin's canonical source path as reported by
//! [`crate::builtins::BuiltinSpec::name`] (`ledger::asset::transfer`,
//! `AccountId::parse`, or a receiver method name such as `get_or_insert`).
//! Editor hover, completion and signature help render these summaries next to
//! the registry's signature, effects and access class, so the prose never has
//! to repeat machine-checked metadata. Tests keep the table and the registry in
//! lockstep: every key names a source-visible builtin and every source-visible
//! builtin has exactly one summary.

/// Sorted `(source path, summary)` pairs for every source-visible builtin.
pub const BUILTIN_DOCS: &[(&str, &str)] = &[
    (
        "AccountId::parse",
        "Parse a canonical account identity string into an `AccountId`.",
    ),
    (
        "AssetDefinitionId::parse",
        "Parse an asset definition identity string into an `AssetDefinitionId`.",
    ),
    (
        "AssetId::parse",
        "Parse an asset identity string into an `AssetId`.",
    ),
    (
        "AxtAnchoredSpendV1::parse",
        "Parse a V1 anchored-spend descriptor for an atomic cross-dataspace transaction.",
    ),
    (
        "AxtDescriptor::parse",
        "Parse an atomic cross-dataspace transaction descriptor.",
    ),
    (
        "DataSpaceId::parse",
        "Parse a dataspace identity string into a `DataSpaceId`.",
    ),
    (
        "DomainId::parse",
        "Parse a domain identity string into a `DomainId`.",
    ),
    (
        "Json::parse",
        "Parse a JSON document from its string representation into a `Json` value.",
    ),
    (
        "Mintable::Infinitely",
        "Compile-time `Mintable` value for elastic supply.",
    ),
    (
        "Mintable::Limited",
        "Compile-time `Mintable` value allowing a limited number of mints.",
    ),
    (
        "Mintable::Not",
        "Compile-time `Mintable` value forbidding mints.",
    ),
    (
        "Mintable::Once",
        "Compile-time `Mintable` value allowing exactly one mint.",
    ),
    ("Name::parse", "Parse and validate a ledger `Name`."),
    (
        "NftId::parse",
        "Parse an NFT identity string into an `NftId`.",
    ),
    (
        "NumericSpec::fractional",
        "Compile-time `NumericSpec` that accepts at most the given decimal scale.",
    ),
    (
        "NumericSpec::integer",
        "Compile-time `NumericSpec` that accepts integers only.",
    ),
    (
        "NumericSpec::unconstrained",
        "Compile-time `NumericSpec` that accepts any scale.",
    ),
    (
        "SignatureScheme::Ed25519",
        "Compile-time `SignatureScheme` value selecting Ed25519 for `crypto::verify_signature`.",
    ),
    (
        "SignatureScheme::MlDsa",
        "Compile-time `SignatureScheme` value selecting ML-DSA for `crypto::verify_signature`.",
    ),
    (
        "SignatureScheme::Secp256k1",
        "Compile-time `SignatureScheme` value selecting secp256k1 ECDSA for `crypto::verify_signature`.",
    ),
    (
        "axt::begin",
        "Begin an atomic cross-dataspace transaction using its descriptor.",
    ),
    (
        "axt::commit",
        "Commit the active atomic cross-dataspace transaction.",
    ),
    (
        "axt::stage_anchored_spend",
        "Stage a V1 anchored spend in an atomic cross-dataspace transaction.",
    ),
    (
        "axt::touch",
        "Declare a dataspace touch and its manifest in an atomic transaction.",
    ),
    ("bytes::concat", "Concatenate two byte values."),
    ("bytes::len", "Read the length of a byte value."),
    (
        "codec::encode",
        "Encode a public value using its canonical typed Norito record.",
    ),
    (
        "contains",
        "Check whether a durable state map contains a key.",
    ),
    (
        "context::authority",
        "Read the current execution authority.",
    ),
    ("context::block_height", "Read the current block height."),
    ("context::chain_id", "Read the encoded chain identity."),
    (
        "context::kotoage",
        "Read the name of the currently invoked `kotoage`/`言挙げ` as bytes.",
    ),
    (
        "context::public_input",
        "Read a named public input as bytes.",
    ),
    (
        "context::seiyaku_address",
        "Read the encoded seiyaku address.",
    ),
    (
        "context::seiyaku_subject",
        "Read the current seiyaku subject account.",
    ),
    (
        "context::transaction_time_ms",
        "Read the signer-supplied transaction creation time in milliseconds.",
    ),
    (
        "context::trigger_event",
        "Read the current trigger event as JSON.",
    ),
    ("crypto::blake2b256", "Hash bytes with BLAKE2b-256."),
    (
        "crypto::commit_output",
        "Commit the current output in ZK mode.",
    ),
    (
        "crypto::execution_summary",
        "Read the encoded execution summary.",
    ),
    (
        "crypto::iroha_hash",
        "Hash bytes with the canonical Iroha hash operation.",
    ),
    ("crypto::keccak256", "Hash bytes with Keccak-256."),
    (
        "crypto::private_input",
        "Read a private numeric input in ZK mode from a prover or local test host. Production consensus hosts never provide raw private witnesses; deploy a public-proof verifier instead.",
    ),
    ("crypto::sha256", "Hash bytes with SHA-256."),
    ("crypto::sha3", "Hash bytes with SHA-3."),
    (
        "crypto::sm2::verify",
        "Verify an SM2 signature with an optional distinguishing identifier.",
    ),
    ("crypto::sm3", "Hash bytes with SM3."),
    (
        "crypto::sm4_ccm::open",
        "Open authenticated bytes using SM4-CCM.",
    ),
    (
        "crypto::sm4_ccm::seal",
        "Seal bytes using SM4-CCM with an optional tag length.",
    ),
    (
        "crypto::sm4_gcm::open",
        "Open authenticated bytes using SM4-GCM.",
    ),
    (
        "crypto::sm4_gcm::seal",
        "Seal bytes using SM4-GCM with nonce and associated data.",
    ),
    ("crypto::valcom", "Commit secret numeric values in ZK mode."),
    (
        "crypto::verify_proof",
        "Verify an encoded proof through the host.",
    ),
    (
        "crypto::verify_signature",
        "Verify `signature` over `message` with `public_key` under a compile-time `SignatureScheme` and return whether it is valid.",
    ),
    (
        "crypto::vrf::epoch_seed",
        "Read the exact epoch’s 32-byte VRF seed, or None when unavailable. No latest-epoch fallback.",
    ),
    (
        "crypto::vrf::verify",
        "Verify an encoded VRF request and return its response.",
    ),
    (
        "crypto::vrf::verify_batch",
        "Verify an encoded batch of VRF requests and return its response.",
    ),
    (
        "crypto::zk::roots",
        "Read encoded roots from the host ZK registry.",
    ),
    (
        "crypto::zk::verify_batch",
        "Ask the host to verify an encoded ZK proof batch.",
    ),
    (
        "debug::info",
        "Emit an informational debug record for a string or integer.",
    ),
    (
        "get_account_id",
        "Read an optional account identity field from JSON.",
    ),
    (
        "get_asset_definition_id",
        "Read an optional asset definition identity field from JSON.",
    ),
    ("get_bool", "Read an optional boolean field from JSON."),
    (
        "get_bytes_hex",
        "Read an optional byte field encoded as hexadecimal in JSON.",
    ),
    ("get_decimal", "Read an optional decimal field from JSON."),
    ("get_int", "Read an optional integer field from JSON."),
    ("get_json", "Read an optional nested JSON field."),
    ("get_name", "Read an optional ledger name field from JSON."),
    (
        "get_nft_id",
        "Read an optional NFT identity field from JSON.",
    ),
    (
        "get_or_insert",
        "Return a durable state map value, first writing the supplied default when the key is absent.",
    ),
    ("get_quantity", "Read an optional quantity field from JSON."),
    ("get_string", "Read an optional string field from JSON."),
    ("json::object", "Create an empty JSON object."),
    (
        "json::set_account_id",
        "Set an account identity in a JSON object.",
    ),
    (
        "ledger::account::add_signatory",
        "Add a signatory to an account.",
    ),
    (
        "ledger::account::recovery::approve",
        "Approve an alias account-recovery request generation.",
    ),
    (
        "ledger::account::recovery::cancel",
        "Cancel an alias account-recovery request generation.",
    ),
    (
        "ledger::account::recovery::finalize",
        "Finalize an alias account-recovery request generation.",
    ),
    (
        "ledger::account::recovery::propose",
        "Propose an alias account-recovery replacement for a request generation.",
    ),
    (
        "ledger::account::register",
        "Register a canonical account identity.",
    ),
    (
        "ledger::account::remove_signatory",
        "Remove a signatory from an account.",
    ),
    (
        "ledger::account::resolve_alias",
        "Resolve an account alias to its canonical account identity.",
    ),
    (
        "ledger::account::set_metadata",
        "Set one JSON metadata entry on an account.",
    ),
    (
        "ledger::account::set_quorum",
        "Set an account's signature quorum.",
    ),
    ("ledger::account::unregister", "Unregister an account."),
    (
        "ledger::asset::balance",
        "Read the quantity held by an account for an asset definition.",
    ),
    (
        "ledger::asset::burn",
        "Burn an asset quantity held by an account.",
    ),
    (
        "ledger::asset::mint",
        "Mint an asset quantity for an account.",
    ),
    (
        "ledger::asset::register",
        "Register an asset definition with its display name, numeric spec and mintability.",
    ),
    (
        "ledger::asset::set_holding_limit",
        "Set or remove an account asset's holding limit.",
    ),
    (
        "ledger::asset::set_transfer_availability",
        "Update an account asset's transfer availability at an expected revision.",
    ),
    (
        "ledger::asset::set_transfer_daily_limit",
        "Set or remove an account asset's daily transfer cap.",
    ),
    (
        "ledger::asset::transfer",
        "Transfer an asset quantity between accounts, optionally scoped to a dataspace.",
    ),
    (
        "ledger::asset::transfer_batch",
        "Lower a bounded list of asset transfers to a host-managed batch.",
    ),
    (
        "ledger::asset::unregister",
        "Unregister an asset definition.",
    ),
    ("ledger::domain::register", "Register a ledger domain."),
    (
        "ledger::domain::transfer",
        "Transfer ownership of a ledger domain between accounts.",
    ),
    ("ledger::domain::unregister", "Unregister a ledger domain."),
    ("ledger::escrow::accept", "Accept a named escrow offer."),
    ("ledger::escrow::cancel", "Cancel a named escrow offer."),
    (
        "ledger::escrow::mark_payment_sent",
        "Mark payment as sent for a named escrow offer.",
    ),
    (
        "ledger::escrow::open_dispute",
        "Open a dispute for an escrow offer with optional evidence.",
    ),
    (
        "ledger::escrow::open_offer",
        "Open an escrow offer with an asset quantity and optional evidence.",
    ),
    ("ledger::escrow::release", "Release a named escrow offer."),
    (
        "ledger::escrow::resolve_dispute",
        "Resolve an escrow dispute with buyer and seller quantities.",
    ),
    (
        "ledger::governance::build_submit_ballot",
        "Build an encoded governance ballot instruction from its proof fields.",
    ),
    (
        "ledger::governance::submit_ballot",
        "Submit the encoded governance ballot instruction.",
    ),
    (
        "ledger::governance::tally",
        "Read an encoded governance vote tally.",
    ),
    (
        "ledger::governance::verify_ballot",
        "Ask the host to verify an encoded governance ballot.",
    ),
    (
        "ledger::governance::verify_tally",
        "Ask the host to verify an encoded governance tally.",
    ),
    ("ledger::nft::burn", "Burn an NFT."),
    (
        "ledger::nft::create_for_all_users",
        "Request host creation of NFTs for all users.",
    ),
    ("ledger::nft::mint", "Mint an NFT for its owner."),
    (
        "ledger::nft::set_metadata",
        "Set one JSON metadata entry on an NFT.",
    ),
    ("ledger::nft::transfer", "Transfer an NFT between accounts."),
    (
        "ledger::peer::register",
        "Register a peer described by JSON.",
    ),
    (
        "ledger::peer::unregister",
        "Unregister a peer described by JSON.",
    ),
    (
        "ledger::permission::grant",
        "Grant a permission to an account.",
    ),
    (
        "ledger::permission::revoke",
        "Revoke a permission from an account.",
    ),
    (
        "ledger::query::account",
        "Query the optional projected view of an account.",
    ),
    (
        "ledger::query::accounts",
        "Query a bounded page of projected account views.",
    ),
    (
        "ledger::query::asset",
        "Query the optional projected view of an asset.",
    ),
    (
        "ledger::query::asset_definition",
        "Query the optional projected view of an asset definition.",
    ),
    (
        "ledger::query::asset_definitions",
        "Query a bounded page of projected asset definition views.",
    ),
    (
        "ledger::query::assets",
        "Query a bounded page of projected asset views.",
    ),
    (
        "ledger::query::assets_of",
        "Read a bounded asset page belonging to the exact account.",
    ),
    (
        "ledger::query::domain",
        "Query the optional projected view of a domain.",
    ),
    (
        "ledger::query::domains",
        "Query a bounded page of projected domain views.",
    ),
    (
        "ledger::query::nft",
        "Query the optional projected view of an NFT.",
    ),
    (
        "ledger::query::nfts",
        "Query a bounded page of projected NFT views.",
    ),
    (
        "ledger::query::parameter",
        "Query a named ledger parameter.",
    ),
    (
        "ledger::query::seiyaku_instance",
        "Query a named seiyaku instance.",
    ),
    (
        "ledger::query::seiyaku_manifest",
        "Query an encoded seiyaku manifest.",
    ),
    ("ledger::role::grant", "Grant a role to an account."),
    (
        "ledger::role::register",
        "Register a named role with a JSON permission set.",
    ),
    ("ledger::role::revoke", "Revoke a role from an account."),
    ("ledger::role::unregister", "Unregister a named role."),
    (
        "ledger::seiyaku::grant_permission",
        "Grant an account a declared instance permission for the authenticated executing seiyaku. Only the instance owner or an exact permission holder may delegate it.",
    ),
    (
        "ledger::seiyaku::revoke_permission",
        "Revoke an account's declared instance permission for the authenticated executing seiyaku.",
    ),
    (
        "ledger::subscription::bill",
        "Bill the active host-managed subscription.",
    ),
    (
        "ledger::subscription::record_usage",
        "Record usage for the active host-managed subscription.",
    ),
    (
        "ledger::trigger::register",
        "Register a trigger described by JSON.",
    ),
    (
        "ledger::trigger::set_enabled",
        "Change a named trigger's enabled state.",
    ),
    ("ledger::trigger::unregister", "Unregister a named trigger."),
    (
        "math::abs",
        "Return the absolute value, preserving its int, decimal, or quantity type.",
    ),
    (
        "math::div_ceil",
        "Divide integers with rounding toward positive infinity.",
    ),
    (
        "math::gcd",
        "Compute the greatest common divisor of two integers.",
    ),
    ("math::isqrt", "Compute the integer square root."),
    (
        "math::max",
        "Select the larger of two values with the same int, decimal, or quantity type.",
    ),
    ("math::mean", "Compute the integer mean of two integers."),
    (
        "math::min",
        "Select the smaller of two values with the same int, decimal, or quantity type.",
    ),
    (
        "math::wrapping_add",
        "Explicit modulo-2^512 `int` addition.",
    ),
    (
        "math::wrapping_mul",
        "Explicit modulo-2^512 `int` multiplication.",
    ),
    (
        "math::wrapping_neg",
        "Explicit modulo-2^512 `int` negation.",
    ),
    (
        "math::wrapping_sub",
        "Explicit modulo-2^512 `int` subtraction.",
    ),
    (
        "path",
        "Build a durable state path key through its receiver method.",
    ),
    (
        "remove",
        "Remove a durable state map entry and return its previous optional value.",
    ),
    (
        "require",
        "Reject contract execution with a typed error when a condition is false.",
    ),
    (
        "state::contains",
        "Check whether a durable state path exists.",
    ),
    ("state::count", "Count entries under a durable state path."),
    ("state::delete", "Delete the value at a durable state path."),
    ("state::get", "Read the byte value at a durable state path."),
    (
        "state::len",
        "Read the length reported by the durable state path syscall.",
    ),
    ("state::set", "Write a byte value at a durable state path."),
    ("string::as_bytes", "Expose the UTF-8 bytes of a string."),
    ("string::concat", "Concatenate two UTF-8 strings."),
    (
        "string::from",
        "Render a public scalar as its canonical string.",
    ),
    (
        "string::from_bytes",
        "Validate UTF-8 bytes and return an optional string.",
    ),
    ("string::len", "Return the UTF-8 byte length of a string."),
    (
        "test::actor_account",
        "Read a fixture actor's canonical account identity.",
    ),
    (
        "test::actor_public_key",
        "Read a fixture actor's public key bytes.",
    ),
    (
        "test::actor_sign",
        "Sign a payload with a fixture actor's test key.",
    ),
    (
        "test::advance_blocks",
        "Advance the block height seen by later seiyaku calls in a local test.",
    ),
    ("test::assert", "Assert a condition in a local test build."),
    (
        "test::assert_eq",
        "Assert that two values of one equality-comparable type are equal in a local test build.",
    ),
    (
        "test::expect_any_reject_as",
        "Require that invoking a target `kotoage`/`言挙げ` or `view fn` as a fixture actor rejects.",
    ),
    (
        "test::expect_reject_as",
        "Require that invoking a target `kotoage`/`言挙げ` or `view fn` as a fixture actor rejects with the expected error.",
    ),
    (
        "test::invoke_kotoage",
        "Invoke a target `kotoage`/`言挙げ` or `view fn` by its declared name from a test with an exact typed argument record, as the current caller.",
    ),
    (
        "test::invoke_kotoage_as",
        "Invoke a target `kotoage`/`言挙げ` or `view fn` by its declared name from a test with an exact typed argument record, as a fixture actor.",
    ),
    (
        "test::set_block_height",
        "Set the block height seen by later seiyaku calls in a local test.",
    ),
    (
        "test::set_transaction_time_ms",
        "Set the transaction time (milliseconds) seen by later seiyaku calls in a local test.",
    ),
];

/// Return the summary for a source-visible builtin by its canonical source path.
#[must_use]
pub fn builtin_doc(path: &str) -> Option<&'static str> {
    BUILTIN_DOCS
        .binary_search_by(|(key, _)| (*key).cmp(path))
        .ok()
        .map(|index| BUILTIN_DOCS[index].1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtins::{Builtin, BuiltinSurface};
    use std::collections::BTreeSet;

    fn source_visible_paths() -> BTreeSet<&'static str> {
        Builtin::registry()
            .filter(|(_, spec)| spec.surface != BuiltinSurface::CompilerInternal)
            .map(|(_, spec)| spec.name)
            .collect()
    }

    #[test]
    fn every_documented_path_names_a_source_visible_builtin() {
        let registry = source_visible_paths();
        for (path, summary) in BUILTIN_DOCS {
            assert!(
                registry.contains(path),
                "builtin_docs documents `{path}`, which is not a source-visible builtin"
            );
            assert!(
                !summary.trim().is_empty() && summary.ends_with('.'),
                "builtin_docs summary for `{path}` must be one complete sentence"
            );
        }
    }

    #[test]
    fn every_source_visible_builtin_has_exactly_one_summary() {
        let documented = BUILTIN_DOCS
            .iter()
            .map(|(path, _)| *path)
            .collect::<Vec<_>>();
        assert!(
            documented.windows(2).all(|pair| pair[0] < pair[1]),
            "builtin_docs must stay strictly sorted for binary search"
        );
        let missing = source_visible_paths()
            .into_iter()
            .filter(|path| builtin_doc(path).is_none())
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "source-visible builtins without a summary: {missing:?}"
        );
    }

    #[test]
    fn lookup_uses_exact_source_paths() {
        assert!(
            builtin_doc("ledger::asset::transfer")
                .is_some_and(|summary| summary.starts_with("Transfer an asset quantity"))
        );
        assert!(builtin_doc("get_or_insert").is_some());
        assert_eq!(
            builtin_doc("bytes::concat"),
            Some("Concatenate two byte values.")
        );
        assert_eq!(
            builtin_doc("string::as_bytes"),
            Some("Expose the UTF-8 bytes of a string.")
        );
        assert_eq!(builtin_doc("ledger::asset"), None);
        assert_eq!(builtin_doc("transfer"), None);
    }
}
