//! Grouped Iroha crypto integration tests.
#[path = "../bls_batch.rs"]
mod bls_batch;
#[path = "../bls_keys_match.rs"]
mod bls_keys_match;
#[path = "../check_pop.rs"]
mod check_pop;
#[path = "../confidential_discard_zeroize.rs"]
mod confidential_discard_zeroize;
#[path = "../confidential_keyset_vectors.rs"]
mod confidential_keyset_vectors;
#[path = "../confidential_vectors.rs"]
mod confidential_vectors;
#[path = "../ed25519_aggregate.rs"]
mod ed25519_aggregate;
#[path = "../gost_wycheproof.rs"]
mod gost_wycheproof;
#[path = "../jurisdiction_merkle_golden.rs"]
mod jurisdiction_merkle_golden;
#[path = "../keypair_from_private.rs"]
mod keypair_from_private;
#[path = "../merkle_domain_vectors.rs"]
mod merkle_domain_vectors;
#[path = "../merkle_norito_roundtrip.rs"]
mod merkle_norito_roundtrip;
#[path = "../merkle_shielded_golden.rs"]
mod merkle_shielded_golden;
#[path = "../merkle_shielded_vectors.rs"]
mod merkle_shielded_vectors;
#[path = "../mldsa_keypair.rs"]
mod mldsa_keypair;
#[path = "../mldsa_multihash.rs"]
mod mldsa_multihash;
#[path = "../mldsa_private_key.rs"]
mod mldsa_private_key;
#[path = "../packed_signature_alignment.rs"]
mod packed_signature_alignment;
#[path = "../pqc_batch.rs"]
mod pqc_batch;
#[path = "../session_key_zeroize.rs"]
mod session_key_zeroize;
#[path = "../signature_layout.rs"]
mod signature_layout;
#[path = "../sm2_annex_d_example.rs"]
mod sm2_annex_d_example;
#[path = "../sm2_fixture_vectors.rs"]
mod sm2_fixture_vectors;
#[path = "../sm2_fuzz.rs"]
mod sm2_fuzz;
#[path = "../sm2_keypair.rs"]
mod sm2_keypair;
#[path = "../sm2_negative_vector_fixture.rs"]
mod sm2_negative_vector_fixture;
#[path = "../sm2_negative_vectors.rs"]
mod sm2_negative_vectors;
#[path = "../sm2_openssl_parity.rs"]
mod sm2_openssl_parity;
#[path = "../sm2_wycheproof.rs"]
mod sm2_wycheproof;
#[path = "../sm3_sm4_vectors.rs"]
mod sm3_sm4_vectors;
#[path = "../sm4_fuzz.rs"]
mod sm4_fuzz;
#[cfg(feature = "sm")]
#[path = "../sm4_wycheproof_fixture.rs"]
mod sm4_wycheproof_fixture;
#[path = "../sm_cli_matrix.rs"]
mod sm_cli_matrix;
#[path = "../sm_openssl_smoke.rs"]
mod sm_openssl_smoke;
#[path = "../streaming_handshake.rs"]
mod streaming_handshake;

#[path = "../schema_identity.rs"]
mod schema_identity;

#[path = "../merkle_schema_identity.rs"]
mod merkle_schema_identity;

#[path = "../key_wire_schema_identity.rs"]
mod key_wire_schema_identity;
