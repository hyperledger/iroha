//! Grouped IVM integration tests.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#[path = "../vm_aes_wide.rs"]
mod vm_aes_wide;
#[path = "../vrf_verify_batch_syscall.rs"]
mod vrf_verify_batch_syscall;
#[path = "../vrf_verify_chain.rs"]
mod vrf_verify_chain;
#[path = "../vrf_verify_envelope.rs"]
mod vrf_verify_envelope;
#[path = "../vrf_verify_syscall.rs"]
mod vrf_verify_syscall;
#[path = "../wide_memory128.rs"]
mod wide_memory128;
#[path = "../wsv_host.rs"]
mod wsv_host;
#[path = "../wsv_host_account_admin.rs"]
mod wsv_host_account_admin;
#[path = "../wsv_host_admin_tlv.rs"]
mod wsv_host_admin_tlv;
#[path = "../wsv_host_decode_syscalls.rs"]
mod wsv_host_decode_syscalls;
#[path = "../wsv_host_grant_revoke_tlv.rs"]
mod wsv_host_grant_revoke_tlv;
#[path = "../wsv_host_input_publish_tlv.rs"]
mod wsv_host_input_publish_tlv;
#[path = "../wsv_host_nft_tlv.rs"]
mod wsv_host_nft_tlv;
#[path = "../wsv_host_nft_unregister_positive.rs"]
mod wsv_host_nft_unregister_positive;
#[path = "../wsv_host_pointer_tlv.rs"]
mod wsv_host_pointer_tlv;
#[path = "../wsv_host_query_boundary.rs"]
mod wsv_host_query_boundary;
#[path = "../wsv_host_register_account_asset_tlv.rs"]
mod wsv_host_register_account_asset_tlv;
#[path = "../wsv_host_register_domain_tlv.rs"]
mod wsv_host_register_domain_tlv;
#[path = "../wsv_host_role_admin_neg.rs"]
mod wsv_host_role_admin_neg;
#[path = "../wsv_host_role_admin_tlv.rs"]
mod wsv_host_role_admin_tlv;
#[path = "../wsv_host_role_vs_direct_perm.rs"]
mod wsv_host_role_vs_direct_perm;
#[path = "../wsv_host_roles_triggers_envelope.rs"]
mod wsv_host_roles_triggers_envelope;
#[path = "../wsv_host_state_syscalls.rs"]
mod wsv_host_state_syscalls;
#[path = "../wsv_host_unregister_neg_cases.rs"]
mod wsv_host_unregister_neg_cases;
#[path = "../wsv_host_unregister_tlv.rs"]
mod wsv_host_unregister_tlv;
#[path = "../wsv_host_zk_perm_and_events.rs"]
mod wsv_host_zk_perm_and_events;
#[path = "../wsv_state_overlay.rs"]
mod wsv_state_overlay;
#[path = "../zk_gating.rs"]
mod zk_gating;
#[path = "../zk_verify_limits.rs"]
mod zk_verify_limits;
