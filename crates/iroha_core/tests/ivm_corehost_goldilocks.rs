//! Core host rejection of polynomial-opening payloads and registered IPA curve policy.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
mod goldilocks {
    use iroha_core::smartcontracts::ivm::host::CoreHost;
    use iroha_data_model::prelude::AccountId;
    use iroha_test_samples::ALICE_ID;
    use ivm::{IVMHost, syscalls as ivm_sys};
    use std::{convert::TryFrom, sync::Arc};
    fn make_goldilocks_envelope() -> iroha_zkp_halo2::OpenVerifyEnvelope {
        use iroha_zkp_halo2::{
            Params, Polynomial, PrimeField64, Transcript, ZkCurveId,
            backend::pallas::PallasBackend, norito_helpers as nh,
        };
        let params = Params::new(8).expect("params");
        let coeffs: Vec<PrimeField64> = (0u64..8).map(|i| PrimeField64::from(i + 1)).collect();
        let poly = Polynomial::from_coeffs(coeffs);
        let label = ivm::host::LABEL_VOTE_BALLOT;
        let mut tr = Transcript::new(label);
        let p_g = poly.commit(&params).expect("commit");
        let z = PrimeField64::from(4u64);
        let (proof, t) = poly.open(&params, &mut tr, z, p_g).expect("open");
        let mut envelope = iroha_zkp_halo2::OpenVerifyEnvelope {
            params: nh::params_to_wire(&params),
            public: nh::poly_open_public::<PallasBackend>(params.n(), z, t, p_g),
            proof: nh::proof_to_wire(&proof),
            transcript_label: label.to_string(),
            vk_commitment: None,
            public_inputs_schema_hash: None,
            domain_tag: None,
        };
        // The unsupported field identity must be rejected before group decoding.
        envelope.params.curve_id = ZkCurveId::Goldilocks.as_u16();
        envelope.public.curve_id = ZkCurveId::Goldilocks.as_u16();
        envelope
    }
    fn envelope_tlv(payload: &[u8]) -> Vec<u8> {
        let mut tlv = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
        tlv.extend_from_slice(&u16::to_be_bytes(ivm::PointerType::NoritoBytes as u16));
        tlv.push(1);
        let payload_len = u32::try_from(payload.len()).expect("payload length fits in u32");
        tlv.extend_from_slice(&payload_len.to_be_bytes());
        tlv.extend_from_slice(payload);
        let hash: [u8; 32] = iroha_crypto::Hash::new(payload).into();
        tlv.extend_from_slice(&hash);
        tlv
    }
    #[test]
    fn core_host_rejects_non_binding_goldilocks_commitments() {
        let env = make_goldilocks_envelope();
        let raw = norito::to_bytes(&env).expect("encode Goldilocks envelope");
        assert!(matches!(
            ivm::zk_verify::verify_open_envelope(&raw),
            Err(iroha_zkp_halo2::Error::UnsupportedBackend {
                backend: iroha_zkp_halo2::ZkCurveId::Goldilocks
            })
        ));
        let tlv = envelope_tlv(&raw);
        for native_enabled in [true, false] {
            let authority: AccountId = ALICE_ID.clone();
            let mut host = CoreHost::with_accounts(authority.clone(), Arc::new(vec![authority]));
            let mut cfg = iroha_core::state::default_zk_config();
            cfg.pipa_r.enabled = native_enabled;
            host.set_zk_config(&cfg);
            let mut vm = ivm::IVM::new(1_000_000);
            let ptr = vm.alloc_input_tlv(&tlv).expect("alloc tlv");
            vm.set_register(10, ptr);
            let gas = host
                .syscall(ivm_sys::SYSCALL_ZK_VOTE_VERIFY_BALLOT, &mut vm)
                .expect("syscall ok");
            assert!(gas > 0);
            assert_eq!(vm.register(10), 0);
            // Production accepts only the registry-bound data-model envelope;
            // a polynomial opening cannot reach curve policy or arm a ballot latch.
            assert_eq!(vm.register(11), ivm::host::ERR_DECODE);
        }
    }
    #[test]
    fn core_host_rejects_retired_ivm_ipa_registry_key() {
        use iroha_core_zk as zk;
        use iroha_data_model::{
            proof::{VerifyingKeyBox, VerifyingKeyId, VerifyingKeyRecord},
            zk::BackendTag,
        };
        use std::collections::BTreeMap;

        let authority: AccountId = ALICE_ID.clone();
        let mut host = CoreHost::with_accounts(authority.clone(), Arc::new(vec![authority]));
        let id = VerifyingKeyId::new("halo2/ipa", "curve_policy");
        let key = VerifyingKeyBox::new("halo2/ipa".into(), vec![0x11; 3]);
        let mut record = VerifyingKeyRecord::new_with_owner(
            1,
            "ivm-execution-v1",
            None,
            "test",
            BackendTag::NativePipaRPasta,
            "pallas",
            iroha_crypto::Hash::new(b"retired-ivm-schema").into(),
            zk::hash_vk(&key),
        );
        record.vk_len = u32::try_from(key.bytes.len()).expect("bounded fixture key");
        record.key = Some(key);
        assert_eq!(
            host.set_verifying_keys(BTreeMap::from([(id, record)])),
            Err(ivm::VMError::NoritoInvalid),
            "retired IVM binding circuit cannot enter the production verifier registry"
        );
    }
}
