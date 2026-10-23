//! Real N=16 native proof controls for the bounded custody/relation component.
//! The IVM bytes below establish only signed schema context, not an executed VM.

use super::*;
use crate::{
    executor::attachment_custody::AttachmentCustody,
    privacy_engines::{
        anonymous_pgc::{
            TwistedElGamalKeyPairV1,
            bootstrap::{AnonymousPgcBootstrapWitnessV1, prove_bootstrap},
            encrypt_with_randomness,
        },
        p256::SecretScalarV1,
    },
    privacy_profiles::compiled_privacy_profile_v1,
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    Level,
    account::AccountId,
    block::BlockHeader,
    isi::{InstructionBox, Log, instruction_wire_id},
    privacy::{
        PrivacyActiveLifecycleV1, PrivacyNamespaceScopeV1, PrivacyNamespaceV1,
        PrivacyP256CiphertextV1, PrivacyP256PointV1, PrivacyPgcAccountV1,
        PrivacyPgcBootstrapProofBytesV1, PrivacyPoolIdV1, PrivacyPoolNamespaceV1,
        PrivacyProtocolLifecycleV1, PrivacyRootV1, PrivacyVerifierDigestV1,
    },
    transaction::{
        Executable, FeePaymentIntent, SignedTransaction, TransactionBuilder,
        executable::IvmBytecode,
        signed_attachments::{
            ActionAuthorityBindingV1, ActionInvocationBindingV1, PlannedActionV1,
            PlannedAttachmentV1, SignedAttachmentPlanV1,
        },
    },
};
use rand_core_06::{CryptoRng, Error as RngError, RngCore};
use sha2::{Digest, Sha256};
use std::{num::NonZeroU32, sync::OnceLock, time::Duration};

struct KatRng(u64);
impl RngCore for KatRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, output: &mut [u8]) {
        for chunk in output.chunks_mut(32) {
            let mut hash = Sha256::new();
            hash.update(b"iroha.i3.pgc-bootstrap.custody.test.v1");
            hash.update(self.0.to_le_bytes());
            self.0 = self.0.checked_add(1).unwrap();
            chunk.copy_from_slice(&hash.finalize()[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(output);
        Ok(())
    }
}
impl CryptoRng for KatRng {}
fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}
fn actor(seed: u8) -> AccountId {
    AccountId::new(key(seed).public_key().clone())
}
fn secret(value: u64) -> SecretScalarV1 {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    SecretScalarV1::from_bytes(bytes).unwrap()
}
fn operation() -> ActionOperationV1 {
    ActionOperationV1::NativeInstruction(BootstrapPrivacyPgcAccountsV1::WIRE_ID.to_owned())
}
fn planned(bootstrap: &PrivacyPgcAccountBootstrapV1, proof: Vec<u8>) -> PlannedActionV1 {
    PlannedActionV1 {
        operation: operation(),
        role: ActionRoleV1::Administrative,
        authority: ActionAuthorityBindingV1::ContractSubject(actor(2)),
        invocation: ActionInvocationBindingV1::Contract {
            root_index: 0,
            call_path: vec![],
        },
        public_inputs_digest: public_inputs_digest(bootstrap).unwrap(),
        attachments: vec![PlannedAttachmentV1 {
            kind: AttachmentKindV1::Proof,
            role: AttachmentRoleV1::ActionProof,
            bytes: proof,
        }],
    }
}
fn draft(network: NetworkId, actions: Vec<PlannedActionV1>) -> TransactionBuilder {
    let mut plan = SignedAttachmentPlanV1::new();
    for action in actions {
        plan.push_action(action);
    }
    let mut builder =
        TransactionBuilder::new(network, actor(1), FeePaymentIntent::authority(vec![], None))
            .with_executable(Executable::Ivm(IvmBytecode::from_compiled(vec![1, 2])))
            .with_signed_attachments(plan.declare());
    builder.set_creation_time(Duration::from_millis(1234));
    builder.set_nonce(NonZeroU32::new(1).unwrap());
    builder
}
fn sign_with_proof(
    builder: TransactionBuilder,
    occurrence: u32,
    proof: Vec<u8>,
) -> SignedTransaction {
    let mut attachments = builder.payload().attachments.clone().unwrap();
    attachments.set_occurrence_bytes(occurrence, proof).unwrap();
    builder
        .with_signed_attachments(attachments)
        .sign(key(1).private_key())
}
fn open<'owner, 'tx>(
    frame: &mut Invocation<'owner, 'tx>,
    tx: &SignedTransaction,
    index: u32,
) -> Result<AttachmentHandle<'owner, 'tx>, CustodyError> {
    let action = tx.attachments().unwrap().action(index).unwrap();
    frame.open(
        ActionRequest {
            index,
            operation: &action.operation,
            role: action.role,
            public_inputs_digest: action.public_inputs_digest,
        },
        0,
        AttachmentKindV1::Proof,
        AttachmentRoleV1::ActionProof,
    )
}
struct Fixture {
    bootstrap: PrivacyPgcAccountBootstrapV1,
    public_keys: Vec<TwistedElGamalPublicKeyV1>,
    balances: Vec<TwistedElGamalCiphertextV1>,
    plaintexts: Vec<u32>,
    randomness: Vec<SecretScalarV1>,
    activation: PrivacyProtocolActivationRecordV1,
    network: NetworkId,
    tx: SignedTransaction,
    old_context_proof: Vec<u8>,
}
impl Fixture {
    fn context(&self) -> BootstrapContext<'_> {
        BootstrapContext {
            network_id: &self.network,
            genesis_hash: *self.network.as_bytes(),
            activation: &self.activation,
        }
    }
    fn prove(&self, statement_digest: [u8; 32], index: u32) -> Vec<u8> {
        let namespace = norito::encode_canonical(&self.bootstrap.namespace).unwrap();
        let parameters = AnonymousPgcParametersV1::get().unwrap();
        let native = AnonymousPgcBootstrapStatementV1::new(
            &namespace,
            *self.bootstrap.initial_root.as_bytes(),
            1,
            self.bootstrap.total_supply,
            &self.public_keys,
            &self.balances,
            TranscriptBindingV1 {
                network_id: self.network.as_bytes(),
                genesis_hash: *self.network.as_bytes(),
                action_index: index,
                statement_digest,
                parameter_id: *self.activation.parameter_id.as_bytes(),
                parameter_digest: *self.activation.parameter_digest.as_bytes(),
                verifier_digest: *self.activation.verifier_digest.as_bytes(),
                statement_schema_digest: *self.activation.statement_schema_digest.as_bytes(),
                engine_manifest_digest: *self.activation.engine_manifest_digest.as_bytes(),
                generator_digest: parameters.generator_digest(),
            },
        )
        .unwrap();
        prove_bootstrap(
            &native,
            &AnonymousPgcBootstrapWitnessV1 {
                balances: &self.plaintexts,
                randomness: &self.randomness,
            },
            &mut KatRng(0),
        )
        .unwrap()
        .encode()
    }
}
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::new(b"i3-native-pgc"),
        ));
        let namespace = PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
                pool_id: PrivacyPoolIdV1::new([0x43; 32]),
            }),
        );
        let mut pairs = (2..18)
            .map(|v| TwistedElGamalKeyPairV1::from_secret(secret(v)).unwrap())
            .collect::<Vec<_>>();
        pairs.sort_by_key(TwistedElGamalKeyPairV1::public_key);
        let public_keys = pairs
            .iter()
            .map(TwistedElGamalKeyPairV1::public_key)
            .collect::<Vec<_>>();
        let plaintexts = vec![100; 16];
        let randomness = (100..116).map(secret).collect::<Vec<_>>();
        let balances = public_keys
            .iter()
            .zip(&randomness)
            .map(|(key, r)| encrypt_with_randomness(*key, 100, r).unwrap())
            .collect::<Vec<_>>();
        let accounts = public_keys
            .iter()
            .zip(&balances)
            .map(|(key, value)| PrivacyPgcAccountV1 {
                public_key: PrivacyP256PointV1::new(*key.as_point().as_bytes()),
                encrypted_balance: PrivacyP256CiphertextV1 {
                    left: PrivacyP256PointV1::new(*value.left().as_bytes()),
                    right: PrivacyP256PointV1::new(*value.right().as_bytes()),
                },
            })
            .collect::<Vec<_>>();
        let bootstrap = PrivacyPgcAccountBootstrapV1 {
            namespace,
            initial_root: derive_privacy_pgc_account_state_root_v1(namespace, 1, 1600, &accounts)
                .unwrap(),
            initial_epoch: 1,
            total_supply: 1600,
            accounts,
        };
        let activation = compiled_privacy_profile_v1(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
            .unwrap()
            .activation_record(PrivacyProtocolLifecycleV1::Active(
                PrivacyActiveLifecycleV1 {
                    proposed_at_height: 1,
                    activated_at_height: 1,
                    state_since_height: 1,
                },
            ));
        // A temporary attachment-free signed owner is only an initialization
        // value; the final fixture below is a real, fully signed N=16 proof.
        let temporary =
            TransactionBuilder::new(network, actor(1), FeePaymentIntent::authority(vec![], None))
                .with_bytecode(IvmBytecode::from_compiled(vec![1, 2]))
                .sign(key(1).private_key());
        let mut fixture = Fixture {
            bootstrap,
            public_keys,
            balances,
            plaintexts,
            randomness,
            activation,
            network,
            tx: temporary,
            old_context_proof: vec![],
        };
        let builder = draft(network, vec![planned(&fixture.bootstrap, vec![])]);
        let digest = builder.payload().action_statement_digests_v1().unwrap()[0];
        let proof = fixture.prove(*digest.as_bytes(), 0);
        fixture.tx = sign_with_proof(builder, 0, proof);
        fixture.old_context_proof =
            fixture.prove(*fixture.bootstrap.digest().unwrap().as_bytes(), 0);
        fixture
    })
}
fn consume(
    tx: &SignedTransaction,
    bootstrap: &PrivacyPgcAccountBootstrapV1,
    context: BootstrapContext<'_>,
) -> Result<(), BootstrapError> {
    let mut custody = AttachmentCustody::new(tx)?;
    custody.contract(0, &actor(2), |frame| {
        let handle = open(frame, tx, 0)?;
        frame
            .consume_pgc_bootstrap(0, bootstrap, handle, context)
            .map(|_| ())
    })?;
    custody.finish()?;
    Ok(())
}
fn original_proof() -> Vec<u8> {
    fixture()
        .tx
        .attachments()
        .unwrap()
        .occurrence(0)
        .unwrap()
        .bytes
        .clone()
}

#[test]
fn real_n16_original_signed_proof_consumes_once_without_source_copy_or_mutation() {
    let f = fixture();
    let bytes = &f.tx.attachments().unwrap().occurrence(0).unwrap().bytes;
    let before = norito::encode_canonical(&f.tx).unwrap();
    let mut pointer_control = AttachmentCustody::new(&f.tx).unwrap();
    pointer_control
        .contract(0, &actor(2), |frame| {
            let handle = open(frame, &f.tx, 0)?;
            let operation = operation();
            let request = ActionRequest {
                index: 0,
                operation: &operation,
                role: ActionRoleV1::Administrative,
                public_inputs_digest: public_inputs_digest(&f.bootstrap).unwrap(),
            };
            let borrowed = frame.consume(
                request,
                handle,
                AttachmentKindV1::Proof,
                AttachmentRoleV1::ActionProof,
            )?;
            assert_eq!(borrowed.as_ptr(), bytes.as_ptr());
            assert_eq!(borrowed, bytes.as_slice());
            frame.finish_action(request)
        })
        .unwrap();
    pointer_control.finish().unwrap();
    consume(&f.tx, &f.bootstrap, f.context()).unwrap();
    assert_eq!(norito::encode_canonical(&f.tx).unwrap(), before);
    assert!(!crate::tx::attachment_operation_is_supported(&operation()));
}

#[test]
fn old_bootstrap_only_transcript_is_not_an_ordered_action_proof() {
    let f = fixture();
    let tx = draft(
        f.network,
        vec![planned(&f.bootstrap, f.old_context_proof.clone())],
    )
    .sign(key(1).private_key());
    assert!(matches!(
        consume(&tx, &f.bootstrap, f.context()),
        Err(BootstrapError::NativeRead(AnonymousPgcReadError::Relation(
            _
        )))
    ));
}

#[test]
fn nonce_and_signed_authority_mutations_require_fresh_native_proofs() {
    let f = fixture();
    let mut changed = TransactionBuilder::from_payload(f.tx.payload().clone()).unwrap();
    changed.set_nonce(NonZeroU32::new(2).unwrap());
    let changed = changed.sign(key(1).private_key());
    assert!(matches!(
        consume(&changed, &f.bootstrap, f.context()),
        Err(BootstrapError::NativeRead(AnonymousPgcReadError::Relation(
            _
        )))
    ));
    let mut action = planned(&f.bootstrap, original_proof());
    action.authority = ActionAuthorityBindingV1::ContractSubject(actor(3));
    let tx = draft(f.network, vec![action]).sign(key(1).private_key());
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result: Result<(), BootstrapError> = custody.contract(0, &actor(3), |frame| {
        let handle = open(frame, &tx, 0)?;
        frame
            .consume_pgc_bootstrap(0, &f.bootstrap, handle, f.context())
            .map(|_| ())
    });
    assert!(matches!(
        result,
        Err(BootstrapError::NativeRead(AnonymousPgcReadError::Relation(
            _
        )))
    ));
}

#[test]
fn actual_wrong_actor_and_rebound_child_path_are_refused() {
    let f = fixture();
    let mut custody = AttachmentCustody::new(&f.tx).unwrap();
    let result: Result<(), BootstrapError> = custody.contract(0, &actor(3), |frame| {
        let handle = open(frame, &f.tx, 0)?;
        frame
            .consume_pgc_bootstrap(0, &f.bootstrap, handle, f.context())
            .map(|_| ())
    });
    assert!(matches!(
        result,
        Err(BootstrapError::Custody(CustodyError::WrongAuthority(0)))
    ));
    let mut action = planned(&f.bootstrap, original_proof());
    action.invocation = ActionInvocationBindingV1::Contract {
        root_index: 0,
        call_path: vec![0],
    };
    let tx = draft(f.network, vec![action]).sign(key(1).private_key());
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result: Result<(), BootstrapError> = custody.contract(0, &actor(2), |frame| {
        frame.child(&actor(2), |child| {
            let handle = open(child, &tx, 0)?;
            child
                .consume_pgc_bootstrap(0, &f.bootstrap, handle, f.context())
                .map(|_| ())
        })
    });
    assert!(matches!(
        result,
        Err(BootstrapError::NativeRead(AnonymousPgcReadError::Relation(
            _
        )))
    ));
}

#[test]
fn reordered_action_ordinal_rejects_a_rebound_old_proof() {
    let f = fixture();
    let instruction: InstructionBox = Log::new(Level::INFO, "preceding".to_owned()).into();
    let noop = PlannedActionV1 {
        operation: ActionOperationV1::NativeInstruction(
            instruction_wire_id(&instruction).unwrap().to_owned(),
        ),
        role: ActionRoleV1::Effect,
        authority: ActionAuthorityBindingV1::ContractSubject(actor(2)),
        invocation: ActionInvocationBindingV1::Contract {
            root_index: 0,
            call_path: vec![],
        },
        public_inputs_digest: ActionPublicInputsDigestV1::new([0x56; 32]),
        attachments: vec![],
    };
    let tx = draft(
        f.network,
        vec![noop, planned(&f.bootstrap, original_proof())],
    )
    .sign(key(1).private_key());
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result: Result<(), BootstrapError> = custody.contract(0, &actor(2), |frame| {
        let handle = open(frame, &tx, 1)?;
        frame
            .consume_pgc_bootstrap(1, &f.bootstrap, handle, f.context())
            .map(|_| ())
    });
    assert!(matches!(
        result,
        Err(BootstrapError::NativeRead(AnonymousPgcReadError::Relation(
            _
        )))
    ));
}

#[test]
fn changed_public_table_supply_root_and_request_digest_are_refused() {
    let f = fixture();
    let mut changed = f.bootstrap.clone();
    changed.total_supply += 1;
    assert!(matches!(
        consume(&f.tx, &changed, f.context()),
        Err(BootstrapError::Custody(CustodyError::WrongAction(0)))
    ));
    let tx = draft(f.network, vec![planned(&changed, original_proof())]).sign(key(1).private_key());
    assert!(matches!(
        consume(&tx, &changed, f.context()),
        Err(BootstrapError::RootMismatch)
    ));
    changed.initial_root = derive_privacy_pgc_account_state_root_v1(
        changed.namespace,
        1,
        changed.total_supply,
        &changed.accounts,
    )
    .unwrap();
    let tx = draft(f.network, vec![planned(&changed, original_proof())]).sign(key(1).private_key());
    assert!(matches!(
        consume(&tx, &changed, f.context()),
        Err(BootstrapError::NativeRead(AnonymousPgcReadError::Relation(
            _
        )))
    ));
    let mut changed = f.bootstrap.clone();
    changed.accounts[0].encrypted_balance = changed.accounts[1].encrypted_balance;
    changed.initial_root = derive_privacy_pgc_account_state_root_v1(
        changed.namespace,
        1,
        changed.total_supply,
        &changed.accounts,
    )
    .unwrap();
    let tx = draft(f.network, vec![planned(&changed, original_proof())]).sign(key(1).private_key());
    assert!(matches!(
        consume(&tx, &changed, f.context()),
        Err(BootstrapError::NativeRead(AnonymousPgcReadError::Relation(
            _
        )))
    ));
    let mut changed = f.bootstrap.clone();
    changed.initial_root = PrivacyRootV1::new([0x77; 32]);
    let tx = draft(f.network, vec![planned(&changed, original_proof())]).sign(key(1).private_key());
    assert!(matches!(
        consume(&tx, &changed, f.context()),
        Err(BootstrapError::RootMismatch)
    ));
}

#[test]
fn trusted_network_genesis_and_profile_cannot_be_replaced() {
    let f = fixture();
    let other = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::new(b"other-network"),
    ));
    assert!(matches!(
        consume(
            &f.tx,
            &f.bootstrap,
            BootstrapContext {
                network_id: &other,
                genesis_hash: *other.as_bytes(),
                ..f.context()
            }
        ),
        Err(BootstrapError::NetworkMismatch)
    ));
    let mut context = f.context();
    context.genesis_hash[0] ^= 1;
    assert!(matches!(
        consume(&f.tx, &f.bootstrap, context),
        Err(BootstrapError::NetworkMismatch)
    ));
    let mut activation = f.activation;
    activation.verifier_digest = PrivacyVerifierDigestV1::new([0x71; 32]);
    assert!(matches!(
        consume(
            &f.tx,
            &f.bootstrap,
            BootstrapContext {
                activation: &activation,
                ..f.context()
            }
        ),
        Err(BootstrapError::Profile(
            CompiledPrivacyProfileValidationErrorV1::VerifierDigestMismatch
        ))
    ));
    let mut activation = f.activation;
    activation.protocol_id = PrivacyProtocolIdV1::ZkAcePqAuthorizationV1;
    assert!(matches!(
        consume(
            &f.tx,
            &f.bootstrap,
            BootstrapContext {
                activation: &activation,
                ..f.context()
            }
        ),
        Err(BootstrapError::WrongProtocol)
    ));
}

#[test]
fn canonical_proof_truncation_and_trailing_bytes_are_native_refusals() {
    let f = fixture();
    for proof in [original_proof()[..original_proof().len() - 1].to_vec(), {
        let mut bytes = original_proof();
        bytes.push(0);
        bytes
    }] {
        let tx = draft(f.network, vec![planned(&f.bootstrap, proof)]).sign(key(1).private_key());
        assert!(matches!(
            consume(&tx, &f.bootstrap, f.context()),
            Err(BootstrapError::NativeRead(AnonymousPgcReadError::Codec(ref original))) if original.local_refusal().is_none()
        ));
    }
}

#[test]
fn wrong_role_operation_and_extra_slot_do_not_become_native_authority() {
    let f = fixture();
    let mut action = planned(&f.bootstrap, original_proof());
    action.role = ActionRoleV1::ProofEffect;
    let tx = draft(f.network, vec![action]).sign(key(1).private_key());
    assert!(matches!(
        consume(&tx, &f.bootstrap, f.context()),
        Err(BootstrapError::Custody(CustodyError::WrongAction(0)))
    ));
    let mut action = planned(&f.bootstrap, original_proof());
    let instruction: InstructionBox = Log::new(Level::INFO, "other".to_owned()).into();
    action.operation =
        ActionOperationV1::NativeInstruction(instruction_wire_id(&instruction).unwrap().to_owned());
    let tx = draft(f.network, vec![action]).sign(key(1).private_key());
    assert!(matches!(
        consume(&tx, &f.bootstrap, f.context()),
        Err(BootstrapError::Custody(CustodyError::WrongAction(0)))
    ));
    let mut action = planned(&f.bootstrap, original_proof());
    action.attachments.push(PlannedAttachmentV1 {
        kind: AttachmentKindV1::KeyMaterial,
        role: AttachmentRoleV1::VerifyingKey,
        bytes: vec![7; 32],
    });
    let tx = draft(f.network, vec![action]).sign(key(1).private_key());
    assert!(matches!(
        consume(&tx, &f.bootstrap, f.context()),
        Err(BootstrapError::AttachmentShape)
    ));
}

#[test]
fn swallowed_native_refusal_poisons_all_custody_bookkeeping() {
    let f = fixture();
    let tx = draft(
        f.network,
        vec![planned(&f.bootstrap, f.old_context_proof.clone())],
    )
    .sign(key(1).private_key());
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result: Result<(), BootstrapError> = custody.contract(0, &actor(2), |frame| {
        let handle = open(frame, &tx, 0)?;
        assert!(matches!(
            frame
                .consume_pgc_bootstrap(0, &f.bootstrap, handle, f.context())
                .map(|_| ()),
            Err(BootstrapError::NativeRead(AnonymousPgcReadError::Relation(
                _
            )))
        ));
        assert!(matches!(
            frame
                .consume_pgc_bootstrap(0, &f.bootstrap, handle, f.context())
                .map(|_| ()),
            Err(BootstrapError::Custody(CustodyError::FailedAttempt))
        ));
        assert_eq!(
            (
                frame.attempt.issued,
                frame.attempt.consumed,
                frame.attempt.completed
            ),
            (0, 0, 0)
        );
        Ok(())
    });
    assert!(matches!(
        result,
        Err(BootstrapError::Custody(CustodyError::FailedAttempt))
    ));
}

#[test]
fn later_native_failure_discards_prior_real_verified_consumption() {
    let f = fixture();
    let builder = draft(
        f.network,
        vec![
            planned(&f.bootstrap, vec![]),
            planned(&f.bootstrap, original_proof()),
        ],
    );
    let digest = builder.payload().action_statement_digests_v1().unwrap()[0];
    let proof = f.prove(*digest.as_bytes(), 0);
    let tx = sign_with_proof(builder, 0, proof);
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result: Result<(), BootstrapError> = custody.contract(0, &actor(2), |frame| {
        let first = open(frame, &tx, 0)?;
        frame
            .consume_pgc_bootstrap(0, &f.bootstrap, first, f.context())
            .map(|_| ())?;
        assert_eq!(frame.attempt.completed, 1);
        let second = open(frame, &tx, 1)?;
        let failure = frame
            .consume_pgc_bootstrap(1, &f.bootstrap, second, f.context())
            .map(|_| ());
        assert!(matches!(
            failure,
            Err(BootstrapError::NativeRead(AnonymousPgcReadError::Relation(
                _
            )))
        ));
        assert_eq!(
            (
                frame.attempt.issued,
                frame.attempt.consumed,
                frame.attempt.completed
            ),
            (0, 0, 0)
        );
        failure
    });
    assert!(matches!(
        result,
        Err(BootstrapError::NativeRead(AnonymousPgcReadError::Relation(
            _
        )))
    ));
    assert!(matches!(custody.finish(), Err(CustodyError::FailedAttempt)));
}

#[test]
fn same_real_proof_cannot_complete_an_action_twice() {
    let f = fixture();
    let mut custody = AttachmentCustody::new(&f.tx).unwrap();
    let result: Result<(), BootstrapError> = custody.contract(0, &actor(2), |frame| {
        let handle = open(frame, &f.tx, 0)?;
        frame
            .consume_pgc_bootstrap(0, &f.bootstrap, handle, f.context())
            .map(|_| ())?;
        frame
            .consume_pgc_bootstrap(0, &f.bootstrap, handle, f.context())
            .map(|_| ())
    });
    assert!(matches!(
        result,
        Err(BootstrapError::Custody(CustodyError::ReusedAction(0)))
    ));
    assert!(matches!(custody.finish(), Err(CustodyError::FailedAttempt)));
}

#[test]
fn missing_or_unconsumed_real_declaration_cannot_finish() {
    let f = fixture();
    let mut custody = AttachmentCustody::new(&f.tx).unwrap();
    let result: Result<(), BootstrapError> = custody.contract(0, &actor(2), |_| Ok(()));
    assert!(matches!(
        result,
        Err(BootstrapError::Custody(CustodyError::UnconsumedAction(0)))
    ));
    let mut custody = AttachmentCustody::new(&f.tx).unwrap();
    let result: Result<(), BootstrapError> = custody.contract(0, &actor(2), |frame| {
        let handle = open(frame, &f.tx, 0)?;
        frame
            .consume_pgc_bootstrap(9, &f.bootstrap, handle, f.context())
            .map(|_| ())
    });
    assert!(matches!(
        result,
        Err(BootstrapError::Custody(CustodyError::MissingAction(9)))
    ));
}

#[test]
fn direct_reference_rejects_a_proof_bound_to_the_old_bootstrap_only_context() {
    let f = fixture();
    let instruction = BootstrapPrivacyPgcAccountsV1::new(
        f.bootstrap.clone(),
        iroha_data_model::transaction::signed_attachments::ActionAttachmentRefV1 {
            action_index: 0,
            slot_index: 0,
        },
    );
    let mut action = planned(&f.bootstrap, f.old_context_proof.clone());
    action.invocation = ActionInvocationBindingV1::Direct {
        instruction_index: 0,
    };
    action.authority = ActionAuthorityBindingV1::TransactionAuthority;
    let tx = draft(f.network, vec![action])
        .with_instructions([instruction])
        .sign(key(1).private_key());
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result: Result<(), BootstrapError> = custody.direct(0, tx.authority(), |frame| {
        let handle = open(frame, &tx, 0)?;
        frame
            .consume_pgc_bootstrap(0, &f.bootstrap, handle, f.context())
            .map(|_| ())
    });
    assert!(matches!(
        result,
        Err(BootstrapError::NativeRead(AnonymousPgcReadError::Relation(
            _
        )))
    ));
}

#[test]
fn signed_key_material_handle_is_not_a_native_action_proof() {
    let f = fixture();
    let mut action = planned(&f.bootstrap, original_proof());
    action.attachments[0].kind = AttachmentKindV1::KeyMaterial;
    action.attachments[0].role = AttachmentRoleV1::VerifyingKey;
    let tx = draft(f.network, vec![action]).sign(key(1).private_key());
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let result: Result<(), BootstrapError> = custody.contract(0, &actor(2), |frame| {
        let operation = operation();
        let request = ActionRequest {
            index: 0,
            operation: &operation,
            role: ActionRoleV1::Administrative,
            public_inputs_digest: public_inputs_digest(&f.bootstrap)?,
        };
        let handle = frame.open(
            request,
            0,
            AttachmentKindV1::KeyMaterial,
            AttachmentRoleV1::VerifyingKey,
        )?;
        frame
            .consume_pgc_bootstrap(0, &f.bootstrap, handle, f.context())
            .map(|_| ())
    });
    assert!(matches!(
        result,
        Err(BootstrapError::Custody(CustodyError::WrongTypeOrRole(0)))
    ));
}

#[test]
fn invalid_public_input_refusal_is_original_and_poisoned() {
    let f = fixture();
    let mut custody = AttachmentCustody::new(&f.tx).unwrap();
    let mut bad = f.bootstrap.clone();
    bad.initial_epoch = 2;
    assert!(matches!(
        public_inputs_digest(&bad),
        Err(BootstrapError::Bootstrap(_))
    ));
    let result: Result<(), BootstrapError> = custody.contract(0, &actor(2), |frame| {
        let handle = open(frame, &f.tx, 0)?;
        let original = frame
            .consume_pgc_bootstrap(0, &bad, handle, f.context())
            .map(|_| ());
        assert!(matches!(original, Err(BootstrapError::Bootstrap(_))));
        assert!(frame.attempt.failed);
        original
    });
    assert!(matches!(result, Err(BootstrapError::Bootstrap(_))));
}

#[test]
fn real_direct_pgc_consumes_signed_global_ordinal_after_another_action() {
    use iroha_data_model::transaction::signed_attachments::ActionAttachmentRefV1;
    let f = fixture();
    let log: InstructionBox = Log::new(Level::INFO, "first action".to_owned()).into();
    let first = PlannedActionV1 {
        operation: ActionOperationV1::NativeInstruction(
            instruction_wire_id(&log).unwrap().to_owned(),
        ),
        role: ActionRoleV1::Effect,
        authority: ActionAuthorityBindingV1::TransactionAuthority,
        invocation: ActionInvocationBindingV1::Direct {
            instruction_index: 0,
        },
        public_inputs_digest: ActionPublicInputsDigestV1::new([0x71; 32]),
        attachments: vec![],
    };
    let request = BootstrapPrivacyPgcAccountsV1::new(
        f.bootstrap.clone(),
        ActionAttachmentRefV1 {
            action_index: 1,
            slot_index: 0,
        },
    );
    let mut second = planned(&f.bootstrap, vec![]);
    second.authority = ActionAuthorityBindingV1::TransactionAuthority;
    second.invocation = ActionInvocationBindingV1::Direct {
        instruction_index: 1,
    };
    let builder =
        draft(f.network, vec![first, second]).with_instructions([log, request.clone().into()]);
    let digest = builder.payload().action_statement_digests_v1().unwrap()[1];
    let tx = sign_with_proof(builder, 0, f.prove(*digest.as_bytes(), 1));
    let mut custody = AttachmentCustody::new(&tx).unwrap();
    let first: Result<(), BootstrapError> = custody.direct(0, tx.authority(), |frame| {
        let action = tx.attachments().unwrap().action(0).unwrap();
        frame.finish_action(ActionRequest {
            index: 0,
            operation: &action.operation,
            role: action.role,
            public_inputs_digest: action.public_inputs_digest,
        })?;
        Ok(())
    });
    first.unwrap();
    let audit: Result<_, BootstrapError> = custody.direct(1, tx.authority(), |frame| {
        let (handle, length) = frame.open_pgc_bootstrap(&request)?;
        assert_eq!(
            length,
            u64::try_from(tx.attachments().unwrap().occurrences()[0].bytes.len()).unwrap()
        );
        frame.consume_pgc_bootstrap(
            request.proof_ref.action_index,
            &request.bootstrap,
            handle,
            f.context(),
        )
    });
    assert_eq!(
        audit.unwrap(),
        PrivacyPgcBootstrapProofBytesV1::digest_bytes(
            &tx.attachments().unwrap().occurrences()[0].bytes
        )
        .unwrap()
    );
    custody.finish().unwrap();
}
#[test]
fn wrong_direct_request_slot_poison_cannot_be_swallowed() {
    use iroha_data_model::transaction::signed_attachments::ActionAttachmentRefV1;
    let f = fixture();
    let mut custody = AttachmentCustody::new(&f.tx).unwrap();
    let request = BootstrapPrivacyPgcAccountsV1::new(
        f.bootstrap.clone(),
        ActionAttachmentRefV1 {
            action_index: 0,
            slot_index: 1,
        },
    );
    let result: Result<(), BootstrapError> = custody.contract(0, &actor(2), |frame| {
        assert!(matches!(
            frame.open_pgc_bootstrap(&request),
            Err(BootstrapError::AttachmentShape)
        ));
        assert!(matches!(
            open(frame, &f.tx, 0),
            Err(CustodyError::FailedAttempt)
        ));
        Ok(())
    });
    assert!(matches!(
        result,
        Err(BootstrapError::Custody(CustodyError::FailedAttempt))
    ));
    assert!(matches!(custody.finish(), Err(CustodyError::FailedAttempt)));
}
