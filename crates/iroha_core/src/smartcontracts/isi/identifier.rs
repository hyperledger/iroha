//! Hidden-function-backed identifier policy instruction handlers.
use super::prelude::*;
use iroha_crypto::{
    Hash, RamLfeBackend, RamLfeVerificationMode, identifier_hashes_from_output_hash,
};
use iroha_data_model::{
    identifier::{
        IdentifierClaimRecord, IdentifierNormalization, IdentifierPolicy,
        IdentifierResolutionReceipt,
    },
    prelude::*,
    ram_lfe::{
        RamLfeExecutionReceiptPayload, RamLfeOutputOpening, RamLfeProgramPolicy,
        RamLfeReceiptAttestation,
    },
};
use iroha_telemetry::metrics;
/// Execution handlers for identifier-policy ISIs.
pub mod isi {
    use super::*;
    use crate::state::StateTransaction;
    impl Execute for iroha_data_model::isi::identifier::RegisterIdentifierPolicy {
        #[metrics(+"register_identifier_policy")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let policy = self.policy;
            if authority != &policy.owner {
                return Err(Error::InvariantViolation(
                    "Only the policy owner can register an identifier policy"
                        .to_owned()
                        .into(),
                ));
            }
            if state_transaction
                .world
                .identifier_policies
                .get(&policy.id)
                .is_some()
            {
                return Err(Error::InvariantViolation(
                    format!("Identifier policy {} is already registered", policy.id).into(),
                ));
            }
            validate_phone_retail_policy_registration(&policy, state_transaction)?;
            state_transaction
                .world
                .identifier_policies
                .insert(policy.id.clone(), policy);
            Ok(())
        }
    }
    impl Execute for iroha_data_model::isi::identifier::ActivateIdentifierPolicy {
        #[metrics(+"activate_identifier_policy")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let policy = state_transaction
                .world
                .identifier_policies
                .get_mut(&self.policy_id)
                .ok_or_else(|| {
                    Error::InvariantViolation(
                        format!("Identifier policy {} is not registered", self.policy_id).into(),
                    )
                })?;
            if authority != &policy.owner {
                return Err(Error::InvariantViolation(
                    "Only the policy owner can activate an identifier policy"
                        .to_owned()
                        .into(),
                ));
            }
            if policy.active {
                return Err(Error::InvariantViolation(
                    format!("Identifier policy {} is already active", policy.id).into(),
                ));
            }
            policy.active = true;
            Ok(())
        }
    }
    impl Execute for iroha_data_model::isi::identifier::ClaimIdentifier {
        #[metrics(+"claim_identifier")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let receipt = self.receipt;
            let receipt_payload = receipt.payload.clone();
            let policy = state_transaction
                .world
                .identifier_policies
                .get(&receipt_payload.policy_id)
                .cloned()
                .ok_or_else(|| {
                    Error::InvariantViolation(
                        format!(
                            "Identifier policy {} is not registered",
                            receipt_payload.policy_id
                        )
                        .into(),
                    )
                })?;
            let program_policy = state_transaction
                .world
                .ram_lfe_program_policies
                .get(&policy.program_id)
                .cloned()
                .ok_or_else(|| {
                    Error::InvariantViolation(
                        format!(
                            "RAM-LFE program policy {} referenced by identifier policy {} is not registered",
                            policy.program_id, policy.id
                        )
                        .into(),
                    )
                })?;
            validate_phone_retail_policy_registration(&policy, state_transaction)?;
            ensure_policy_authorized(authority, &policy, Some(&self.account))?;
            if !policy.active {
                return Err(Error::InvariantViolation(
                    format!("Identifier policy {} is not active", policy.id).into(),
                ));
            }
            if !program_policy.active {
                return Err(Error::InvariantViolation(
                    format!(
                        "RAM-LFE program policy {} referenced by identifier policy {} is not active",
                        program_policy.program_id, policy.id
                    )
                    .into(),
                ));
            }
            validate_identifier_receipt_metadata(&receipt)?;
            let now_ms = state_transaction.block_unix_timestamp_ms();
            validate_program_receipt(
                &receipt,
                &policy,
                &program_policy,
                state_transaction.network_id(),
                now_ms,
                crate::zk_guardrails::guardrails_from_config(&state_transaction.zk),
            )?;
            apply_verified_identifier_claim(
                self.account,
                VerifiedIdentifierClaim { receipt, policy },
                state_transaction,
            )
        }
    }

    fn validate_identifier_receipt_metadata(
        receipt: &IdentifierResolutionReceipt,
    ) -> Result<(), Error> {
        if let Some(expires_at_ms) = receipt.expires_at_ms()
            && expires_at_ms <= receipt.resolved_at_ms()
        {
            return Err(Error::InvariantViolation(
                "identifier receipt expiry must be greater than resolved_at_ms"
                    .to_owned()
                    .into(),
            ));
        }
        if receipt.payload.receipt_hash == Hash::prehashed([0; Hash::LENGTH]) {
            return Err(Error::InvariantViolation(
                "Identifier receipt hash must not be zero".to_owned().into(),
            ));
        }
        Ok(())
    }

    // Constructed only after policy, authority and execution validation above.
    // Keeping the private binding transition separate allows index/lifetime
    // invariants to remain testable independently of the native owner evaluator.
    struct VerifiedIdentifierClaim {
        receipt: IdentifierResolutionReceipt,
        policy: IdentifierPolicy,
    }

    fn apply_verified_identifier_claim(
        account: AccountId,
        verified: VerifiedIdentifierClaim,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let VerifiedIdentifierClaim { receipt, policy } = verified;
        let receipt_payload = receipt.payload.clone();
        let now_ms = state_transaction.block_unix_timestamp_ms();
        let uaid = *state_transaction
            .world
            .account(&account)
            .map_err(Error::from)?
            .uaid()
            .ok_or_else(|| {
                Error::InvariantViolation(
                    format!("Account {} does not have a UAID", account).into(),
                )
            })?;
        if receipt_payload.account_id != account {
            return Err(Error::InvariantViolation(
                format!(
                    "Identifier receipt account {} does not match claim account {}",
                    receipt_payload.account_id, account
                )
                .into(),
            ));
        }
        if receipt_payload.uaid != uaid {
            return Err(Error::InvariantViolation(
                format!(
                    "Identifier receipt UAID {} does not match account {} UAID {uaid}",
                    receipt_payload.uaid, account
                )
                .into(),
            ));
        }
        if receipt.resolved_at_ms() > now_ms {
            return Err(Error::InvariantViolation(
                format!(
                    "Identifier receipt for policy {} was issued in the future ({}) relative to block time ({now_ms})",
                    policy.id,
                    receipt.resolved_at_ms()
                )
                .into(),
            ));
        }
        if receipt_payload.opening.payload.opened_at_ms > now_ms {
            return Err(Error::InvariantViolation(
                format!(
                    "Identifier output opening for policy {} was issued in the future ({}) relative to block time ({now_ms})",
                    policy.id, receipt_payload.opening.payload.opened_at_ms
                )
                .into(),
            ));
        }
        if receipt
            .expires_at_ms()
            .is_some_and(|expires_at_ms| expires_at_ms <= now_ms)
        {
            return Err(Error::InvariantViolation(
                format!(
                    "Identifier receipt for policy {} expired at or before block time {now_ms}",
                    policy.id
                )
                .into(),
            ));
        }
        if receipt_payload
            .opening
            .payload
            .expires_at_ms
            .is_some_and(|expires_at_ms| expires_at_ms <= now_ms)
        {
            return Err(Error::InvariantViolation(
                format!(
                    "Identifier output opening for policy {} expired at or before block time {now_ms}",
                    policy.id
                )
                .into(),
            ));
        }
        evict_expired_identifier_binding(state_transaction, &receipt_payload.opaque_id, now_ms)?;
        if let Some(existing_uaid) = state_transaction
            .world
            .opaque_uaids
            .get(&receipt_payload.opaque_id)
        {
            if existing_uaid != &uaid {
                return Err(Error::InvariantViolation(
                    format!(
                        "Opaque identifier {} is already bound to UAID {existing_uaid}",
                        receipt_payload.opaque_id
                    )
                    .into(),
                ));
            }
        }
        if let Some(existing_claim) = state_transaction
            .world
            .identifier_claims
            .get(&receipt_payload.opaque_id)
        {
            if existing_claim.policy_id != receipt_payload.policy_id
                || existing_claim.uaid != uaid
                || existing_claim.account_id != account
            {
                return Err(Error::InvariantViolation(
                    format!(
                        "Opaque identifier {} is already claimed under a different binding",
                        receipt_payload.opaque_id
                    )
                    .into(),
                ));
            }
        }
        let details = state_transaction
            .world
            .account_mut(&account)
            .map_err(Error::from)?;
        let mut opaque_ids = details.opaque_ids().to_vec();
        if !opaque_ids.contains(&receipt_payload.opaque_id) {
            opaque_ids.push(receipt_payload.opaque_id);
            details.set_opaque_ids(opaque_ids);
        }
        state_transaction
            .world
            .opaque_uaids
            .insert(receipt_payload.opaque_id, uaid);
        state_transaction.world.identifier_claims.insert(
            receipt_payload.opaque_id,
            IdentifierClaimRecord {
                policy_id: receipt_payload.policy_id,
                opaque_id: receipt_payload.opaque_id,
                receipt_hash: receipt_payload.receipt_hash,
                phone_retail_nullifier: receipt
                    .phone_retail_canonicality
                    .as_ref()
                    .map(|attestation| attestation.payload.canonical_phone_nullifier),
                uaid,
                account_id: account,
                verified_at_ms: receipt.resolved_at_ms(),
                expires_at_ms: receipt.expires_at_ms(),
            },
        );
        Ok(())
    }
    impl Execute for iroha_data_model::isi::identifier::RevokeIdentifier {
        #[metrics(+"revoke_identifier")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let claim = state_transaction
                .world
                .identifier_claims
                .get(&self.opaque_id)
                .cloned()
                .ok_or_else(|| {
                    Error::InvariantViolation(
                        format!("Identifier claim {} is not registered", self.opaque_id).into(),
                    )
                })?;
            if claim.policy_id != self.policy_id {
                return Err(Error::InvariantViolation(
                    format!(
                        "Opaque identifier {} is not registered under policy {}",
                        self.opaque_id, self.policy_id
                    )
                    .into(),
                ));
            }
            let policy = state_transaction
                .world
                .identifier_policies
                .get(&self.policy_id)
                .cloned();
            if let Some(policy) = &policy {
                ensure_policy_authorized(authority, policy, Some(&claim.account_id))?;
            } else if authority != &claim.account_id {
                return Err(Error::InvariantViolation(
                    "Only the claimed account can revoke an identifier when the policy is missing"
                        .to_owned()
                        .into(),
                ));
            }
            let details = state_transaction
                .world
                .account_mut(&claim.account_id)
                .map_err(Error::from)?;
            let retained: Vec<_> = details
                .opaque_ids()
                .iter()
                .copied()
                .filter(|opaque| opaque != &self.opaque_id)
                .collect();
            details.set_opaque_ids(retained);
            state_transaction.world.opaque_uaids.remove(self.opaque_id);
            state_transaction
                .world
                .identifier_claims
                .remove(self.opaque_id);
            Ok(())
        }
    }
    fn ensure_policy_authorized(
        authority: &AccountId,
        policy: &IdentifierPolicy,
        account: Option<&AccountId>,
    ) -> Result<(), Error> {
        if authority == &policy.owner || account.is_some_and(|account| authority == account) {
            return Ok(());
        }
        Err(Error::InvariantViolation(
            "Authority is not allowed to mutate this identifier binding"
                .to_owned()
                .into(),
        ))
    }
    fn validate_phone_retail_policy_registration(
        policy: &IdentifierPolicy,
        state_transaction: &StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        validate_phone_retail_policy(
            policy,
            state_transaction
                .world
                .ram_lfe_program_policies
                .get(&policy.program_id),
        )
    }
    /// Enforce the same phone policy contract on registration, claims and restored state.
    pub(crate) fn validate_phone_retail_policy(
        policy: &IdentifierPolicy,
        program: Option<&RamLfeProgramPolicy>,
    ) -> Result<(), Error> {
        let is_phone = policy.id.kind.as_ref() == "phone"
            || policy.normalization == IdentifierNormalization::PhoneE164
            || policy.program_id.to_string() == "phone_retail";
        if !is_phone {
            if policy.phone_retail_attestor_public_key.is_some() {
                return Err(Error::InvariantViolation(
                    "phone attestor key is only valid for phone#retail"
                        .to_owned()
                        .into(),
                ));
            }
            return Ok(());
        }
        if !policy.id.is_phone_retail()
            || policy.normalization != IdentifierNormalization::PhoneE164
            || policy.program_id.to_string() != "phone_retail"
        {
            return Err(Error::InvariantViolation(
                "first-release phone bindings require exactly phone#retail with PhoneE164 and program phone_retail"
                    .to_owned().into(),
            ));
        }
        if policy.phone_retail_attestor_public_key.is_none() {
            return Err(Error::InvariantViolation(
                "phone#retail requires an explicit pinned canonicality attestor key"
                    .to_owned()
                    .into(),
            ));
        }
        let program = program.ok_or_else(|| {
            Error::InvariantViolation(
                "phone#retail requires its pinned RAM-LFE program to be registered first"
                    .to_owned()
                    .into(),
            )
        })?;
        // Preserve early rejection of diagnostic backends before HKDF metadata.
        program
            .backend
            .require_production_support()
            .map_err(|error| Error::InvariantViolation(error.to_string().into()))?;
        program
            .commitment
            .backend
            .require_production_support()
            .map_err(|error| Error::InvariantViolation(error.to_string().into()))?;
        if program.program_id != policy.program_id
            || program.owner != policy.owner
            || program.backend != RamLfeBackend::HkdfSha3_512PrfV1
            || program.commitment.backend != program.backend
            || program.verification_mode != RamLfeVerificationMode::Signed
        {
            return Err(Error::InvariantViolation(
                "phone#retail requires one owner-pinned signed native HKDF policy"
                    .to_owned()
                    .into(),
            ));
        }
        let attestor = policy
            .phone_retail_attestor_public_key
            .as_ref()
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "phone#retail requires its pinned attestor"
                        .to_owned()
                        .into(),
                )
            })?;
        if attestor == &program.resolver_public_key
            || attestor == &program.output_opening_public_key
        {
            return Err(Error::InvariantViolation(
                "phone attestor must be independent of the resolver and opener"
                    .to_owned()
                    .into(),
            ));
        }
        crate::smartcontracts::isi::ram_lfe::validate_program_policy(program)
    }
    fn evict_expired_identifier_binding(
        state_transaction: &mut StateTransaction<'_, '_>,
        opaque_id: &OpaqueAccountId,
        now_ms: u64,
    ) -> Result<(), Error> {
        let Some(existing_claim) = state_transaction
            .world
            .identifier_claims
            .get(opaque_id)
            .cloned()
        else {
            return Ok(());
        };
        if !existing_claim
            .expires_at_ms
            .is_some_and(|expires_at_ms| expires_at_ms <= now_ms)
        {
            return Ok(());
        }
        let retained: Vec<_> = state_transaction
            .world
            .account(&existing_claim.account_id)
            .map_err(Error::from)?
            .opaque_ids()
            .iter()
            .copied()
            .filter(|existing| existing != opaque_id)
            .collect();
        state_transaction
            .world
            .account_mut(&existing_claim.account_id)
            .map_err(Error::from)?
            .set_opaque_ids(retained);
        state_transaction
            .world
            .opaque_uaids
            .remove(opaque_id.clone());
        state_transaction
            .world
            .identifier_claims
            .remove(opaque_id.clone());
        Ok(())
    }
    fn validate_program_receipt(
        receipt: &IdentifierResolutionReceipt,
        policy: &IdentifierPolicy,
        program_policy: &RamLfeProgramPolicy,
        network_id: &iroha_data_model::NetworkId,
        now_ms: u64,
        _guardrails: crate::zk::ZkVerifyGuardrails,
    ) -> Result<(), Error> {
        // Refuse insecure diagnostic backends before any metadata/private decoding.
        program_policy
            .backend
            .require_production_support()
            .map_err(|error| Error::InvariantViolation(error.to_string().into()))?;
        program_policy
            .commitment
            .backend
            .require_production_support()
            .map_err(|error| Error::InvariantViolation(error.to_string().into()))?;
        crate::smartcontracts::isi::ram_lfe::validate_program_policy(program_policy)?;
        let execution = &receipt.payload.execution;
        if receipt.payload.network_id != *network_id
            || receipt.payload.policy_id != policy.id
            || policy.owner != program_policy.owner
            || policy.program_id != program_policy.program_id
            || execution.program_id != policy.program_id
            || execution.backend != RamLfeBackend::HkdfSha3_512PrfV1
            || execution.backend != program_policy.backend
            || execution.verification_mode != RamLfeVerificationMode::Signed
        {
            return Err(Error::InvariantViolation(
                "Identifier receipt differs from the current network, policy, owner or signed HKDF program".to_owned().into(),
            ));
        }
        let expected = iroha_data_model::identifier::hkdf_identifier_execution_metadata_v1(
            &program_policy.commitment,
        )
        .map_err(|error| Error::InvariantViolation(error.to_string().into()))?;
        let program_bytes = norito::encode_canonical(&program_policy.program_id)
            .map_err(|error| Error::InvariantViolation(error.to_string().into()))?;
        if (
            execution.program_digest,
            execution.parameter_digest,
            execution.evaluation_key_digest,
        ) != expected
            || execution.associated_data_hash != Hash::new(&program_bytes)
            || execution.input_ciphertext_hash == Hash::prehashed([0; Hash::LENGTH])
            || execution.output_hash == Hash::prehashed([0; Hash::LENGTH])
            || execution.output_hash != execution.output_ciphertext_hash
        {
            return Err(Error::InvariantViolation(
                "Identifier receipt metadata differs from its current pinned HKDF policy and opaque output".to_owned().into(),
            ));
        }
        let original = &receipt.payload.opening.payload;
        let expires = original.expires_at_ms.ok_or_else(|| {
            Error::InvariantViolation(
                "Identifier owner opening requires its original bounded expiry"
                    .to_owned()
                    .into(),
            )
        })?;
        // Consensus validation samples only the deterministic block clock.
        if now_ms == 0
            || original.opened_at_ms == 0
            || original.opened_at_ms > now_ms
            || expires <= now_ms
            || expires <= original.opened_at_ms
            || expires - original.opened_at_ms > 120_000
            || execution.executed_at_ms != original.opened_at_ms
            || execution.expires_at_ms != Some(expires)
            || original.opened_output_hash != execution.output_hash
        {
            return Err(Error::InvariantViolation(
                "Identifier receipt changed its original opening, opaque output or bounded lease"
                    .to_owned()
                    .into(),
            ));
        }
        validate_output_opening(&receipt.payload.opening, execution, program_policy)?;
        let phone_nullifier = validate_phone_retail_canonicality(
            receipt,
            policy,
            program_policy,
            network_id,
            now_ms,
        )?;
        validate_identifier_output_binding(receipt, policy, phone_nullifier.as_ref())?;
        if !matches!(&receipt.attestation, RamLfeReceiptAttestation::Signed(_)) {
            return Err(Error::InvariantViolation(
                "Identifier receipt requires the pinned resolver signature"
                    .to_owned()
                    .into(),
            ));
        }
        receipt
            .verify(&program_policy.resolver_public_key)
            .map_err(|error| {
                Error::InvariantViolation(
                    format!("Identifier receipt signature is invalid: {error}").into(),
                )
            })
    }
    fn validate_identifier_output_binding(
        receipt: &IdentifierResolutionReceipt,
        policy: &IdentifierPolicy,
        phone_nullifier: Option<&Hash>,
    ) -> Result<(), Error> {
        let expected_hashes =
            expected_identifier_hashes(policy, &receipt.payload.opening, phone_nullifier)?;
        if receipt.payload.opaque_id != OpaqueAccountId::from(expected_hashes.0) {
            return Err(Error::InvariantViolation(
                format!(
                    "Identifier receipt opaque_id does not match program output hash for policy {}",
                    policy.id
                )
                .into(),
            ));
        }
        if receipt.payload.receipt_hash != expected_hashes.1 {
            return Err(Error::InvariantViolation(
                format!(
                    "Identifier receipt hash does not match program output hash for policy {}",
                    policy.id
                )
                .into(),
            ));
        }
        Ok(())
    }

    fn expected_identifier_hashes(
        policy: &IdentifierPolicy,
        opening: &RamLfeOutputOpening,
        phone_nullifier: Option<&Hash>,
    ) -> Result<(Hash, Hash), Error> {
        let program_id_bytes = norito::encode_canonical(&policy.program_id).map_err(|err| {
            Error::InvariantViolation(
                format!(
                    "Failed to canonically encode RAM-LFE program id {} for identifier policy {}: {err}",
                    policy.program_id, policy.id
                )
                .into(),
            )
        })?;
        Ok(identifier_hashes_from_output_hash(
            &program_id_bytes,
            phone_nullifier.unwrap_or(&opening.payload.opened_output_hash),
        ))
    }
    fn validate_phone_retail_canonicality(
        receipt: &IdentifierResolutionReceipt,
        policy: &IdentifierPolicy,
        program_policy: &RamLfeProgramPolicy,
        network_id: &iroha_data_model::NetworkId,
        now_ms: u64,
    ) -> Result<Option<Hash>, Error> {
        if !policy.id.is_phone_retail() {
            if receipt.phone_retail_canonicality.is_some() {
                return Err(Error::InvariantViolation(
                    "canonical phone attestation is only valid for phone#retail"
                        .to_owned()
                        .into(),
                ));
            }
            return Ok(None);
        }
        let attestation = receipt.phone_retail_canonicality.as_ref().ok_or_else(|| {
            Error::InvariantViolation(
                "phone#retail requires a trusted canonical E.164 nullifier attestation"
                    .to_owned()
                    .into(),
            )
        })?;
        let pinned_key = policy
            .phone_retail_attestor_public_key
            .as_ref()
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "phone#retail attestor key is not pinned".to_owned().into(),
                )
            })?;
        let statement = &attestation.payload;
        let execution = &receipt.payload.execution;
        let opening = &receipt.payload.opening.payload;
        if statement.network_id != *network_id
            || statement.policy_id != policy.id
            || statement.program_id != policy.program_id
            || statement.program_id != program_policy.program_id
            || statement.input_ciphertext_hash != execution.input_ciphertext_hash
            || statement.output_ciphertext_hash != execution.output_ciphertext_hash
            || statement.opened_output_hash != opening.opened_output_hash
            || statement.uaid != receipt.payload.uaid
            || statement.account_id != receipt.payload.account_id
        {
            return Err(Error::InvariantViolation(
                "phone#retail canonicality statement differs from network, program, ciphertext, opening, or beneficiary"
                    .to_owned().into(),
            ));
        }
        if pinned_key == &program_policy.resolver_public_key
            || pinned_key == &program_policy.output_opening_public_key
            || statement.canonical_phone_nullifier != opening.opened_output_hash
            || statement.issued_at_ms != opening.opened_at_ms
            || Some(statement.expires_at_ms) != opening.expires_at_ms
            || statement.canonical_phone_nullifier == Hash::prehashed([0; Hash::LENGTH])
            || statement.issued_at_ms > now_ms
            || statement.expires_at_ms <= now_ms
            || statement.expires_at_ms <= statement.issued_at_ms
        {
            return Err(Error::InvariantViolation(
                "phone#retail canonicality nullifier or validity window is invalid"
                    .to_owned()
                    .into(),
            ));
        }
        attestation.verify(pinned_key).map_err(|err| {
            Error::InvariantViolation(
                format!("phone#retail canonicality signature is invalid: {err}").into(),
            )
        })?;
        Ok(Some(statement.canonical_phone_nullifier))
    }
    fn validate_output_opening(
        opening: &RamLfeOutputOpening,
        execution: &RamLfeExecutionReceiptPayload,
        program_policy: &RamLfeProgramPolicy,
    ) -> Result<(), Error> {
        let payload = &opening.payload;
        if payload.program_id != execution.program_id {
            return Err(Error::InvariantViolation(
                format!(
                    "RAM-LFE output opening program {} does not match execution program {}",
                    payload.program_id, execution.program_id
                )
                .into(),
            ));
        }
        if payload.input_ciphertext_hash != execution.input_ciphertext_hash {
            return Err(Error::InvariantViolation(
                "RAM-LFE output opening input ciphertext hash does not match execution receipt"
                    .to_owned()
                    .into(),
            ));
        }
        if payload.output_ciphertext_hash != execution.output_ciphertext_hash {
            return Err(Error::InvariantViolation(
                "RAM-LFE output opening output ciphertext hash does not match execution receipt"
                    .to_owned()
                    .into(),
            ));
        }
        if payload.parameter_digest != execution.parameter_digest {
            return Err(Error::InvariantViolation(
                "RAM-LFE output opening parameter digest does not match execution receipt"
                    .to_owned()
                    .into(),
            ));
        }
        if payload.evaluation_key_digest != execution.evaluation_key_digest {
            return Err(Error::InvariantViolation(
                "RAM-LFE output opening evaluation-key digest does not match execution receipt"
                    .to_owned()
                    .into(),
            ));
        }
        if payload.opened_output_hash == Hash::prehashed([0; Hash::LENGTH]) {
            return Err(Error::InvariantViolation(
                "RAM-LFE output opening hash must not be zero"
                    .to_owned()
                    .into(),
            ));
        }
        if payload
            .expires_at_ms
            .is_some_and(|expires_at_ms| expires_at_ms <= payload.opened_at_ms)
        {
            return Err(Error::InvariantViolation(
                "RAM-LFE output opening expiry must be greater than opened_at_ms"
                    .to_owned()
                    .into(),
            ));
        }
        opening
            .verify_signature(&program_policy.output_opening_public_key)
            .map_err(|err| {
                Error::InvariantViolation(
                    format!(
                        "RAM-LFE output opening signature is invalid for program {}: {err}",
                        program_policy.program_id
                    )
                    .into(),
                )
            })
    }
    fn verify_execution_proof(
        proof: &iroha_data_model::proof::ProofBox,
        execution: &RamLfeExecutionReceiptPayload,
        verifier: &iroha_crypto::RamLfeProofVerifierMetadata,
        guardrails: crate::zk::ZkVerifyGuardrails,
    ) -> Result<(), Error> {
        crate::smartcontracts::isi::ram_lfe::verify_execution_proof(
            proof, execution, verifier, guardrails,
        )
        .map_err(|err| Error::InvariantViolation(err.into()))
    }
    #[cfg(test)]
    mod proof_tests {
        use super::*;
        use iroha_crypto::RamLfeProofVerifierMetadata;
        use iroha_data_model::{
            proof::{ProofBox, VerifyingKeyBox},
            ram_lfe::{RamLfeExecutionReceiptPayload, RamLfeProgramId},
            zk::{BackendTag, OpenVerifyEnvelope},
        };
        use std::str::FromStr as _;
        fn sample_proof_payload() -> RamLfeExecutionReceiptPayload {
            RamLfeExecutionReceiptPayload {
                program_id: RamLfeProgramId::from_str("identifier_proof_program")
                    .expect("program id"),
                program_digest: Hash::new(b"program"),
                backend: RamLfeBackend::BfvProgrammedV1,
                verification_mode: RamLfeVerificationMode::Proof,
                input_ciphertext_hash: Hash::new(b"input-ciphertext"),
                output_ciphertext_hash: Hash::new(b"output-ciphertext"),
                parameter_digest: Hash::new(b"parameters"),
                evaluation_key_digest: Hash::new(b"evaluation-keys"),
                output_hash: Hash::new(b"output"),
                associated_data_hash: Hash::new(b"associated-data"),
                executed_at_ms: 100,
                expires_at_ms: None,
            }
        }
        fn sample_proof_verifier() -> RamLfeProofVerifierMetadata {
            RamLfeProofVerifierMetadata {
                proof_backend: crate::zk::ZK_BACKEND_NATIVE_PIPA_R.to_owned(),
                circuit_id: crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID
                    .to_owned(),
                public_inputs_schema_hash: Hash::new(b"identifier-ram-lfe-proof-schema"),
                verifying_key_bytes: b"identifier-ram-lfe-proof-vk".to_vec(),
            }
        }
        #[cfg(feature = "zk-stark")]
        #[test]
        fn identifier_execution_relation_rejects_a_valid_unrelated_native_proof() {
            let fixture = crate::zk::test_utils::stark_public_binding_fixture_envelope();
            let proof = fixture.proof_box(crate::zk::ZK_BACKEND_STARK_FRI_V1);
            let key = fixture
                .vk_box(crate::zk::ZK_BACKEND_STARK_FRI_V1)
                .expect("key");
            crate::zk::verify_for_relation(
                crate::zk::ProofRelation::PublicInputBinding,
                &proof,
                &key,
                test_guardrails(),
            )
            .expect("control is a valid native public-input binding proof");
            let verifier = RamLfeProofVerifierMetadata {
                proof_backend: proof.backend.to_string(),
                circuit_id: format!("{}:public-binding-demo", crate::zk::ZK_BACKEND_STARK_FRI_V1),
                public_inputs_schema_hash: Hash::new(&fixture.public_inputs),
                verifying_key_bytes: key.bytes,
            };
            let error = verify_execution_proof(
                &proof,
                &sample_proof_payload(),
                &verifier,
                test_guardrails(),
            )
            .expect_err("a valid binding proof cannot establish hidden program execution");
            assert!(
                error
                    .to_string()
                    .contains("no compiled program-execution proof relation"),
                "unexpected error: {error}"
            );
        }
        fn test_guardrails() -> crate::zk::ZkVerifyGuardrails {
            crate::zk::ZkVerifyGuardrails {
                pipa_r_enabled: true,
                pipa_r_max_envelope_bytes: usize::MAX,
                pipa_r_max_proof_bytes: usize::MAX,

                stark_enabled: true,
                stark_max_envelope_bytes: usize::MAX,
                stark_max_proof_bytes: usize::MAX,
            }
        }
        fn sample_proof_box(
            verifier: &RamLfeProofVerifierMetadata,
            mutate: impl FnOnce(&mut OpenVerifyEnvelope),
        ) -> ProofBox {
            let vk = VerifyingKeyBox::new(
                verifier.proof_backend.clone().into(),
                verifier.verifying_key_bytes.clone(),
            );
            let mut envelope = OpenVerifyEnvelope {
                backend: BackendTag::NativePipaRPasta,
                circuit_id: verifier.circuit_id.clone(),
                vk_hash: crate::zk::hash_vk(&vk),
                public_inputs: b"identifier-ram-lfe-proof-schema".to_vec(),
                proof_bytes: vec![0xCA, 0xFE],
                aux: Vec::new(),
            };
            mutate(&mut envelope);
            ProofBox::new(
                verifier.proof_backend.clone().into(),
                norito::encode_canonical(&envelope).expect("encode canonical OpenVerifyEnvelope"),
            )
        }
        #[test]
        fn identifier_verify_execution_proof_rejects_noncanonical_envelope_metadata() {
            let verifier = sample_proof_verifier();
            let execution = sample_proof_payload();
            let bad_backend = sample_proof_box(&verifier, |envelope| {
                envelope.backend = BackendTag::Stark;
            });
            let err =
                verify_execution_proof(&bad_backend, &execution, &verifier, test_guardrails())
                    .expect_err("wrong envelope backend tag must reject before proof parsing");
            let message = err.to_string();
            assert!(
                message.contains("no compiled program-execution proof relation"),
                "unexpected error: {message}"
            );
            for (backend, expected_message) in [
                (
                    "halo2/ipa:production-ready",
                    "no compiled program-execution proof relation",
                ),
                (
                    "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                    "no compiled program-execution proof relation",
                ),
            ] {
                let mut backend_verifier = verifier.clone();
                backend_verifier.proof_backend = backend.to_owned();
                let backend_proof = sample_proof_box(&backend_verifier, |_| {});
                let err = verify_execution_proof(
                    &backend_proof,
                    &execution,
                    &backend_verifier,
                    test_guardrails(),
                )
                .expect_err("unexpected RAM-LFE verifier backend must reject before proof parsing");
                let message = err.to_string();
                assert!(
                    message.contains(expected_message),
                    "backend {backend}: expected {expected_message:?}, got {message:?}"
                );
            }
            let aux = sample_proof_box(&verifier, |envelope| {
                envelope.aux = b"unbound-identifier-proof-metadata".to_vec();
            });
            let err = verify_execution_proof(&aux, &execution, &verifier, test_guardrails())
                .expect_err("non-empty auxiliary bytes must reject before proof parsing");
            let message = err.to_string();
            assert!(
                message.contains("no compiled program-execution proof relation"),
                "unexpected error: {message}"
            );
            let zero_vk_hash = sample_proof_box(&verifier, |envelope| {
                envelope.vk_hash = [0u8; Hash::LENGTH];
            });
            let err =
                verify_execution_proof(&zero_vk_hash, &execution, &verifier, test_guardrails())
                    .expect_err("zero verifier-key hash must reject before proof parsing");
            let message = err.to_string();
            assert!(
                message.contains("no compiled program-execution proof relation"),
                "unexpected error: {message}"
            );
            let schema_drift = sample_proof_box(&verifier, |envelope| {
                envelope.public_inputs.extend_from_slice(b":schema-drift");
            });
            let err =
                verify_execution_proof(&schema_drift, &execution, &verifier, test_guardrails())
                    .expect_err("public-input schema drift must reject before proof parsing");
            let message = err.to_string();
            assert!(
                message.contains("no compiled program-execution proof relation"),
                "unexpected error: {message}"
            );
            let wrong_vk_hash = sample_proof_box(&verifier, |envelope| {
                envelope.vk_hash = [0xA5; Hash::LENGTH];
            });
            let err =
                verify_execution_proof(&wrong_vk_hash, &execution, &verifier, test_guardrails())
                    .expect_err("wrong verifier-key hash must reject before proof parsing");
            let message = err.to_string();
            assert!(
                message.contains("no compiled program-execution proof relation"),
                "unexpected error: {message}"
            );
        }
        #[test]
        fn identifier_verify_execution_proof_rejects_alternate_norito_layout() {
            let verifier = sample_proof_verifier();
            let execution = sample_proof_payload();
            let canonical = sample_proof_box(&verifier, |_| {});
            let envelope = norito::decode_canonical::<OpenVerifyEnvelope>(&canonical.bytes)
                .expect("decode canonical identifier proof envelope");
            let alternate_flags =
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
            let alternate_bytes = {
                let _guard = norito::core::DecodeFlagsGuard::enter(alternate_flags);
                norito::to_bytes(&envelope)
                    .expect("encode alternate-layout identifier proof envelope")
            };
            assert_ne!(alternate_bytes, canonical.bytes);
            let alternate = ProofBox::new(canonical.backend, alternate_bytes);
            let err = verify_execution_proof(&alternate, &execution, &verifier, test_guardrails())
                .expect_err("alternate-layout identifier proof envelope must reject");
            assert!(
                err.to_string()
                    .contains("no compiled program-execution proof relation"),
                "unexpected error: {err}"
            );
        }
        #[test]
        fn identifier_verify_execution_proof_refuses_even_when_backend_is_disabled() {
            let verifier = sample_proof_verifier();
            let execution = sample_proof_payload();
            let proof = sample_proof_box(&verifier, |_| {});
            let mut guardrails = test_guardrails();
            guardrails.pipa_r_enabled = false;
            let err = verify_execution_proof(&proof, &execution, &verifier, guardrails)
                .expect_err("identifier claim verification must honor disabled native PIPA-R");
            assert!(
                err.to_string()
                    .contains("no compiled program-execution proof relation"),
                "unexpected error: {err}"
            );
        }
    }
    #[cfg(test)]
    mod tests {
        include!("identifier_tests.rs");
    }
}
