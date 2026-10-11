//! Original WSV transaction adapter. Every read is from the same disposable overlay and every
//! monetary batch goes through the canonical asset movement/custody/transcript owner.
use super::{custody, storage, *};
use crate::state::StateTransaction;
use iroha_data_model::asset::{AssetBalancePolicy, AssetId};
use iroha_primitives::numeric::{Numeric, Quantity};
use mv::storage::StorageReadOnly as _;

pub(crate) struct WsvLedger<'borrow, 'block, 'state> {
    state: &'borrow mut StateTransaction<'block, 'state>,
    authority: AccountId,
    transaction: Digest,
}
impl<'borrow, 'block, 'state> WsvLedger<'borrow, 'block, 'state> {
    pub(crate) fn new(
        state: &'borrow mut StateTransaction<'block, 'state>,
        authority: &AccountId,
    ) -> Result<Self> {
        let transaction = state
            .current_network_entrypoint_hash
            .ok_or(Error::Binding)?;
        Ok(Self {
            state,
            authority: authority.clone(),
            transaction: *transaction.as_ref(),
        })
    }
    fn read<T>(&self, key: &KagemushaWalletLedgerKeyV1) -> Result<Option<T>>
    where
        T: norito::NoritoSerialize,
        for<'de> T: norito::NoritoDeserialize<'de>,
    {
        self.state
            .world
            .kagemusha_wallet_ledger
            .get(key)
            .map(|bytes| {
                validate_row(key, bytes)?;
                storage::decode(bytes, bytes.len())
            })
            .transpose()
    }
    fn row<T: norito::NoritoSerialize>(
        key: KagemushaWalletLedgerKeyV1,
        value: &T,
    ) -> Result<(KagemushaWalletLedgerKeyV1, Vec<u8>)> {
        let bytes = storage::encode(value)?;
        validate_row(&key, &bytes)?;
        Ok((key, bytes))
    }
    /// Register a permanent exact reserve bucket. Asset governance must delegate the
    /// dedicated permission to the consenting reserve account before this call.
    pub(crate) fn register(&mut self, registration: Registration) -> Result<()> {
        use iroha_executor_data_model::permission::asset_definition::CanManageKagemushaWallet;
        let scheme = registration.scheme.scheme_id();
        let asset = registration.asset.asset_digest();
        registration.require(&scheme, &asset)?;
        self.require_asset(&registration)?;
        if self.authority != registration.reserve
            || !crate::smartcontracts::isi::helpers::world_account_has_permission(
                self.state.world(),
                &self.authority,
                CanManageKagemushaWallet {
                    asset_definition: registration.asset.asset.clone(),
                }
                .into(),
            )
        {
            return Err(Error::Execution(iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
                "KAGEMUSHA registration requires reserve-account consent and exact CanManageKagemushaWallet".into(),
            )));
        }
        let registration_key = storage::key(storage::REGISTRATION, scheme, asset);
        let row = Self::row(registration_key, &registration)?;
        if let Some(prior) = self
            .state
            .world
            .kagemusha_wallet_ledger
            .get(&registration_key)
        {
            // No setter changes a reserve, root, signer or balance scope after publication.
            if prior != &row.1 {
                return Err(Error::Conflict);
            }
            if custody::reserve_registration(
                self.state.world(),
                &custody::reserve_id(&registration),
            )?
            .is_none()
            {
                return Err(Error::Unavailable);
            }
            self.registration(&scheme, &asset)?;
            return Ok(());
        }
        let reserve = custody::reserve_id(&registration);
        crate::smartcontracts::isi::asset::isi::ensure_kagemusha_reserve_available(
            self.state, &reserve,
        )?;
        let reserve_key = storage::reserve_key(&reserve)?;
        if self
            .state
            .world
            .kagemusha_wallet_ledger
            .get(&reserve_key)
            .is_some()
        {
            return Err(Error::Conflict);
        }
        let mut rows = vec![
            row,
            Self::row(reserve_key, &storage::ReserveOwner { scheme, asset })?,
        ];
        for key in [
            storage::reserve_account_key(&registration.reserve)?,
            storage::reserve_definition_key(&registration.asset.asset)?,
        ] {
            let references: u64 = self.read(&key)?.unwrap_or(0);
            rows.push(Self::row(
                key,
                &references.checked_add(1).ok_or(Error::Overflow)?,
            )?);
        }
        self.insert_immutable(rows)
    }
    /// Reserve one bounded native package verification under the existing transaction
    /// and block proof quotas. Transport bytes include both carried accumulator originals.
    pub(crate) fn reserve_package_proof(
        &mut self,
        package: &KagemushaWalletPackageV1,
    ) -> Result<()> {
        self.state.register_kagemusha_package_proof(package)?;
        Ok(())
    }
    /// Retain original native verifier material only after exact reserve consent and
    /// registered-asset governance. The scheme install cannot be replaced or deleted.
    pub(crate) fn install_verifier_pack(
        &mut self,
        scheme: Digest,
        asset: Digest,
        manifest_digest: Digest,
        pack: Vec<u8>,
    ) -> Result<()> {
        use iroha_executor_data_model::permission::asset_definition::CanManageKagemushaWallet;
        let registration = self.registration(&scheme, &asset)?;
        self.require_asset(&registration)?;
        if self.authority != registration.reserve
            || !crate::smartcontracts::isi::helpers::world_account_has_permission(
                self.state.world(),
                &self.authority,
                CanManageKagemushaWallet {
                    asset_definition: registration.asset.asset.clone(),
                }
                .into(),
            )
        {
            return Err(Error::Execution(iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
                "KAGEMUSHA verifier install requires reserve consent and exact CanManageKagemushaWallet".into(),
            )));
        }
        let value = super::artifacts::VerifierInstallation::authenticate(
            &registration,
            manifest_digest,
            pack,
        )?;
        self.insert_immutable(vec![Self::row(super::artifacts::key(scheme), &value)?])
    }
    fn insert_immutable(&mut self, rows: Vec<(KagemushaWalletLedgerKeyV1, Vec<u8>)>) -> Result<()> {
        // Prepare and compare every row before the first mutation. Permanent reference counts
        // are the sole incrementing records in this helper.
        for (key, bytes) in &rows {
            if let Some(prior) = self.state.world.kagemusha_wallet_ledger.get(key) {
                validate_row(key, prior)?;
                if prior != bytes && !storage::is_reference_key(key) {
                    return Err(Error::Conflict);
                }
            }
        }
        for (key, bytes) in rows {
            self.state.world.kagemusha_wallet_ledger.insert(key, bytes);
        }
        Ok(())
    }
    pub(crate) fn retain_certificate(
        &mut self,
        asset: Digest,
        certificate: KagemushaWalletSignerCertificateV1,
    ) -> Result<()> {
        let scheme = certificate.body.scheme_id;
        certificate.verify(&self.registration(&scheme, &asset)?.scheme)?;
        self.insert_immutable(vec![Self::row(
            storage::key(
                storage::CERTIFICATE,
                scheme,
                certificate.certificate_digest(),
            ),
            &certificate,
        )?])
    }
    pub(crate) fn retain_credential(&mut self, value: CredentialRecord) -> Result<()> {
        let body = &value.credential.body;
        let registration = self.registration(&body.scheme_id, &body.asset_digest)?;
        value.certificates.verify(&registration.scheme)?;
        let issuer = value.certificates.certificate(
            &body.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        )?;
        value.credential.verify(&registration.scheme, issuer)?;
        let mut rows = vec![Self::row(
            storage::key(
                storage::CREDENTIAL,
                body.scheme_id,
                value.credential.credential_digest(),
            ),
            &value,
        )?];
        for certificate in &value.certificates.certificates {
            rows.push(Self::row(
                storage::key(
                    storage::CERTIFICATE,
                    body.scheme_id,
                    certificate.certificate_digest(),
                ),
                certificate,
            )?);
        }
        self.insert_immutable(rows)
    }
    pub(crate) fn retain_request(&mut self, request: KagemushaWalletRequestV1) -> Result<()> {
        let scheme = request.body.scheme_id;
        request.verify(
            &self
                .registration(&scheme, &request.body.asset_digest)?
                .scheme,
        )?;
        let mut rows = vec![Self::row(
            storage::key(storage::REQUEST, scheme, request.request_digest()),
            &request,
        )?];
        let credential = CredentialRecord {
            credential: request.receiver_credential,
            certificates: request.certificates.clone(),
        };
        rows.push(Self::row(
            storage::key(
                storage::CREDENTIAL,
                scheme,
                credential.credential.credential_digest(),
            ),
            &credential,
        )?);
        for certificate in &request.certificates.certificates {
            rows.push(Self::row(
                storage::key(
                    storage::CERTIFICATE,
                    scheme,
                    certificate.certificate_digest(),
                ),
                certificate,
            )?);
        }
        self.insert_immutable(rows)
    }
    fn require_asset(&self, registration: &Registration) -> Result<()> {
        if &registration.scheme.network_id != self.state.network_id.as_bytes() {
            return Err(Error::Binding);
        }
        let definition = self
            .state
            .world
            .asset_definitions
            .get(&registration.asset.asset)
            .ok_or(Error::Unavailable)?;
        let incarnation = self
            .state
            .world
            .axt_asset_incarnations
            .get(&registration.asset.asset)
            .ok_or(Error::Unavailable)?;
        if incarnation.as_bytes() != &registration.asset.asset_incarnation
            || definition
                .spec()
                .scale()
                .unwrap_or(iroha_primitives::numeric::MAX_DECIMAL_SCALE)
                != registration.asset.scale
        {
            return Err(Error::Binding);
        }
        if !registration_scope_matches_home(
            &self.state.world,
            definition,
            registration.balance_scope,
        ) {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

/// A registration's balance scope must be exactly the definition's balance home.
///
/// Global definitions register the global scope. A dataspace-restricted definition registers
/// `Dataspace(H)` for its non-universal home H, never a foreign or universal bucket.
pub(crate) fn registration_scope_matches_home(
    world: &(impl crate::state::WorldReadOnly + ?Sized),
    definition: &iroha_data_model::asset::AssetDefinition,
    scope: AssetBalanceScope,
) -> bool {
    match (definition.balance_scope_policy(), scope) {
        (AssetBalancePolicy::Global, AssetBalanceScope::Global) => true,
        (AssetBalancePolicy::DataspaceRestricted, AssetBalanceScope::Dataspace(dataspace)) => {
            crate::read_scope::confined_home(world, definition)
                .ok()
                .flatten()
                == Some(dataspace)
        }
        _ => false,
    }
}

/// Consumed only by the canonical asset owner. No public constructor or serialized decoder can
/// produce this capability; it comes from an already verified ledger batch and original WSV.
pub(crate) struct VerifiedMovements {
    authority: AccountId,
    reserve: AssetId,
    release: bool,
    binding: Vec<u8>,
    entries: Vec<(AssetId, AssetId, Quantity)>,
}
impl VerifiedMovements {
    pub(crate) fn into_parts(
        self,
    ) -> (
        AccountId,
        AssetId,
        bool,
        Vec<u8>,
        Vec<(AssetId, AssetId, Quantity)>,
    ) {
        (
            self.authority,
            self.reserve,
            self.release,
            self.binding,
            self.entries,
        )
    }
}
impl Transaction for WsvLedger<'_, '_, '_> {
    fn authority(&self) -> &AccountId {
        &self.authority
    }
    fn transaction_hash(&self) -> Digest {
        self.transaction
    }
    fn block_height(&self) -> u64 {
        self.state.block_height()
    }
    fn registration(&self, scheme: &Digest, asset: &Digest) -> Result<Registration> {
        let registration: Registration = self
            .read(&storage::key(storage::REGISTRATION, *scheme, *asset))?
            .ok_or(Error::Unavailable)?;
        self.require_asset(&registration)?;
        Ok(registration)
    }
    fn wallet(&self, scheme: &Digest, wallet: &Digest) -> Result<Option<WalletRecord>> {
        self.read(&storage::key(storage::WALLET, *scheme, *wallet))
    }
    fn issuance(
        &self,
        scheme: &Digest,
        wallet: &Digest,
        request: &Digest,
    ) -> Result<Option<Issuance>> {
        self.read(&storage::issuance_key(*scheme, *wallet, *request))
    }
    fn payout(
        &self,
        scheme: &Digest,
        key: KagemushaWalletPayoutKeyV1,
    ) -> Result<Option<KagemushaWalletPayoutRecordV1>> {
        let (kind, id) = match key {
            KagemushaWalletPayoutKeyV1::Unload(id) => (storage::UNLOAD, id),
            KagemushaWalletPayoutKeyV1::Fee(id) => (storage::FEE, id),
        };
        self.read(&storage::key(kind, *scheme, id))
    }
    fn certificate(
        &self,
        scheme: &Digest,
        digest: &Digest,
    ) -> Result<KagemushaWalletSignerCertificateV1> {
        self.read(&storage::key(storage::CERTIFICATE, *scheme, *digest))?
            .ok_or(Error::Unavailable)
    }
    fn fee_inputs(&self, claim: &KagemushaWalletFeeClaimV1) -> Result<FeeInputs> {
        let scheme = claim.payment.request.body.scheme_id;
        let request = self
            .read(&storage::key(
                storage::REQUEST,
                scheme,
                claim.payment.request.request_digest(),
            ))?
            .ok_or(Error::Unavailable)?;
        let credential: CredentialRecord = self
            .read(&storage::key(
                storage::CREDENTIAL,
                scheme,
                claim.payment.payer_credential_digest,
            ))?
            .ok_or(Error::Unavailable)?;
        Ok(FeeInputs {
            request,
            payer: credential.credential,
            certificates: credential.certificates,
        })
    }
    fn apply(&mut self, batch: Batch) -> Result<()> {
        let registration = self.registration(&batch.scheme, &batch.asset)?;
        let mut rows = Vec::with_capacity(3);
        let mut load_event = None;
        if let Some((wallet, record)) = batch.wallet {
            if record.asset != batch.asset {
                return Err(Error::Binding);
            }
            rows.push(Self::row(
                storage::key(storage::WALLET, batch.scheme, wallet),
                &record,
            )?);
        }
        if let Some(issuance) = batch.issuance {
            if issuance.body.scheme_id != batch.scheme || issuance.body.asset_digest != batch.asset
            {
                return Err(Error::Binding);
            }
            if self
                .issuance(
                    &batch.scheme,
                    &issuance.command.wallet,
                    &issuance.command.request_id,
                )?
                .is_some()
            {
                return Err(Error::Conflict);
            }
            rows.push(Self::row(
                storage::issuance_key(
                    batch.scheme,
                    issuance.command.wallet,
                    issuance.command.request_id,
                ),
                &issuance,
            )?);
            // This event is an execution effect authenticated by the ordinary event
            // commitment in R. Construct it before any effects, emit only after the
            // atomic debit and immutable receipt insertion. Exact execution retry
            // returns the retained issuance without entering this batch again.
            load_event = Some(
                iroha_data_model::events::data::kagemusha::KagemushaLoadCommittedV1::from_receipt(
                    &issuance.body,
                )?,
            );
        }
        let release = batch.payout.is_some();
        if let Some(payout) = batch.payout {
            if self.payout(&batch.scheme, payout.key)?.is_some() {
                return Err(Error::Conflict);
            }
            let (kind, id) = match payout.key {
                KagemushaWalletPayoutKeyV1::Unload(id) => (storage::UNLOAD, id),
                KagemushaWalletPayoutKeyV1::Fee(id) => (storage::FEE, id),
            };
            rows.push(Self::row(storage::key(kind, batch.scheme, id), &payout)?);
        }
        if !batch.transfers.is_empty() {
            let reserve = custody::reserve_id(&registration);
            if custody::reserve_registration(&*self.state.world, &reserve)?.is_none() {
                return Err(Error::Unavailable);
            }
            let entries = batch
                .transfers
                .into_iter()
                .map(|transfer| {
                    if transfer.amount == 0
                        || (release && transfer.from != registration.reserve)
                        || (!release && transfer.from != self.authority)
                    {
                        return Err(Error::Binding);
                    }
                    let amount = Quantity::try_from_numeric(
                        Numeric::try_new(transfer.amount, registration.asset.scale)
                            .map_err(|_| Error::Overflow)?,
                    )
                    .map_err(|_| Error::Overflow)?;
                    Ok((
                        AssetId::with_scope(
                            registration.asset.asset.clone(),
                            transfer.from,
                            registration.balance_scope,
                        ),
                        AssetId::with_scope(
                            registration.asset.asset.clone(),
                            transfer.to,
                            registration.balance_scope,
                        ),
                        amount,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let rows_digest = iroha_crypto::Hash::new(storage::encode(&rows)?);
            let binding =
                storage::encode(&(batch.scheme, batch.asset, self.transaction, rows_digest))?;
            let capability = VerifiedMovements {
                authority: self.authority.clone(),
                reserve,
                release,
                binding,
                entries,
            };
            crate::smartcontracts::isi::asset::isi::execute_verified_kagemusha_movements(
                self.state, capability,
            )?;
        }
        // Every fallible encoding, index conflict, balance and transcript check completed above.
        // The outer WSV transaction keeps these rows and every numeric effect in one rollback scope.
        for (key, bytes) in rows {
            self.state.world.kagemusha_wallet_ledger.insert(key, bytes);
        }
        self.state.world.emit_events(load_event);
        Ok(())
    }
}
