//! Read-only DATA from the canonical ledger plan and retained Unload originals.
use super::*;

/// Exact terms and instruction selected by the one canonical Native Load producer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePreparedLedgerLoadV1 {
    /// Durable App correlation identity; never inferred from the ordinal.
    pub request_id: [u8; 32],
    /// Authenticated installed scheme.
    pub scheme_id: [u8; 32],
    /// Admitted wallet incarnation.
    pub wallet_id: [u8; 32],
    /// Admitted asset scope.
    pub asset_digest: [u8; 32],
    /// Admitted existing account.
    pub payer_account_digest: [u8; 32],
    /// Exactly reserved Native Load ordinal.
    pub ordinal: u128,
    /// Exactly selected amount in atomic units.
    pub amount: u128,
    /// The current producer permits only unquoted Loads, therefore zero.
    pub online_charge: u128,
    /// Exact canonical KagemushaWalletLedger instruction retained by Native.
    pub instruction_original: Vec<u8>,
}

impl LoadPlan {
    fn projection(&self, scope: [[u8; 32]; 4]) -> Result<NativePreparedLedgerLoadV1, Error> {
        if self.request == [0; 32]
            || self.amount == 0
            || scope.contains(&[0; 32])
            || self.instruction.is_empty()
            || self.instruction.len() > LEDGER_INSTRUCTION_MAX_BYTES_V1
        {
            return Err(Error::WitnessLost("retained ledger Load plan bounds"));
        }
        let instruction: KagemushaWalletLedgerV1 = archive::decode(&self.instruction)?;
        let KagemushaWalletLedgerActionV1::IssueLoad {
            wallet,
            asset,
            ordinal,
            request_id,
            amount,
            charge,
        } = instruction.action
        else {
            return Err(Error::WitnessLost("retained ledger Load instruction kind"));
        };
        if instruction.scheme != scope[0]
            || wallet != scope[1]
            || asset != scope[2]
            || ordinal != self.ordinal
            || request_id != self.request
            || amount != self.amount
            || charge.is_some()
        {
            return Err(Error::WitnessLost(
                "retained ledger Load instruction binding",
            ));
        }
        Ok(NativePreparedLedgerLoadV1 {
            request_id,
            scheme_id: scope[0],
            wallet_id: wallet,
            asset_digest: asset,
            payer_account_digest: scope[3],
            ordinal,
            amount,
            online_charge: 0,
            instruction_original: self.instruction.clone(),
        })
    }
}

pub(super) fn selected_load_plan(
    archive: &mut impl index::ObjectStore,
    plans: &index::IndexRoot,
    ordinals: &index::IndexRoot,
    request: &[u8; 32],
    scope: [[u8; 32]; 4],
) -> Result<Option<NativePreparedLedgerLoadV1>, Error> {
    if *request == [0; 32] {
        return Err(Error::Invalid("ledger Load request identity"));
    }
    let Some(address) = plans.get(archive, request)? else {
        return Ok(None);
    };
    let address: [u8; 32] = address
        .try_into()
        .map_err(|_| Error::WitnessLost("ledger Load plan address"))?;
    let plan: LoadPlan =
        archive::decode(&archive.read_object(&address, LEDGER_INSTRUCTION_MAX_BYTES_V1)?)?;
    let value = plan.projection(scope)?;
    if value.request_id != *request
        || ordinals
            .get(archive, &manifest::sequence_key(value.ordinal))?
            .as_deref()
            != Some(address.as_slice())
    {
        return Err(Error::WitnessLost("ledger Load ordinal reservation"));
    }
    Ok(Some(value))
}

// Both roots select the same immutable original. The caller publishes the complete manifest once.
pub(super) fn reserve_load_plan(
    archive: &mut impl index::ObjectStore,
    plans: &mut index::IndexRoot,
    ordinals: &mut index::IndexRoot,
    plan: &LoadPlan,
    scope: [[u8; 32]; 4],
) -> Result<(), Error> {
    plan.projection(scope)?;
    let ordinal = manifest::sequence_key(plan.ordinal);
    if plans.get(archive, &plan.request)?.is_some() || ordinals.get(archive, &ordinal)?.is_some() {
        return Err(Error::OperationConflict);
    }
    let address = archive.write_object(&archive::encode(plan)?, LEDGER_INSTRUCTION_MAX_BYTES_V1)?;
    let next_plans = plans.set(archive, plan.request, &address)?;
    let next_ordinals = ordinals.set(archive, ordinal, &address)?;
    *plans = next_plans;
    *ordinals = next_ordinals;
    Ok(())
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    pub(super) fn load_plan_scope(&self) -> [[u8; 32]; 4] {
        [
            self.scheme_id,
            self.wallet_id,
            self.proofs.asset.asset_digest(),
            self.proofs.enrollment.body.account_digest,
        ]
    }
    /// Recover only the exact retained request. True absence creates no replacement plan.
    /// # Errors
    /// Unavailable custody, malformed or changed original, or inconsistent ordinal reservation.
    pub fn recover_ledger_load(
        &mut self,
        request: &[u8; 32],
    ) -> Result<Option<NativePreparedLedgerLoadV1>, Error> {
        self.metadata()?;
        let selected = self.status()?;
        let (root, manifest) = self.manifest()?;
        let scope = self.load_plan_scope();
        let value = selected_load_plan(
            &mut self.archive,
            &manifest.ledger_load_plans,
            &manifest.ledger_load_ordinals,
            request,
            scope,
        )?;
        if self.manifest()?.0 != root || self.status()? != selected {
            return Err(Error::WitnessLost("ledger Load projection source changed"));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kagemusha_wallet_state_v1::tests::MemoryArchive;
    fn plan(request: u8, ordinal: u128) -> (LoadPlan, [[u8; 32]; 4]) {
        let scope = [[11; 32], [12; 32], [13; 32], [14; 32]];
        let request = [request; 32];
        let instruction = KagemushaWalletLedgerV1 {
            scheme: scope[0],
            action: KagemushaWalletLedgerActionV1::IssueLoad {
                wallet: scope[1],
                asset: scope[2],
                ordinal,
                request_id: request,
                amount: 123,
                charge: None,
            },
        };
        (
            LoadPlan {
                request,
                ordinal,
                amount: 123,
                instruction: archive::encode(&instruction).unwrap(),
            },
            scope,
        )
    }
    #[test]
    fn canonical_load_reservation_refuses_a_second_request_at_the_same_ordinal() {
        let mut store = MemoryArchive::new();
        let (mut requests, mut ordinals) =
            (index::IndexRoot::default(), index::IndexRoot::default());
        let (first, scope) = plan(21, 0);
        reserve_load_plan(&mut store, &mut requests, &mut ordinals, &first, scope).unwrap();
        let roots = (requests, ordinals);
        let (second, _) = plan(22, 0);
        assert!(matches!(
            reserve_load_plan(&mut store, &mut requests, &mut ordinals, &second, scope),
            Err(Error::OperationConflict)
        ));
        assert_eq!(roots, (requests, ordinals));
        assert!(
            selected_load_plan(&mut store, &requests, &ordinals, &second.request, scope)
                .unwrap()
                .is_none()
        );
        let value = selected_load_plan(&mut store, &requests, &ordinals, &first.request, scope)
            .unwrap()
            .unwrap();
        assert_eq!(value.instruction_original, first.instruction);
        let (next, _) = plan(22, 1);
        reserve_load_plan(&mut store, &mut requests, &mut ordinals, &next, scope).unwrap();
        assert_eq!(
            selected_load_plan(&mut store, &requests, &ordinals, &first.request, scope)
                .unwrap()
                .unwrap(),
            value
        );
    }
    #[test]
    fn canonical_load_projection_rejects_changed_scope_terms_and_missing_reservation() {
        let mut store = MemoryArchive::new();
        let (mut requests, mut ordinals) =
            (index::IndexRoot::default(), index::IndexRoot::default());
        let (original, scope) = plan(21, 7);
        reserve_load_plan(&mut store, &mut requests, &mut ordinals, &original, scope).unwrap();
        for i in 0..3 {
            let mut other = scope;
            other[i][0] ^= 1;
            assert!(
                selected_load_plan(&mut store, &requests, &ordinals, &original.request, other)
                    .is_err()
            );
        }
        assert!(
            selected_load_plan(
                &mut store,
                &requests,
                &index::IndexRoot::default(),
                &original.request,
                scope
            )
            .is_err()
        );
        for i in 0..4 {
            let mut altered = original.clone();
            match i {
                0 => altered.request[0] ^= 1,
                1 => altered.amount += 1,
                2 => altered.ordinal += 1,
                _ => altered.instruction.push(0),
            };
            assert!(altered.projection(scope).is_err());
        }
        assert!(selected_load_plan(&mut store, &requests, &ordinals, &[0; 32], scope).is_err());
    }
    #[test]
    fn retained_unload_absence_is_distinct_from_changed_or_corrupt_confirmation() {
        let mut store = MemoryArchive::new();
        let mut confirmations = index::IndexRoot::default();
        let transaction = [31; 32];
        let digest = [32; 32];
        assert!(
            retained_unload_confirmation(&mut store, &confirmations, &transaction, &digest)
                .unwrap()
                .is_none()
        );
        let original = UnloadConfirmation {
            original_digest: digest,
            height: 17,
            block_hash: [33; 32],
        };
        confirmations = confirmations
            .set(
                &mut store,
                transaction,
                &archive::encode(&original).unwrap(),
            )
            .unwrap();
        let found = retained_unload_confirmation(&mut store, &confirmations, &transaction, &digest)
            .unwrap()
            .unwrap();
        assert_eq!(found.height, 17);
        assert_eq!(found.block_hash, [33; 32]);
        assert!(
            retained_unload_confirmation(&mut store, &confirmations, &transaction, &[34; 32])
                .is_err()
        );
        for i in 0..3 {
            let mut changed = original.clone();
            match i {
                0 => changed.original_digest[0] ^= 1,
                1 => changed.height = 1,
                _ => changed.block_hash = [0; 32],
            };
            let altered = confirmations
                .set(&mut store, transaction, &archive::encode(&changed).unwrap())
                .unwrap();
            assert!(
                retained_unload_confirmation(&mut store, &altered, &transaction, &digest).is_err()
            );
        }
    }
}
