//! Canonical online Unload DATA from a permanent request and released original.
use super::*;
use iroha_data_model::account::AccountId;

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    pub(in crate::kagemusha_wallet_state_v1) fn retained_unload_claim(
        &mut self,
        request_id: &[u8; 32],
        account: &AccountId,
        beneficiary_original: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        if *request_id == [0; 32] {
            return Err(Error::Invalid("Unload request identity"));
        }
        if beneficiary_original.is_some_and(|bytes| {
            bytes.is_empty() || bytes.len() > KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1
        }) {
            return Err(Error::Invalid("Unload beneficiary original bound"));
        }
        let (_, manifest) = self.manifest()?;
        let entry = self
            .preparation_entry(&manifest, request_id)?
            .ok_or(Error::Invalid("unknown Unload request"))?;
        let original = self
            .archive
            .read_object(&entry.request, REQUEST_MAX_BYTES)?;
        let (scheme, _) = self.proofs.ledger_scope()?;
        let intent = NativeIntentV1::decode(&original, &scheme)?;
        intent
            .validate(&scheme)
            .map_err(|_| Error::WitnessLost("Unload retained intent"))?;
        let request = intent
            .user_request()
            .ok_or(Error::Invalid("Unload request kind"))?;
        let OperationActionV1::Unload { amount, charge } = &request.action else {
            return Err(Error::Invalid("Unload request kind"));
        };
        if request.request_id != *request_id {
            return Err(Error::WitnessLost("Unload request binding"));
        }
        if entry.capsule.is_some() != entry.operation.is_some() {
            return Err(Error::WitnessLost("Unload operation mapping"));
        }
        let operation = entry.operation.ok_or(Error::Pending)?;
        let capsule = entry
            .capsule
            .ok_or(Error::WitnessLost("Unload capsule mapping"))?;
        let retained = match self.custody.lookup(&operation)? {
            Lookup::Retained(value) => value,
            Lookup::SelectedUnsigned { capsule_digest } if capsule_digest == capsule => {
                return Err(Error::Pending);
            }
            Lookup::Unknown => return Err(Error::Pending),
            Lookup::SelectedUnsigned { .. } | Lookup::Archived(_) | Lookup::DeliveryDataLoss => {
                return Err(Error::WitnessLost("Unload completion custody"));
            }
        };
        if retained.operation_id != operation
            || retained.capsule_digest != capsule
            || retained.record.version != KAGEMUSHA_WALLET_VERSION_V1
            || retained.record.wallet_id != self.wallet_id
            || retained.record.operation_id != operation
            || retained.record.capsule_digest != capsule
        {
            return Err(Error::WitnessLost("Unload retained operation binding"));
        }
        let plan_address = entry
            .plan
            .ok_or(Error::WitnessLost("Unload plan mapping"))?;
        let plan: Plan = archive::decode(&self.archive.read_object(&plan_address, PLAN_BOUND)?)?;
        plan.require(&self.scheme_id, &self.wallet_id, &intent, &original)?;
        if plan.request_object != entry.request
            || manifest
                .capsule_plans
                .get(&mut self.archive, &capsule)?
                .as_deref()
                != Some(plan_address.as_slice())
        {
            return Err(Error::WitnessLost("Unload selected plan binding"));
        }
        let package: KagemushaWalletPackageV1 = archive::decode(&retained.record.output)?;
        if package.receipt != retained.record.receipt
            || package.receipt.operation_id != operation
            || package.receipt.capsule_digest != capsule
        {
            return Err(Error::WitnessLost("Unload package binding"));
        }
        let (credential, certificates) = plan.draft.unload_identity(
            &mut self.archive,
            &package,
            &self.scheme_id,
            &self.wallet_id,
        )?;
        compose(
            &scheme,
            *amount,
            charge.as_ref(),
            credential,
            certificates,
            package,
            account,
            beneficiary_original,
        )
    }
}

// Each argument is one already selected original or an explicit DATA projection input. This
// does not receive proof/readiness verdicts and does not re-sign, submit or acknowledge a claim.
#[expect(
    clippy::too_many_arguments,
    reason = "exact retained Unload originals and projection inputs"
)]
fn compose(
    scheme: &KagemushaWalletSchemeV1,
    amount: u128,
    charge: Option<&ChargeOriginalsV1>,
    credential: KagemushaWalletCredentialV1,
    certificates: KagemushaWalletCertificateSetV1,
    package: KagemushaWalletPackageV1,
    account: &AccountId,
    beneficiary_original: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    if !matches!(package.statement.effect, KagemushaWalletEffectV1::Unload { amount: actual, .. } if actual == amount)
    {
        return Err(Error::WitnessLost("Unload retained amount"));
    }
    let mut selected = vec![*valid(certificates.certificate(
        &credential.body.issuer_certificate,
        KagemushaWalletSignerRoleV1::Enrollment,
    ))?];
    let charge = match (charge, beneficiary_original) {
        (None, None) => KagemushaWalletUnloadChargeV1::None,
        (Some(originals), Some(bytes)) => {
            let quote = valid(KagemushaWalletChargeQuoteV1::decode_canonical(
                &originals.quote,
                &scheme.scheme_id(),
            ))?;
            let set: KagemushaWalletCertificateSetV1 = archive::decode(&originals.certificates)?;
            selected.push(*valid(set.certificate(
                &quote.body.signer_certificate,
                KagemushaWalletSignerRoleV1::RegulatoryPolicy,
            ))?);
            let beneficiary: AccountId = archive::decode(bytes)
                .map_err(|_| Error::Invalid("Unload beneficiary canonical original"))?;
            KagemushaWalletUnloadChargeV1::Quoted { quote, beneficiary }
        }
        _ => return Err(Error::Invalid("Unload charge beneficiary presence")),
    };
    let claim = KagemushaWalletUnloadClaimV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        credential,
        package,
        account: account.clone(),
        charge,
        certificates: valid(KagemushaWalletCertificateSetV1::new(selected))?,
    };
    valid(claim.verify(scheme))?;
    valid(claim.to_canonical_bytes())
}

#[cfg(test)]
#[path = "unload_tests.rs"]
mod tests;
