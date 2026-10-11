//! KAGEMUSHA's closed instruction boundary. Foreign callers never supply a proof verdict.
//! All ledger effects use the original WSV transaction and canonical asset movement owner.
use super::*;
use crate::kagemusha_wallet_v1::{self as wallet, NativePackageVerifier, wsv::WsvLedger};
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1 as Action, KagemushaWalletLedgerV1},
    kagemusha::*,
};

fn error(error: wallet::Error) -> Error {
    match error {
        wallet::Error::Execution(error) => error,
        error => Error::InvariantViolation(format!("KAGEMUSHA ledger: {error}").into()),
    }
}
fn decode<T>(bytes: &[u8], max: usize) -> wallet::Result<T>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    if bytes.len() > max {
        return Err(wallet::Error::Binding);
    }
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(max))
        .map_err(|_| wallet::Error::Binding)
}

impl Execute for KagemushaWalletLedgerV1 {
    fn execute(
        self,
        authority: &AccountId,
        state: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let verifier = wallet::artifacts::LedgerVerifier::from_state(state, self.scheme);
        match execute_with_verifier(self, authority, state, &verifier) {
            Err(wallet::Error::ArtifactsUnavailable) => {
                Err(state.world.attempt_error_to_instruction_error(
                    crate::execution_attempt::ExecutionAttemptError::Deferred(
                        ivm::error::ExecutionDeferral::VerifierArtifactsUnavailable.into(),
                    ),
                ))
            }
            result => result.map_err(error),
        }
    }
}

/// Internal dependency boundary. Production uses the same-overlay immutable World
/// installation; explicit test fixture verifiers establish orchestration only.
pub(crate) fn execute_with_verifier(
    instruction: KagemushaWalletLedgerV1,
    authority: &AccountId,
    state: &mut StateTransaction<'_, '_>,
    verifier: &impl NativePackageVerifier,
) -> wallet::Result<()> {
    let scheme_id = instruction.scheme;
    if scheme_id == [0; 32] {
        return Err(wallet::Error::Binding);
    }
    if matches!(&instruction.action, Action::IssueLoad { .. }) {
        state.require_direct_kagemusha_load(&instruction, authority)?;
        // Receipt evidence authenticates the original global root, including work on
        // its dataspace lanes. The current execution dataspace is not the root scope.
        let scope = match crate::executor::root_scope::execution_root_scope(state) {
            Ok(scope) => scope,
            Err(_) => {
                if let Some(original) = state.execution_deferral() {
                    return Err(state
                        .attempt_error_to_instruction_error(
                            crate::execution_attempt::ExecutionAttemptError::Deferred(original),
                        )
                        .into());
                }
                return Err(Error::InvariantViolation(
                    "KAGEMUSHA Load requires the original Global root".into(),
                )
                .into());
            }
        };
        if scope != SumeragiRootScope::Global {
            return Err(Error::InvariantViolation(
                "KAGEMUSHA Load requires the original Global root".into(),
            )
            .into());
        }
    }
    let mut ledger = WsvLedger::new(state, authority)?;
    match instruction.action {
        Action::Register {
            scheme,
            asset,
            reserve,
            balance_scope,
        } => {
            let scheme = KagemushaWalletSchemeV1::decode_canonical(&scheme, &scheme_id)?;
            ledger.register(wallet::Registration {
                scheme,
                // AssetScope consists only of a version, UUID, digest and fixed-width scale.
                asset: decode(&asset, KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1)?,
                reserve,
                balance_scope,
            })
        }
        Action::InstallVerifierPack {
            asset,
            manifest_digest,
            pack,
        } => ledger.install_verifier_pack(scheme_id, asset, manifest_digest, pack),
        Action::Activate(bytes) => {
            let activation = KagemushaWalletActivationV1::decode_canonical(&bytes, &scheme_id)?;
            ledger.reserve_package_proof(&activation.bootstrap)?;
            wallet::activate(&mut ledger, verifier, &activation)
        }
        Action::Abandon(bytes) => wallet::abandon(
            &mut ledger,
            &KagemushaWalletAbandonmentV1::decode_canonical(&bytes, &scheme_id)?,
        ),
        Action::CloseLoads(bytes) => {
            let close = KagemushaWalletCloseLoadsV1::decode_canonical(&bytes, &scheme_id)?;
            ledger.reserve_package_proof(&close.package)?;
            wallet::close_loads(&mut ledger, verifier, &close)
        }
        Action::IssueLoad {
            wallet: wallet_id,
            asset,
            ordinal,
            request_id,
            amount,
            charge,
        } => {
            let charge = charge
                .map(|charge| {
                    Ok::<_, wallet::Error>(wallet::LoadCharge {
                        quote: decode(&charge.quote, KAGEMUSHA_WALLET_CHARGE_QUOTE_MAX_BYTES_V1)?,
                        beneficiary: charge.beneficiary,
                    })
                })
                .transpose()?;
            wallet::issue_load(
                &mut ledger,
                &wallet::LoadCommand {
                    scheme: scheme_id,
                    wallet: wallet_id,
                    asset,
                    ordinal,
                    request_id,
                    amount,
                    charge,
                },
            )
            .map(|_| ())
        }
        Action::Unload(bytes) => {
            let claim = KagemushaWalletUnloadClaimV1::decode_canonical(&bytes, &scheme_id)?;
            ledger.reserve_package_proof(&claim.package)?;
            wallet::pay_unload(&mut ledger, verifier, &claim).map(|_| ())
        }
        Action::ClaimFee(bytes) => {
            let claim = KagemushaWalletFeeClaimV1::decode_canonical(&bytes, &scheme_id)?;
            ledger.reserve_package_proof(&claim.payment.send)?;
            wallet::pay_fee(&mut ledger, verifier, &claim).map(|_| ())
        }
        Action::RetainCertificate { asset, certificate } => {
            let certificate: KagemushaWalletSignerCertificateV1 =
                decode(&certificate, KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1)?;
            if certificate.body.scheme_id != scheme_id {
                return Err(wallet::Error::Binding);
            }
            ledger.retain_certificate(asset, certificate)
        }
        Action::RetainCredential {
            credential,
            certificates,
        } => {
            let credential =
                KagemushaWalletCredentialV1::decode_canonical(&credential, &scheme_id)?;
            let certificates = decode(
                &certificates,
                KAGEMUSHA_WALLET_CERTIFICATE_SET_MAX_V1 * KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1
                    + 128,
            )?;
            ledger.retain_credential(wallet::CredentialRecord {
                credential,
                certificates,
            })
        }
        Action::RetainRequest(bytes) => {
            let request: KagemushaWalletRequestV1 =
                decode(&bytes, KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1)?;
            if request.body.scheme_id != scheme_id {
                return Err(wallet::Error::Binding);
            }
            ledger.retain_request(request)
        }
    }
}
