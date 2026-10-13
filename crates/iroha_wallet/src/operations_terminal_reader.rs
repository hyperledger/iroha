//! Call-local immutable terminal records with fresh native custody on every inspection.
use super::super::stream_token_custody::CustodyExpectation;
use super::*;

/// Read-only custody inspector retaining at most one immutable retired request.
///
/// Every call reacquires the native journal and lock, reads its complete fixed inventory and
/// exact bounded records, and verifies the newly supplied request and options. Only unchanged
/// canonical Request/Retired bytes under the same native identities can reuse their privately
/// decoded values and the retained Plan's validation timestamp. Each new expected Plan is
/// still constructed and compared. No journal handle, lock, phase verdict or authorization
/// survives a call.
/// The borrowed account fixes the original configuration; the private records have no mutation
/// interface. This owner cannot prepare, retire, sign or submit an operation.
pub struct CustodyPreparationReader<'account> {
    account: &'account AccountService,
    previous: Option<TerminalRecords>,
}

impl<'account> CustodyPreparationReader<'account> {
    /// Bind one call-local reader to the exact immutable account owner.
    #[must_use]
    pub const fn new(account: &'account AccountService) -> Self {
        Self {
            account,
            previous: None,
        }
    }

    /// Inspect the exact Configure request under its retained native parent.
    ///
    /// # Errors
    /// Refuses unsafe or changed custody, malformed records, or different request and fee terms.
    pub fn inspect_configure_in_parent(
        &mut self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        expected: &StreamTokenCustodyConfigureRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect(
            parent,
            name,
            NativeOperationKind::StreamTokenCustodyConfigure,
            CustodyExpectation::Configure(expected),
        )
    }

    /// Inspect the exact Enroll request under its retained native parent.
    ///
    /// # Errors
    /// Refuses unsafe or changed custody, malformed records, or different request and fee terms.
    pub fn inspect_enroll_in_parent(
        &mut self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        expected: &StreamTokenCustodyEnrollRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect(
            parent,
            name,
            NativeOperationKind::StreamTokenCustodyEnroll,
            CustodyExpectation::Enroll(expected),
        )
    }

    fn inspect(
        &mut self,
        parent: &iroha_fs::PrivateDirectory,
        name: &std::ffi::OsStr,
        kind: NativeOperationKind,
        expected: CustodyExpectation<'_>,
    ) -> Result<VerifiedNativePreparation> {
        // Eligibility is decided before the wallet's own finite decoder scope. An inherited
        // owner gets the literal original physical recipe, including its early refusals.
        if norito::core::decode_limits_active() {
            self.previous = None;
            return self.account.inspect_preparation_in_parent(
                parent,
                name,
                kind,
                Some(OperationExpectation::Custody(expected)),
            );
        }
        // Taking the sole entry before I/O makes every refusal/absence clear it. No success or
        // source observation is lent across this call; exact bytes are freshly read lazily in
        // the original Request -> Payload -> Operation -> Retired -> dispatch order.
        let mut previous = self.previous.take();
        let _profile =
            ChainDiscriminantGuard::enter(self.account.config.account_chain_discriminant);
        let (inspection, next) =
            norito::core::with_decode_limits_scope(LIMITS, || -> Result<_> {
                let Some(journal) = Journal::open_optional_child(parent, name)? else {
                    return Ok((VerifiedNativePreparation::missing(), None));
                };
                let (retained, observed) = Retained::read_with_recipe(
                    &journal,
                    &self.account.config,
                    ReadRecipe::Terminal(&mut previous),
                )?;
                // Keep the exact purpose gate before the fresh expectation. The optional
                // timestamp belongs to these just-observed Request bytes, not this caller.
                eyre::ensure!(
                    retained.request.operation.kind() == kind,
                    "different native preparation purpose"
                );
                let custody_plan = expected.verify_with_timestamp(
                    &retained.request.selection(),
                    observed.as_ref().and_then(|value| value.custody_plan),
                )?;
                if !retained.retired {
                    return Ok((retained.into_inspection()?, None));
                }
                let observed =
                    observed.ok_or_else(|| eyre!("terminal read lost its native observation"))?;
                let retirement = observed
                    .retirement
                    .ok_or_else(|| eyre!("terminal read lost its original retirement"))?;
                let inspection = VerifiedNativePreparation {
                    phase: retained.phase(),
                    request_sha256: Some(retained.request.commitment()?),
                    signed: retained.signed,
                    unprepared: None,
                };
                Ok((
                    inspection,
                    Some(TerminalRecords {
                        request: ObservedRecord {
                            value: retained.request,
                            observation: observed.request,
                        },
                        retirement,
                        custody_plan: Some(custody_plan),
                    }),
                ))
            })?;
        self.previous = next;
        Ok(inspection)
    }
}

#[cfg(test)]
thread_local! {
    static REQUEST_VERIFICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
pub(super) fn record_request_verification() {
    REQUEST_VERIFICATIONS.with(|count| count.set(count.get() + 1));
}
#[cfg(test)]
pub(in crate::operations) fn count_request_verifications<T>(
    read: impl FnOnce() -> T,
) -> (T, usize) {
    REQUEST_VERIFICATIONS.with(|count| {
        let before = count.get();
        let result = read();
        (result, count.get() - before)
    })
}
