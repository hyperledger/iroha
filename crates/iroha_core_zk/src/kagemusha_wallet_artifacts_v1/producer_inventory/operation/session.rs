//! Complete logical-route qualification with private Receive-program reuse.

use std::sync::Arc;

use super::*;

/// Observation of one route in complete source qualification; never authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationQualificationProgressV1 {
    /// Qualification is beginning for this zero-based compiled route.
    Started {
        /// Exact zero-based index in the compiled route order.
        route_index: u32,
    },
    /// All source and original checks succeeded for this compiled route.
    Completed {
        /// Exact zero-based index in the compiled route order.
        route_index: u32,
    },
}

// Borrowed once for the entire batch; aliases cannot replace installation, Q
// owners or resource configuration between first admission and reuse.
struct QualificationInputs<'a> {
    inventory: &'a AuthenticatedProducerInventoryV1,
    installed: &'a InstalledVerifierPackV1,
    qualified_q: &'a [QualifiedQProgramV1],
    config: ReadConfig,
    admission: super::super::builtin::Admission<'a>,
}

// This cannot be constructed from signed metadata alone. The only production
// constructor caller is the batch below, after its own complete typed import.
struct AdmittedReceive {
    installation: ([u8; 32], [u8; 32]),
    program: u32,
    record: OperationV1,
    owner: Arc<receive::Prover>,
    terminal: KeyArtifact<Eq>,
    omega: KeyArtifact<Ep>,
    a_seals: Vec<InstalledSourceSealV1<Eq>>,
    w_seals: Vec<InstalledSourceSealV1<Ep>>,
    stage_memory: u64,
}

impl AdmittedReceive {
    fn from_qualified_route(
        route: &QualifiedOperationRouteV1,
        record: &OperationV1,
    ) -> Result<Self, OperationQualificationErrorV1> {
        let QualifiedOperationOwnerV1::Receive(owner) = &route.owner else {
            return Err(OperationQualificationErrorV1::Source);
        };
        Ok(Self {
            installation: route.installation,
            program: route.program,
            // Successful typed qualification already compared every context
            // word with the canonical native Plan before importing all stages.
            record: record.clone(),
            owner: Arc::clone(owner),
            terminal: route.terminal.clone(),
            omega: route.omega.clone().ok_or(Error::Inventory)?,
            a_seals: route.a_seals.clone(),
            w_seals: route.w_seals.clone(),
            stage_memory: route.stage_memory,
        })
    }

    fn qualify_alias(
        &self,
        inputs: &QualificationInputs<'_>,
        route_index: u32,
        originals: &mut dyn OriginalSourceV1,
    ) -> Result<QualifiedOperationRouteV1, OperationQualificationErrorV1> {
        let inventory = inputs.inventory;
        let installed = inputs.installed;
        let config = inputs.config;
        let identity = (
            installed.verifier().scheme().scheme_id(),
            installed.verifier().manifest_digest(),
        );
        let index = usize::try_from(route_index).map_err(|_| Error::Inventory)?;
        let route = *compiled_routes().get(index).ok_or(Error::Inventory)?;
        let program = *inventory
            .inventory
            .routes
            .get(index)
            .ok_or(Error::Inventory)?;
        let qualified_q = inputs
            .qualified_q
            .get(usize::try_from(program).map_err(|_| Error::Inventory)?)
            .ok_or(Error::Inventory)?;
        if identity != inventory.installation()
            || identity != self.installation
            || program != self.program
            || qualified_q.identity() != (identity, program)
        {
            return Err(Error::Authority.into());
        }
        let record = inventory
            .inventory
            .operations
            .get(usize::try_from(program).map_err(|_| Error::Inventory)?)
            .ok_or(Error::Inventory)?;
        require_route(record, route)?;
        if !matches!(route.variant, Variant::Receive | Variant::ReceiveRenewed)
            || record != &self.record
            || record.a.len() != self.a_seals.len()
            || record.w.len() != self.w_seals.len()
            || record.a.len() != receive::A_STAGE_COUNT
            || record.w.len() != receive::W_STAGE_COUNT
        {
            return Err(OperationQualificationErrorV1::Source);
        }
        if config.maximum_bytes == 0 || config.maximum_bytes > PROVING_KEY_MAX_BYTES_V1 {
            return Err(Error::Inventory.into());
        }
        // All profile/member/row/role-byte preflights precede any original I/O,
        // including the Omega metadata read. No previous, larger cap is inherited.
        for (stage, member) in record.a.iter().copied().enumerate() {
            let seal = self.a_seals[stage].seal(member)?;
            let view = self
                .owner
                .bind_a(stage, seal, None)
                .map_err(|error| import_error(error, OperationQualificationErrorV1::A(stage)))?;
            if view.binding().n() > config.maximum_rows {
                return Err(OperationQualificationErrorV1::A(stage));
            }
            preflight_original(inventory, member, config.maximum_bytes)?;
        }
        for (stage, member) in record.w.iter().copied().enumerate() {
            let seal = self.w_seals[stage].seal(member)?;
            let view = self
                .owner
                .bind_w(stage, seal, None)
                .map_err(|error| import_error(error, OperationQualificationErrorV1::W(stage)))?;
            if view.binding().n() > config.maximum_rows {
                return Err(OperationQualificationErrorV1::W(stage));
            }
            preflight_original(inventory, member, config.maximum_bytes)?;
        }
        let omega =
            metadata(inventory.read_verifier_original(inventory.inventory.omega, originals)?)?;
        if omega.binding() != self.omega.binding()
            || omega.key().to_bytes() != self.omega.key().to_bytes()
        {
            return Err(OperationQualificationErrorV1::Source);
        }
        for (stage, member) in record.a.iter().copied().enumerate() {
            let compiled = inputs.admission.member(&[
                3,
                route_index,
                u32::try_from(stage).map_err(|_| Error::Inventory)?,
            ])?;
            match compiled {
                Some(compiled) => {
                    let bytes = inventory.read_original(member, originals, config.maximum_bytes)?;
                    let seal = self.a_seals[stage].seal(member)?;
                    let view = self.owner.bind_a(stage, seal, None).map_err(|error| {
                        import_error(error, OperationQualificationErrorV1::A(stage))
                    })?;
                    super::super::builtin::require_member_source(
                        compiled,
                        &bytes,
                        installed.verifier().vesta_parameters(16)?.as_ref(),
                        config,
                        view,
                        seal,
                    )?;
                }
                None => inventory.revalidate_original_cancellable(
                    member,
                    originals,
                    config.maximum_bytes,
                    None,
                )?,
            }
            if let Some(member) = record.w.get(stage).copied() {
                let compiled = inputs.admission.member(&[
                    4,
                    route_index,
                    u32::try_from(stage).map_err(|_| Error::Inventory)?,
                ])?;
                match compiled {
                    Some(compiled) => {
                        let bytes =
                            inventory.read_original(member, originals, config.maximum_bytes)?;
                        let seal = self.w_seals[stage].seal(member)?;
                        let view = self.owner.bind_w(stage, seal, None).map_err(|error| {
                            import_error(error, OperationQualificationErrorV1::W(stage))
                        })?;
                        super::super::builtin::require_member_source(
                            compiled,
                            &bytes,
                            installed.verifier().pallas_parameters().as_ref(),
                            config,
                            view,
                            seal,
                        )?;
                    }
                    None => inventory.revalidate_original_cancellable(
                        member,
                        originals,
                        config.maximum_bytes,
                        None,
                    )?,
                }
            }
        }
        Ok(QualifiedOperationRouteV1 {
            installation: identity,
            route: route_index,
            program,
            owner: QualifiedOperationOwnerV1::Receive(Arc::clone(&self.owner)),
            terminal: self.terminal.clone(),
            omega: Some(omega),
            a_seals: self.a_seals.clone(),
            w_seals: self.w_seals.clone(),
            stage_memory: self.stage_memory,
        })
    }
}

fn preflight_original(
    inventory: &AuthenticatedProducerInventoryV1,
    member: u32,
    maximum_pk_bytes: usize,
) -> Result<(), Error> {
    let original = inventory.inventory.member(member)?;
    original.descriptor.length(DESCRIPTOR_MAX_BYTES_V1)?;
    original.verifying_key.length(VERIFYING_KEY_MAX_BYTES_V1)?;
    original.proving_key.length(maximum_pk_bytes)?;
    Ok(())
}

// Identity-only preflight; this has no source or key-authority return value.
fn require_program_identities(
    installation: ([u8; 32], [u8; 32]),
    expected_count: usize,
    identities: impl ExactSizeIterator<Item = (([u8; 32], [u8; 32]), u32)>,
) -> Result<(), Error> {
    if identities.len() != expected_count {
        return Err(Error::Inventory);
    }
    for (program, observed) in identities.enumerate() {
        if observed
            != (
                installation,
                u32::try_from(program).map_err(|_| Error::Inventory)?,
            )
        {
            return Err(Error::Authority);
        }
    }
    Ok(())
}

impl AuthenticatedProducerInventoryV1 {
    /// Qualify every compiled route against this installation and complete Q vector.
    ///
    /// Each distinct Receive program is strictly source imported once within this
    /// call. Its later selector aliases share that immutable native owner and its
    /// private seals only after all exact signed originals have been reread under
    /// the current limits. Other operations always use their strict route importer.
    /// Original-reader cancellation has the same semantics as the standalone
    /// qualifier: a source's cancellation error propagates without a success result.
    /// All returned route identities remain distinct; complete Omega source closure
    /// and native genesis/finality qualification are separate mandatory operations.
    /// # Errors
    /// Wrong/incomplete Q vector or installation, any route/source mismatch,
    /// unavailable/corrupt original, cancellation or a local resource bound failure.
    pub fn qualify_operation_routes(
        &self,
        installed: &InstalledVerifierPackV1,
        qualified_q: &[QualifiedQProgramV1],
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        observer: impl FnMut(OperationQualificationProgressV1),
    ) -> Result<Vec<QualifiedOperationRouteV1>, OperationQualificationErrorV1> {
        self.qualify_operation_routes_with_admission(
            installed,
            qualified_q,
            originals,
            config,
            observer,
            super::super::builtin::Admission::Strict,
        )
    }

    // Only the complete built-in profile owner selects the compiled mode.
    pub(in super::super) fn qualify_operation_routes_with_admission(
        &self,
        installed: &InstalledVerifierPackV1,
        qualified_q: &[QualifiedQProgramV1],
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        mut observer: impl FnMut(OperationQualificationProgressV1),
        admission: super::super::builtin::Admission<'_>,
    ) -> Result<Vec<QualifiedOperationRouteV1>, OperationQualificationErrorV1> {
        let identity = (
            installed.verifier().scheme().scheme_id(),
            installed.verifier().manifest_digest(),
        );
        if identity != self.installation() {
            return Err(Error::Authority.into());
        }
        require_program_identities(
            identity,
            self.inventory.operations.len(),
            qualified_q.iter().map(QualifiedQProgramV1::identity),
        )?;
        let inputs = QualificationInputs {
            inventory: self,
            installed,
            qualified_q,
            config,
            admission,
        };
        let mut receive: Vec<Option<AdmittedReceive>> =
            (0..qualified_q.len()).map(|_| None).collect();
        let mut routes = Vec::with_capacity(self.inventory.routes.len());
        for (index, program) in self.inventory.routes.iter().copied().enumerate() {
            let route_index = u32::try_from(index).map_err(|_| Error::Inventory)?;
            let program = usize::try_from(program).map_err(|_| Error::Inventory)?;
            let q = qualified_q.get(program).ok_or(Error::Inventory)?;
            let route = *compiled_routes().get(index).ok_or(Error::Inventory)?;
            observer(OperationQualificationProgressV1::Started { route_index });
            let qualified = if matches!(route.variant, Variant::Receive | Variant::ReceiveRenewed) {
                if let Some(admitted) = &receive[program] {
                    admitted.qualify_alias(&inputs, route_index, originals)?
                } else {
                    let qualified = self.qualify_operation_route_with_admission(
                        installed,
                        q,
                        route_index,
                        originals,
                        config,
                        admission,
                    )?;
                    receive[program] = Some(AdmittedReceive::from_qualified_route(
                        &qualified,
                        self.inventory
                            .operations
                            .get(program)
                            .ok_or(Error::Inventory)?,
                    )?);
                    qualified
                }
            } else {
                self.qualify_operation_route_with_admission(
                    installed,
                    q,
                    route_index,
                    originals,
                    config,
                    admission,
                )?
            };
            observer(OperationQualificationProgressV1::Completed { route_index });
            routes.push(qualified);
        }
        Ok(routes)
    }
}

#[cfg(test)]
#[path = "session/tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) use tests::{assert_builtin_receive_alias_controls, assert_receive_alias_controls};
