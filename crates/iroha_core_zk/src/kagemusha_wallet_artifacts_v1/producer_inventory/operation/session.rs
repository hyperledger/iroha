//! Complete logical-route qualification with private Receive-program reuse.
//!
//! Routes are independent except a Receive alias, which reuses the strict owner of
//! its program's lowest-index route after that route qualified. When the original
//! source is an immutable snapshot, a bounded set of workers qualifies routes at once
//! in index order of claim. Results, the reported error, progress events and opening
//! work equal those of one worker, which runs every route in index order.

use std::sync::{Arc, Mutex};

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
// owners or resource configuration between first admission and reuse. The
// descriptor memo is the calling qualification's own and leaves with it.
struct QualificationInputs<'a> {
    inventory: &'a AuthenticatedProducerInventoryV1,
    installed: &'a InstalledVerifierPackV1,
    qualified_q: &'a [QualifiedQProgramV1],
    config: ReadConfig,
    admission: super::super::builtin::Admission<'a>,
    descriptors: &'a DescriptorMemo,
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
    stage_memory: crate::kagemusha_wallet_capacity_v1::KagemushaWalletProvingMemoryV1,
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
        let omega = metadata(inventory.read_verifier_metadata(
            inventory.inventory.omega,
            originals,
            inputs.descriptors,
        )?)?;
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

/// Declared original bytes that concurrent route workers may read together. One
/// worker always runs, so a route larger than this still qualifies alone, exactly
/// as in the one-worker order.
const ROUTE_WORKERS_MEMORY_BUDGET_BYTES: u64 = 32 << 20;

// Every original byte one route can read, by signed extent: Omega's and the
// terminal's metadata, then each A and W member's metadata and complete original.
// A read of any other extent is refused, so no route holds more. `None` for a
// route whose records do not resolve; it then runs alone and fails in its turn.
fn route_read_bytes(inventory: &ProducerInventoryV1, program: u32) -> Option<u64> {
    let record = inventory.operations.get(usize::try_from(program).ok()?)?;
    let metadata = |member: u32| {
        let original = inventory.member(member).ok()?;
        Some(
            original
                .descriptor
                .bytes
                .saturating_add(original.verifying_key.bytes),
        )
    };
    let mut bytes = metadata(inventory.omega)?.saturating_add(metadata(*record.a.last()?)?);
    for member in record.a.iter().chain(&record.w).copied() {
        let proving_key = inventory.member(member).ok()?.proving_key.bytes;
        bytes = bytes
            .saturating_add(metadata(member)?.saturating_mul(2))
            .saturating_add(proving_key);
    }
    Some(bytes)
}

// The most workers whose routes' declared reads fit under the budget together, at
// most one per route and per pool thread, and never fewer than one: any `n` routes
// in flight read at most what the `n` largest read.
fn route_workers(mut bytes: Vec<u64>, threads: usize) -> usize {
    bytes.sort_unstable_by_key(|route| core::cmp::Reverse(*route));
    let mut held = 0_u64;
    let mut workers = 0_usize;
    for route in bytes.into_iter().take(threads) {
        held = held.saturating_add(route);
        if workers != 0 && held > ROUTE_WORKERS_MEMORY_BUDGET_BYTES {
            break;
        }
        workers += 1;
    }
    workers.max(1)
}

// One route's checks before its Started event, exactly as the one-worker loop
// made them, and whether it is a Receive route.
#[derive(Clone, Copy)]
struct RouteJob<'a> {
    route_index: u32,
    program: usize,
    q: &'a QualifiedQProgramV1,
    receive: bool,
}

fn route_job(
    index: usize,
    program: u32,
    qualified_q: &[QualifiedQProgramV1],
) -> Result<RouteJob<'_>, Error> {
    let route_index = u32::try_from(index).map_err(|_| Error::Inventory)?;
    let program = usize::try_from(program).map_err(|_| Error::Inventory)?;
    let q = qualified_q.get(program).ok_or(Error::Inventory)?;
    let route = *compiled_routes().get(index).ok_or(Error::Inventory)?;
    Ok(RouteJob {
        route_index,
        program,
        q,
        receive: matches!(route.variant, Variant::Receive | Variant::ReceiveRenewed),
    })
}

// One route's place in the shared batch.
enum Slot<T, E> {
    // Not claimed yet.
    Waiting,
    // Claimed by a worker that has not recorded its result yet.
    Running,
    Qualified(T),
    // Refused before its Started event (`started == false`) or by its own checks.
    Refused { error: E, started: bool },
}

// The state every worker of one route stage shares, behind one lock that is never
// held while a route qualifies.
struct Batch<T, A, E> {
    slots: Vec<Slot<T, E>>,
    // For a Receive alias: its program's lowest-index route, whose owner it reuses.
    leads: Vec<Option<usize>>,
    // A lead's admitted owner, from the moment that lead qualified.
    admitted: Vec<Option<Arc<A>>>,
    // The lowest refused route. No route at or above it starts any more, so later
    // routes never report anything; routes below it all still run.
    refused: usize,
    // Opening work the helper threads did for this stage, taken off their counts.
    helped: OpeningWorkV1,
}

impl<T, A, E> Batch<T, A, E> {
    // Claim the lowest waiting route below the lowest refusal whose lead, for an
    // alias, already qualified. Lower routes are always claimed first, so one
    // worker runs every route in index order.
    fn claim(&mut self) -> Option<(usize, Option<Arc<A>>)> {
        for index in 0..self.refused {
            if !matches!(self.slots.get(index), Some(Slot::Waiting)) {
                continue;
            }
            let lead = match self.leads.get(index).copied().flatten() {
                None => None,
                Some(lead) => match self.admitted.get(lead) {
                    Some(Some(admitted)) => Some(Arc::clone(admitted)),
                    _ => continue,
                },
            };
            if let Some(slot) = self.slots.get_mut(index) {
                *slot = Slot::Running;
            }
            return Some((index, lead));
        }
        None
    }

    fn record(&mut self, index: usize, result: Result<(T, Option<A>), E>) {
        let slot = match result {
            Ok((qualified, admitted)) => {
                if let (Some(admitted), Some(entry)) = (admitted, self.admitted.get_mut(index)) {
                    *entry = Some(Arc::new(admitted));
                }
                Slot::Qualified(qualified)
            }
            Err(error) => {
                self.refused = self.refused.min(index);
                Slot::Refused {
                    error,
                    started: true,
                }
            }
        };
        if let Some(entry) = self.slots.get_mut(index) {
            *entry = slot;
        }
    }
}

// Progress events, reported only by the calling thread and in route order: `next`
// is the lowest route whose Completed event is not reported, `started` whether its
// Started event is. With one worker each event is reported as it happens.
struct Progress<'a> {
    observer: &'a mut dyn FnMut(OperationQualificationProgressV1),
    next: usize,
    started: bool,
}

impl Progress<'_> {
    fn report<T, A, E>(&mut self, batch: &Mutex<Batch<T, A, E>>) {
        let mut events = Vec::new();
        if let Ok(state) = batch.lock() {
            while let Some(slot) = state.slots.get(self.next) {
                let Ok(route_index) = u32::try_from(self.next) else {
                    break;
                };
                let completed = match slot {
                    Slot::Qualified(_) => true,
                    Slot::Running | Slot::Refused { started: true, .. } => false,
                    Slot::Waiting | Slot::Refused { started: false, .. } => break,
                };
                if !self.started {
                    events.push(OperationQualificationProgressV1::Started { route_index });
                    self.started = true;
                }
                if !completed {
                    break;
                }
                events.push(OperationQualificationProgressV1::Completed { route_index });
                self.next += 1;
                self.started = false;
            }
        }
        for event in events {
            (self.observer)(event);
        }
    }
}

// One helper's own handle on a shared immutable view.
struct SharedReader<'a>(&'a (dyn SharedOriginalSourceV1 + Sync));

impl OriginalSourceV1 for SharedReader<'_> {
    fn open(&mut self, digest: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        self.0.open_shared(digest)
    }

    fn shared_view(&self) -> Option<&(dyn SharedOriginalSourceV1 + Sync)> {
        Some(self.0)
    }
}

// Qualify every route on at most `workers` workers and return the results in route
// order, or the error of the lowest refused route: exactly what one worker returns
// for the same immutable source. `routes[i]` is route i's check before it starts
// (an error refuses it unstarted) and, for a Receive alias, the lead whose admitted
// owner it reuses; an alias starts only after its lead qualified. Helpers read the
// source's shared immutable view on the pool; a source without one keeps a single
// worker, the calling thread. Success needs every route qualified once all workers
// joined: a route that never ran is never reported as success.
fn schedule<T, A, E, R>(
    routes: Vec<Result<Option<usize>, E>>,
    workers: usize,
    originals: &mut dyn OriginalSourceV1,
    run: &R,
    observer: &mut dyn FnMut(OperationQualificationProgressV1),
) -> Result<Vec<T>, E>
where
    T: Send,
    A: Send + Sync,
    E: Send + From<Error>,
    R: Fn(usize, Option<&A>, &mut dyn OriginalSourceV1) -> Result<(T, Option<A>), E> + Sync,
{
    let count = routes.len();
    let mut batch = Batch {
        slots: Vec::with_capacity(count),
        leads: Vec::with_capacity(count),
        admitted: (0..count).map(|_| None).collect(),
        refused: count,
        helped: OpeningWorkV1::default(),
    };
    for (index, route) in routes.into_iter().enumerate() {
        match route {
            Ok(lead) => {
                batch.slots.push(Slot::Waiting);
                batch.leads.push(lead);
            }
            Err(error) => {
                batch.refused = batch.refused.min(index);
                batch.slots.push(Slot::Refused {
                    error,
                    started: false,
                });
                batch.leads.push(None);
            }
        }
    }
    let batch = Mutex::new(batch);
    let mut progress = Progress {
        observer,
        next: 0,
        started: false,
    };
    match originals.shared_view() {
        Some(view) => run_workers(
            &batch,
            run,
            &mut SharedReader(view),
            Some(view),
            workers,
            &mut progress,
        ),
        None => run_workers(&batch, run, &mut *originals, None, 1, &mut progress),
    }
    progress.report(&batch);
    let batch = batch.into_inner().map_err(|_| E::from(Error::Inventory))?;
    // Every helper has joined: its work counts once, on this opening's thread.
    super::super::opening_metrics::adopt(batch.helped);
    if batch.refused < count {
        return Err(match batch.slots.into_iter().nth(batch.refused) {
            Some(Slot::Refused { error, .. }) => error,
            _ => Error::Inventory.into(),
        });
    }
    batch
        .slots
        .into_iter()
        .map(|slot| match slot {
            Slot::Qualified(route) => Ok(route),
            _ => Err(Error::Inventory.into()),
        })
        .collect()
}

// The calling thread works on `first` and reports progress; `workers - 1` helpers
// on the pool read `shared`, each through its own handle. All of them join before
// this returns, and helpers never wait for one another: a worker that finds no
// route it may claim stops, and the worker whose lead qualifies claims its aliases.
fn run_workers<T, A, E, R>(
    batch: &Mutex<Batch<T, A, E>>,
    run: &R,
    first: &mut dyn OriginalSourceV1,
    shared: Option<&(dyn SharedOriginalSourceV1 + Sync)>,
    workers: usize,
    progress: &mut Progress<'_>,
) where
    T: Send,
    A: Send + Sync,
    E: Send,
    R: Fn(usize, Option<&A>, &mut dyn OriginalSourceV1) -> Result<(T, Option<A>), E> + Sync,
{
    rayon::in_place_scope(|scope| {
        if let Some(view) = shared {
            for _ in 1..workers {
                scope.spawn(move |_| {
                    let ((), helped) = super::super::opening_metrics::attributed(|| {
                        work(batch, run, &mut SharedReader(view), None);
                    });
                    if let Ok(mut state) = batch.lock() {
                        state.helped = state.helped.plus(helped);
                    }
                });
            }
        }
        work(batch, run, first, Some(progress));
    });
}

// Claim, qualify and record routes until none may be claimed.
fn work<T, A, E, R>(
    batch: &Mutex<Batch<T, A, E>>,
    run: &R,
    originals: &mut dyn OriginalSourceV1,
    mut progress: Option<&mut Progress<'_>>,
) where
    R: Fn(usize, Option<&A>, &mut dyn OriginalSourceV1) -> Result<(T, Option<A>), E>,
{
    loop {
        if let Some(progress) = progress.as_deref_mut() {
            progress.report(batch);
        }
        let Some((index, lead)) = batch.lock().ok().and_then(|mut state| state.claim()) else {
            break;
        };
        if let Some(progress) = progress.as_deref_mut() {
            progress.report(batch);
        }
        let result = run(index, lead.as_deref(), &mut *originals);
        let Ok(mut state) = batch.lock() else {
            break;
        };
        state.record(index, result);
    }
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
    /// Strict import keeps one worker, so routes qualify in index order.
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
            &DescriptorMemo::default(),
        )
    }

    // Only the complete built-in profile owner selects the compiled mode. Every
    // route reuses `descriptors`, which the caller drops when it returns. Routes
    // qualify on as many workers as their declared reads fit under the memory
    // budget, at most one per pool thread, when the source has a shared view.
    #[allow(clippy::too_many_arguments)]
    pub(in super::super) fn qualify_operation_routes_with_admission(
        &self,
        installed: &InstalledVerifierPackV1,
        qualified_q: &[QualifiedQProgramV1],
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        observer: impl FnMut(OperationQualificationProgressV1),
        admission: super::super::builtin::Admission<'_>,
        descriptors: &DescriptorMemo,
    ) -> Result<Vec<QualifiedOperationRouteV1>, OperationQualificationErrorV1> {
        let workers = match admission {
            // Strict import reconstructs each member's proving tables, which no
            // signed extent bounds, so the independent strict generator keeps one
            // worker. A compiled member only hashes and compares what it reads.
            super::super::builtin::Admission::Strict => 1,
            super::super::builtin::Admission::Builtin(_) => route_workers(
                self.inventory
                    .routes
                    .iter()
                    .map(|program| route_read_bytes(&self.inventory, *program).unwrap_or(u64::MAX))
                    .collect(),
                rayon::current_num_threads(),
            ),
        };
        self.qualify_operation_routes_with_workers(
            installed,
            qualified_q,
            originals,
            config,
            observer,
            admission,
            descriptors,
            workers,
        )
    }

    // The route stage on at most `workers` workers (tests choose the count). The
    // result, the reported error, every progress event and, on success, the opening
    // work equal those of one worker, which runs the routes in index order.
    #[allow(clippy::too_many_arguments)]
    fn qualify_operation_routes_with_workers(
        &self,
        installed: &InstalledVerifierPackV1,
        qualified_q: &[QualifiedQProgramV1],
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        mut observer: impl FnMut(OperationQualificationProgressV1),
        admission: super::super::builtin::Admission<'_>,
        descriptors: &DescriptorMemo,
        workers: usize,
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
            descriptors,
        };
        // Each Receive route after the first of its program is an alias of that
        // lead, which is the route whose strict owner the one-worker loop kept.
        let mut jobs = Vec::with_capacity(self.inventory.routes.len());
        let mut routes: Vec<Result<Option<usize>, OperationQualificationErrorV1>> =
            Vec::with_capacity(self.inventory.routes.len());
        let mut receive: Vec<Option<usize>> = vec![None; qualified_q.len()];
        for (index, program) in self.inventory.routes.iter().copied().enumerate() {
            match route_job(index, program, qualified_q) {
                Ok(job) => {
                    let lead = if job.receive {
                        let lead = receive[job.program];
                        receive[job.program] = lead.or(Some(index));
                        lead
                    } else {
                        None
                    };
                    routes.push(Ok(lead));
                    jobs.push(Some(job));
                }
                Err(error) => {
                    routes.push(Err(error.into()));
                    jobs.push(None);
                }
            }
        }
        let run = |index: usize,
                   lead: Option<&AdmittedReceive>,
                   originals: &mut dyn OriginalSourceV1|
         -> Result<
            (QualifiedOperationRouteV1, Option<AdmittedReceive>),
            OperationQualificationErrorV1,
        > {
            let job = jobs.get(index).copied().flatten().ok_or(Error::Inventory)?;
            if let Some(admitted) = lead {
                return Ok((
                    admitted.qualify_alias(&inputs, job.route_index, originals)?,
                    None,
                ));
            }
            let qualified = self.qualify_operation_route_with_admission(
                installed,
                job.q,
                job.route_index,
                originals,
                config,
                admission,
                descriptors,
            )?;
            if !job.receive {
                return Ok((qualified, None));
            }
            let admitted = AdmittedReceive::from_qualified_route(
                &qualified,
                self.inventory
                    .operations
                    .get(job.program)
                    .ok_or(Error::Inventory)?,
            )?;
            Ok((qualified, Some(admitted)))
        };
        schedule(routes, workers, originals, &run, &mut observer)
    }
}

#[cfg(test)]
#[path = "session/tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) use tests::{assert_builtin_receive_alias_controls, assert_receive_alias_controls};
