//! One genuine native A/W task with complete ordered source restoration.
//!
//! The family session is prepared from the step's complete inputs, or resumed from the
//! previous sub-proof of the same step (D6a/D6b) together with the A and W checkpoints that
//! sub-proof restored. Either way, every durable checkpoint beyond those is restored strictly
//! from its bytes before the next proof uses it, and only the session and restored checkpoints
//! are retained afterwards, never the proof this task produced.

use super::*;

/// The family session of a step and the latest A and W checkpoints restored from durable
/// bytes into it, detached between two sub-proofs. Never a produced checkpoint.
pub(super) struct ChainStateV1<S, A, W> {
    session: S,
    a: Option<A>,
    w: Option<W>,
}

/// A one-stage family's session: lean Bootstrap, Load, Unload and Retiring. Its one
/// unsplit A has no W and its only checkpoint, the terminal, is restored straight into
/// the Omega input, so no checkpoint is retained.
pub(super) struct SingleStateV1<S> {
    session: S,
}

/// The retained family session of one route, by native family.
pub(super) enum FamilyStateV1 {
    Bootstrap(Box<SingleStateV1<bootstrap::RetainedSession>>),
    Load(Box<SingleStateV1<load::RetainedSession>>),
    Send(Box<ChainStateV1<send::RetainedSession, send::ACheckpoint, send::WCheckpoint>>),
    Receive(
        Box<ChainStateV1<receive::RetainedSession, receive::ACheckpoint, receive::WCheckpoint>>,
    ),
    Archive(
        Box<ChainStateV1<archive::RetainedSession, archive::ACheckpoint, archive::WCheckpoint>>,
    ),
    Consuming(Box<SingleStateV1<consuming::RetainedSession>>),
    Refresh(
        Box<ChainStateV1<refresh::RetainedSession, refresh::ACheckpoint, refresh::WCheckpoint>>,
    ),
}

/// Where a family session comes from.
pub(super) enum SessionSourceV1 {
    /// The step's complete inputs, verified again by the family `prepare`.
    Prepare(Box<OperationInputsV1>),
    /// The session the previous sub-proof of this step retained, re-admitted by the locked
    /// prepare on this installed prover instance.
    Resume(FamilyStateV1),
}

// The native families deliberately retain their typed source capabilities. This
// macro shares the scheduler only; every proof/restore dispatch remains static.
macro_rules! chain {
    ($worker:expr, $route:expr, $owner:expr, $session:expr, $restored:expr, $checkpoints:expr,
     $cancel:expr, $public:expr, $order:ident, $family:ident) => {{
        let owner = $owner;
        #[cfg(test)]
        eprintln!(
            "NATIVE_FOLD_STAGE route={:?} phase=prepare retained={}",
            $route,
            $checkpoints.len()
        );
        let (session, mut a, mut w, restored) = match $session {
            SessionSourceV1::Prepare(inputs) => match *inputs {
                OperationInputsV1::$family(input) => (
                    proof(owner.prepare_cancellable(
                        input,
                        $worker.budget,
                        Some($cancel.prover_token()),
                    ))?,
                    None,
                    None,
                    0,
                ),
                _ => return Err(Error::Proof("native route/input mismatch")),
            },
            SessionSourceV1::Resume(FamilyStateV1::$family(state)) => {
                let ChainStateV1 { session, a, w } = *state;
                // The locked prepare re-admitted this session on this same installed prover
                // instance, which every job reaches through the shared sources, so this
                // resume cannot refuse. A refusal is never a proof verdict: the turn ends
                // unpublished and the next one runs cold. Tests count it, and the genuine
                // fold helper requires zero.
                let Ok(session) = owner.resume(session) else {
                    #[cfg(test)]
                    super::retention::count(|counts| counts.refusals += 1);
                    return Err(Error::Cancelled);
                };
                #[cfg(test)]
                super::retention::count(|counts| counts.resumes += 1);
                (session, a, w, $restored)
            }
            SessionSourceV1::Resume(_) => {
                return Err(Error::Proof("native route/input mismatch"));
            }
        };
        let layouts = proof(owner.checkpoint_layouts())?;
        let checkpoints = $checkpoints;
        if checkpoints.len() > layouts.len() {
            return Err(Error::Proof("extra native checkpoint"));
        }
        if restored > checkpoints.len() {
            // The locked prepare admitted the retained payloads as a prefix of this list.
            #[cfg(test)]
            super::retention::count(|counts| counts.refusals += 1);
            return Err(Error::Cancelled);
        }
        for (position, original) in checkpoints.iter().enumerate().skip(restored) {
            #[cfg(test)]
            eprintln!(
                "NATIVE_FOLD_STAGE route={:?} phase=restore position={position}",
                $route
            );
            $cancel.check()?;
            if original.len() != layouts[position].payload_bytes() {
                return Err(Error::Proof("native checkpoint length"));
            }
            if position == 0 {
                a = Some(proof(session.restore_first_checkpoint_cancellable(
                    original,
                    $worker.budget,
                    Some($cancel.prover_token()),
                ))?);
            } else if position % 2 == 1 {
                w = Some(proof(session.restore_wrapper_checkpoint_cancellable(
                    a.as_ref().ok_or(Error::Proof("native A source"))?,
                    original,
                    $worker.budget,
                    Some($cancel.prover_token()),
                ))?);
            } else {
                a = Some(proof(session.restore_a_checkpoint_cancellable(
                    w.as_ref().ok_or(Error::Proof("native W source"))?,
                    original,
                    $worker.budget,
                    Some($cancel.prover_token()),
                ))?);
            }
            #[cfg(test)]
            super::retention::count(|counts| counts.restores += 1);
        }
        $cancel.check()?;
        let position = checkpoints.len();
        #[cfg(test)]
        eprintln!(
            "NATIVE_FOLD_STAGE route={:?} phase=produce position={position}",
            $route
        );
        if position == layouts.len() {
            let terminal = proof(session.terminal_cancellable(
                a.as_ref().ok_or(Error::Proof("native terminal source"))?,
                $worker.budget,
                Some($cancel.prover_token()),
            ))?;
            (
                NativeStageProgressV1::Terminal(omega::Input {
                    key: proof($worker.sources.route($route))?
                        .terminal()
                        .key()
                        .clone(),
                    proof: terminal.proof,
                    frame: terminal
                        .instances
                        .try_into()
                        .map_err(|_| Error::Proof("terminal frame"))?,
                    public: $public,
                    pallas: terminal.pallas,
                }),
                None,
            )
        } else {
            let fold = $worker.fold_config($cancel);
            let config = $worker.prover_config($cancel);
            let encoded = if position == 0 {
                let key = $worker
                    .sources
                    .bind_a_cancellable($route, 0, $worker.read, Some($cancel.prover_token()))
                    .map_err(artifact)?;
                $cancel.check()?;
                fold_metrics::enter(FoldPhaseV1::Prove);
                let source = proof(session.first(
                    &key,
                    fresh_fold_tape::<Ep>($cancel.prover_token())?,
                    &fold,
                    ProverRandomness::os(),
                    config,
                ))?;
                proof(session.encode_a_checkpoint_cancellable(
                    &source,
                    $worker.budget,
                    Some($cancel.prover_token()),
                ))?
            } else if position % 2 == 1 {
                let key = $worker
                    .sources
                    .bind_w_cancellable(
                        $route,
                        position / 2,
                        $worker.read,
                        Some($cancel.prover_token()),
                    )
                    .map_err(artifact)?;
                $cancel.check()?;
                fold_metrics::enter(FoldPhaseV1::Prove);
                let source = a.as_ref().ok_or(Error::Proof("native A source"))?;
                let next = proof(call_wrapper!(
                    $order, session, source, key, fold, config, $cancel
                ))?;
                proof(session.encode_wrapper_checkpoint_cancellable(
                    &next,
                    $worker.budget,
                    Some($cancel.prover_token()),
                ))?
            } else {
                let key = $worker
                    .sources
                    .bind_a_cancellable(
                        $route,
                        position / 2,
                        $worker.read,
                        Some($cancel.prover_token()),
                    )
                    .map_err(artifact)?;
                $cancel.check()?;
                fold_metrics::enter(FoldPhaseV1::Prove);
                let source = w.as_ref().ok_or(Error::Proof("native W source"))?;
                let next = proof(call_advance!(
                    $order, session, source, key, fold, config, $cancel
                ))?;
                proof(session.encode_a_checkpoint_cancellable(
                    &next,
                    $worker.budget,
                    Some($cancel.prover_token()),
                ))?
            };
            if encoded.len() != layouts[position].payload_bytes() {
                return Err(Error::Proof("native output length"));
            }
            $cancel.check()?;
            (
                NativeStageProgressV1::Checkpoint(PrivateArchiveBytes::from_guarded(
                    zeroize::Zeroizing::new(encoded),
                )),
                // Only the session and the checkpoints restored from durable bytes are kept;
                // the proof produced above enters the next sub-proof through its bytes.
                Some(FamilyStateV1::$family(Box::new(ChainStateV1 {
                    session: session.into_retained(),
                    a,
                    w,
                }))),
            )
        }
    }};
}
macro_rules! call_wrapper {
    (source_first,$session:ident,$source:ident,$key:ident,$fold:ident,$config:ident,$cancel:expr) => {
        $session.wrapper(
            $source,
            &$key,
            fresh_fold_tape::<Eq>($cancel.prover_token())?,
            &$fold,
            ProverRandomness::os(),
            $config,
        )
    };
    (key_first,$session:ident,$source:ident,$key:ident,$fold:ident,$config:ident,$cancel:expr) => {
        $session.wrapper(
            &$key,
            $source,
            fresh_fold_tape::<Eq>($cancel.prover_token())?,
            &$fold,
            ProverRandomness::os(),
            $config,
        )
    };
}
macro_rules! call_advance {
    (source_first,$session:ident,$source:ident,$key:ident,$fold:ident,$config:ident,$cancel:expr) => {
        $session.advance(
            $source,
            &$key,
            fresh_fold_tape::<Ep>($cancel.prover_token())?,
            &$fold,
            ProverRandomness::os(),
            $config,
        )
    };
    (key_first,$session:ident,$source:ident,$key:ident,$fold:ident,$config:ident,$cancel:expr) => {
        $session.advance(
            &$key,
            $source,
            fresh_fold_tape::<Ep>($cancel.prover_token())?,
            &$fold,
            ProverRandomness::os(),
            $config,
        )
    };
}

// Bootstrap's terminal forwards its single Q opening; Load, Unload and Retiring fold their
// hard predecessor with it and take the fold tape from the caller, as a first A does.
macro_rules! call_terminal {
    (plain, $session:ident, $key:ident, $worker:expr, $cancel:expr) => {
        $session.terminal(
            &$key,
            ProverRandomness::os(),
            $worker.prover_config($cancel),
        )
    };
    (folded, $session:ident, $key:ident, $worker:expr, $cancel:expr) => {
        $session.terminal(
            &$key,
            fresh_fold_tape::<Ep>($cancel.prover_token())?,
            &$worker.fold_config($cancel),
            ProverRandomness::os(),
            $worker.prover_config($cancel),
        )
    };
}

// One-stage families (lean Bootstrap, Load, Unload and Retiring) share this terminal-only
// schedule; every proof and restore dispatch stays static per family.
macro_rules! single {
    ($worker:expr, $route:expr, $prover:expr, $session:expr, $restored:expr, $checkpoints:expr,
     $cancel:expr, $public:expr, $selected:expr, $family:ident, $name:literal, $form:ident) => {{
        let owner = $prover;
        // One unsplit terminal A: its checkpoint is the whole A schedule.
        let [layout] = proof(owner.checkpoint_layouts())?;
        if $checkpoints.len() > 1 {
            return Err(Error::Proof(concat!("extra ", $name, " checkpoint")));
        }
        let session = match $session {
            SessionSourceV1::Prepare(inputs) => match *inputs {
                OperationInputsV1::$family(input) => proof(owner.prepare_cancellable(
                    input,
                    $worker.budget,
                    Some($cancel.prover_token()),
                ))?,
                _ => return Err(Error::Proof("native route/input mismatch")),
            },
            SessionSourceV1::Resume(FamilyStateV1::$family(state)) => {
                let SingleStateV1 { session } = *state;
                // Re-admitted by the locked prepare on this same instance; a refusal
                // is never a proof verdict. Tests count it.
                let Ok(session) = owner.resume(session) else {
                    #[cfg(test)]
                    super::retention::count(|counts| counts.refusals += 1);
                    return Err(Error::Cancelled);
                };
                #[cfg(test)]
                super::retention::count(|counts| counts.resumes += 1);
                session
            }
            SessionSourceV1::Resume(_) => {
                return Err(Error::Proof("native route/input mismatch"));
            }
        };
        if $restored != 0 {
            // A retained one-stage session holds no restored checkpoint: the terminal
            // is restored straight into the Omega input.
            #[cfg(test)]
            super::retention::count(|counts| counts.refusals += 1);
            return Err(Error::Cancelled);
        }
        $cancel.check()?;
        if let Some(original) = $checkpoints.first() {
            if original.len() != layout.payload_bytes() {
                return Err(Error::Proof(concat!($name, " checkpoint length")));
            }
            let terminal = proof(session.restore_terminal_checkpoint_cancellable(
                original,
                $worker.budget,
                Some($cancel.prover_token()),
            ))?;
            #[cfg(test)]
            super::retention::count(|counts| counts.restores += 1);
            $cancel.check()?;
            (
                NativeStageProgressV1::Terminal(omega::Input {
                    key: $selected.terminal().key().clone(),
                    proof: terminal.proof,
                    frame: terminal
                        .instances
                        .try_into()
                        .map_err(|_| Error::Proof(concat!($name, " terminal frame")))?,
                    public: $public,
                    pallas: terminal.pallas,
                }),
                None,
            )
        } else {
            let key = $worker
                .sources
                .bind_a_cancellable($route, 0, $worker.read, Some($cancel.prover_token()))
                .map_err(artifact)?;
            $cancel.check()?;
            fold_metrics::enter(FoldPhaseV1::Prove);
            let terminal = proof(call_terminal!($form, session, key, $worker, $cancel))?;
            let encoded = PrivateArchiveBytes::from_guarded(zeroize::Zeroizing::new(proof(
                session.encode_terminal_checkpoint_cancellable(
                    &terminal,
                    $worker.budget,
                    Some($cancel.prover_token()),
                ),
            )?));
            if encoded.len() != layout.payload_bytes() {
                return Err(Error::Proof(concat!($name, " output length")));
            }
            $cancel.check()?;
            (
                NativeStageProgressV1::Checkpoint(encoded),
                // Only the session is kept; the proof produced above enters the next
                // sub-proof through its bytes.
                Some(FamilyStateV1::$family(Box::new(SingleStateV1 {
                    session: session.into_retained(),
                }))),
            )
        }
    }};
}

impl NativeFoldWorkerV1 {
    /// Restore all prior A/W sources and produce exactly one next proof with the A or W
    /// source whose originals the locked prepare revalidated. Once the terminal checkpoint
    /// exists, return its verified source to the separate Omega task.
    ///
    /// A resumed session already holds the first `restored` durable checkpoints of
    /// `checkpoints`; only the later ones are restored. With a checkpoint, the session and the
    /// checkpoints restored from durable bytes are returned for the next sub-proof of the step.
    pub(super) fn stage(
        &self,
        route: OperationRoute,
        session: SessionSourceV1,
        public: &[Fp; 18],
        checkpoints: &[PrivateArchiveBytes],
        restored: usize,
        cancellation: &Cancellation,
    ) -> Result<(NativeStageProgressV1, Option<FamilyStateV1>), Error> {
        let public = *public;
        cancellation.check()?;
        fold_metrics::enter(FoldPhaseV1::Restore);
        let selected = proof(self.sources.route(route))?;
        Ok(match selected.owner() {
            QualifiedOperationOwnerV1::Bootstrap(owner) => single!(
                self,
                route,
                owner.prover(),
                session,
                restored,
                checkpoints,
                cancellation,
                public,
                selected,
                Bootstrap,
                "Bootstrap",
                plain
            ),
            QualifiedOperationOwnerV1::Load(owner) => single!(
                self,
                route,
                owner,
                session,
                restored,
                checkpoints,
                cancellation,
                public,
                selected,
                Load,
                "Load",
                folded
            ),
            QualifiedOperationOwnerV1::Send(owner) => chain!(
                self,
                route,
                owner,
                session,
                restored,
                checkpoints,
                cancellation,
                public,
                source_first,
                Send
            ),
            QualifiedOperationOwnerV1::Receive(owner) => chain!(
                self,
                route,
                owner,
                session,
                restored,
                checkpoints,
                cancellation,
                public,
                key_first,
                Receive
            ),
            QualifiedOperationOwnerV1::Archive(owner) => chain!(
                self,
                route,
                owner,
                session,
                restored,
                checkpoints,
                cancellation,
                public,
                key_first,
                Archive
            ),
            QualifiedOperationOwnerV1::Consuming(owner) => single!(
                self,
                route,
                owner,
                session,
                restored,
                checkpoints,
                cancellation,
                public,
                selected,
                Consuming,
                "Unload/Retiring",
                folded
            ),
            QualifiedOperationOwnerV1::Refresh(owner) => chain!(
                self,
                route,
                owner,
                session,
                restored,
                checkpoints,
                cancellation,
                public,
                source_first,
                Refresh
            ),
        })
    }

    /// Re-admit a retained family session on the prover instance of `route`: resume it and
    /// detach it again, which moves nothing and verifies nothing. `None` when another instance
    /// prepared it, including an identically installed one, or when its family is not the
    /// route's; the session is then dropped and the caller prepares cold in the same call.
    pub(super) fn admit_family(
        &self,
        route: OperationRoute,
        family: FamilyStateV1,
    ) -> Option<FamilyStateV1> {
        macro_rules! readmit {
            ($owner:expr, $state:expr, $variant:ident) => {{
                let ChainStateV1 { session, a, w } = *$state;
                let session = $owner.resume(session).ok()?.into_retained();
                FamilyStateV1::$variant(Box::new(ChainStateV1 { session, a, w }))
            }};
        }
        macro_rules! readmit_single {
            ($prover:expr, $state:expr, $variant:ident) => {{
                let SingleStateV1 { session } = *$state;
                let session = $prover.resume(session).ok()?.into_retained();
                FamilyStateV1::$variant(Box::new(SingleStateV1 { session }))
            }};
        }
        let selected = self.sources.route(route).ok()?;
        Some(match (selected.owner(), family) {
            (QualifiedOperationOwnerV1::Bootstrap(owner), FamilyStateV1::Bootstrap(state)) => {
                readmit_single!(owner.prover(), state, Bootstrap)
            }
            (QualifiedOperationOwnerV1::Load(owner), FamilyStateV1::Load(state)) => {
                readmit_single!(owner, state, Load)
            }
            (QualifiedOperationOwnerV1::Send(owner), FamilyStateV1::Send(state)) => {
                readmit!(owner, state, Send)
            }
            (QualifiedOperationOwnerV1::Receive(owner), FamilyStateV1::Receive(state)) => {
                readmit!(owner, state, Receive)
            }
            (QualifiedOperationOwnerV1::Archive(owner), FamilyStateV1::Archive(state)) => {
                readmit!(owner, state, Archive)
            }
            (QualifiedOperationOwnerV1::Consuming(owner), FamilyStateV1::Consuming(state)) => {
                readmit_single!(owner, state, Consuming)
            }
            (QualifiedOperationOwnerV1::Refresh(owner), FamilyStateV1::Refresh(state)) => {
                readmit!(owner, state, Refresh)
            }
            _ => return None,
        })
    }
}

/// Countersign Z1(4) one level down, for the retention module's type check: an exhaustive
/// destructuring of every retained family state with explicit field types, so a new field fails
/// to compile here. The session and the restored checkpoints are the family's own in-call types
/// (D6a), opaque outside their crate: the session's verified preparation holds the step's
/// originals and Q proofs, and each restored checkpoint the proof bytes its restore decoded, as
/// plain bytes, exactly as during a call. They hold no copy of a durable payload.
#[cfg(test)]
pub(super) fn family_state_fields(family: FamilyStateV1) {
    macro_rules! chain_fields {
        ($state:expr, $family:ident) => {{
            let ChainStateV1 { session, a, w } = *$state;
            let _: $family::RetainedSession = session;
            let _: Option<$family::ACheckpoint> = a;
            let _: Option<$family::WCheckpoint> = w;
        }};
    }
    macro_rules! single_fields {
        ($state:expr, $family:ident) => {{
            let SingleStateV1 { session } = *$state;
            let _: $family::RetainedSession = session;
        }};
    }
    match family {
        FamilyStateV1::Bootstrap(state) => single_fields!(state, bootstrap),
        FamilyStateV1::Load(state) => single_fields!(state, load),
        FamilyStateV1::Send(state) => chain_fields!(state, send),
        FamilyStateV1::Receive(state) => chain_fields!(state, receive),
        FamilyStateV1::Archive(state) => chain_fields!(state, archive),
        FamilyStateV1::Consuming(state) => single_fields!(state, consuming),
        FamilyStateV1::Refresh(state) => chain_fields!(state, refresh),
    }
}
