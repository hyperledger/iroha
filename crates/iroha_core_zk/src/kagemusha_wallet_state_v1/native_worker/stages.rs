//! One genuine native A/W task with complete ordered source restoration.

use super::*;

// The native families deliberately retain their typed source capabilities. This
// macro shares the scheduler only; every proof/restore dispatch remains static.
macro_rules! chain {
    ($worker:expr, $route:expr, $owner:expr, $inputs:expr, $checkpoints:expr,
     $originals:expr, $cancel:expr, $public:expr, $order:ident) => {{
        let owner = $owner;
        let session = proof(owner.prepare_cancellable(
            $inputs,
            $worker.budget,
            Some($cancel.prover_token()),
        ))?;
        let layouts = proof(owner.checkpoint_layouts())?;
        let originals = $originals;
        let checkpoints = $checkpoints;
        if checkpoints.len() > layouts.len() {
            return Err(Error::Proof("extra native checkpoint"));
        }
        let mut a = None;
        let mut w = None;
        for (position, original) in checkpoints.iter().enumerate() {
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
        }
        $cancel.check()?;
        let position = checkpoints.len();
        if position == layouts.len() {
            let terminal = proof(session.terminal_cancellable(
                a.as_ref().ok_or(Error::Proof("native terminal source"))?,
                $worker.budget,
                Some($cancel.prover_token()),
            ))?;
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
            })
        } else {
            let fold = $worker.fold_config($cancel);
            let config = $worker.prover_config($cancel);
            let encoded = if position == 0 {
                let key = $worker
                    .sources
                    .import_a_cancellable(
                        $route,
                        0,
                        originals,
                        $worker.read,
                        Some($cancel.prover_token()),
                    )
                    .map_err(artifact)?;
                $cancel.check()?;
                let source = proof(session.first(
                    &key,
                    fresh_fold_salt::<Fp>($cancel.prover_token())?,
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
                    .import_w_cancellable(
                        $route,
                        position / 2,
                        originals,
                        $worker.read,
                        Some($cancel.prover_token()),
                    )
                    .map_err(artifact)?;
                $cancel.check()?;
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
                    .import_a_cancellable(
                        $route,
                        position / 2,
                        originals,
                        $worker.read,
                        Some($cancel.prover_token()),
                    )
                    .map_err(artifact)?;
                $cancel.check()?;
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
            NativeStageProgressV1::Checkpoint(encoded)
        }
    }};
}
macro_rules! call_wrapper {
    (source_first,$session:ident,$source:ident,$key:ident,$fold:ident,$config:ident,$cancel:expr) => {
        $session.wrapper(
            $source,
            &$key,
            fresh_fold_salt::<Fq>($cancel.prover_token())?,
            &$fold,
            ProverRandomness::os(),
            $config,
        )
    };
    (key_first,$session:ident,$source:ident,$key:ident,$fold:ident,$config:ident,$cancel:expr) => {
        $session.wrapper(
            &$key,
            $source,
            fresh_fold_salt::<Fq>($cancel.prover_token())?,
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
            fresh_fold_salt::<Fp>($cancel.prover_token())?,
            &$fold,
            ProverRandomness::os(),
            $config,
        )
    };
    (key_first,$session:ident,$source:ident,$key:ident,$fold:ident,$config:ident,$cancel:expr) => {
        $session.advance(
            &$key,
            $source,
            fresh_fold_salt::<Fp>($cancel.prover_token())?,
            &$fold,
            ProverRandomness::os(),
            $config,
        )
    };
}

impl NativeFoldWorkerV1 {
    /// Restore all prior A/W sources and produce exactly one next proof. Once the
    /// terminal checkpoint exists, return its verified source to the separate Omega task.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stage(
        &self,
        route: OperationRoute,
        inputs: OperationInputsV1,
        public: [Fp; 18],
        checkpoints: &[Vec<u8>],
        originals: &mut dyn OriginalSourceV1,
        cancellation: &Cancellation,
    ) -> Result<NativeStageProgressV1, Error> {
        cancellation.check()?;
        let selected = proof(self.sources.route(route))?;
        Ok(match (selected.owner(), inputs) {
            (QualifiedOperationOwnerV1::Bootstrap(owner), OperationInputsV1::Bootstrap(input)) => {
                let owner = owner.prover();
                let layouts = proof(owner.checkpoint_layouts())?;
                if checkpoints.len() > layouts.len() {
                    return Err(Error::Proof("extra Bootstrap checkpoint"));
                }
                let session = proof(owner.prepare_cancellable(
                    input,
                    self.budget,
                    Some(cancellation.prover_token()),
                ))?;
                let mut first = None;
                let mut wrapper = None;
                let mut terminal = None;
                for (position, original) in checkpoints.iter().enumerate() {
                    cancellation.check()?;
                    if original.len() != layouts[position].payload_bytes() {
                        return Err(Error::Proof("Bootstrap checkpoint length"));
                    }
                    match position {
                        0 => {
                            first = Some(proof(session.restore_first_checkpoint_cancellable(
                                original,
                                self.budget,
                                Some(cancellation.prover_token()),
                            ))?)
                        }
                        1 => {
                            wrapper = Some(proof(session.restore_wrapper_checkpoint_cancellable(
                                original,
                                self.budget,
                                Some(cancellation.prover_token()),
                            ))?)
                        }
                        2 => {
                            terminal =
                                Some(proof(session.restore_terminal_checkpoint_cancellable(
                                    wrapper.as_ref().ok_or(Error::Proof("Bootstrap W source"))?,
                                    original,
                                    self.budget,
                                    Some(cancellation.prover_token()),
                                ))?)
                        }
                        _ => return Err(Error::Proof("Bootstrap stage")),
                    }
                }
                cancellation.check()?;
                if let Some(terminal) = terminal {
                    NativeStageProgressV1::Terminal(omega::Input {
                        key: selected.terminal().key().clone(),
                        proof: terminal.proof,
                        frame: terminal
                            .instances
                            .try_into()
                            .map_err(|_| Error::Proof("Bootstrap terminal frame"))?,
                        public,
                        pallas: terminal.pallas,
                    })
                } else {
                    let position = checkpoints.len();
                    let fold = self.fold_config(cancellation);
                    let config = self.prover_config(cancellation);
                    let encoded = match position {
                        0 => {
                            let key = self
                                .sources
                                .import_a_cancellable(
                                    route,
                                    0,
                                    originals,
                                    self.read,
                                    Some(cancellation.prover_token()),
                                )
                                .map_err(artifact)?;
                            cancellation.check()?;
                            let source =
                                proof(session.first(&key, ProverRandomness::os(), config))?;
                            proof(session.encode_first_checkpoint_cancellable(
                                &source,
                                self.budget,
                                Some(cancellation.prover_token()),
                            ))?
                        }
                        1 => {
                            let key = self
                                .sources
                                .import_w_cancellable(
                                    route,
                                    0,
                                    originals,
                                    self.read,
                                    Some(cancellation.prover_token()),
                                )
                                .map_err(artifact)?;
                            cancellation.check()?;
                            let source = proof(session.wrapper(
                                first.as_ref().ok_or(Error::Proof("Bootstrap A source"))?,
                                &key,
                                fresh_fold_salt::<Fq>(cancellation.prover_token())?,
                                &fold,
                                ProverRandomness::os(),
                                config,
                            ))?;
                            proof(session.encode_wrapper_checkpoint_cancellable(
                                &source,
                                self.budget,
                                Some(cancellation.prover_token()),
                            ))?
                        }
                        2 => {
                            let key = self
                                .sources
                                .import_a_cancellable(
                                    route,
                                    1,
                                    originals,
                                    self.read,
                                    Some(cancellation.prover_token()),
                                )
                                .map_err(artifact)?;
                            cancellation.check()?;
                            let prior =
                                wrapper.as_ref().ok_or(Error::Proof("Bootstrap W source"))?;
                            let salt = fresh_fold_salt::<Fp>(cancellation.prover_token())?;
                            let source = proof(session.terminal(
                                prior,
                                &key,
                                salt,
                                &fold,
                                ProverRandomness::os(),
                                config,
                            ))?;
                            proof(session.encode_terminal_checkpoint_cancellable(
                                prior,
                                &source,
                                salt,
                                self.budget,
                                Some(cancellation.prover_token()),
                            ))?
                        }
                        _ => return Err(Error::Proof("Bootstrap stage")),
                    };
                    if encoded.len() != layouts[position].payload_bytes() {
                        return Err(Error::Proof("Bootstrap output length"));
                    }
                    cancellation.check()?;
                    NativeStageProgressV1::Checkpoint(encoded)
                }
            }
            (QualifiedOperationOwnerV1::Load(owner), OperationInputsV1::Load(input)) => chain!(
                self,
                route,
                owner,
                input,
                checkpoints,
                originals,
                cancellation,
                public,
                source_first
            ),
            (QualifiedOperationOwnerV1::Send(owner), OperationInputsV1::Send(input)) => chain!(
                self,
                route,
                owner,
                input,
                checkpoints,
                originals,
                cancellation,
                public,
                source_first
            ),
            (QualifiedOperationOwnerV1::Receive(owner), OperationInputsV1::Receive(input)) => {
                chain!(
                    self,
                    route,
                    owner,
                    input,
                    checkpoints,
                    originals,
                    cancellation,
                    public,
                    key_first
                )
            }
            (QualifiedOperationOwnerV1::Archive(owner), OperationInputsV1::Archive(input)) => {
                chain!(
                    self,
                    route,
                    owner,
                    input,
                    checkpoints,
                    originals,
                    cancellation,
                    public,
                    key_first
                )
            }
            (QualifiedOperationOwnerV1::Consuming(owner), OperationInputsV1::Consuming(input)) => {
                chain!(
                    self,
                    route,
                    owner,
                    input,
                    checkpoints,
                    originals,
                    cancellation,
                    public,
                    source_first
                )
            }
            (QualifiedOperationOwnerV1::Refresh(owner), OperationInputsV1::Refresh(input)) => {
                chain!(
                    self,
                    route,
                    owner,
                    input,
                    checkpoints,
                    originals,
                    cancellation,
                    public,
                    source_first
                )
            }
            _ => return Err(Error::Proof("native route/input mismatch")),
        })
    }
}
