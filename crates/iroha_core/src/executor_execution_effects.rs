//! Actual signed-root instruction admission before business effects apply.
//!
//! The agreed limits count InstructionBox entries and their individual fixed V1
//! bare encodings. They do not bound durable state, AXT, callbacks or host memory.
//! Every authored group and consumed VM/replay group debits one retained owner.

use super::*;
use std::io::{self, Write};

/// Private state of the sole instruction budget for one signed execution.
#[derive(Default)]
pub(crate) struct ExecutionEffects {
    state: EffectState,
}

#[derive(Default)]
enum EffectState {
    #[default]
    Idle,
    Root(RootEffects),
    Broken(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RootKind {
    Instructions,
    Replay,
    Vm,
    Batch,
}

struct RootEffects {
    source: iroha_crypto::HashOf<SignedTransaction>,
    call: iroha_crypto::Hash,
    proposal: iroha_crypto::HashOf<BlockHeader>,
    network: iroha_data_model::NetworkId,
    lane: Option<iroha_model_base::topology::LaneId>,
    dataspace: Option<DataSpaceId>,
    index: Option<u64>,
    kind: RootKind,
    max_instructions: usize,
    max_bytes: u64,
    cycle_budget: Option<ivm::VmCycleBudget>,
    instructions: usize,
    bytes: u64,
    authored: bool,
    artifact_groups: usize,
    closed: bool,
    fault: Option<EffectFault>,
}

#[derive(Clone)]
enum EffectFault {
    Instructions { attempted: usize, maximum: usize },
    Bytes { maximum: u64 },
    Cycles { maximum: u64 },
    Owner(String),
    NativeAmx(iroha_data_model::isi::error::InstructionExecutionError),
}

impl EffectFault {
    fn validation(&self) -> ValidationFail {
        match self {
            Self::Instructions { attempted, maximum } => ValidationFail::NotPermitted(format!(
                "overlay exceeds max instructions: {attempted} > {maximum}"
            )),
            // Encoding stops at the agreed bound, so do not claim the unmeasured
            // full encoded length in the canonical diagnostic.
            Self::Bytes { maximum } => ValidationFail::NotPermitted(format!(
                "overlay exceeds max bytes: more than {maximum}"
            )),
            Self::Cycles { maximum } => {
                ValidationFail::NotPermitted(format!("quarantine cycle budget exceeded: {maximum}"))
            }
            Self::Owner(message) => ValidationFail::InternalError(message.clone()),
            Self::NativeAmx(error) => ValidationFail::InstructionFailed(error.clone()),
        }
    }
}

struct BoundedByteCount {
    bytes: u64,
    maximum: u64,
    exceeded: bool,
}

impl Write for BoundedByteCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let len = u64::try_from(bytes.len()).map_err(io::Error::other)?;
        let total = self
            .bytes
            .checked_add(len)
            .ok_or_else(|| io::Error::other("instruction byte count overflows u64"))?;
        if self.maximum != 0 && total > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other("instruction byte budget exhausted"));
        }
        self.bytes = total;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl RootEffects {
    fn matches(&self, state: &StateTransaction<'_, '_>) -> bool {
        self.proposal == state._curr_block.hash()
            && self.network == state.network_id
            && self.lane == state.current_lane_id
            && self.dataspace == state.current_dataspace_id
            && self.dataspace == state.world.current_dataspace_id
            && self.index == state.current_entrypoint_index
            && state.current_tx_hash == Some(self.source)
            && state.tx_call_hash == Some(self.call)
    }

    fn admit<'a>(
        &mut self,
        instructions: impl ExactSizeIterator<Item = &'a InstructionBox> + 'a,
    ) -> Result<(), EffectFault> {
        let count = self
            .instructions
            .checked_add(instructions.len())
            .ok_or_else(|| EffectFault::Owner("instruction count overflows usize".into()))?;
        if self.max_instructions != 0 && count > self.max_instructions {
            return Err(EffectFault::Instructions {
                attempted: count,
                maximum: self.max_instructions,
            });
        }
        let mut writer = BoundedByteCount {
            bytes: self.bytes,
            maximum: self.max_bytes,
            exceeded: false,
        };
        for instruction in instructions {
            if let Err(error) = norito::codec::encode_adaptive_into(instruction, &mut writer) {
                return Err(if writer.exceeded {
                    EffectFault::Bytes {
                        maximum: self.max_bytes,
                    }
                } else {
                    EffectFault::Owner(format!(
                        "cannot measure actual instruction encoding: {error}"
                    ))
                });
            }
        }
        // A whole group is admitted atomically before its first instruction.
        self.instructions = count;
        self.bytes = writer.bytes;
        Ok(())
    }
}

impl StateTransaction<'_, '_> {
    /// Retain a completed native AMX monetary failure across an inner contract catch.
    /// The actual signed root closes with the same deterministic instruction failure;
    /// its disposable World/transcript overlay cannot publish partial policy effects.
    pub(crate) fn reject_native_amx_effects(
        &mut self,
        error: iroha_data_model::isi::error::InstructionExecutionError,
    ) {
        let matches = matches!(&self.execution_effects.state, EffectState::Root(root)
            if root.matches(self) && !root.closed);
        if matches {
            if let EffectState::Root(root) = &mut self.execution_effects.state
                && root.fault.is_none()
            {
                root.fault = Some(EffectFault::NativeAmx(error));
            }
        } else {
            self.break_execution_effect_owner(
                "native AMX monetary failure lost its signed execution owner",
            );
        }
    }
    /// Start the actual signed root, freezing its agreed instruction limits.
    pub(crate) fn begin_execution_effect_budget(
        &mut self,
        signed: &SignedTransaction,
    ) -> Result<(), ValidationFail> {
        if !matches!(self.execution_effects.state, EffectState::Idle) {
            return Err(self.break_execution_effect_owner(
                "signed execution already owns an instruction budget",
            ));
        }
        let kind = match signed.instructions() {
            Executable::Instructions(_) => RootKind::Instructions,
            Executable::IvmProved(_) => RootKind::Replay,
            Executable::Ivm(_) | Executable::ContractCall(_) => RootKind::Vm,
            Executable::Batch(_) => RootKind::Batch,
        };
        let root = RootEffects {
            source: signed.hash(),
            call: iroha_crypto::Hash::from(signed.hash_as_entrypoint()),
            proposal: self._curr_block.hash(),
            network: self.network_id,
            lane: self.current_lane_id,
            dataspace: self.current_dataspace_id,
            index: self.current_entrypoint_index,
            kind,
            max_instructions: self.pipeline.overlay_max_instructions,
            max_bytes: self.pipeline.overlay_max_bytes,
            cycle_budget: crate::tx::is_quarantine_transaction(signed)
                .then(|| core::num::NonZeroU64::new(self.pipeline.quarantine_tx_max_cycles))
                .flatten()
                .map(ivm::VmCycleBudget::new),
            instructions: 0,
            bytes: 0,
            authored: false,
            artifact_groups: 0,
            closed: false,
            fault: None,
        };
        if self.execution_callback_active() || !root.matches(self) {
            return Err(self.break_execution_effect_owner(
                "signed instruction budget has no exact root context",
            ));
        }
        self.execution_effects.state = EffectState::Root(root);
        Ok(())
    }

    fn break_execution_effect_owner(&mut self, message: impl Into<String>) -> ValidationFail {
        let message = message.into();
        self.execution_effects.state = EffectState::Broken(message.clone());
        ValidationFail::InternalError(message)
    }

    /// Borrow the actual signed root's sole cycle allowance for this VM segment.
    /// Actual trigger execution is a separate scope, including generic callbacks.
    pub(crate) fn execution_cycle_budget(
        &self,
    ) -> Result<Option<&ivm::VmCycleBudget>, ValidationFail> {
        match &self.execution_effects.state {
            EffectState::Broken(message) => {
                return Err(ValidationFail::InternalError(message.clone()));
            }
            EffectState::Root(RootEffects {
                fault: Some(fault), ..
            }) => return Err(fault.validation()),
            _ => {}
        }
        if self.execution_callback_active() {
            return Ok(None);
        }
        match &self.execution_effects.state {
            EffectState::Root(root) if root.matches(self) && !root.closed => {
                Ok(root.cycle_budget.as_ref())
            }
            _ => Err(ValidationFail::InternalError(
                "VM execution has no active exact signed-root owner".into(),
            )),
        }
    }

    /// Admit the actual authored signed instruction set, exactly once.
    pub(crate) fn admit_authored_execution_effects<'a>(
        &mut self,
        instructions: impl ExactSizeIterator<Item = &'a InstructionBox> + 'a,
    ) -> Result<(), ValidationFail> {
        self.admit_execution_effect_group(instructions, false, false)
    }

    /// Admit an authenticated replay's actual queued instructions before applying it.
    pub(crate) fn admit_replayed_execution_effects<'a>(
        &mut self,
        instructions: impl ExactSizeIterator<Item = &'a InstructionBox> + 'a,
    ) -> Result<(), ValidationFail> {
        self.admit_execution_effect_group(instructions, true, false)
    }

    /// Called only by the consuming actual HostExecutionArtifacts apply boundary.
    pub(crate) fn admit_host_execution_effects<'a>(
        &mut self,
        instructions: impl ExactSizeIterator<Item = &'a InstructionBox> + 'a,
    ) -> Result<(), ValidationFail> {
        self.admit_execution_effect_group(instructions, false, true)
    }

    fn admit_execution_effect_group<'a>(
        &mut self,
        instructions: impl ExactSizeIterator<Item = &'a InstructionBox> + 'a,
        replay: bool,
        host: bool,
    ) -> Result<(), ValidationFail> {
        match &self.execution_effects.state {
            EffectState::Broken(message) => {
                return Err(ValidationFail::InternalError(message.clone()));
            }
            EffectState::Root(RootEffects {
                fault: Some(fault), ..
            }) => return Err(fault.validation()),
            _ => {}
        }
        // Use the actual shared trigger wrapper, including generic triggers and
        // callbacks synchronously invoked while a root ExecuteTrigger ISI runs.
        if host && self.execution_callback_active() {
            return Ok(());
        }
        let context_matches = match &self.execution_effects.state {
            EffectState::Root(root) => root.matches(self),
            _ => false,
        };
        if !context_matches {
            return Err(self.break_execution_effect_owner(
                "instruction effects have no exact signed-root budget",
            ));
        }
        let EffectState::Root(root) = &mut self.execution_effects.state else {
            return Err(
                self.break_execution_effect_owner("instruction budget disappeared from its owner")
            );
        };
        let legal_group = if host {
            (root.kind == RootKind::Vm && root.artifact_groups == 0)
                || (root.kind == RootKind::Batch && root.authored)
        } else if replay {
            root.kind == RootKind::Replay && !root.authored
        } else {
            matches!(root.kind, RootKind::Instructions | RootKind::Batch) && !root.authored
        };
        let next_artifact_groups = root.artifact_groups.checked_add(usize::from(host));
        let result = if next_artifact_groups.is_none() {
            Err(EffectFault::Owner("artifact group count overflow".into()))
        } else if root.closed || !legal_group {
            Err(EffectFault::Owner(
                "instruction group is repeated, closed or belongs to another root kind".into(),
            ))
        } else {
            root.admit(instructions)
        };
        if let Err(fault) = result {
            let error = fault.validation();
            root.fault = Some(fault);
            return Err(error);
        }
        if host {
            if let Some(next) = next_artifact_groups {
                root.artifact_groups = next;
            }
        } else {
            root.authored = true;
        }
        Ok(())
    }

    /// Close every direct Executor exit, retaining any refusal even if caught below it.
    pub(crate) fn finish_execution_effect_budget(&mut self) -> Result<(), ValidationFail> {
        let valid = match &self.execution_effects.state {
            EffectState::Idle => return Ok(()),
            EffectState::Broken(message) => {
                return Err(ValidationFail::InternalError(message.clone()));
            }
            EffectState::Root(root) => {
                root.matches(self) && !root.closed && !self.execution_callback_active()
            }
        };
        if !valid {
            return Err(self.break_execution_effect_owner(
                "instruction budget cannot close outside its actual root",
            ));
        }
        let EffectState::Root(root) = &mut self.execution_effects.state else {
            return Err(
                self.break_execution_effect_owner("instruction budget disappeared from its owner")
            );
        };
        root.closed = true;
        if let Some(cycles) = &root.cycle_budget {
            if !cycles.is_open() {
                root.fault = Some(EffectFault::Owner(
                    "signed-root cycle owner is invalid or closed".into(),
                ));
            } else if root.fault.is_none() && cycles.exhausted() {
                root.fault = Some(EffectFault::Cycles {
                    maximum: cycles.limit(),
                });
            }
        }
        root.fault
            .as_ref()
            .map_or(Ok(()), |fault| Err(fault.validation()))
    }

    /// Observe the actual retained counter in tests, including a closed root.
    #[cfg(test)]
    pub(super) fn completed_execution_cycles_for_tests(&self) -> Option<u64> {
        match &self.execution_effects.state {
            EffectState::Root(root) => root.cycle_budget.as_ref().map(ivm::VmCycleBudget::consumed),
            _ => None,
        }
    }

    /// Exact typed preparation-limit refusal, independent of diagnostic strings.
    pub(crate) fn execution_effect_limit_exceeded(&self) -> bool {
        matches!(&self.execution_effects.state, EffectState::Root(root)
            if matches!(&root.fault, Some(EffectFault::Instructions { .. } | EffectFault::Bytes { .. })))
    }

    /// Detect local owner failures before producing any canonical output row.
    pub(crate) fn require_completed_execution_effect_owner(&self) -> Result<(), String> {
        match &self.execution_effects.state {
            EffectState::Idle => Ok(()),
            EffectState::Broken(message) => Err(message.clone()),
            EffectState::Root(root)
                if !root.closed
                    || !root.matches(self)
                    || self.execution_callback_active()
                    || root
                        .cycle_budget
                        .as_ref()
                        .is_some_and(|budget| !budget.is_open()) =>
            {
                Err("instruction effect owner is incomplete or foreign".into())
            }
            EffectState::Root(root) => match &root.fault {
                Some(EffectFault::Owner(message)) => Err(message.clone()),
                _ => Ok(()),
            },
        }
    }

    /// A refused, unclosed, foreign or unwound root must never apply its effects.
    pub(crate) fn execution_effects_allow_apply(&self) -> bool {
        match &self.execution_effects.state {
            EffectState::Idle => true,
            EffectState::Broken(_) => false,
            EffectState::Root(root) => {
                root.closed
                    && root.fault.is_none()
                    && root.matches(self)
                    && !self.execution_callback_active()
                    && root
                        .cycle_budget
                        .as_ref()
                        .is_none_or(|budget| budget.is_open() && !budget.exhausted())
            }
        }
    }
}

#[cfg(test)]
mod byte_tests {
    use super::*;
    use iroha_data_model::{
        isi::{Log, SetKeyValue},
        prelude::TransactionBuilder,
    };
    use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
    use norito::core::{self as ncore, header_flags};

    fn instructions() -> Vec<InstructionBox> {
        let mut instructions: Vec<_> = [0, 1, 127, 128, 255, 256, 4096]
            .into_iter()
            .map(|len| Log::new(iroha_logger::Level::INFO, "x".repeat(len)).into())
            .collect();
        instructions.push(
            SetKeyValue::account(
                ALICE_ID.clone(),
                "byte_counter_utf8".parse().unwrap(),
                Json::new("日本語".repeat(43)),
            )
            .into(),
        );
        instructions
    }

    // These private counter tests use a well-formed signed fixture to populate
    // unused context fields. They never claim source admission or State authority.
    fn counter_root(max_bytes: u64) -> RootEffects {
        let header = BlockHeader::new(core::num::NonZeroU64::new(2).unwrap(), None, None, 0, 0);
        let proposal = header.hash();
        let network = iroha_data_model::NetworkId::from_genesis_hash(proposal);
        let source = TransactionBuilder::new(
            network,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(1_000_000)),
        )
        .with_instructions(instructions())
        .sign(ALICE_KEYPAIR.private_key());
        RootEffects {
            source: source.hash(),
            call: iroha_crypto::Hash::from(source.hash_as_entrypoint()),
            proposal,
            network,
            lane: None,
            dataspace: None,
            index: None,
            kind: RootKind::Instructions,
            max_instructions: 0,
            max_bytes,
            cycle_budget: None,
            instructions: 0,
            bytes: 0,
            authored: false,
            artifact_groups: 0,
            closed: false,
            fault: None,
        }
    }

    #[test]
    fn bounded_counter_matches_each_bare_v1_instruction_under_ambient_flags() {
        let instructions = instructions();
        let expected: Vec<_> = instructions.iter().map(Encode::encode).collect();
        let original_flags = ncore::get_decode_flags();
        for flags in [0, header_flags::COMPACT_LEN] {
            let _ambient = ncore::DecodeFlagsGuard::enter(flags);
            assert_eq!(ncore::get_decode_flags(), flags);
            for (instruction, bytes) in instructions.iter().zip(&expected) {
                assert_eq!(instruction.encode(), *bytes, "bare Encode is fixed V1");
                let exact = u64::try_from(bytes.len()).unwrap();
                let mut count = BoundedByteCount {
                    bytes: 0,
                    maximum: exact,
                    exceeded: false,
                };
                let written = norito::codec::encode_adaptive_into(instruction, &mut count)
                    .expect("fixed V1 instruction fits its own bare encoding length");
                assert_eq!(written, bytes.len());
                assert_eq!(count.bytes, exact);
                assert!(!count.exceeded);
                assert_eq!(
                    ncore::get_decode_flags(),
                    flags,
                    "writer restores ambient flags"
                );
            }
        }
        assert_eq!(ncore::get_decode_flags(), original_flags);
    }

    #[test]
    fn exact_group_byte_fit_and_one_below_preserve_atomic_counter_state() {
        let instructions = instructions();
        let lengths: Vec<_> = instructions
            .iter()
            .map(|instruction| u64::try_from(instruction.encode().len()).unwrap())
            .collect();
        let exact: u64 = lengths.iter().sum();
        let _ambient = ncore::DecodeFlagsGuard::enter(0);
        for maximum in [0, exact] {
            let mut root = counter_root(maximum);
            assert!(root.admit(instructions[..1].iter()).is_ok());
            assert_eq!((root.instructions, root.bytes), (1, lengths[0]));
            assert!(root.admit(instructions[1..].iter()).is_ok());
            assert_eq!((root.instructions, root.bytes), (instructions.len(), exact));
        }
        let mut root = counter_root(exact - 1);
        assert!(root.admit(instructions[..1].iter()).is_ok());
        let before = (root.instructions, root.bytes);
        let error = root
            .admit(instructions[1..].iter())
            .expect_err("one byte short must refuse the entire next group");
        assert!(matches!(error, EffectFault::Bytes { maximum } if maximum == exact - 1));
        assert_eq!(
            (root.instructions, root.bytes),
            before,
            "no partial debit from a refused group"
        );
        assert!(root.bytes <= root.max_bytes);
    }

    #[test]
    fn bounded_writer_never_commits_an_over_limit_write() {
        let bytes = instructions().pop().unwrap().encode();
        let exact = u64::try_from(bytes.len()).unwrap();
        let mut count = BoundedByteCount {
            bytes: 0,
            maximum: exact - 1,
            exceeded: false,
        };
        let error = count
            .write_all(&bytes)
            .expect_err("actual complete instruction is one byte too large");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            count.bytes, 0,
            "rejected write does not advance the counter"
        );
        assert!(count.exceeded);
        let mut exact_count = BoundedByteCount {
            bytes: 0,
            maximum: exact,
            exceeded: false,
        };
        exact_count
            .write_all(&bytes)
            .expect("exact same instruction fits");
        assert_eq!(exact_count.bytes, exact);
        assert!(!exact_count.exceeded);
    }

    #[test]
    fn arithmetic_overflow_is_local_failure_not_consensus_cap_exhaustion() {
        for maximum in [0, u64::MAX] {
            let mut count = BoundedByteCount {
                bytes: u64::MAX - 1,
                maximum,
                exceeded: false,
            };
            let error = count
                .write_all(&[1, 2])
                .expect_err("checked count must not wrap");
            assert_eq!(error.to_string(), "instruction byte count overflows u64");
            assert_eq!(count.bytes, u64::MAX - 1);
            assert!(
                !count.exceeded,
                "arithmetic failure is not the agreed byte ceiling"
            );
        }
        let instructions = instructions();
        let mut root = counter_root(0);
        root.bytes = u64::MAX - 1;
        let error = root
            .admit(instructions[..1].iter())
            .expect_err("encoding cannot wrap the retained counter");
        assert!(matches!(error, EffectFault::Owner(_)));
        assert!(matches!(
            error.validation(),
            ValidationFail::InternalError(_)
        ));
        assert_eq!((root.instructions, root.bytes), (0, u64::MAX - 1));

        let mut root = counter_root(0);
        root.instructions = usize::MAX;
        let error = root
            .admit(instructions[..1].iter())
            .expect_err("instruction count cannot wrap either");
        assert!(
            matches!(&error, EffectFault::Owner(message) if message == "instruction count overflows usize")
        );
        assert!(matches!(
            error.validation(),
            ValidationFail::InternalError(_)
        ));
        assert_eq!((root.instructions, root.bytes), (usize::MAX, 0));
    }
}
