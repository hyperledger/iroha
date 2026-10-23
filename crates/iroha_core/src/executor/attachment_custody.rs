//! Borrowed, invocation-scoped custody of original signed attachment data.
//!
//! Handles are private host values, not serializable addresses or verification
//! capabilities. The source signature and shared I.1 predicate are checked;
//! committed crypto policy, replay admission, permissions and native proof
//! verification remain their existing owners' responsibilities. A caller must
//! supply an already authorized actor, never one read from a guest request.
//!
//! TODO(I.2, I.3, I.4): integrate this owner with actual host entry/child/exit,
//! native consumers and the same atomic State attempt. Until then the existing
//! no-authoritative-consumer admission refusal remains mandatory. This module
//! neither applies effects nor turns consumption into proof acceptance.

use iroha_data_model::{
    account::AccountId,
    transaction::{
        SignedTransaction,
        signed::TransactionSignatureError,
        signed_attachments::{
            ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1, ActionAuthorityBindingV1, ActionIntentV1,
            ActionInvocationBindingV1, ActionOperationV1, ActionPublicInputsDigestV1, ActionRoleV1,
            AttachmentKindV1, AttachmentRoleV1, SIGNED_ATTACHMENTS_MAX_ACTIONS_V1,
            SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1, SignedAttachmentErrorV1,
        },
    },
};

/// A deterministic custody refusal; original signature/schema causes are retained.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CustodyError {
    /// The original signature cannot be verified; this is not an admission verdict.
    #[error(transparent)]
    Signature(#[from] TransactionSignatureError),
    /// The shared signed attachment predicate refused the original source.
    #[error(transparent)]
    Declaration(#[from] SignedAttachmentErrorV1),
    /// Any earlier refusal discarded this attempt's consumption bookkeeping.
    #[error("attachment custody attempt has failed")]
    FailedAttempt,
    /// No declared action has this ordinal.
    #[error("missing attachment action {0}")]
    MissingAction(u32),
    /// The action belongs to another signed invocation.
    #[error("attachment action {0} belongs to another invocation")]
    WrongInvocation(u32),
    /// The supplied authorized actor is not the signed authority.
    #[error("attachment action {0} has another authority")]
    WrongAuthority(u32),
    /// The consumer's exact operation, role or normalized inputs differ.
    #[error("attachment action {0} does not match the native request")]
    WrongAction(u32),
    /// No declared slot has this position within the selected action.
    #[error("missing attachment slot {slot} of action {action}")]
    MissingSlot { action: u32, slot: u32 },
    /// The consumer requested another attachment type or role.
    #[error("attachment {0} has another type or role")]
    WrongTypeOrRole(u32),
    /// The host token was minted by another custody owner, including an exact clone.
    #[error("attachment handle belongs to another original owner")]
    ForeignOwner,
    /// An invocation has ended or another invocation is attempting to use its token.
    #[error("attachment handle belongs to another invocation generation")]
    ExpiredHandle,
    /// A declaration may be opened and consumed only once per attempt.
    #[error("attachment {0} was already opened or consumed")]
    ReusedAttachment(u32),
    /// The same action cannot be completed a second time.
    #[error("attachment action {0} was already completed")]
    ReusedAction(u32),
    /// A declared attachment was not consumed before completion.
    #[error("attachment {0} remains unconsumed")]
    UnconsumedAttachment(u32),
    /// A declared action was not explicitly completed before invocation/attempt exit.
    #[error("attachment action {0} remains unconsumed")]
    UnconsumedAction(u32),
    /// Only a contract invocation can open a child, within the signed depth bound.
    #[error("attachment child invocation is outside the contract path bound")]
    InvalidChild,
    /// The host's monotone invocation/child ordinal would overflow.
    #[error("attachment invocation generation or ordinal exhausted")]
    GenerationExhausted,
}

/// Proof-free values supplied by the native consumer, not copied from the guest.
#[derive(Clone, Copy)]
pub(crate) struct ActionRequest<'a> {
    pub(crate) index: u32,
    pub(crate) operation: &'a ActionOperationV1,
    pub(crate) role: ActionRoleV1,
    pub(crate) public_inputs_digest: ActionPublicInputsDigestV1,
}

// Nonzero-sized host identity anchored by the borrowed signed source. Equality
// below tests object identity only; addresses never enter a token's wire form,
// a commitment, a protocol result or a guest-visible value. There is no wire form.
struct Owner<'tx> {
    source: &'tx SignedTransaction,
}

/// An opaque, copyable host token; copying it never duplicates consumption rights.
#[derive(Clone, Copy)]
pub(crate) struct AttachmentHandle<'owner, 'tx> {
    owner: &'owner Owner<'tx>,
    generation: u64,
    action: u32,
    slot: u32,
}

// The shared schema validator bounds every index before the masks below are used.
// A future schema expansion must change this owner instead of truncating a mask.
const _: () = assert!(SIGNED_ATTACHMENTS_MAX_ACTIONS_V1 <= u16::BITS as usize);
const _: () = assert!(SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1 <= u16::BITS as usize);

#[derive(Default)]
struct Attempt {
    issued: u16,
    consumed: u16,
    completed: u16,
    generation: u64,
    failed: bool,
}

impl Attempt {
    fn ensure_active(&self) -> Result<(), CustodyError> {
        if self.failed {
            Err(CustodyError::FailedAttempt)
        } else {
            Ok(())
        }
    }

    fn refuse<T>(&mut self, error: CustodyError) -> Result<T, CustodyError> {
        self.issued = 0;
        self.consumed = 0;
        self.completed = 0;
        self.failed = true;
        Err(error)
    }

    fn next_generation(&mut self) -> Result<u64, CustodyError> {
        self.ensure_active()?;
        let Some(next) = self.generation.checked_add(1) else {
            return self.refuse(CustodyError::GenerationExhausted);
        };
        self.generation = next;
        Ok(next)
    }
}

/// One local attempt borrowing the complete original signed owner.
pub(crate) struct AttachmentCustody<'tx> {
    owner: Owner<'tx>,
    attempt: Attempt,
}

impl<'tx> AttachmentCustody<'tx> {
    /// Check original signature and schema, without cloning the attachment data.
    ///
    /// This does not replace consensus admission or the actor's authorization.
    pub(crate) fn new(source: &'tx SignedTransaction) -> Result<Self, CustodyError> {
        source.verify_signature()?;
        source.validate_signed_attachments_v1()?;
        Ok(Self {
            owner: Owner { source },
            attempt: Attempt::default(),
        })
    }

    /// Require the actual direct instruction object borrowed from this signed owner.
    /// An equal re-encoding or clone is not the original executable source.
    pub(super) fn require_original_direct_instruction(
        &mut self,
        index: u32,
        instruction: &iroha_data_model::isi::InstructionBox,
    ) -> Result<(), CustodyError> {
        use iroha_data_model::transaction::{Executable, ExecutableBatchItem};
        self.attempt.ensure_active()?;
        let position = usize::try_from(index).map_err(|_| CustodyError::WrongInvocation(index));
        let Ok(position) = position else {
            return self.attempt.refuse(CustodyError::WrongInvocation(index));
        };
        let original = match self.owner.source.instructions() {
            Executable::Instructions(instructions) => instructions.get(position),
            Executable::Batch(items) => items.get(position).and_then(|item| match item {
                ExecutableBatchItem::Instruction(original) => Some(original),
                ExecutableBatchItem::ContractCall(_) => None,
            }),
            Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_) => None,
        };
        if original.is_some_and(|original| core::ptr::eq(original, instruction)) {
            Ok(())
        } else {
            self.attempt.refuse(CustodyError::ForeignOwner)
        }
    }

    /// Visit the transaction-level carrier scope under the original signer.
    pub(crate) fn transaction<T, E: From<CustodyError>>(
        &mut self,
        visit: impl FnOnce(&mut Invocation<'_, 'tx>) -> Result<T, E>,
    ) -> Result<T, E> {
        self.invoke(
            ActionInvocationBindingV1::Transaction,
            self.owner.source.authority(),
            visit,
        )
    }

    /// Visit an already authorized direct native instruction at its exact position.
    pub(crate) fn direct<T, E: From<CustodyError>>(
        &mut self,
        instruction_index: u32,
        actor: &AccountId,
        visit: impl FnOnce(&mut Invocation<'_, 'tx>) -> Result<T, E>,
    ) -> Result<T, E> {
        self.invoke(
            ActionInvocationBindingV1::Direct { instruction_index },
            actor,
            visit,
        )
    }

    /// Visit an already authorized root contract call at its exact batch position.
    pub(crate) fn contract<T, E: From<CustodyError>>(
        &mut self,
        root_index: u32,
        actor: &AccountId,
        visit: impl FnOnce(&mut Invocation<'_, 'tx>) -> Result<T, E>,
    ) -> Result<T, E> {
        self.invoke(
            ActionInvocationBindingV1::Contract {
                root_index,
                call_path: Vec::new(),
            },
            actor,
            visit,
        )
    }

    fn invoke<T, E: From<CustodyError>>(
        &mut self,
        binding: ActionInvocationBindingV1,
        actor: &AccountId,
        visit: impl FnOnce(&mut Invocation<'_, 'tx>) -> Result<T, E>,
    ) -> Result<T, E> {
        let generation = self.attempt.next_generation()?;
        let mut frame = Invocation {
            owner: &self.owner,
            attempt: &mut self.attempt,
            binding,
            actor,
            generation,
            next_child: 0,
        };
        frame.run(visit)
    }

    /// Consume the attempt only after every declaration completed locally.
    ///
    /// Success is bookkeeping, not a proof-verification or State-commit capability.
    pub(crate) fn finish(mut self) -> Result<(), CustodyError> {
        self.attempt.ensure_active()?;
        if let Some(attachments) = self.owner.source.attachments() {
            for action in attachments.actions() {
                if self.attempt.completed & bit(action.action_index) == 0 {
                    return self
                        .attempt
                        .refuse(CustodyError::UnconsumedAction(action.action_index));
                }
            }
        }
        Ok(())
    }
}

/// A lexical host invocation; its actor is supplied by the ordinary authorization owner.
pub(crate) struct Invocation<'owner, 'tx> {
    owner: &'owner Owner<'tx>,
    attempt: &'owner mut Attempt,
    binding: ActionInvocationBindingV1,
    actor: &'owner AccountId,
    generation: u64,
    next_child: u32,
}

impl<'owner, 'tx> Invocation<'owner, 'tx> {
    fn run<T, E: From<CustodyError>>(
        &mut self,
        visit: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        // Dropping this guard also poisons the attempt during an unwind.
        let mut guard = InvocationGuard {
            frame: self,
            completed: false,
        };
        let value = visit(guard.frame)?;
        guard.frame.check_exit()?;
        guard.completed = true;
        Ok(value)
    }

    fn check_exit(&mut self) -> Result<(), CustodyError> {
        self.attempt.ensure_active()?;
        if let Some(attachments) = self.owner.source.attachments() {
            for action in attachments.actions() {
                if action.invocation == self.binding
                    && self.attempt.completed & bit(action.action_index) == 0
                {
                    return self
                        .attempt
                        .refuse(CustodyError::UnconsumedAction(action.action_index));
                }
            }
        }
        Ok(())
    }

    fn action(&mut self, request: ActionRequest<'_>) -> Result<&'tx ActionIntentV1, CustodyError> {
        self.attempt.ensure_active()?;
        let Some(action) = self
            .owner
            .source
            .attachments()
            .and_then(|a| a.action(request.index))
        else {
            return self
                .attempt
                .refuse(CustodyError::MissingAction(request.index));
        };
        if action.invocation != self.binding {
            return self
                .attempt
                .refuse(CustodyError::WrongInvocation(request.index));
        }
        let authority = match &action.authority {
            ActionAuthorityBindingV1::TransactionAuthority => self.owner.source.authority(),
            ActionAuthorityBindingV1::ContractSubject(account)
            | ActionAuthorityBindingV1::Account(account) => account,
        };
        if authority != self.actor {
            return self
                .attempt
                .refuse(CustodyError::WrongAuthority(request.index));
        }
        if &action.operation != request.operation
            || action.role != request.role
            || action.public_inputs_digest != request.public_inputs_digest
        {
            return self
                .attempt
                .refuse(CustodyError::WrongAction(request.index));
        }
        if self.attempt.completed & bit(request.index) != 0 {
            return self
                .attempt
                .refuse(CustodyError::ReusedAction(request.index));
        }
        Ok(action)
    }

    /// Open exactly one declared slot for this native request and authorized invocation.
    pub(crate) fn open(
        &mut self,
        request: ActionRequest<'_>,
        slot: u32,
        kind: AttachmentKindV1,
        role: AttachmentRoleV1,
    ) -> Result<AttachmentHandle<'owner, 'tx>, CustodyError> {
        let action = self.action(request)?;
        let Some(reference) = usize::try_from(slot)
            .ok()
            .and_then(|i| action.attachments.get(i))
        else {
            return self.attempt.refuse(CustodyError::MissingSlot {
                action: request.index,
                slot,
            });
        };
        if reference.kind != kind || reference.role != role {
            return self
                .attempt
                .refuse(CustodyError::WrongTypeOrRole(reference.index));
        }
        if self.attempt.issued & bit(reference.index) != 0 {
            return self
                .attempt
                .refuse(CustodyError::ReusedAttachment(reference.index));
        }
        self.attempt.issued |= bit(reference.index);
        Ok(AttachmentHandle {
            owner: self.owner,
            generation: self.generation,
            action: request.index,
            slot,
        })
    }

    /// Consume a host token and borrow its original bytes for this native call.
    /// The returned data is not evidence that a verifier accepted those bytes.
    pub(crate) fn consume(
        &mut self,
        request: ActionRequest<'_>,
        handle: AttachmentHandle<'_, '_>,
        kind: AttachmentKindV1,
        role: AttachmentRoleV1,
    ) -> Result<&[u8], CustodyError> {
        self.attempt.ensure_active()?;
        if !std::ptr::eq(self.owner, handle.owner) {
            return self.attempt.refuse(CustodyError::ForeignOwner);
        }
        if self.generation != handle.generation {
            return self.attempt.refuse(CustodyError::ExpiredHandle);
        }
        if handle.action != request.index {
            return self
                .attempt
                .refuse(CustodyError::WrongAction(request.index));
        }
        let action = self.action(request)?;
        let Some(reference) = action.attachments.get(handle.slot as usize) else {
            return self.attempt.refuse(CustodyError::MissingSlot {
                action: handle.action,
                slot: handle.slot,
            });
        };
        if reference.kind != kind || reference.role != role {
            return self
                .attempt
                .refuse(CustodyError::WrongTypeOrRole(reference.index));
        }
        if self.attempt.issued & bit(reference.index) == 0
            || self.attempt.consumed & bit(reference.index) != 0
        {
            return self
                .attempt
                .refuse(CustodyError::ReusedAttachment(reference.index));
        }
        let Some(occurrence) = self
            .owner
            .source
            .attachments()
            .and_then(|a| a.occurrence(reference.index))
        else {
            return self
                .attempt
                .refuse(CustodyError::UnconsumedAttachment(reference.index));
        };
        self.attempt.consumed |= bit(reference.index);
        Ok(&occurrence.bytes)
    }

    /// Complete this action's consumption, after the caller's actual native work.
    pub(crate) fn finish_action(&mut self, request: ActionRequest<'_>) -> Result<(), CustodyError> {
        let action = self.action(request)?;
        for reference in &action.attachments {
            if self.attempt.consumed & bit(reference.index) == 0 {
                return self
                    .attempt
                    .refuse(CustodyError::UnconsumedAttachment(reference.index));
            }
        }
        self.attempt.completed |= bit(request.index);
        Ok(())
    }

    /// Enter the next child in actual call order, under its separately authorized actor.
    /// Parent handles remain usable only by the parent after a successful child exit.
    pub(crate) fn child<T, E: From<CustodyError>>(
        &mut self,
        actor: &AccountId,
        visit: impl FnOnce(&mut Invocation<'_, 'tx>) -> Result<T, E>,
    ) -> Result<T, E> {
        self.attempt.ensure_active()?;
        let ActionInvocationBindingV1::Contract {
            root_index,
            call_path,
        } = &self.binding
        else {
            return self
                .attempt
                .refuse(CustodyError::InvalidChild)
                .map_err(E::from);
        };
        if call_path.len() >= ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1 {
            return self
                .attempt
                .refuse(CustodyError::InvalidChild)
                .map_err(E::from);
        }
        let Some(next_child) = self.next_child.checked_add(1) else {
            return self
                .attempt
                .refuse(CustodyError::GenerationExhausted)
                .map_err(E::from);
        };
        let mut child_path = call_path.clone();
        child_path.push(self.next_child);
        self.next_child = next_child;
        let binding = ActionInvocationBindingV1::Contract {
            root_index: *root_index,
            call_path: child_path,
        };
        let generation = self.attempt.next_generation()?;
        let mut child = Invocation {
            owner: self.owner,
            attempt: self.attempt,
            binding,
            actor,
            generation,
            next_child: 0,
        };
        child.run(visit)
    }
}

// Never reset failed state when an invocation unwinds or its caller swallows an error.
struct InvocationGuard<'frame, 'owner, 'tx> {
    frame: &'frame mut Invocation<'owner, 'tx>,
    completed: bool,
}
impl Drop for InvocationGuard<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.frame.attempt.refuse::<()>(CustodyError::FailedAttempt);
        }
    }
}

// Shared validation establishes contiguous indices in 0..16 before any use.
fn bit(index: u32) -> u16 {
    1_u16 << index
}

/// Bounded native PGC relation consumer; no executor or State authority.
pub(crate) mod pgc_bootstrap;

#[cfg(test)]
mod tests;
