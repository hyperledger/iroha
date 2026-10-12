//! Finish-local immutable wallet records; every callback retains its fresh native inspection.

use super::*;
use iroha_wallet::operations::{CustodyPreparationReader, VerifiedNativePreparation};
use std::cell::OnceCell;

// Kept separately from its borrowed readers, so neither owner is self-referential. The
// account cannot be injected or replaced. Construction stays at the first actual callback;
// AccountService's constructor validates this immutable config and creates lazy transports.
pub(super) struct FinishWalletAccount<'owner> {
    owner: &'owner ManagedStreamTokenCustody,
    root: Arc<PrivateDirectory>,
    account: OnceCell<AccountService>,
}
impl<'owner> FinishWalletAccount<'owner> {
    pub(super) fn new(
        owner: &'owner ManagedStreamTokenCustody,
        root: Arc<PrivateDirectory>,
    ) -> Self {
        Self {
            owner,
            root,
            account: OnceCell::new(),
        }
    }
    fn get(&self) -> Result<&AccountService> {
        if self.account.get().is_none() {
            self.account
                .set(self.owner.wallet()?)
                .map_err(|_| invalid("Finish wallet account was already initialized"))?;
        }
        self.account
            .get()
            .ok_or_else(|| invalid("Finish wallet account initialization absent"))
    }
}

// This workspace is never a BodyHistory field or a returned receipt. One Finish creates it
// after its original live entry checks, lends it only to canonical read-only reparses, and
// drops it before returning. Body ordinals select bounded heap slots, never prove identity:
// the sole wallet reader still locks, inventories and freshly reads all records, and can
// reuse values only for exact original journal/lock identities and unchanged bytes.
pub(super) struct FinishWalletReads<'account> {
    account: &'account FinishWalletAccount<'account>,
    readers: Vec<Option<CustodyPreparationReader<'account>>>,
}
impl<'account> FinishWalletReads<'account> {
    pub(super) fn new(account: &'account FinishWalletAccount<'account>) -> Self {
        Self {
            account,
            readers: Vec::new(),
        }
    }
    pub(super) fn clear(&mut self) {
        self.readers.clear();
    }
    pub(super) fn inspect(
        &mut self,
        owner: &ManagedStreamTokenCustody,
        root: &PrivateDirectory,
        ordinal: u8,
        original: &Original,
        attempt: &attempts::Attempt,
    ) -> Result<VerifiedNativePreparation> {
        let result = self.inspect_inner(owner, root, ordinal, original, attempt);
        // Refusal cannot lend any earlier body image to a subsequent retry. The enclosing
        // reparse also clears this workspace if a later source or parser exit refuses.
        if result.is_err() {
            self.clear();
        }
        result
    }
    fn inspect_inner(
        &mut self,
        owner: &ManagedStreamTokenCustody,
        root: &PrivateDirectory,
        ordinal: u8,
        original: &Original,
        attempt: &attempts::Attempt,
    ) -> Result<VerifiedNativePreparation> {
        if !std::ptr::eq(owner, self.account.owner)
            || !std::ptr::eq(root, self.account.root.as_ref())
            || ordinal == 0
            || ordinal > MAX_BODIES
        {
            return Err(invalid(
                "Finish wallet read belongs to another original body owner",
            ));
        }
        // Preserve original callback order: account construction precedes freshly derived
        // request/observation/options. No wall-clock permission is carried by these images;
        // all supplied Plan bytes and fees are reconstructed and compared on every call.
        let account = self.account.get()?;
        let request = original.request(attempt.terms(), attempt.observation()?, Instant::now())?;
        if norito::core::decode_limits_active() {
            self.clear();
            return request.inspect_in_parent(account, attempt.directory());
        }
        let index = usize::from(ordinal - 1);
        if self.readers.len() <= index {
            self.readers
                .try_reserve_exact(index + 1 - self.readers.len())
                .map_err(|_| invalid("cannot retain bounded Finish wallet records"))?;
            self.readers.resize_with(index + 1, || None);
        }
        let slot = &mut self.readers[index];
        #[cfg(test)]
        finish_wallet_tests::reader_used(slot.is_none());
        request.inspect_with_reader(
            slot.get_or_insert_with(|| CustodyPreparationReader::new(account)),
            attempt.directory(),
        )
    }
}
