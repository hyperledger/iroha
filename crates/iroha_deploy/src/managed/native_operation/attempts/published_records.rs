//! Share immutable terminal records only under the concrete same-owner publication parser.
//!
//! A returned History has newly supplied head evidence and no currentness verdict. The caller
//! must still run the existing epoch/wallet/local checks and complete parser exits. Every source
//! is freshly read there; this avoids only recovery parsing of records already held immutably.

use super::*;
use crate::managed::stream_token_custody::body_history::PublishedBodyRead;
use std::sync::Arc;

impl History {
    // Called only at the successful terminal closure's consuming receipt boundary. Keeping
    // Owned as the parser representation preserves the inherited decoder's allocation recipe.
    pub(super) fn into_retained_records(self) -> Self {
        let Self { records, scope } = self;
        Self {
            records: match records {
                HistoryRecordsOwner::Owned(records) => {
                    HistoryRecordsOwner::Retained(Arc::new(records))
                }
                retained @ HistoryRecordsOwner::Retained(_) => retained,
            },
            scope,
        }
    }

    /// Borrow already parsed terminal records into a fresh scope after one owned publication.
    /// The boolean marks only the omitted recovery parse, never source or wallet admission.
    pub(in crate::managed) fn read_published_with_pass(
        operation: &PrivateDirectory,
        purpose: Purpose,
        semantic: [u8; 32],
        scope: &HistoryScope,
        retained: &History,
        published: &PublishedBodyRead<'_>,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<(Self, bool)> {
        // At-use admission, including a decode owner installed after the capability was made.
        // Uncovered/current/recovery paths keep the existing parser and its exact errors.
        if norito::core::decode_limits_active() || pass.is_none() {
            return Self::read_retained_with_pass(
                operation, purpose, semantic, scope, retained, pass,
            )
            .map(|history| (history, false));
        }
        let HistoryScope::Enrollment(_) = scope else {
            return Self::read_retained_with_pass(
                operation, purpose, semantic, scope, retained, pass,
            )
            .map(|history| (history, false));
        };
        if !published.matches(scope.enrollment()?)? {
            return Self::read_retained_with_pass(
                operation, purpose, semantic, scope, retained, pass,
            )
            .map(|history| (history, false));
        }
        let covered = pass.is_some_and(|pass| pass.covers_retained(retained));
        if !covered {
            retained.revalidate_retained_handles()?;
        }
        // Preserve the original bounded full path/identity census, including duplicate refusal.
        let mut current = Some(retained);
        let mut matched = None;
        let mut count = 0usize;
        while let Some(history) = current {
            count += 1;
            if count > MAX_ATTEMPTS {
                return Err(invalid("retained dispatch graph exceeds its body bound"));
            }
            if history.operation.path() == operation.path() {
                if matched.is_some()
                    || history.purpose != purpose
                    || history.semantic != semantic
                    || history.operation.identity()? != operation.identity()?
                {
                    return Err(invalid("retained dispatch belongs to another original"));
                }
                matched = Some(history);
            }
            current = history
                .scope
                .predecessor()
                .map(VerifiedUnsignedClosure::retained_history);
        }
        let Some(prior) = matched else {
            return Self::read_retained_with_pass(
                operation, purpose, semantic, scope, retained, pass,
            )
            .map(|history| (history, false));
        };
        let HistoryRecordsOwner::Retained(records) = &prior.records else {
            return Self::read_retained_with_pass(
                operation, purpose, semantic, scope, retained, pass,
            )
            .map(|history| (history, false));
        };
        if prior.closed.is_none()
            || !published.matches(prior.scope.enrollment()?)?
            || prior.scope.commitment()? != scope.commitment()?
        {
            return Self::read_retained_with_pass(
                operation, purpose, semantic, scope, retained, pass,
            )
            .map(|history| (history, false));
        }
        // Only the admitted immutable record owner is copied here. Both reference clones are
        // infallible and callback-free; the new scope does not enter this handle census.
        // Preserve all original physical checks for a decoder active at this use boundary.
        let repeat_prior_handles = norito::core::decode_limits_active();
        #[cfg(test)]
        let repeat_prior_handles = repeat_prior_handles || original_handle_recipe();
        if repeat_prior_handles {
            prior.revalidate_handles()?;
        }
        let history = Self {
            records: HistoryRecordsOwner::Retained(Arc::clone(records)),
            scope: scope.retained_copy(),
        };
        #[cfg(test)]
        let copied = after_record_copy();
        if repeat_prior_handles {
            prior.revalidate_handles()?;
        }
        // The full final census closes the same original operation/root/attempt handles.
        // A source change restored wholly between omitted observations may be unseen.
        // Existing fresh record/scope validation still precedes the first wallet callback.
        history.revalidate_handles()?;
        #[cfg(test)]
        copied?;
        if !covered {
            retained.revalidate_retained_handles()?;
        }
        Ok((history, true))
    }

    /// Close fresh metadata and original custody when epoch admission fails before wallets.
    pub(in crate::managed) fn close_published_epoch_error(
        &self,
        pass: Option<&EnrollmentReadPass<'_>>,
    ) -> Result<()> {
        self.revalidate_parser_handles(pass)?;
        let current = self.require_current_with_pass(pass);
        self.revalidate_parser_handles(pass)?;
        current
    }
}

#[cfg(test)]
type AfterRecordCopy = Box<dyn FnOnce() -> Result<()>>;
#[cfg(test)]
thread_local! {
    static ORIGINAL_HANDLE_RECIPE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static AFTER_RECORD_COPY: std::cell::RefCell<Option<AfterRecordCopy>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn original_handle_recipe() -> bool {
    ORIGINAL_HANDLE_RECIPE.with(std::cell::Cell::get)
}
#[cfg(test)]
fn after_record_copy() -> Result<()> {
    AFTER_RECORD_COPY
        .with(|state| state.take())
        .map_or(Ok(()), |action| action())
}

#[cfg(test)]
impl History {
    pub(in crate::managed) fn test_published_handle_recipe<T>(
        original: bool,
        after_copy: Option<Box<dyn FnOnce() -> Result<()>>>,
        read: impl FnOnce() -> T,
    ) -> T {
        struct Restore(bool, Option<AfterRecordCopy>);
        impl Drop for Restore {
            fn drop(&mut self) {
                ORIGINAL_HANDLE_RECIPE.with(|state| state.set(self.0));
                AFTER_RECORD_COPY.with(|state| state.replace(self.1.take()));
            }
        }
        let _restore = Restore(
            ORIGINAL_HANDLE_RECIPE.with(|state| state.replace(original)),
            AFTER_RECORD_COPY.with(|state| state.replace(after_copy)),
        );
        read()
    }

    pub(in crate::managed) fn test_published_read(
        &self,
        source: &History,
        published: &PublishedBodyRead<'_>,
        pass: Option<&EnrollmentReadPass<'_>>,
        canonical: bool,
    ) -> Result<(Self, bool)> {
        if canonical {
            Self::read_retained_with_pass(
                &self.operation,
                self.purpose,
                self.semantic,
                &self.scope,
                source,
                pass,
            )
            .map(|history| (history, false))
        } else {
            Self::read_published_with_pass(
                &self.operation,
                self.purpose,
                self.semantic,
                &self.scope,
                source,
                published,
                pass,
            )
        }
    }

    pub(in crate::managed) fn test_shares_published_records(&self, other: &Self) -> bool {
        match (&self.records, &other.records) {
            (HistoryRecordsOwner::Retained(left), HistoryRecordsOwner::Retained(right)) => {
                Arc::ptr_eq(left, right)
            }
            _ => false,
        }
    }
}
