//! Exact original epoch images during one concrete read-only body-history parser.
//!
//! Selected origins still freshly read their epoch and optional claim before semantic use.
//! Other epoch siblings and namespace changes close at the unconditional complete exit;
//! rejection can occur after later read-only wallet inspections. No freshness receipt leaves
//! this scope. A sibling changed and restored wholly between its observations can go
//! unobserved; this is not an atomic snapshot or an unwind guarantee. Signing, retirement,
//! publication and live Lease checks never borrow it.

use super::*;
use crate::managed::{
    native_operation::attempts::EnrollmentReadPass,
    stream_token_custody::body_history::ReadOnlyHistoryParser,
};

/// The concrete body owner supplies the original parent and exact historical bindings.
pub(in crate::managed) struct BodyParserEpochContext {
    /// Original native enrollment root, never an independently reopened equivalent path.
    pub(in crate::managed) parent: Arc<PrivateDirectory>,
    /// Canonical selection digest already verified by the concrete body parser.
    pub(in crate::managed) parent_intent: [u8; 32],
    /// Original bounded fee authorization metadata; this grants no live authorization.
    pub(in crate::managed) fees: Fees,
    /// Exact closed purpose of this historical epoch sequence.
    pub(in crate::managed) scope: Scope,
}
pub(super) struct Source {
    context: BodyParserEpochContext,
    root: Option<PrivateDirectory>,
}
impl Source {
    fn revalidate(&self) -> Result<()> {
        let root = self
            .root
            .as_ref()
            .map_or(Ok(()), PrivateDirectory::revalidate);
        // Always close the original parent, even when the held child refuses.
        self.context.parent.revalidate()?;
        root.map_err(Into::into)
    }
    fn matches(
        &self,
        directory: &PrivateDirectory,
        intent: [u8; 32],
        fees: &Fees,
        scope: Scope,
    ) -> bool {
        std::ptr::eq(self.context.parent.as_ref(), directory)
            && self.context.parent_intent == intent
            && self.context.fees == *fees
            && self.context.scope == scope
    }
}

impl EpochReader {
    // Only a sealed concrete parser can create this scope; no arbitrary callback receives it.
    // Preserve the independent initial census in BodyHistory::read. This is a second full
    // entry followed by selected-origin reads and one full exit, all with original limits.
    pub(in crate::managed) fn read_body_histories(
        &mut self,
        parser: ReadOnlyHistoryParser<'_>,
        pass: &EnrollmentReadPass<'_>,
    ) -> Result<()> {
        if norito::core::decode_limits_active() {
            return parser.read(pass, self);
        }
        #[cfg(test)]
        if tests::original_recipe() {
            return parser.read(pass, self);
        }
        let Some(context) = parser.epoch_context()? else {
            return parser.read(pass, self);
        };
        if self.parser_source.is_some() {
            return Err(invalid("epoch parser source is already borrowed"));
        }
        let source = self.open_parser_source(context)?;
        self.parser_source = Some(source);
        let result = parser.read(pass, self);
        // Clear the source before any fallible projection. Even an ordinary exit refusal
        // cannot leave coverage armed in this reusable metadata workspace.
        let source = self
            .parser_source
            .take()
            .expect("concrete parser owns its epoch source");
        let exit = self.close_parser_source(&source);
        exit?;
        result
    }

    pub(super) fn validate_parser_references<'a>(
        &self,
        directory: &PrivateDirectory,
        original_digest: [u8; 32],
        fees: &Fees,
        scope: Scope,
        origins: impl Iterator<Item = &'a Origin>,
    ) -> Result<()> {
        let source = self
            .parser_source
            .as_ref()
            .expect("selected parser source exists");
        if norito::core::decode_limits_active()
            || !source.matches(directory, original_digest, fees, scope)
        {
            // Foreign/native-path-equal callers and another decode owner receive independent
            // full admission. They cannot change the exact images owned by this scope.
            return EpochReader::default().validate_references(
                directory,
                original_digest,
                fees,
                scope,
                origins,
            );
        }
        source.revalidate()?;
        let result = (|| {
            for origin in origins {
                let Origin::Generated {
                    ordinal,
                    epoch,
                    parent_intent,
                } = origin
                else {
                    continue;
                };
                let index = usize::from(*ordinal)
                    .checked_sub(1)
                    .ok_or_else(|| invalid("generated epoch ordinal is zero"))?;
                let selected = self.records.get(index).ok_or_else(|| {
                    invalid("retained dispatch lost its original authorization epoch")
                })?;
                let root = source.root.as_ref().ok_or_else(|| {
                    invalid("retained dispatch lost its original authorization epoch")
                })?;
                require_exact_image(
                    root,
                    &format!("{:04}.nrt", index + 1),
                    Some(&selected.epoch),
                )?;
                require_exact_image(
                    root,
                    &format!("{:04}-replacement.nrt", index + 1),
                    selected.claim.as_ref(),
                )?;
                validate_epoch(
                    &selected.epoch,
                    index + 1,
                    index
                        .checked_sub(1)
                        .and_then(|prior| self.records.get(prior))
                        .map(|prior| &prior.epoch),
                    original_digest,
                    fees,
                )?;
                if let Some(claim) = &selected.claim {
                    validate_claim(claim, &selected.epoch, scope)?;
                }
                if *parent_intent != original_digest || *epoch != selected.epoch.digest()? {
                    return Err(invalid(
                        "retained dispatch changed its original authorization epoch",
                    ));
                }
            }
            Ok(())
        })();
        source.revalidate()?;
        result
    }

    fn open_parser_source(&mut self, context: BodyParserEpochContext) -> Result<Source> {
        let root = context.parent.open_child_optional("epochs");
        // The original parent closes even when opening the current child fails.
        context.parent.revalidate()?;
        let source = Source {
            root: root?,
            context,
        };
        source.revalidate()?;
        let entry = match &source.root {
            Some(root) => read_epochs(
                root,
                source.context.parent_intent,
                &source.context.fees,
                source.context.scope,
                std::mem::take(&mut self.records),
            ),
            None => Ok(Vec::new()),
        };
        // Failed entry metadata cannot reach body inspection. Native exit wins its error.
        source.revalidate()?;
        self.records = entry?;
        Ok(source)
    }

    fn close_parser_source(&mut self, source: &Source) -> Result<()> {
        let result = match &source.root {
            Some(root) => read_epochs_using(
                root,
                source.context.parent_intent,
                &source.context.fees,
                source.context.scope,
                std::mem::take(&mut self.records),
                true,
            ),
            None => source
                .context
                .parent
                .open_child_optional("epochs")
                .map_err(Into::into)
                .and_then(|current| {
                    if current.is_some() {
                        Err(invalid("original epoch absence changed"))
                    } else {
                        Ok(Vec::new())
                    }
                }),
        };
        // Independently close original native custody after every ordinary census result.
        source.revalidate()?;
        self.records = result?;
        Ok(())
    }
}

// The sole physical source reader preserves every native leaf check and original allocation.
// Only exact current equality to an entry-owned canonical image avoids another decoder.
fn require_exact_image<T>(
    root: &PrivateDirectory,
    name: &str,
    expected: Option<&RecordImage<T>>,
) -> Result<()> {
    let current = read_source_image(root, name)?;
    if current.as_deref() != expected.map(|image| image.bytes.as_slice()) {
        return Err(invalid("original epoch parser image changed"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;
