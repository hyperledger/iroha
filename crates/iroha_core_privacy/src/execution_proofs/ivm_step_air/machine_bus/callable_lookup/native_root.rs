//! Public callable selection from a sealed native root, never a supplied count.

use super::*;

impl SelectedCallable {
    /// This establishes the narrow component's public root shape only. Signed
    /// intent, execution-statement and finalized-State authority remain separate.
    pub(in super::super) fn native_public_leaf_root(
        native: &ivm::execution_packets::NativeInvocation,
    ) -> Option<Self> {
        use ivm_abi::{call::CallTypeNodeV1, entrypoint::EntrypointValueKindV1};
        let artifact = native.artifact();
        let interface = artifact.contract_interface();
        let public = interface.entrypoints.get(native.entrypoint_index())?;
        let callable = interface
            .callables
            .iter()
            .find(|callable| callable.entry_pc == public.entry_pc)?;
        if public.argument_schema.is_some()
            || !callable.arguments.nodes.is_empty()
            || !matches!(
                callable.results.nodes.as_slice(),
                [CallTypeNodeV1::Unit | CallTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)]
            )
        {
            return None;
        }
        let mut result = Self::zero();
        result.include(
            F::ONE,
            Callable {
                entry: callable.entry_pc,
                absolute: artifact
                    .code_offset()
                    .checked_sub(artifact.header_len())?
                    .try_into()
                    .ok()
                    .and_then(|prefix: u64| prefix.checked_add(callable.entry_pc))?,
                frame: callable.frame_bytes,
                arguments: callable.arguments.analyze()?.word_count(),
                results: callable.results.analyze()?.word_count(),
            },
        );
        Some(result)
    }
}
