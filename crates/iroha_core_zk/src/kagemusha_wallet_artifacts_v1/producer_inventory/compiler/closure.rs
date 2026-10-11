//! Full unsigned catalog assembly after exact source dependency closure.

use super::*;

fn intern(originals: &mut Vec<OriginalV1>, item: OriginalV1) -> Result<u32, CompilationErrorV1> {
    let i = if let Some(i) = originals.iter().position(|old| *old == item) {
        i
    } else {
        if originals.len() >= ARTIFACT_MAX_COUNT_V1 {
            return Err(CompilationErrorV1::Closure);
        }
        originals.push(item);
        originals.len() - 1
    };
    u32::try_from(i).map_err(|_| CompilationErrorV1::Closure)
}

impl OfflineCompilerV1<'_> {
    /// Assemble the complete unsigned inventory only after every logical route
    /// closes under the exact newly compiled Omega key and ordered terminal catalog.
    /// Signing, independent genesis authentication, direct receipt verification,
    /// measured proof bounds and authenticated installation remain separate.
    /// # Errors
    /// Missing/reordered route, another scope/dependency,
    /// nonuniform terminal catalog or invalid/over-capacity canonical metadata.
    pub fn inventory(
        &self,
        sigmas: &CompiledSigmasV1,
        operations: &[CompiledOperationV1],
        omega: &CompiledOmegaV1,
    ) -> Result<ProducerInventoryV1, CompilationErrorV1> {
        let routes = compiled_routes();
        if operations.len() != routes.len() {
            return Err(CompilationErrorV1::Closure);
        }
        let mut originals = Vec::new();
        let mut sigma = [0; 16];
        for (out, key) in sigma.iter_mut().zip(sigmas.keys()) {
            *out = intern(&mut originals, key.original)?;
        }
        let mut programs = Vec::new();
        let mut dispatch = Vec::new();
        let mut terminals = Vec::new();
        let mut terminal_keys: Vec<&KeyArtifact<Eq>> = Vec::new();
        for (operation, route) in operations.iter().zip(routes) {
            if operation.scope != self.scope
                || operation.route != route
                || if route.variant == Variant::Bootstrap {
                    operation.predecessor.is_some()
                } else {
                    operation
                        .predecessor
                        .as_ref()
                        .is_none_or(|k| !equal(k, &omega.key.metadata))
                }
            {
                return Err(CompilationErrorV1::Closure);
            }
            let record = OperationV1 {
                variant: u8::try_from(
                    Variant::ALL
                        .iter()
                        .position(|v| *v == route.variant)
                        .ok_or(CompilationErrorV1::Closure)?
                        + 1,
                )
                .map_err(|_| CompilationErrorV1::Closure)?,
                own_class: operation.own.clone(),
                incoming_class: operation.incoming.clone(),
                context: operation.context.clone(),
                q: operation
                    .q
                    .iter()
                    .map(|k| intern(&mut originals, k.original))
                    .collect::<Result<_, _>>()?,
                a: operation
                    .a
                    .iter()
                    .map(|k| intern(&mut originals, k.original))
                    .collect::<Result<_, _>>()?,
                w: operation
                    .w
                    .iter()
                    .map(|k| intern(&mut originals, k.original))
                    .collect::<Result<_, _>>()?,
            };
            let index = if let Some(index) = programs.iter().position(|old| *old == record) {
                index
            } else {
                let terminal = &operation.terminal().metadata;
                if !terminal_keys.iter().any(|old| equal(old, terminal)) {
                    if terminal_keys
                        .first()
                        .is_some_and(|first| first.binding() != terminal.binding())
                    {
                        return Err(CompilationErrorV1::Closure);
                    }
                    terminal_keys.push(terminal);
                    terminals.push(*record.a.last().ok_or(CompilationErrorV1::Closure)?);
                }
                programs.push(record);
                programs.len() - 1
            };
            dispatch.push(u32::try_from(index).map_err(|_| CompilationErrorV1::Closure)?);
        }
        if terminal_keys.len() != omega.terminals.len()
            || !terminal_keys
                .iter()
                .zip(&omega.terminals)
                .all(|(a, b)| equal(a, b))
        {
            return Err(CompilationErrorV1::Closure);
        }
        let omega = intern(&mut originals, omega.key.original)?;
        let inventory = ProducerInventoryV1 {
            version: 1,
            native_profile: artifact_digest(b"native-profile", &native_profile_transcript_v1()?),
            originals,
            sigma,
            operations: programs,
            routes: dispatch,
            terminals,
            omega,
        };
        inventory.validate()?;
        Ok(inventory)
    }
}
