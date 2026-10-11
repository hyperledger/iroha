//! Complete offline source walk, followed by exact final-key reconstruction.

use super::*;

fn selected_class(
    route: OperationRoute,
    classes: &[QClassesV1],
) -> Result<usize, CompilationErrorV1> {
    let mut selected = None;
    for (index, class) in classes.iter().enumerate() {
        if class.own.contains(&route.own)
            && match route.incoming {
                Some(incoming) => class.incoming.contains(&incoming),
                None => class.incoming.is_empty(),
            }
            && selected.replace(index).is_some()
        {
            return Err(CompilationErrorV1::Closure);
        }
    }
    selected.ok_or(CompilationErrorV1::Closure)
}

impl OfflineCompilerV1<'_> {
    /// Compile every fixed logical wallet route and close its original sources
    /// under the exact final compact Omega key before emitting unsigned metadata.
    ///
    /// The initial single-terminal Omega is only a raw witness-key source recipe.
    /// All A/W originals are strictly reconstructed under the completed catalog's
    /// final key before any inventory is returned. No temporary inventory is signed
    /// or installed, and no provisional key is retained in the returned inventory.
    /// Authenticated installation, actual proof bounds and performance qualification
    /// remain required. Ordinary Load finality is verified directly from BLS certificates.
    /// Partial content-addressed outputs are preserved on failure.
    ///
    /// # Errors
    /// Absent or ambiguous source class, any source or
    /// original failure, nonuniform/over-capacity terminal catalog, changed final
    /// descriptor, or failure to close any of the complete logical routes.
    pub fn wallet(&mut self) -> Result<ProducerInventoryV1, CompilationErrorV1> {
        let sigmas = self.sigmas()?;
        let mut programs = Vec::new();
        let mut selectors = Vec::new();
        for variant in Variant::ALL {
            let classes = q_classes(variant, &sigmas);
            for route in compiled_routes()
                .into_iter()
                .filter(|r| r.variant == variant)
            {
                selected_class(route, &classes)?;
            }
            for class in classes {
                programs.push(self.q(variant, &class.own, &class.incoming, &sigmas)?);
                selectors.push((variant, class));
            }
        }
        let routes = compiled_routes();
        if routes
            .first()
            .is_none_or(|route| route.variant != Variant::Bootstrap)
        {
            return Err(CompilationErrorV1::Closure);
        }
        let mut operations = Vec::with_capacity(routes.len());
        let mut program_indices = Vec::with_capacity(routes.len());
        let mut provisional: Option<CompiledOmegaV1> = None;
        for route in routes {
            let matching: Vec<_> = selectors
                .iter()
                .enumerate()
                .filter(|(_, (variant, class))| {
                    *variant == route.variant
                        && class.own.contains(&route.own)
                        && match route.incoming {
                            Some(incoming) => class.incoming.contains(&incoming),
                            None => class.incoming.is_empty(),
                        }
                })
                .map(|(index, _)| index)
                .collect();
            let [index] = matching.as_slice() else {
                return Err(CompilationErrorV1::Closure);
            };
            let operation = self.operation(
                route,
                &programs[*index],
                if route.variant == Variant::Bootstrap {
                    None
                } else {
                    Some(
                        provisional
                            .as_ref()
                            .ok_or(CompilationErrorV1::Closure)?
                            .key(),
                    )
                },
            )?;
            if route.variant == Variant::Bootstrap {
                if provisional.is_some() {
                    return Err(CompilationErrorV1::Closure);
                }
                provisional = Some(self.omega(&[operation.terminal()])?);
            }
            operations.push(operation);
            program_indices.push(*index);
        }
        let mut terminals: Vec<&CompiledKeyV1<Eq>> = Vec::new();
        for operation in &operations {
            let terminal = operation.terminal();
            if !terminals
                .iter()
                .any(|old| equal(&old.metadata, &terminal.metadata))
            {
                terminals.push(terminal);
            }
        }
        let omega = self.omega(&terminals)?;
        let mut closed = Vec::with_capacity(operations.len());
        for (operation, index) in operations.iter().zip(program_indices) {
            closed.push(self.close_operation(operation, &programs[index], &omega)?);
        }
        self.inventory(&sigmas, &closed, &omega)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_logical_route_requires_exactly_one_own_and_incoming_class() {
        for route in compiled_routes() {
            let class = QClassesV1 {
                own: vec![route.own],
                incoming: route.incoming.into_iter().collect(),
            };
            assert_eq!(
                selected_class(route, std::slice::from_ref(&class)).unwrap(),
                0
            );
            assert!(selected_class(route, &[]).is_err());
            assert!(selected_class(route, &[class.clone(), class.clone()]).is_err());
            let mut wrong = class.clone();
            wrong.own = vec![(route.own + 1) % 16];
            assert!(selected_class(route, &[wrong]).is_err());
            let mut wrong = class;
            wrong.incoming = route.incoming.map_or_else(|| vec![0], |_| vec![]);
            assert!(selected_class(route, &[wrong]).is_err());
        }
    }
}
