//! Canonical public entrypoint descriptors, schemas, access hints and triggers.
//!
//! Descriptor construction joins typed entrypoints with their compiled offsets
//! and deterministic access reports. Every public argument/result schema and
//! trigger binding is validated here before the artifact publishes its interface.

use super::*;

pub(super) fn build_entrypoint_descriptors(
    typed: &TypedProgram,
    access_sets: &[AccessSets],
    ir_functions: &[ir::Function],
    hint_reports: &[HintReport],
    func_start_offsets: &HashMap<String, usize>,
) -> Result<Vec<EmbeddedEntrypointDescriptor>, String> {
    let mut hints_by_name: HashMap<&str, (&IndexSet<String>, &IndexSet<String>)> = HashMap::new();
    let mut hint_report_by_name: HashMap<&str, &HintReport> = HashMap::new();
    for ((func, sets), report) in ir_functions
        .iter()
        .zip(access_sets.iter())
        .zip(hint_reports.iter())
    {
        hints_by_name.insert(&func.name, (&sets.reads, &sets.writes));
        hint_report_by_name.insert(&func.name, report);
    }
    let mut triggers_by_name: HashMap<String, Vec<TriggerDescriptor>> = HashMap::new();
    for trigger in &typed.triggers {
        let descriptor = TriggerDescriptor {
            id: trigger.id.clone(),
            repeats: trigger.repeats,
            filter: trigger.filter.clone(),
            authority: trigger.authority.clone(),
            metadata: trigger.metadata.clone(),
            callback: TriggerCallback {
                namespace: None,
                entrypoint: trigger.call.entrypoint.clone(),
            },
        };
        triggers_by_name
            .entry(trigger.call.entrypoint.clone())
            .or_default()
            .push(descriptor);
    }
    let build_descriptor = |func: &semantic::TypedFunction,
                            kind: EntryPointKind|
     -> Result<EmbeddedEntrypointDescriptor, String> {
        let hint_name = entrypoint_ir_symbol_name(func);
        let mut hint_names = vec![hint_name.as_str()];
        if hint_name != func.name {
            hint_names.push(func.name.as_str());
        }
        let reports = hint_names
            .iter()
            .map(|name| {
                hint_report_by_name.get(name).copied().ok_or_else(|| {
                    format!("missing access-hint report for entrypoint function `{name}`")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let include_hints = reports.iter().any(|report| report.emitted);
        let mut read_set = IndexSet::new();
        let mut write_set = IndexSet::new();
        if include_hints {
            for name in &hint_names {
                let (reads, writes) = hints_by_name.get(name).copied().ok_or_else(|| {
                    format!("missing access hints for entrypoint function `{name}`")
                })?;
                read_set.extend(reads.iter().cloned());
                write_set.extend(writes.iter().cloned());
            }
        }
        let mut reads = read_set.into_iter().collect::<Vec<_>>();
        let mut writes = write_set.into_iter().collect::<Vec<_>>();
        if include_hints && (reads.is_empty() || writes.is_empty()) {
            let (fallback_reads, fallback_writes) =
                crate::semantic::function_state_accesses(func, &typed.states);
            if reads.is_empty() && !fallback_reads.is_empty() {
                reads = fallback_reads.iter().cloned().collect();
            }
            if writes.is_empty() && !fallback_writes.is_empty() {
                writes = fallback_writes.iter().cloned().collect();
            }
        }
        let reads = canonical_state_hint_keys(reads);
        let writes = canonical_state_hint_keys(writes);
        let triggers = triggers_by_name
            .get(func.name.as_str())
            .cloned()
            .unwrap_or_default();
        let skipped_reasons = reports
            .iter()
            .flat_map(|report| report.skipped_reasons.iter().cloned())
            .collect::<IndexSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let entry_pc = func_start_offsets
            .get(&func.name)
            .copied()
            .ok_or_else(|| format!("missing function offset for entrypoint `{}`", func.name))?;
        let argument_schema = crate::ir::entrypoint_argument_schema(&func.param_types)?;
        let params = match argument_schema.as_ref() {
            None if func.param_types.is_empty() => Vec::new(),
            Some(schema) if schema.fields.len() == func.param_types.len() => func
                .param_types
                .iter()
                .zip(&schema.fields)
                .map(|(param, field)| {
                    let type_name = field.ty.canonical_type_name().ok_or_else(|| {
                        format!(
                            "entrypoint `{}` parameter `{}` has no canonical ABI type name",
                            func.name, param.name
                        )
                    })?;
                    Ok(EntrypointParamDescriptor {
                        name: param.name.clone(),
                        type_name,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
            _ => {
                return Err(format!(
                    "entrypoint `{}` argument schema does not match its declared parameters",
                    func.name
                ));
            }
        };
        let return_schema = crate::ir::entrypoint_return_schema(&func.name, func.ret_ty.as_ref())?;
        let return_type = return_schema
            .as_ref()
            .map(|schema| {
                schema.canonical_type_name().ok_or_else(|| {
                    format!(
                        "entrypoint `{}` return schema has no canonical ABI type name",
                        func.name
                    )
                })
            })
            .transpose()?;
        Ok(EmbeddedEntrypointDescriptor {
            name: func.name.clone(),
            kind,
            params,
            argument_schema,
            return_type,
            return_schema,
            authorization: match func.modifiers.kind {
                crate::ast::FunctionKind::Hajimari | crate::ast::FunctionKind::Kaizen => iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::RuntimeLifecycle,
                _ => match func.modifiers.authorization.as_deref() {
                    Some("anyone") => iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
                    Some(name) => iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(name.parse().map_err(|error| format!("invalid permission name `{name}`: {error}"))?),
                    None => return Err(format!("public function `{}` has no authorization policy", func.name)),
                },
            },
            read_keys: reads,
            write_keys: writes,
            access_hints_complete: include_hints
                .then_some(reports.iter().all(|report| report.complete)),
            access_hints_skipped: skipped_reasons,
            triggers,
            entry_pc: u64::try_from(entry_pc)
                .map_err(|_| format!("entrypoint `{}` PC does not fit u64", func.name))?,
        })
    };
    let entrypoints: Vec<EmbeddedEntrypointDescriptor> = typed
        .items
        .iter()
        .filter_map(|item| match item {
            TypedItem::Function(func) => {
                let kind = entrypoint_kind_from_modifiers(&func.modifiers)?;
                Some(build_descriptor(func, kind))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(entrypoints)
}
fn entrypoint_kind_from_modifiers(modifiers: &FunctionModifiers) -> Option<EntryPointKind> {
    match modifiers.kind {
        FunctionKind::Kotoage => Some(EntryPointKind::Kotoage),
        FunctionKind::View => Some(EntryPointKind::View),
        FunctionKind::Hajimari => Some(EntryPointKind::Hajimari),
        FunctionKind::Kaizen => Some(EntryPointKind::Kaizen),
        FunctionKind::Private => None,
    }
}
