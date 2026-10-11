//! Authenticated contract namespaces, nominal schema reconstruction, and typed calls.
use super::*;
use ivm_abi::entrypoint::{
    EntrypointValueKindV1 as Kind, EntrypointValueTypeNodeV1 as Node, EntrypointValueTypeV1,
};

fn leaf_type(kind: Kind) -> Type {
    match kind {
        Kind::Int => Type::Int,
        Kind::Decimal => Type::Decimal,
        Kind::Quantity => Type::Quantity,
        Kind::Bool => Type::Bool,
        Kind::String => Type::String,
        Kind::Blob => Type::Bytes,
        Kind::Json => Type::Json,
        Kind::Name => Type::Name,
        Kind::AccountId => Type::AccountId,
        Kind::AssetDefinitionId => Type::AssetDefinitionId,
        Kind::AssetId => Type::AssetId,
        Kind::DomainId => Type::DomainId,
        Kind::NftId => Type::NftId,
        Kind::DataSpaceId => Type::DataSpaceId,
    }
}
/// Keep execution-local references out of heap containers even in unused annotations.
pub(super) fn validate_reference_containers(root: &Type) -> Result<(), SemanticError> {
    let mut pending = vec![(root, false)];
    let mut visited = HashSet::new();
    while let Some((ty, contained)) = pending.pop() {
        if !visited.insert((ty as *const Type, contained)) {
            continue;
        }
        match ty {
            Type::ContractRef(_) if contained => {
                return Err(sem_err(
                    "K2003",
                    "Option, Result, and List payloads cannot contain contract references".into(),
                ));
            }
            Type::Option(inner) | Type::List(inner, _) => pending.push((inner, true)),
            Type::Result(ok, error) => {
                pending.push((error, true));
                pending.push((ok, true));
            }
            Type::Tuple(items) => pending.extend(items.iter().rev().map(|ty| (ty, contained))),
            Type::Struct { fields, .. } => {
                pending.extend(fields.iter().rev().map(|(_, ty)| (ty, contained)))
            }
            _ => {}
        }
    }
    Ok(())
}
/// Reconstruct the exact nominal source type of an admitted public schema.
pub(crate) fn schema_type(schema: &EntrypointValueTypeV1) -> Result<Type, SemanticError> {
    if !schema.validate() {
        return Err(sem_err(
            "E_CONTRACT_IMPORT_INVALID",
            "imported public schema is not canonical".into(),
        ));
    }
    fn node(nodes: &[Node], index: &mut usize) -> Type {
        let current = &nodes[*index];
        *index += 1;
        match current {
            Node::Leaf(kind) => leaf_type(*kind),
            Node::Unit => Type::Unit,
            Node::Enum(value) => Type::Enum(Arc::new(value.clone())),
            Node::Error(value) => Type::ErrorEnum(Arc::new(value.clone())),
            Node::StateCursor(key) => Type::StateCursor(Box::new(node(&key.nodes, &mut 0))),
            Node::Option => Type::Option(Box::new(node(nodes, index))),
            Node::Result => {
                Type::Result(Box::new(node(nodes, index)), Box::new(node(nodes, index)))
            }
            Node::Tuple(arity) => Type::Tuple((0..*arity).map(|_| node(nodes, index)).collect()),
            Node::Struct(record) => Type::Struct {
                name: record.name.clone(),
                fields: record
                    .fields
                    .iter()
                    .map(|name| (name.clone(), node(nodes, index)))
                    .collect::<Vec<_>>()
                    .into(),
            },
            Node::List(list) => Type::List(Box::new(node(nodes, index)), list.capacity),
        }
    }
    Ok(node(&schema.nodes, &mut 0))
}
fn public_types(
    contract: &ImportedContractInterface,
) -> Result<BTreeMap<String, Type>, SemanticError> {
    let mut result = BTreeMap::new();
    let mut pending = Vec::new();
    for entry in &contract.interface.entrypoints {
        if !matches!(
            entry.kind,
            iroha_data_model::smart_contract::manifest::EntryPointKind::View
                | iroha_data_model::smart_contract::manifest::EntryPointKind::Kotoage
        ) {
            continue;
        }
        if let Some(schema) = &entry.argument_schema {
            for field in &schema.fields {
                pending.push(schema_type(&field.ty)?);
            }
        }
        if let Some(schema) = &entry.return_schema {
            pending.push(schema_type(schema)?);
        }
    }
    while let Some(ty) = pending.pop() {
        let identity = match &ty {
            Type::Struct { name, fields } => {
                pending.extend(fields.iter().map(|(_, ty)| ty.clone()));
                Some(name.clone())
            }
            Type::Enum(value) => Some(value.identity.clone()),
            Type::ErrorEnum(value) => Some(value.identity.clone()),
            Type::Option(inner) | Type::List(inner, _) => {
                pending.push((**inner).clone());
                None
            }
            Type::Result(ok, error) => {
                pending.push((**ok).clone());
                pending.push((**error).clone());
                None
            }
            Type::Tuple(items) => {
                pending.extend(items.iter().cloned());
                None
            }
            _ => None,
        };
        if let Some(identity) = identity
            && let Some(prior) = result.insert(identity.clone(), ty.clone())
            && prior != ty
        {
            return Err(sem_err(
                "E_CONTRACT_IMPORT_INVALID",
                format!("imported identity `{identity}` has conflicting public schemas"),
            ));
        }
    }
    Ok(result)
}
/// Resolve contract namespace aliases without changing authenticated type identities.
pub(crate) fn namespace_types(
    contracts: &BTreeMap<String, ImportedContractInterface>,
    directives: &[SourceDirective],
) -> Result<BTreeMap<String, Type>, SemanticError> {
    let mut result = BTreeMap::new();
    let mut catalogs = BTreeMap::new();
    for (alias, contract) in contracts {
        result.insert(alias.clone(), Type::ContractRef(Arc::new(contract.clone())));
        let catalog = public_types(contract)?;
        let mut candidates = BTreeMap::<String, Option<Type>>::new();
        for (identity, ty) in &catalog {
            if identity.starts_with("kotodama::") {
                continue;
            }
            let parts = identity.split("::").collect::<Vec<_>>();
            let suffix = if parts.len() == 2 && parts[0] == contract.interface.seiyaku_name {
                parts[1].to_owned()
            } else {
                parts[parts.len().saturating_sub(2)..].join("::")
            };
            let name = format!("{alias}::{suffix}");
            candidates
                .entry(name)
                .and_modify(|existing| {
                    if existing.as_ref() != Some(ty) {
                        *existing = None;
                    }
                })
                .or_insert_with(|| Some(ty.clone()));
        }
        result.extend(
            candidates
                .into_iter()
                .filter_map(|(name, ty)| ty.map(|ty| (name, ty))),
        );
        catalogs.insert(alias, catalog);
    }
    for directive in directives {
        let SourceDirectiveKind::ContractTypeImport {
            identity,
            contract,
            alias,
        } = &directive.kind
        else {
            continue;
        };
        let ty = catalogs
            .get(contract)
            .and_then(|catalog| catalog.get(identity))
            .ok_or_else(|| {
                sem_err(
                    "E_CONTRACT_IMPORT_INVALID",
                    format!("type `{identity}` is not exposed by imported contract `{contract}`"),
                )
            })?;
        if result.insert(alias.clone(), ty.clone()).is_some() {
            return Err(sem_err(
                "E_DUPLICATE_DECLARATION",
                format!("imported type alias `{alias}` is declared more than once"),
            ));
        }
    }
    Ok(result)
}
/// Install constructor signatures solely to give resolution/editor an exact named interface.
pub(crate) fn constructor_signature(contract: &ImportedContractInterface) -> FunctionSignature {
    FunctionSignature {
        params: vec![TypedParam {
            name: "address".into(),
            ty: Type::Bytes,
            call_mode: ParameterCallMode::Named,
            is_state: false,
        }],
        return_type: Type::ContractRef(Arc::new(contract.clone())),
        modifiers: FunctionModifiers::default(),
    }
}
pub(super) fn analyze_contract_call(
    context: &SemanticContext,
    name: &str,
    args: &[Expr],
    names: Option<&[Option<String>]>,
    receiver: bool,
    vars: &mut HashMap<String, Type>,
) -> Option<Result<TypedExpr, SemanticError>> {
    if !receiver {
        let (alias, method) = name.split_once("::")?;
        let contract = context.contracts.borrow().get(alias)?.clone();
        return Some((|| {
            if method != "at" {
                return Err(sem_err(
                    "E_CONTRACT_METHOD",
                    format!(
                        "contract namespace `{alias}` exposes `at(address: ...)`; call public methods on that reference"
                    ),
                ));
            }
            let plan =
                reorder_call_arguments(name, args, names, false, &["address".into()], &[true], 0)?;
            let mut address =
                analyze_expr_expected(context, &plan.ordered[0], vars, Some(&Type::Bytes))?;
            ensure_assignable_and_coerce(&Type::Bytes, &mut address)?;
            Ok(TypedExpr {
                expr: ExprKind::Call {
                    target: CallTarget::Intrinsic(CompilerIntrinsic::ContractAt),
                    args: vec![address],
                },
                ty: Type::ContractRef(Arc::new(contract)),
            })
        })());
    }
    let first = args.first()?;
    let object = match analyze_expr(context, first, vars) {
        Ok(value) => value,
        // Other receiver families may infer an empty literal or sum constructor
        // from their method arguments. Leave those diagnostics to their owner.
        Err(_) => return None,
    };
    let Type::ContractRef(contract) = &object.ty else {
        return None;
    };
    let contract = Arc::clone(contract);
    Some((|| {
        let (ordinal, entry) = contract
            .interface
            .entrypoints
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.name == name)
            .ok_or_else(|| {
                sem_err(
                    "E_CONTRACT_METHOD",
                    format!(
                        "contract `{}` has no public method `{name}`",
                        contract.interface.seiyaku_name
                    ),
                )
            })?;
        if !matches!(
            entry.kind,
            iroha_data_model::smart_contract::manifest::EntryPointKind::View
                | iroha_data_model::smart_contract::manifest::EntryPointKind::Kotoage
        ) {
            return Err(sem_err(
                "E_CONTRACT_METHOD",
                "contract lifecycle hooks cannot be invoked as imported methods".into(),
            ));
        }
        let fields = entry
            .argument_schema
            .as_ref()
            .map(|schema| schema.fields.as_slice())
            .unwrap_or_default();
        let parameter_names = fields
            .iter()
            .map(|field| field.name.clone())
            .collect::<Vec<_>>();
        let plan = reorder_call_arguments(
            name,
            args,
            names,
            true,
            &parameter_names,
            &vec![true; fields.len()],
            0,
        )?;
        let mut typed = vec![Some(object)];
        typed.resize_with(plan.ordered.len(), || None);
        for &slot in &plan.evaluation_order {
            if slot == 0 {
                continue;
            }
            let expected = schema_type(&fields[slot - 1].ty)?;
            let mut value =
                analyze_expr_expected(context, &plan.ordered[slot], vars, Some(&expected))?;
            ensure_assignable_and_coerce(&expected, &mut value)?;
            typed[slot] = Some(value);
        }
        let result = schema_type(entry.return_schema.as_ref().ok_or_else(|| {
            sem_err(
                "E_CONTRACT_IMPORT_INVALID",
                "public method has no return schema".into(),
            )
        })?)?;
        Ok(retain_named_call_evaluation_order(
            TypedExpr {
                expr: ExprKind::Call {
                    target: CallTarget::Contract(ContractMethod {
                        contract,
                        entrypoint: ordinal as u32,
                    }),
                    args: typed.into_iter().map(Option::unwrap).collect(),
                },
                ty: result,
            },
            &plan,
        ))
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::smart_contract::manifest::{
        ContractEnumTypeDescriptorV1, ContractEnumVariantDescriptorV1,
    };

    #[test]
    fn colliding_package_type_paths_require_exact_identity_bindings() {
        let output = crate::session::CompilerSession::default()
            .build(crate::session::CompileRequest {
                source: "seiyaku Pool { view fn value() authorize(anyone) -> int { 1 } }",
                source_name: Some("pool.ko"),
            })
            .unwrap();
        let mut interface = output.contract_interface;
        let descriptor = |identity: &str| ContractEnumTypeDescriptorV1 {
            identity: identity.into(),
            variants: vec![ContractEnumVariantDescriptorV1 {
                name: "Active".into(),
                code: 7,
            }],
        };
        let old = descriptor("data@1.0.0::Data::Status");
        let new = descriptor("data@2.0.0::Data::Status");
        interface.entrypoints[0].return_schema = Some(EntrypointValueTypeV1 {
            nodes: vec![
                Node::Tuple(2),
                Node::Enum(old.clone()),
                Node::Enum(new.clone()),
            ],
        });
        let contracts = BTreeMap::from([(
            "Pool".into(),
            ImportedContractInterface {
                code_hash: output.report.artifact_hash,
                interface: Arc::new(interface),
            },
        )]);
        let imports = crate::parser::parse(
            r#"seiyaku Caller {
            import type "data@1.0.0::Data::Status" from Pool as OldStatus;
            import type "data@2.0.0::Data::Status" from Pool as NewStatus;
        }"#,
        )
        .unwrap();
        let types = namespace_types(&contracts, &imports.directives).unwrap();
        assert!(!types.contains_key("Pool::Data::Status"));
        assert_eq!(types["OldStatus"], Type::Enum(Arc::new(old)));
        assert_eq!(types["NewStatus"], Type::Enum(Arc::new(new)));
        assert_ne!(types["OldStatus"], types["NewStatus"]);
        let hidden = crate::parser::parse(
            r#"seiyaku Caller {
            import type "data@3.0.0::Data::Status" from Pool as Hidden;
        }"#,
        )
        .unwrap();
        assert_eq!(
            namespace_types(&contracts, &hidden.directives)
                .unwrap_err()
                .code,
            "E_CONTRACT_IMPORT_INVALID"
        );
    }
}
