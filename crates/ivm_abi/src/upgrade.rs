//! Exact durable-state compatibility for replacements of an admitted contract artifact.

use std::{collections::BTreeMap, fmt};

use iroha_data_model::smart_contract::manifest::EntryPointKind;

use crate::metadata::{EmbeddedContractInterfaceV1, EmbeddedStateDescriptor, EmbeddedStateType};

/// A replacement's new scalar state, which must be initialized before `kaizen` completes.
#[derive(Debug, PartialEq, Eq)]
pub struct ContractUpgradePlan<'a> {
    /// Exact replacement descriptors requiring canonical, present durable values.
    pub added_scalars: Vec<&'a EmbeddedStateDescriptor>,
}

/// An incompatible change to an instance's existing durable storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContractUpgradeError {
    /// A durable key appears more than once in an input interface.
    DuplicateState(String),
    /// An existing durable key was removed or renamed.
    RemovedState(String),
    /// An existing durable key no longer has its exact complete type.
    ChangedStateType(String),
    /// New scalar state requires the replacement's `kaizen` hook.
    ScalarWithoutKaizen(String),
}

impl fmt::Display for ContractUpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateState(name) => write!(f, "duplicate durable state `{name}`"),
            Self::RemovedState(name) => write!(f, "upgrade removes durable state `{name}`"),
            Self::ChangedStateType(name) => {
                write!(f, "upgrade changes the complete durable type of `{name}`")
            }
            Self::ScalarWithoutKaizen(name) => {
                write!(
                    f,
                    "new scalar state `{name}` requires kaizen/改善 initialization"
                )
            }
        }
    }
}

impl std::error::Error for ContractUpgradeError {}

/// Compare the complete authenticated interfaces of an instance's old and new artifacts.
///
/// Existing names and complete types, including map keys, nominal identities, error catalogs,
/// field order and list capacities, must remain exact. New maps begin empty. New scalar keys
/// require `kaizen`; the returned plan is a runtime obligation, not proof of initialization.
/// Both inputs must come from canonical artifact admission, never a lossy manifest type name.
///
/// # Errors
/// Rejects removed, changed or duplicate state and new scalar state without a `kaizen` hook.
pub fn validate_contract_upgrade<'a>(
    previous: &EmbeddedContractInterfaceV1,
    replacement: &'a EmbeddedContractInterfaceV1,
) -> Result<ContractUpgradePlan<'a>, ContractUpgradeError> {
    compare_states(
        &previous.states,
        &replacement.states,
        replacement
            .entrypoints
            .iter()
            .any(|entry| entry.kind == EntryPointKind::Kaizen),
    )
}

fn compare_states<'a>(
    previous: &[EmbeddedStateDescriptor],
    replacement: &'a [EmbeddedStateDescriptor],
    has_kaizen: bool,
) -> Result<ContractUpgradePlan<'a>, ContractUpgradeError> {
    fn indexed(
        states: &[EmbeddedStateDescriptor],
    ) -> Result<BTreeMap<&str, &EmbeddedStateDescriptor>, ContractUpgradeError> {
        let mut index = BTreeMap::new();
        for state in states {
            if index.insert(state.name.as_str(), state).is_some() {
                return Err(ContractUpgradeError::DuplicateState(state.name.clone()));
            }
        }
        Ok(index)
    }
    let previous = indexed(previous)?;
    let replacement = indexed(replacement)?;
    for (name, state) in &previous {
        let next = replacement
            .get(name)
            .ok_or_else(|| ContractUpgradeError::RemovedState((*name).to_owned()))?;
        if state.ty != next.ty {
            return Err(ContractUpgradeError::ChangedStateType((*name).to_owned()));
        }
    }
    let mut added_scalars = Vec::new();
    for (name, state) in replacement {
        if previous.contains_key(name) || matches!(state.ty, EmbeddedStateType::StateMap { .. }) {
            continue;
        }
        if !has_kaizen {
            return Err(ContractUpgradeError::ScalarWithoutKaizen(name.to_owned()));
        }
        added_scalars.push(state);
    }
    Ok(ContractUpgradePlan { added_scalars })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(name: &str, ty: EmbeddedStateType) -> EmbeddedStateDescriptor {
        EmbeddedStateDescriptor {
            name: name.to_owned(),
            ty,
        }
    }

    #[test]
    fn upgrades_preserve_complete_existing_state_types() {
        let old = vec![state(
            "balances",
            EmbeddedStateType::StateMap {
                key: Box::new(EmbeddedStateType::AccountId),
                value: Box::new(EmbeddedStateType::List {
                    element: Box::new(EmbeddedStateType::Quantity),
                    capacity: 3,
                }),
            },
        )];
        assert!(
            compare_states(&old, &old, false)
                .unwrap()
                .added_scalars
                .is_empty()
        );
        for ty in [
            EmbeddedStateType::StateMap {
                key: Box::new(EmbeddedStateType::Name),
                value: Box::new(EmbeddedStateType::List {
                    element: Box::new(EmbeddedStateType::Quantity),
                    capacity: 3,
                }),
            },
            EmbeddedStateType::StateMap {
                key: Box::new(EmbeddedStateType::AccountId),
                value: Box::new(EmbeddedStateType::List {
                    element: Box::new(EmbeddedStateType::Quantity),
                    capacity: 4,
                }),
            },
            EmbeddedStateType::Quantity,
        ] {
            assert_eq!(
                compare_states(&old, &[state("balances", ty)], true),
                Err(ContractUpgradeError::ChangedStateType("balances".into()))
            );
        }
        assert_eq!(
            compare_states(&old, &[], true),
            Err(ContractUpgradeError::RemovedState("balances".into()))
        );
        assert_eq!(
            compare_states(&old, &[old[0].clone(), old[0].clone()], true),
            Err(ContractUpgradeError::DuplicateState("balances".into()))
        );
    }

    #[test]
    fn new_maps_are_empty_and_new_scalars_require_runtime_initialization() {
        let mut replacement = vec![state(
            "balances",
            EmbeddedStateType::StateMap {
                key: Box::new(EmbeddedStateType::AccountId),
                value: Box::new(EmbeddedStateType::Quantity),
            },
        )];
        assert!(
            compare_states(&[], &replacement, false)
                .unwrap()
                .added_scalars
                .is_empty()
        );
        replacement.push(state("enabled", EmbeddedStateType::Bool));
        assert_eq!(
            compare_states(&[], &replacement, false),
            Err(ContractUpgradeError::ScalarWithoutKaizen("enabled".into()))
        );
        assert_eq!(
            compare_states(&[], &replacement, true)
                .unwrap()
                .added_scalars,
            vec![&replacement[1]]
        );
    }
}
