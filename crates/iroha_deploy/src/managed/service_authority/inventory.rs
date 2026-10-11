//! One parent-authenticated, existing-only child census; absence grants no native authority.

use super::*;
use std::{cell::RefCell, ffi::OsString};

// Original runtime branches contain a fixed small set of purpose directories. This ceiling
// bounds the whole direct-name observation; operation records remain with their own owners.
const MAX_BRANCH_NAMES: usize = 64;
const MAX_EMPTY_PREFIXES: usize = 32;

struct Branch {
    directory: PrivateDirectory,
    names: Vec<OsString>,
}
impl Branch {
    fn capture(directory: PrivateDirectory) -> Result<Self> {
        let names = directory.entries(MAX_BRANCH_NAMES)?;
        directory.revalidate()?;
        Ok(Self { directory, names })
    }

    fn capture_empty(directory: PrivateDirectory) -> Result<Self> {
        let prefix = Self::capture(directory)?;
        if !prefix.names.is_empty() {
            return Err(invalid("service empty prefix changed during inventory"));
        }
        Ok(prefix)
    }

    fn revalidate(&self) -> Result<()> {
        self.directory.revalidate()?;
        let names = self.directory.entries(MAX_BRANCH_NAMES)?;
        #[cfg(test)]
        tree_tests::observe(&self.directory, tree_tests::Recipe::Full);
        if names != self.names {
            return Err(invalid("service child namespace changed during inventory"));
        }
        self.directory.revalidate()?;
        Ok(())
    }

    fn revalidate_in_tree(&self, tree: &mut iroha_fs::PrivateReadTreeScope<'_>) -> Result<()> {
        tree.read_scope(&self.directory, |reader| {
            let names = reader.entries(MAX_BRANCH_NAMES)?;
            #[cfg(test)]
            tree_tests::observe(&self.directory, tree_tests::Recipe::Tree);
            if names != self.names {
                return Err(invalid("service child namespace changed during inventory"));
            }
            Ok(())
        })
    }
}

/// Borrowed original parent and retained branch identities for one read-only census.
///
/// Present purpose custody borrows only the parent's immutable original constructor bundle,
/// after fresh whole-profile admission. Active decode limits retain the full capture recipe.
/// A separate cold three-slot import memo lives only for this census; child owners still read
/// their fresh sources, and every namespace, profile and lock check remains independent.
/// Names and absence observations never become signing or native state evidence.
pub(in crate::managed) struct ServiceChildInventory<'a> {
    parent: &'a ServiceAuthority,
    checkpoint_import_scope: Option<CheckpointImportScope>,
    share_ancestry: bool,
    branches: Vec<Branch>,
    network: usize,
    providers: [Option<usize>; 3],
    empty_prefixes: RefCell<Vec<Branch>>,
}

impl<'a> ServiceChildInventory<'a> {
    pub(in crate::managed) fn begin(parent: &'a ServiceAuthority) -> Result<Self> {
        parent.validate_profile()?;
        if !matches!(parent.scope, Scope::Network) {
            return Err(invalid(
                "service inventory requires its original network parent",
            ));
        }
        let path = parent
            .prepared
            .context
            .client_config
            .parent()
            .ok_or_else(|| invalid("service inventory generation is absent"))?;
        if parent.directory.path()
            != path
                .join("runtime/service-operations/network")
                .join(NetworkPurpose::ServiceBootstrap.directory_name())
        {
            return Err(invalid("service inventory selected another parent purpose"));
        }
        // Retain the exact original runtime and all native ancestors already held by this owner.
        parent.validate_operation_custody()?;
        let runtime = Branch::capture(parent.profile.runtime().retain()?)?;
        parent.validate_operation_custody()?;
        let operations = Branch::capture(runtime.directory.open_child("service-operations")?)?;
        let network = Branch::capture(operations.directory.open_child("network")?)?;
        let provider_root = if operations.names.iter().any(|name| name == "providers") {
            Some(Branch::capture(
                operations.directory.open_child("providers")?,
            )?)
        } else {
            None
        };
        let mut branches = Vec::with_capacity(7);
        branches.extend([runtime, operations, network]);
        let mut providers = [None; 3];
        if let Some(provider_root) = provider_root {
            for (slot, selected) in providers.iter_mut().enumerate() {
                let name = slot.to_string();
                if provider_root
                    .names
                    .iter()
                    .any(|entry| entry == name.as_str())
                {
                    *selected = Some(branches.len());
                    branches.push(Branch::capture(provider_root.directory.open_child(name)?)?);
                }
            }
            branches.push(provider_root);
        }
        let value = Self {
            parent,
            checkpoint_import_scope: CheckpointImportScope::for_original(parent),
            // An inventory admitted under active limits or from an owned original keeps its
            // physical recipe even when a later observation occurs outside those limits.
            share_ancestry: !norito::core::decode_limits_active()
                && matches!(&parent.profile, AuthorityProfile::Shared(_)),
            branches,
            network: 2,
            providers,
            empty_prefixes: RefCell::new(Vec::new()),
        };
        value.revalidate()?;
        Ok(value)
    }

    fn revalidate(&self) -> Result<()> {
        self.parent.validate_operation_custody()?;
        if self.share_ancestry && !norito::core::decode_limits_active() {
            let (runtime, descendants) = self
                .branches
                .split_first()
                .ok_or_else(|| invalid("service inventory runtime is absent"))?;
            // Only this consecutive read-only census shares the original runtime ancestry.
            // The native tree owner closes it on every ordinary result, including a name
            // mismatch. Exact shared native prefixes qualify; independent owners fall back
            // to full checks. Keep the anchor's original full recipe and the census order.
            // Intermediate prefix/suffix observations consolidate: changes restored inside
            // the bracket may be unseen. This is not an atomic snapshot or retained verdict.
            runtime.directory.read_tree_scope(|tree| -> Result<()> {
                runtime.revalidate()?;
                for branch in descendants {
                    branch.revalidate_in_tree(tree)?;
                }
                for prefix in self.empty_prefixes.borrow().iter() {
                    prefix.revalidate_in_tree(tree)?;
                }
                Ok(())
            })?;
        } else {
            for branch in &self.branches {
                branch.revalidate()?;
            }
            for prefix in self.empty_prefixes.borrow().iter() {
                prefix.revalidate()?;
            }
        }
        self.parent.validate_operation_custody()?;
        Ok(())
    }

    pub(in crate::managed) fn open_network(
        &self,
        purpose: NetworkPurpose,
    ) -> Result<Option<ServiceAuthority>> {
        self.open(None, Some(self.network), purpose.directory_name())
    }

    pub(in crate::managed) fn open_provider(
        &self,
        provider: ProviderId,
        purpose: ProviderPurpose,
    ) -> Result<Option<ServiceAuthority>> {
        let slot = usize::from(self.parent.manifest.provider(provider)?.slot);
        let selected = *self
            .providers
            .get(slot)
            .ok_or_else(|| invalid("service inventory provider slot is invalid"))?;
        self.open(Some(provider), selected, purpose.directory_name())
    }

    fn open(
        &self,
        provider: Option<ProviderId>,
        branch: Option<usize>,
        purpose: &'static str,
    ) -> Result<Option<ServiceAuthority>> {
        self.revalidate()?;
        let Some(branch) = branch.map(|index| &self.branches[index]) else {
            return Ok(None);
        };
        if !branch.names.iter().any(|name| name == purpose) {
            self.revalidate()?;
            return Ok(None);
        }
        let retained = branch.directory.open_child(purpose)?;
        let result = ServiceAuthority::open_existing_from_original(
            self.parent,
            provider,
            purpose,
            self.checkpoint_import_scope.as_ref(),
        );
        retained.revalidate()?;
        self.revalidate()?;
        let owner = result?;
        if let Some(owner) = &owner {
            if owner.directory.path() != retained.path()
                || owner.directory.identity()? != retained.identity()?
            {
                return Err(invalid("retained service child changed during inventory"));
            }
        } else {
            // The ordinary existing-only owner permits only an exact empty pre-lock prefix.
            super::super::native_operation::require_empty(&retained)?;
            let mut prefixes = self.empty_prefixes.borrow_mut();
            if !prefixes
                .iter()
                .any(|prefix| prefix.directory.path() == retained.path())
            {
                if prefixes.len() == MAX_EMPTY_PREFIXES {
                    return Err(invalid("service empty-prefix inventory exceeds its bound"));
                }
                prefixes.push(Branch::capture_empty(retained.retain()?)?);
            }
        }
        retained.revalidate()?;
        self.revalidate()?;
        Ok(owner)
    }

    /// Observe only genuine first-reserve purpose absence within this fresh parent census.
    /// Present names retain their ordinary standalone owner, including empty pre-lock prefixes.
    /// Consume every native namespace and whole-profile exit check before returning; this
    /// supplies neither a child lock, persistent absence nor native dispatch authority.
    pub(in crate::managed) fn initial_reserve_policy_absent(self) -> Result<bool> {
        self.revalidate()?;
        let absent = !self.branches[self.network]
            .names
            .iter()
            .any(|name| name == NetworkPurpose::InitialReservePolicy.directory_name());
        self.finish()?;
        Ok(absent)
    }

    /// A fresh closed name observation used only to select bounded bootstrap scheduling.
    /// Any existing purpose, including an empty pre-lock prefix, selects serial scheduling.
    /// Ordinary child admission and shared lease fences still decide every action afterwards;
    /// this observation grants no retained absence, signing or completion authority.
    pub(in crate::managed) fn bootstrap_provider_purposes_absent(self) -> Result<bool> {
        self.revalidate()?;
        let absent = self.providers.iter().all(|branch| {
            branch.is_none_or(|index| {
                !self.branches[index].names.iter().any(|name| {
                    [
                        ProviderPurpose::Custody,
                        ProviderPurpose::ReserveAccountRegistration,
                        ProviderPurpose::ProviderFundingBootstrap,
                        ProviderPurpose::ReserveTopUpRequest,
                        ProviderPurpose::ReserveTopUpApproval,
                        ProviderPurpose::InitialProviderCredit,
                        ProviderPurpose::ProviderCapacityDeclaration,
                        ProviderPurpose::InitialProviderIngestAuthority,
                        ProviderPurpose::InitialGatewaySetup,
                    ]
                    .into_iter()
                    .any(|purpose| name == purpose.directory_name())
                })
            })
        });
        self.finish()?;
        Ok(absent)
    }

    /// Scheduling only: every catalog purpose must be absent in this closed original census.
    /// A present empty purpose still selects serial recovery; each later owner independently
    /// admits its original files, profile and lock before observing or publishing anything.
    pub(in crate::managed) fn gateway_catalog_purposes_absent(self) -> Result<bool> {
        self.revalidate()?;
        let absent = self.providers.iter().all(|branch| {
            branch.is_none_or(|index| {
                !self.branches[index]
                    .names
                    .iter()
                    .any(|name| name == ProviderPurpose::GatewayCompliance.directory_name())
            })
        });
        self.finish()?;
        Ok(absent)
    }

    pub(in crate::managed) fn finish(self) -> Result<()> {
        self.revalidate()?;
        self.parent.validate_profile()?;
        self.revalidate()
    }
}

#[cfg(test)]
std::thread_local! {
    static AUTHORITY_OPENS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(super) fn record_authority_open() {
    AUTHORITY_OPENS.with(|value| {
        if let Some(count) = value.get() {
            value.set(Some(
                count.checked_add(1).expect("test authority count bound"),
            ));
        }
    });
}

#[cfg(test)]
impl ServiceChildInventory<'_> {
    pub(in crate::managed) fn test_count_authority_opens<T>(
        action: impl FnOnce() -> T,
    ) -> (T, usize) {
        struct Restore(Option<usize>);
        impl Drop for Restore {
            fn drop(&mut self) {
                AUTHORITY_OPENS.with(|value| value.set(self.0));
            }
        }
        let _restore = Restore(AUTHORITY_OPENS.with(|value| value.replace(Some(0))));
        let result = action();
        let count = AUTHORITY_OPENS.with(|value| value.get().expect("test observer retained"));
        (result, count)
    }
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "inventory_tree_tests.rs"]
mod tree_tests;
