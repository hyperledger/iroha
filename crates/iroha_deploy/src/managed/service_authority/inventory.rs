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
        if self.directory.entries(MAX_BRANCH_NAMES)? != self.names {
            return Err(invalid("service child namespace changed during inventory"));
        }
        self.directory.revalidate()?;
        Ok(())
    }
}

/// Borrowed original parent and retained branch identities for one read-only census.
///
/// Only present purpose custody reaches the ordinary full authority constructor. No decoded
/// profile, directory name, or absence observation becomes signing or native state evidence.
pub(in crate::managed) struct ServiceChildInventory<'a> {
    parent: &'a ServiceAuthority,
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
        for branch in &self.branches {
            branch.revalidate()?;
        }
        for prefix in self.empty_prefixes.borrow().iter() {
            prefix.revalidate()?;
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
        let result = ServiceAuthority::open(&self.parent.prepared, provider, purpose, false);
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
