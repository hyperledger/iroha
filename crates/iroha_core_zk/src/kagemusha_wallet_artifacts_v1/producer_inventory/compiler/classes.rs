//! Deterministic raw Q class grouping from actual descriptors, never estimated key counts.

use super::*;

/// Exact raw selector classes for one compiled Q program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QClassesV1 {
    /// Ordered own-sigma selectors sharing a complete actual descriptor.
    pub own: Vec<u8>,
    /// Ordered incoming selectors sharing a descriptor, or empty when absent.
    pub incoming: Vec<u8>,
}

fn groups(selectors: &[u8], keys: &[CompiledKeyV1<Eq>; 16]) -> Vec<Vec<u8>> {
    let mut groups: Vec<Vec<u8>> = Vec::new();
    for selector in selectors {
        if let Some(group) = groups.iter_mut().find(|group| {
            keys[usize::from(group[0])].metadata.binding()
                == keys[usize::from(*selector)].metadata.binding()
        }) {
            group.push(*selector);
        } else {
            groups.push(vec![*selector]);
        }
    }
    groups
}

/// Partition only the compiled variant's selectors by complete actual descriptors.
/// The Cartesian class list is deterministic; each actual logical route must still
/// reconstruct its own native plan and complete originals before terminal deduplication.
#[must_use]
pub fn q_classes(variant: Variant, sigmas: &CompiledSigmasV1) -> Vec<QClassesV1> {
    let keys = sigmas.keys();
    let routes: Vec<_> = compiled_routes()
        .into_iter()
        .filter(|r| r.variant == variant)
        .collect();
    let mut own: Vec<_> = routes.iter().map(|r| r.own).collect();
    own.sort_unstable();
    own.dedup();
    let mut incoming: Vec<_> = routes.iter().filter_map(|r| r.incoming).collect();
    incoming.sort_unstable();
    incoming.dedup();
    let own = groups(&own, keys);
    let incoming = if incoming.is_empty() {
        vec![Vec::new()]
    } else {
        groups(&incoming, keys)
    };
    own.into_iter()
        .flat_map(|own| {
            incoming.iter().map(move |incoming| QClassesV1 {
                own: own.clone(),
                incoming: incoming.clone(),
            })
        })
        .collect()
}
