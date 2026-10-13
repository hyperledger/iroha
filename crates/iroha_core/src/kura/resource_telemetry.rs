//! Fresh fixed-family Kura exposition without cached values or storage work.
//!
//! The surrounding `/metrics` handler also exposes unrelated metrics and may
//! wait on its own locks. Only this collector's owner observation is nonblocking.

use std::sync::{Arc, Weak};

use iroha_telemetry::metrics::{
    Collector, CollectorDesc, CollectorRegistrationError, Metrics, proto,
};

use super::{
    Kura,
    resource_inventory::{ALL_FAMILIES, Family, Snapshot, Unavailable, Usage},
};

/// Largest consecutive integer exactly represented by the exposition's f64.
const MAX_EXACT_INTEGER: u64 = 1_u64 << 53;
const PREFIX: &str = "iroha_kura_resource_";
const SPECS: [(&str, &str, Option<&str>); 15] = [
    (
        "available",
        "Whether one complete Kura resource observation can be exposed exactly.",
        None,
    ),
    (
        "status",
        "Current Kura resource export status; exactly one fixed reason is present.",
        Some("reason"),
    ),
    (
        "generation",
        "Generation of this complete resource observation in the current process.",
        None,
    ),
    (
        "fault_count",
        "Accounting publication faults recorded in the current process.",
        None,
    ),
    (
        "resident_associations",
        "Stored resident lookup associations by fixed owner family.",
        Some("family"),
    ),
    (
        "persisted_entries",
        "Physical index slots and standalone index records by fixed owner family.",
        Some("family"),
    ),
    (
        "index_bytes",
        "Stable index file logical bytes by fixed owner family.",
        Some("family"),
    ),
    (
        "temporary_index_bytes",
        "Present temporary index file logical bytes by fixed owner family.",
        Some("family"),
    ),
    (
        "storage_bytes",
        "Logical file bytes in the declared Kura storage scope by fixed owner family.",
        Some("family"),
    ),
    (
        "resident_associations_sum",
        "Checked sum of all resident lookup associations.",
        None,
    ),
    (
        "persisted_entries_sum",
        "Checked sum of all physical index slots and standalone records.",
        None,
    ),
    (
        "index_bytes_sum",
        "Checked sum of stable index file logical bytes.",
        None,
    ),
    (
        "temporary_index_bytes_sum",
        "Checked sum of present temporary index file logical bytes.",
        None,
    ),
    (
        "storage_bytes_sum",
        "Checked logical bytes in the complete declared Kura storage scope.",
        None,
    ),
    (
        "represented_entries",
        "Checked resident-association plus persisted-entry count; not RSS or transaction count.",
        None,
    ),
];

fn family_label(family: Family) -> &'static str {
    match family {
        Family::ResidentCanonical => "resident_canonical",
        Family::ResidentTransaction => "resident_transaction",
        Family::ResidentFrontier => "resident_frontier",
        Family::ResidentQueue => "resident_queue",
        Family::CanonicalIndex => "canonical_index",
        Family::CanonicalHashes => "canonical_hashes",
        Family::PipelineIndex => "pipeline_index",
        Family::QueryMarkerRecords => "query_marker_records",
        Family::EvidenceKeyRecords => "evidence_key_records",
        Family::StorageBytes => "storage_bytes",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExportFailure {
    OwnerUnavailable,
    Inventory(Unavailable),
    NumericRange,
}

impl ExportFailure {
    fn label(self) -> &'static str {
        match self {
            Self::OwnerUnavailable => "owner_unavailable",
            Self::Inventory(Unavailable::Unregistered) => "unregistered",
            Self::Inventory(Unavailable::Busy) => "busy",
            Self::Inventory(Unavailable::Interrupted) => "interrupted",
            Self::Inventory(Unavailable::Arithmetic) => "arithmetic",
            Self::Inventory(Unavailable::GenerationChanged) => "generation_changed",
            Self::Inventory(Unavailable::OwnerMismatch) => "owner_mismatch",
            Self::Inventory(Unavailable::InvalidInventory) => "invalid_inventory",
            Self::NumericRange => "numeric_range",
        }
    }
}

fn values(usage: Usage) -> [u64; 5] {
    [
        usage.resident_associations,
        usage.persisted_entries,
        usage.index_bytes,
        usage.temporary_index_bytes,
        usage.storage_bytes,
    ]
}

/// Validate every emitted integer before constructing any numeric projection.
fn checked_projection(snapshot: &Snapshot) -> Result<u64, ExportFailure> {
    let represented = snapshot
        .total
        .represented_entries()
        .map_err(ExportFailure::Inventory)?;
    if snapshot
        .components
        .iter()
        .flat_map(|usage| values(*usage))
        .chain(values(snapshot.total))
        .chain([snapshot.generation, snapshot.fault_count, represented])
        .any(|value| value > MAX_EXACT_INTEGER)
    {
        return Err(ExportFailure::NumericRange);
    }
    Ok(represented)
}

#[derive(Clone)]
struct ResourceCollector {
    owner: Weak<Kura>,
    descriptors: Arc<[CollectorDesc]>,
    #[cfg(test)]
    source_reads: Arc<std::sync::atomic::AtomicUsize>,
}

impl ResourceCollector {
    fn new(owner: Weak<Kura>) -> Result<Self, CollectorRegistrationError> {
        let descriptors = SPECS
            .iter()
            .map(|(name, help, label)| {
                CollectorDesc::new(
                    format!("{PREFIX}{name}"),
                    (*help).to_owned(),
                    label.iter().map(|label| (*label).to_owned()).collect(),
                    std::collections::HashMap::default(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            owner,
            descriptors: descriptors.into(),
            #[cfg(test)]
            source_reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    fn observe(&self) -> Result<Snapshot, ExportFailure> {
        let owner = self
            .owner
            .upgrade()
            .ok_or(ExportFailure::OwnerUnavailable)?;
        #[cfg(test)]
        self.source_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        owner
            .resource_inventory_snapshot()
            .map_err(ExportFailure::Inventory)
    }

    fn family(
        &self,
        index: usize,
        rows: impl IntoIterator<Item = (u64, Option<&'static str>)>,
    ) -> proto::MetricFamily {
        let descriptor = &self.descriptors[index];
        let mut family = proto::MetricFamily::default();
        family.set_name(descriptor.fq_name.clone());
        family.set_help(descriptor.help.clone());
        family.set_field_type(proto::MetricType::GAUGE);
        family.set_metric(
            rows.into_iter()
                .map(|(value, label)| {
                    let mut metric = proto::Metric::default();
                    let mut gauge = proto::Gauge::default();
                    // checked_projection validated every source integer before this path.
                    // Availability/status values are only zero or one.
                    gauge.set_value(value as f64);
                    metric.set_gauge(gauge);
                    if let Some(label) = label {
                        let mut pair = proto::LabelPair::default();
                        pair.set_name(descriptor.variable_labels[0].clone());
                        pair.set_value(label.to_owned());
                        metric.set_label(vec![pair]);
                    }
                    metric
                })
                .collect(),
        );
        family
    }

    fn project(&self, observation: Result<Snapshot, ExportFailure>) -> Vec<proto::MetricFamily> {
        let qualified = observation.and_then(|snapshot| {
            checked_projection(&snapshot).map(|represented| (snapshot, represented))
        });
        let (snapshot, represented) = match qualified {
            Ok(value) => value,
            Err(reason) => {
                return vec![
                    self.family(0, [(0, None)]),
                    self.family(1, [(1, Some(reason.label()))]),
                ];
            }
        };
        let mut result = Vec::with_capacity(SPECS.len());
        result.push(self.family(0, [(1, None)]));
        result.push(self.family(1, [(1, Some("available"))]));
        result.push(self.family(2, [(snapshot.generation, None)]));
        result.push(self.family(3, [(snapshot.fault_count, None)]));
        for column in 0..5 {
            result.push(self.family(
                4 + column,
                ALL_FAMILIES.map(|family| {
                    (
                        values(snapshot.components[family as usize])[column],
                        Some(family_label(family)),
                    )
                }),
            ));
        }
        for (column, value) in values(snapshot.total).into_iter().enumerate() {
            result.push(self.family(9 + column, [(value, None)]));
        }
        result.push(self.family(14, [(represented, None)]));
        result
    }
}

impl Collector for ResourceCollector {
    fn desc(&self) -> Vec<&CollectorDesc> {
        self.descriptors.iter().collect()
    }

    fn collect(&self) -> Vec<proto::MetricFamily> {
        self.project(self.observe())
    }
}

impl Kura {
    /// Bind exactly one weak, fresh resource source to this metrics registry.
    pub(crate) fn register_resource_telemetry(
        self: &Arc<Self>,
        metrics: &Metrics,
    ) -> Result<(), CollectorRegistrationError> {
        metrics.register_collector(Box::new(ResourceCollector::new(Arc::downgrade(self))?))
    }
}

#[cfg(test)]
#[path = "resource_telemetry_tests.rs"]
mod tests;
