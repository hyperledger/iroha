//! Row fields of every collection (the field tables in
//! `specs/torii/collection_queries.md`).
use iroha_torii_shared::list_query::Order;

/// Value class of a row field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FieldType {
    /// JSON string; compared and sorted as text.
    String,
    /// Integer or exact decimal (number or decimal string); compared numerically.
    Number,
    /// JSON boolean.
    Bool,
    /// Any JSON value (metadata entries and structured fields).
    Json,
}

impl FieldType {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Bool => "boolean",
            Self::Json => "JSON",
        }
    }

    pub(crate) const fn is_scalar(self) -> bool {
        !matches!(self, Self::Json)
    }
}

/// One filterable row field.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FieldSpec {
    /// Dotted field path.
    pub(crate) name: &'static str,
    /// Value class.
    pub(crate) ty: FieldType,
    /// Whether the field may appear in `sort`.
    pub(crate) sortable: bool,
    /// Whether filter literals are account identifiers that the producer
    /// canonicalises (so aliases and alternate spellings match).
    pub(crate) account: bool,
    /// Whether the field holds a list; a comparison matches when any element
    /// does, and range comparisons are rejected.
    pub(crate) list: bool,
}

const fn text(name: &'static str) -> FieldSpec {
    FieldSpec {
        name,
        ty: FieldType::String,
        sortable: true,
        account: false,
        list: false,
    }
}

const fn unsorted_text(name: &'static str) -> FieldSpec {
    FieldSpec {
        name,
        ty: FieldType::String,
        sortable: false,
        account: false,
        list: false,
    }
}

const fn text_list(name: &'static str) -> FieldSpec {
    FieldSpec {
        name,
        ty: FieldType::String,
        sortable: false,
        account: false,
        list: true,
    }
}

const fn account(name: &'static str) -> FieldSpec {
    FieldSpec {
        name,
        ty: FieldType::String,
        sortable: true,
        account: true,
        list: false,
    }
}

const fn number(name: &'static str) -> FieldSpec {
    FieldSpec {
        name,
        ty: FieldType::Number,
        sortable: true,
        account: false,
        list: false,
    }
}

const fn boolean(name: &'static str) -> FieldSpec {
    FieldSpec {
        name,
        ty: FieldType::Bool,
        sortable: false,
        account: false,
        list: false,
    }
}

const fn json(name: &'static str) -> FieldSpec {
    FieldSpec {
        name,
        ty: FieldType::Json,
        sortable: false,
        account: false,
        list: false,
    }
}

/// A collection's query surface.
#[derive(Debug)]
pub(crate) struct CollectionSpec {
    /// Stable collection identifier (also binds cursors).
    pub(crate) id: &'static str,
    /// Cursor tag; unique per collection.
    pub(crate) tag: u8,
    /// Declared row fields.
    pub(crate) fields: &'static [FieldSpec],
    /// Whether `metadata` and `metadata.<key>` are part of each row.
    pub(crate) metadata: bool,
    /// Order applied when the request has no `sort`.
    pub(crate) default_sort: &'static [(&'static str, Order)],
    /// Fields that identify a row uniquely; appended to every ordering so
    /// keyset positions are total.
    pub(crate) identity: &'static [&'static str],
    /// Rows come in history order (newest first) and cursors carry block
    /// coordinates (`block_height`, `block_index`, optionally `movement_index`)
    /// instead of sort keys; this is their count (zero for ordinary rows);
    /// `sort`, totals and aggregates would need a full history scan and are
    /// rejected.
    pub(crate) positioned: usize,
    /// Rows are stored by their `id` and can be streamed in canonical
    /// identifier order from a cursor: the default order and `sort=id` /
    /// `sort=-id` follow that order and seek instead of sorting.
    pub(crate) ordered: bool,
}

impl CollectionSpec {
    /// Resolve a field path, including `metadata`/`metadata.<key>` and
    /// object prefixes of declared nested fields (`alias_binding`).
    pub(crate) fn field(&self, name: &str) -> Option<FieldSpec> {
        if let Some(field) = self.fields.iter().find(|field| field.name == name) {
            return Some(*field);
        }
        let dynamic = self.metadata
            && (name == "metadata"
                || name
                    .strip_prefix("metadata.")
                    .is_some_and(|key| !key.is_empty()));
        let object_prefix = self.fields.iter().any(|field| {
            field
                .name
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('.'))
        });
        (dynamic || object_prefix).then_some(FieldSpec {
            name: "",
            ty: FieldType::Json,
            sortable: dynamic && name != "metadata",
            account: false,
            list: false,
        })
    }

    /// Human-readable list of the accepted fields for error messages.
    pub(crate) fn field_list(&self) -> String {
        let mut names: Vec<&str> = self.fields.iter().map(|field| field.name).collect();
        if self.metadata {
            names.push("metadata.<key>");
        }
        names.join(", ")
    }

    /// Human-readable list of the sortable fields for error messages.
    pub(crate) fn sortable_list(&self) -> String {
        let mut names: Vec<&str> = self
            .fields
            .iter()
            .filter(|field| field.sortable)
            .map(|field| field.name)
            .collect();
        if self.metadata {
            names.push("metadata.<key>");
        }
        names.join(", ")
    }

    /// Fields whose filter literals are account identifiers.
    pub(crate) fn account_fields(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.fields
            .iter()
            .filter(|field| field.account)
            .map(|field| field.name)
    }
}

/// `/v1/domains`
pub(crate) static DOMAINS: CollectionSpec = CollectionSpec {
    id: "domains",
    tag: 1,
    fields: &[text("id"), account("owned_by"), unsorted_text("logo")],
    metadata: true,
    default_sort: &[("id", Order::Asc)],
    identity: &["id"],
    positioned: 0,
    ordered: true,
};

/// `/v1/accounts`
pub(crate) static ACCOUNTS: CollectionSpec = CollectionSpec {
    id: "accounts",
    tag: 2,
    fields: &[account("id"), text("label"), text("uaid")],
    metadata: true,
    default_sort: &[("id", Order::Asc)],
    identity: &["id"],
    positioned: 0,
    ordered: true,
};

/// `/v1/assets/definitions`
pub(crate) static ASSET_DEFINITIONS: CollectionSpec = CollectionSpec {
    id: "asset_definitions",
    tag: 3,
    fields: &[
        text("id"),
        text("name"),
        text("alias"),
        account("owned_by"),
        text("owning_domain"),
        text("owning_dataspace"),
        json("mintable"),
        unsorted_text("alias_binding.alias"),
        unsorted_text("alias_binding.status"),
        number("alias_binding.lease_expiry_ms"),
        number("alias_binding.grace_until_ms"),
        number("alias_binding.bound_at_ms"),
    ],
    metadata: true,
    default_sort: &[("id", Order::Asc)],
    identity: &["id"],
    positioned: 0,
    ordered: true,
};

/// `/v1/nfts`
pub(crate) static NFTS: CollectionSpec = CollectionSpec {
    id: "nfts",
    tag: 4,
    fields: &[text("id"), account("owned_by")],
    metadata: true,
    default_sort: &[("id", Order::Asc)],
    identity: &["id"],
    positioned: 0,
    ordered: true,
};

/// `/v1/rwas`
pub(crate) static RWAS: CollectionSpec = CollectionSpec {
    id: "rwas",
    tag: 5,
    fields: &[
        text("id"),
        account("owned_by"),
        text("primary_reference"),
        text("status"),
        number("quantity"),
        boolean("is_frozen"),
    ],
    metadata: true,
    default_sort: &[("id", Order::Asc)],
    identity: &["id"],
    positioned: 0,
    ordered: true,
};

/// `/v1/accounts/{account_id}/assets`
pub(crate) static ACCOUNT_ASSETS: CollectionSpec = CollectionSpec {
    id: "account_assets",
    tag: 6,
    fields: &[
        text("asset"),
        text("asset_name"),
        text("asset_alias"),
        text("scope"),
        account("account_id"),
        number("quantity"),
    ],
    metadata: false,
    default_sort: &[("asset", Order::Asc), ("scope", Order::Asc)],
    identity: &["account_id", "asset", "scope"],
    positioned: 0,
    ordered: false,
};

/// `/v1/assets/{definition_id}/holders`
pub(crate) static ASSET_HOLDERS: CollectionSpec = CollectionSpec {
    id: "asset_holders",
    tag: 7,
    fields: &[
        account("account_id"),
        text("asset"),
        text("asset_alias"),
        text("scope"),
        number("quantity"),
    ],
    metadata: false,
    default_sort: &[("account_id", Order::Asc), ("scope", Order::Asc)],
    identity: &["account_id", "asset", "scope"],
    positioned: 0,
    ordered: false,
};

/// Committed transaction rows, newest first.
const TRANSACTION_FIELDS: &[FieldSpec] = &[
    text("entrypoint_hash"),
    number("block_height"),
    number("block_index"),
    text("block_hash"),
    account("authority"),
    number("timestamp_ms"),
    text("entrypoint_kind"),
    boolean("result_ok"),
    text_list("asset_ids"),
    text_list("asset_definition_ids"),
];

/// `/v1/accounts/{account_id}/transactions`
pub(crate) static ACCOUNT_TRANSACTIONS: CollectionSpec = CollectionSpec {
    id: "account_transactions",
    tag: 8,
    fields: TRANSACTION_FIELDS,
    metadata: true,
    default_sort: &[],
    identity: &[],
    positioned: 2,
    ordered: false,
};

/// `/v1/transactions/query`
pub(crate) static TRANSACTIONS: CollectionSpec = CollectionSpec {
    id: "transactions",
    tag: 10,
    fields: TRANSACTION_FIELDS,
    metadata: true,
    default_sort: &[],
    identity: &[],
    positioned: 2,
    ordered: false,
};

/// `/v1/repo/agreements`
pub(crate) static REPO_AGREEMENTS: CollectionSpec = CollectionSpec {
    id: "repo_agreements",
    tag: 9,
    fields: &[
        text("id"),
        account("initiator"),
        account("counterparty"),
        account("custodian"),
        text("status"),
        text("cash_source"),
        text("cash_leg.asset_definition_id"),
        number("cash_leg.quantity"),
        text("collateral_leg.asset_definition_id"),
        number("collateral_leg.quantity"),
        text("collateral_custody_asset"),
        number("rate_bps"),
        number("maturity_timestamp_ms"),
        number("initiated_timestamp_ms"),
        number("last_margin_check_timestamp_ms"),
        number("settlement_timestamp_ms"),
        number("governance.haircut_bps"),
        number("governance.margin_frequency_secs"),
    ],
    metadata: false,
    default_sort: &[("id", Order::Asc)],
    identity: &["id"],
    positioned: 0,
    ordered: true,
};

/// `/v1/accounts/{account_id}/permissions`: effective direct and role permissions.
pub(crate) static ACCOUNT_PERMISSIONS: CollectionSpec = CollectionSpec {
    id: "account_permissions",
    tag: 11,
    fields: &[text("name"), json("payload")],
    metadata: false,
    default_sort: &[("name", Order::Asc)],
    identity: &["name", "payload"],
    positioned: 0,
    ordered: false,
};

/// `/v1/subscriptions/plans`
pub(crate) static SUBSCRIPTION_PLANS: CollectionSpec = CollectionSpec {
    id: "subscription_plans",
    tag: 12,
    fields: &[
        text("id"),
        account("provider"),
        json("billing"),
        json("pricing"),
    ],
    metadata: false,
    default_sort: &[("id", Order::Asc)],
    identity: &["id"],
    positioned: 0,
    ordered: true,
};

/// `/v1/subscriptions`
pub(crate) static SUBSCRIPTIONS: CollectionSpec = CollectionSpec {
    id: "subscriptions",
    tag: 13,
    fields: &[
        text("id"),
        account("owned_by"),
        text("plan_id"),
        account("provider"),
        account("subscriber"),
        text("status"),
        number("current_period_start_ms"),
        number("current_period_end_ms"),
        number("next_charge_ms"),
        boolean("cancel_at_period_end"),
        number("cancel_at_ms"),
        number("failure_count"),
        json("usage_accumulated"),
        text("billing_trigger_id"),
        json("invoice"),
        json("plan"),
    ],
    metadata: false,
    default_sort: &[("id", Order::Asc)],
    identity: &["id"],
    positioned: 0,
    ordered: true,
};

/// `/v1/space-directory/uaids/{uaid}/manifests`
pub(crate) static UAID_MANIFESTS: CollectionSpec = CollectionSpec {
    id: "uaid_manifests",
    tag: 14,
    fields: &[
        number("dataspace_id"),
        text("dataspace_alias"),
        json("manifest"),
        text("manifest_hash"),
        text("status"),
        json("lifecycle"),
        text_list("accounts"),
    ],
    metadata: false,
    default_sort: &[("dataspace_id", Order::Asc)],
    identity: &["dataspace_id"],
    positioned: 0,
    ordered: false,
};

/// Account movements within committed transactions, in descending chain order.
pub(crate) static ACCOUNT_HISTORY: CollectionSpec = CollectionSpec {
    id: "account_history",
    tag: 15,
    fields: &[
        text("id"),
        text("source"),
        text("type"),
        number("timestamp_ms"),
        text("status"),
        boolean("result_ok"),
        text("direction"),
        account("account_id"),
        account("counterparty_account_id"),
        text("asset_id"),
        text("asset_definition_id"),
        number("amount"),
        text("tx_hash"),
        number("block_height"),
        number("block_index"),
        number("movement_index"),
        text("operation_id"),
        number("expires_at_ms"),
        number("finalized_at_ms"),
        text("requesting_fi_id"),
    ],
    metadata: false,
    default_sort: &[],
    identity: &["block_height", "block_index", "movement_index"],
    positioned: 3,
    ordered: false,
};

/// `/v1/contracts/activity`: newest-first committed contract calls.
pub(crate) static CONTRACT_ACTIVITY: CollectionSpec = CollectionSpec {
    id: "contract_activity",
    tag: 16,
    fields: &[
        number("block_height"),
        number("block_index"),
        account("authority"),
        number("timestamp_ms"),
        text("entrypoint_hash"),
        boolean("result_ok"),
        text("contract_address"),
        text("contract_alias"),
        text("contract_entrypoint"),
        json("contract_payload"),
        json("fee_payment"),
    ],
    metadata: false,
    default_sort: &[],
    identity: &[],
    positioned: 2,
    ordered: false,
};

/// `/v1/contracts/events`: newest-first committed contract events.
pub(crate) static CONTRACT_EVENTS: CollectionSpec = CollectionSpec {
    id: "contract_events",
    tag: 17,
    fields: &[
        number("block_height"),
        number("output_index"),
        number("emission_index"),
        text("event_id"),
        number("schema_version"),
        text("provenance"),
        account("authority"),
        number("timestamp_ms"),
        text("execution_hash_hex"),
        text("block_hash_hex"),
        boolean("result_ok"),
        text("contract_address"),
        text("event_kind"),
        text_list("participants"),
        text_list("asset_ids"),
        json("numeric_fields"),
        json("payload"),
        json("emission"),
        json("fee_payment"),
    ],
    metadata: false,
    default_sort: &[],
    identity: &["block_height", "output_index", "emission_index"],
    positioned: 3,
    ordered: false,
};

/// Every collection, in cursor-tag order.
pub(crate) const ALL: [&CollectionSpec; 17] = [
    &DOMAINS,
    &ACCOUNTS,
    &ASSET_DEFINITIONS,
    &NFTS,
    &RWAS,
    &ACCOUNT_ASSETS,
    &ASSET_HOLDERS,
    &ACCOUNT_TRANSACTIONS,
    &REPO_AGREEMENTS,
    &TRANSACTIONS,
    &ACCOUNT_PERMISSIONS,
    &SUBSCRIPTION_PLANS,
    &SUBSCRIPTIONS,
    &UAID_MANIFESTS,
    &ACCOUNT_HISTORY,
    &CONTRACT_ACTIVITY,
    &CONTRACT_EVENTS,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs_are_internally_consistent() {
        let mut tags = std::collections::BTreeSet::new();
        for spec in ALL {
            assert!(tags.insert(spec.tag), "duplicate tag in {}", spec.id);
            assert_eq!(
                usize::from(spec.tag),
                tags.len(),
                "{} is out of tag order",
                spec.id
            );
            assert_eq!(
                spec.positioned > 0,
                spec.default_sort.is_empty(),
                "{}",
                spec.id
            );
            if spec.ordered {
                assert_eq!(spec.identity, &["id"], "{}", spec.id);
                assert_eq!(spec.default_sort, &[("id", Order::Asc)], "{}", spec.id);
            }
            if spec.positioned > 0 {
                for field in ["block_height", "block_index"] {
                    let field = spec
                        .field(field)
                        .expect("positioned rows carry coordinates");
                    assert_eq!(field.ty, FieldType::Number, "{}", spec.id);
                }
            }
            for (field, _) in spec.default_sort {
                assert!(
                    spec.field(field).is_some(),
                    "{}: default sort {field}",
                    spec.id
                );
            }
            for field in spec.identity {
                assert!(spec.field(field).is_some(), "{}: identity {field}", spec.id);
            }
        }
    }

    #[test]
    fn asset_definition_direct_home_is_exact_text() {
        let field = ASSET_DEFINITIONS
            .field("owning_dataspace")
            .expect("direct home field");
        assert_eq!(field.ty, FieldType::String);
        assert!(field.sortable);
        assert!(!field.account);
    }

    #[test]
    fn dynamic_and_prefix_fields_resolve() {
        assert!(DOMAINS.field("metadata.tier").is_some());
        assert!(DOMAINS.field("metadata").is_some());
        assert!(DOMAINS.field("metadata.").is_none());
        assert!(ACCOUNT_ASSETS.field("metadata.tier").is_none());
        assert_eq!(
            ASSET_DEFINITIONS
                .field("alias_binding")
                .map(|field| field.ty),
            Some(FieldType::Json)
        );
        assert!(ASSET_DEFINITIONS.field("alias_bind").is_none());
        assert!(DOMAINS.field("owner").is_none());
    }
}
