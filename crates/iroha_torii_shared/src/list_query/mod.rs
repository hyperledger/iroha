//! The Torii list-query language, shared by Torii, the SDKs and the CLI.
//!
//! Every collection endpoint (`GET /v1/<collection>` and
//! `POST /v1/<collection>/query`) accepts the same controls, and every page
//! response has the same envelope:
//!
//! | Control | GET parameter | JSON member | Meaning |
//! | --- | --- | --- | --- |
//! | filter | `filter=<text>` | `"filter": "<text>"` or the JSON form | rows to keep |
//! | sort | `sort=-quantity,id` | `"sort": ["-quantity", "id"]` | order; `-` is descending |
//! | projection | `select=id,quantity` | `"select": ["id", "quantity"]` | fields per item |
//! | aggregation | — | `"aggregate": {...}` | grouped metrics (POST only) |
//! | page size | `limit=50` | `"limit": 50` | rows per page |
//! | continuation | `cursor=<token>` | `"cursor": "<token>"` | resume after the previous page |
//! | total | `include_total=true` | `"include_total": true` | add the exact match count |
//!
//! ```json
//! {"items": [ ... ], "next_cursor": "opaque-or-null", "total": 42}
//! ```
//!
//! Text filters read like a SQL `WHERE` clause:
//!
//! ```text
//! owned_by = "sorau…" and quantity >= 10.5
//! status in ["active", "paused"] or not exists(metadata.archived)
//! metadata.`display-name` is not null
//! ```
//!
//! See [`text`] for the grammar, [`builder`] for Rust construction helpers
//! and [`FilterExpr`] for the JSON form. Unknown members, unknown parameters,
//! unknown fields and malformed values are rejected with an error naming the
//! offending parameter; nothing is silently ignored.
pub mod aggregate;
pub mod builder;
pub mod filter;
pub mod sort;
pub mod text;

pub use aggregate::{AggregateFn, AggregateMetric, AggregateSpec};
pub use builder::{Field, IntoLiteral, field};
pub use filter::{
    FIELD_PATH_MAX_BYTES, FILTER_MAX_DEPTH, FILTER_MAX_MEMBERSHIP_VALUES, FILTER_MAX_NODES,
    FILTER_MAX_TOTAL_MEMBERSHIP_VALUES, FieldPath, FilterError, FilterExpr, FilterParseError,
    filter_from_json_or_text, is_decimal_text, is_numeric_literal,
};
pub use sort::{Order, SortKey, sort_to_string};
pub use text::{FILTER_TEXT_MAX_BYTES, FilterSyntaxError, SORT_MAX_KEYS, parse_sort};

use norito::json::{self, FastJsonWrite, JsonDeserialize, JsonSerialize, Map, Value};
use std::fmt;

/// Maximum number of fields in one projection.
pub const SELECT_MAX_FIELDS: usize = 64;
/// Maximum encoded length of a pagination cursor.
pub const CURSOR_MAX_BYTES: usize = 4096;
/// Maximum number of `group_by` fields in one aggregate.
pub const AGGREGATE_MAX_GROUP_BY: usize = 8;
/// Maximum number of metrics in one aggregate.
pub const AGGREGATE_MAX_METRICS: usize = 16;

/// JSON members accepted in a list-query body, in canonical order.
pub const LIST_QUERY_MEMBERS: [&str; 7] = [
    "filter",
    "sort",
    "select",
    "aggregate",
    "limit",
    "cursor",
    "include_total",
];
/// URL parameters accepted by `GET` collection endpoints.
pub const LIST_QUERY_PARAMETERS: [&str; 6] = [
    "filter",
    "sort",
    "select",
    "limit",
    "cursor",
    "include_total",
];

/// Filter, ordering, projection and page controls for one collection read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListQuery {
    /// Rows to keep.
    pub filter: Option<FilterExpr>,
    /// Ordering; the collection's default order applies when empty.
    pub sort: Vec<SortKey>,
    /// Fields to return per item; all fields when `None`.
    pub select: Option<Vec<FieldPath>>,
    /// Grouped metrics instead of items.
    pub aggregate: Option<AggregateSpec>,
    /// Rows per page; the server default applies when `None`.
    pub limit: Option<u32>,
    /// Continuation token from a previous page's `next_cursor`.
    pub cursor: Option<String>,
    /// Whether to compute the exact number of matching rows.
    pub include_total: bool,
}

/// A rejected list-query control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListQueryError {
    /// The control at fault: one of [`LIST_QUERY_MEMBERS`] or `query` for the
    /// request as a whole.
    pub parameter: &'static str,
    /// Human-readable description including a fix where one is obvious.
    pub message: String,
}

impl ListQueryError {
    /// Construct an error for `parameter`.
    pub fn new(parameter: &'static str, message: impl Into<String>) -> Self {
        Self {
            parameter,
            message: message.into(),
        }
    }

    /// Stable error code for the Torii error envelope.
    pub fn code(&self) -> &'static str {
        match self.parameter {
            "filter" => "invalid_filter",
            "sort" => "invalid_sort",
            "select" => "invalid_select",
            "aggregate" => "invalid_aggregate",
            "limit" => "invalid_limit",
            "cursor" => "invalid_cursor",
            "include_total" => "invalid_include_total",
            _ => "invalid_query",
        }
    }
}

impl fmt::Display for ListQueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid `{}`: {}", self.parameter, self.message)
    }
}

impl std::error::Error for ListQueryError {}

impl ListQuery {
    /// An empty query: default order, all fields, server page size.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the filter.
    #[must_use]
    pub fn filter(mut self, filter: FilterExpr) -> Self {
        self.filter = Some(filter);
        self
    }

    /// AND another condition into the filter.
    #[must_use]
    pub fn and_filter(mut self, filter: FilterExpr) -> Self {
        self.filter = Some(match self.filter.take() {
            Some(existing) => existing.and(filter),
            None => filter,
        });
        self
    }

    /// Append a sort key.
    #[must_use]
    pub fn sort_by(mut self, key: SortKey) -> Self {
        self.sort.push(key);
        self
    }

    /// Return only these fields per item.
    #[must_use]
    pub fn select<I>(mut self, fields: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<FieldPath>,
    {
        self.select = Some(fields.into_iter().map(Into::into).collect());
        self
    }

    /// Return grouped metrics instead of items.
    #[must_use]
    pub fn aggregate(mut self, spec: AggregateSpec) -> Self {
        self.aggregate = Some(spec);
        self
    }

    /// Rows per page.
    #[must_use]
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Continue after a previous page.
    #[must_use]
    pub fn cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    /// Ask for the exact number of matching rows.
    #[must_use]
    pub fn include_total(mut self) -> Self {
        self.include_total = true;
        self
    }

    /// The same query positioned after `page`, or `None` on the last page.
    pub fn next_page<T>(&self, page: &Page<T>) -> Option<Self> {
        page.next_cursor.as_ref().map(|cursor| {
            let mut next = self.clone();
            next.cursor = Some(cursor.clone());
            next
        })
    }

    /// Check every control without contacting a server.
    ///
    /// # Errors
    /// Returns the first invalid control.
    pub fn validate(&self) -> Result<(), ListQueryError> {
        if let Some(filter) = &self.filter {
            filter
                .validate()
                .map_err(|err| ListQueryError::new("filter", err.to_string()))?;
        }
        validate_sort(&self.sort)?;
        if let Some(select) = &self.select {
            validate_select(select)?;
        }
        if self.select.is_some() && self.aggregate.is_some() {
            return Err(ListQueryError::new(
                "select",
                "`select` and `aggregate` cannot be combined; aggregates define their own columns",
            ));
        }
        if let Some(aggregate) = &self.aggregate {
            if aggregate.metrics.is_empty() {
                return Err(ListQueryError::new(
                    "aggregate",
                    "`metrics` must list at least one metric",
                ));
            }
            if aggregate.group_by.len() > AGGREGATE_MAX_GROUP_BY {
                return Err(ListQueryError::new(
                    "aggregate",
                    format!("`group_by` lists at most {AGGREGATE_MAX_GROUP_BY} fields"),
                ));
            }
            if aggregate.metrics.len() > AGGREGATE_MAX_METRICS {
                return Err(ListQueryError::new(
                    "aggregate",
                    format!("`metrics` lists at most {AGGREGATE_MAX_METRICS} metrics"),
                ));
            }
            for field in aggregate.group_by.iter().chain(
                aggregate
                    .metrics
                    .iter()
                    .filter_map(|metric| metric.field.as_ref()),
            ) {
                field
                    .validate()
                    .map_err(|err| ListQueryError::new("aggregate", err.to_string()))?;
            }
            if let Some(having) = &aggregate.having {
                having
                    .validate()
                    .map_err(|err| ListQueryError::new("aggregate", format!("having: {err}")))?;
            }
        }
        if self.limit == Some(0) {
            return Err(ListQueryError::new("limit", "`limit` must be at least 1"));
        }
        if let Some(cursor) = &self.cursor {
            validate_cursor(cursor)?;
        }
        Ok(())
    }

    /// Canonical JSON body for `POST /v1/<collection>/query`.
    pub fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        if let Some(filter) = &self.filter {
            map.insert("filter".into(), filter.to_json_value());
        }
        if !self.sort.is_empty() {
            map.insert(
                "sort".into(),
                Value::Array(
                    self.sort
                        .iter()
                        .map(|key| Value::String(key.to_string()))
                        .collect(),
                ),
            );
        }
        if let Some(select) = &self.select {
            map.insert(
                "select".into(),
                Value::Array(
                    select
                        .iter()
                        .map(|field| Value::String(field.0.clone()))
                        .collect(),
                ),
            );
        }
        if let Some(aggregate) = &self.aggregate {
            map.insert(
                "aggregate".into(),
                json::to_value(aggregate).expect("aggregate specs serialize"),
            );
        }
        if let Some(limit) = self.limit {
            map.insert("limit".into(), Value::from(u64::from(limit)));
        }
        if let Some(cursor) = &self.cursor {
            map.insert("cursor".into(), Value::String(cursor.clone()));
        }
        if self.include_total {
            map.insert("include_total".into(), Value::Bool(true));
        }
        Value::Object(map)
    }

    /// Decode a `POST /v1/<collection>/query` body.
    ///
    /// # Errors
    /// Returns a [`ListQueryError`] naming the offending member.
    pub fn from_json_value(value: Value) -> Result<Self, ListQueryError> {
        let Value::Object(map) = value else {
            return Err(ListQueryError::new(
                "query",
                "the request body must be a JSON object such as {\"filter\": \"...\", \"limit\": 50}",
            ));
        };
        let mut query = Self::default();
        for (key, value) in map {
            match key.as_str() {
                "filter" => {
                    query.filter = match value {
                        Value::Null => None,
                        value => Some(
                            filter_from_json_or_text(value)
                                .map_err(|err| ListQueryError::new("filter", err.to_string()))?,
                        ),
                    };
                }
                "sort" => query.sort = sort_from_json(value)?,
                "select" => {
                    query.select = match value {
                        Value::Null => None,
                        Value::Array(fields) => Some(
                            fields
                                .into_iter()
                                .map(|field| match field {
                                    Value::String(field) => Ok(FieldPath(field)),
                                    _ => Err(ListQueryError::new(
                                        "select",
                                        "`select` must be an array of field names",
                                    )),
                                })
                                .collect::<Result<_, _>>()?,
                        ),
                        _ => {
                            return Err(ListQueryError::new(
                                "select",
                                "`select` must be an array of field names such as [\"id\", \"quantity\"]",
                            ));
                        }
                    };
                }
                "aggregate" => {
                    query.aggregate = match value {
                        Value::Null => None,
                        value => Some(
                            json::from_value::<AggregateSpec>(value)
                                .map_err(|err| ListQueryError::new("aggregate", err.to_string()))?,
                        ),
                    };
                }
                "limit" => {
                    query.limit = match value {
                        Value::Null => None,
                        value => Some(limit_from_u64(value.as_u64().ok_or_else(|| {
                            ListQueryError::new("limit", "`limit` must be a positive integer")
                        })?)?),
                    };
                }
                "cursor" => {
                    query.cursor = match value {
                        Value::Null => None,
                        Value::String(cursor) => Some(cursor),
                        _ => {
                            return Err(ListQueryError::new(
                                "cursor",
                                "`cursor` must be the string returned as `next_cursor`",
                            ));
                        }
                    };
                }
                "include_total" => {
                    query.include_total = match value {
                        Value::Null => false,
                        Value::Bool(flag) => flag,
                        _ => {
                            return Err(ListQueryError::new(
                                "include_total",
                                "`include_total` must be true or false",
                            ));
                        }
                    };
                }
                other => {
                    return Err(ListQueryError::new(
                        "query",
                        format!(
                            "unknown member `{other}`; expected one of: {}",
                            LIST_QUERY_MEMBERS.join(", ")
                        ),
                    ));
                }
            }
        }
        query.validate()?;
        Ok(query)
    }

    /// Decode `GET` parameters given as already percent-decoded pairs.
    ///
    /// # Errors
    /// Returns a [`ListQueryError`] naming the offending parameter.
    pub fn from_query_pairs<I, K, V>(pairs: I) -> Result<Self, ListQueryError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut query = Self::default();
        let mut seen: Vec<&'static str> = Vec::new();
        for (key, value) in pairs {
            let (key, value) = (key.as_ref(), value.as_ref());
            let Some(parameter) = LIST_QUERY_PARAMETERS
                .iter()
                .copied()
                .find(|candidate| *candidate == key)
            else {
                let hint = if key == "aggregate" {
                    "; aggregates are only available through POST /query".to_owned()
                } else {
                    String::new()
                };
                return Err(ListQueryError::new(
                    "query",
                    format!(
                        "unknown parameter `{key}`; expected one of: {}{hint}",
                        LIST_QUERY_PARAMETERS.join(", ")
                    ),
                ));
            };
            if seen.contains(&parameter) {
                return Err(ListQueryError::new(
                    parameter,
                    format!("`{parameter}` must appear at most once"),
                ));
            }
            seen.push(parameter);
            match parameter {
                "filter" => {
                    query.filter = Some(
                        FilterExpr::parse(value)
                            .map_err(|err| ListQueryError::new("filter", err.to_string()))?,
                    );
                }
                "sort" => {
                    query.sort = parse_sort(value)
                        .map_err(|err| ListQueryError::new("sort", err.to_string()))?;
                }
                "select" => {
                    let fields = value
                        .split(',')
                        .map(|field| FieldPath(field.trim().to_owned()))
                        .collect();
                    query.select = Some(fields);
                }
                "limit" => {
                    let parsed = value.parse::<u64>().map_err(|_| {
                        ListQueryError::new(
                            "limit",
                            format!("`limit` must be a positive integer, got `{value}`"),
                        )
                    })?;
                    query.limit = Some(limit_from_u64(parsed)?);
                }
                "cursor" => query.cursor = Some(value.to_owned()),
                _ => {
                    query.include_total = match value {
                        "true" => true,
                        "false" => false,
                        other => {
                            return Err(ListQueryError::new(
                                "include_total",
                                format!("`include_total` must be `true` or `false`, got `{other}`"),
                            ));
                        }
                    };
                }
            }
        }
        query.validate()?;
        Ok(query)
    }

    /// Encode as `GET` parameters (not yet percent-encoded).
    ///
    /// # Errors
    /// Aggregates have no URL form; use `POST /query` for them.
    pub fn to_query_pairs(&self) -> Result<Vec<(&'static str, String)>, ListQueryError> {
        if self.aggregate.is_some() {
            return Err(ListQueryError::new(
                "aggregate",
                "aggregates are only available through POST /query",
            ));
        }
        let mut pairs = Vec::new();
        if let Some(filter) = &self.filter {
            pairs.push(("filter", filter.to_string()));
        }
        if !self.sort.is_empty() {
            pairs.push(("sort", sort_to_string(&self.sort)));
        }
        if let Some(select) = &self.select {
            pairs.push((
                "select",
                select
                    .iter()
                    .map(|field| field.0.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        if let Some(cursor) = &self.cursor {
            pairs.push(("cursor", cursor.clone()));
        }
        if self.include_total {
            pairs.push(("include_total", "true".to_owned()));
        }
        Ok(pairs)
    }
}

fn limit_from_u64(limit: u64) -> Result<u32, ListQueryError> {
    if limit == 0 {
        return Err(ListQueryError::new("limit", "`limit` must be at least 1"));
    }
    u32::try_from(limit).map_err(|_| ListQueryError::new("limit", "`limit` is too large"))
}

fn sort_from_json(value: Value) -> Result<Vec<SortKey>, ListQueryError> {
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Array(keys) => keys
            .into_iter()
            .map(|key| match key {
                Value::String(text) => SortKey::parse(&text)
                    .map_err(|err| ListQueryError::new("sort", err.to_string())),
                _ => Err(ListQueryError::new(
                    "sort",
                    "sort keys are strings such as \"-quantity\" or \"id\"",
                )),
            })
            .collect(),
        _ => Err(ListQueryError::new(
            "sort",
            "`sort` must be an array of keys such as [\"-quantity\", \"id\"]",
        )),
    }
}

fn validate_sort(keys: &[SortKey]) -> Result<(), ListQueryError> {
    if keys.len() > SORT_MAX_KEYS {
        return Err(ListQueryError::new(
            "sort",
            format!("at most {SORT_MAX_KEYS} sort keys are allowed"),
        ));
    }
    for (index, key) in keys.iter().enumerate() {
        key.key
            .validate()
            .map_err(|err| ListQueryError::new("sort", err.to_string()))?;
        if keys[..index].iter().any(|earlier| earlier.key == key.key) {
            return Err(ListQueryError::new(
                "sort",
                format!("sort key `{}` appears more than once", key.key),
            ));
        }
    }
    Ok(())
}

fn validate_select(fields: &[FieldPath]) -> Result<(), ListQueryError> {
    if fields.is_empty() {
        return Err(ListQueryError::new(
            "select",
            "`select` must list at least one field",
        ));
    }
    if fields.len() > SELECT_MAX_FIELDS {
        return Err(ListQueryError::new(
            "select",
            format!("at most {SELECT_MAX_FIELDS} fields can be selected"),
        ));
    }
    for (index, field) in fields.iter().enumerate() {
        field
            .validate()
            .map_err(|err| ListQueryError::new("select", err.to_string()))?;
        if fields[..index].contains(field) {
            return Err(ListQueryError::new(
                "select",
                format!("field `{field}` is selected more than once"),
            ));
        }
    }
    Ok(())
}

fn validate_cursor(cursor: &str) -> Result<(), ListQueryError> {
    if cursor.is_empty()
        || cursor.len() > CURSOR_MAX_BYTES
        || !cursor
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(ListQueryError::new(
            "cursor",
            "`cursor` must be a `next_cursor` value returned by a previous page",
        ));
    }
    Ok(())
}

impl FastJsonWrite for ListQuery {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }

    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            let mut first = true;
            let mut field =
                |name: &str, value: &dyn JsonSerialize| -> Result<(), json::BoundedJsonError> {
                    if !first {
                        out.push(',')?;
                    }
                    first = false;
                    name.json_serialize_to(out)?;
                    out.push(':')?;
                    value.json_serialize_to(out)
                };
            if let Some(value) = &self.aggregate {
                field("aggregate", value)?;
            }
            if let Some(value) = &self.cursor {
                field("cursor", value)?;
            }
            if let Some(value) = &self.filter {
                field("filter", value)?;
            }
            if self.include_total {
                field("include_total", &true)?;
            }
            if let Some(value) = self.limit {
                field("limit", &value)?;
            }
            if let Some(value) = &self.select {
                field("select", value)?;
            }
            if !self.sort.is_empty() {
                field("sort", &self.sort)?;
            }
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl JsonDeserialize for ListQuery {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = Value::json_deserialize(parser)?;
        Self::from_json_value(value).map_err(|err| json::Error::Message(err.to_string()))
    }
}

/// One page of a collection read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// Items on this page, in the requested order.
    pub items: Vec<T>,
    /// Pass as `cursor` to fetch the next page; `None` on the last page.
    pub next_cursor: Option<String>,
    /// Exact number of matching rows, present only when `include_total` was requested.
    pub total: Option<u64>,
}

impl<T> Page<T> {
    /// A page with no further pages and no total.
    pub fn last(items: Vec<T>) -> Self {
        Self {
            items,
            next_cursor: None,
            total: None,
        }
    }

    /// Whether another page follows.
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    /// Convert every item.
    pub fn map<U>(self, convert: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(convert).collect(),
            next_cursor: self.next_cursor,
            total: self.total,
        }
    }
}

impl<T: JsonSerialize> FastJsonWrite for Page<T> {
    fn write_json(&self, out: &mut String) {
        json::write_json_unbounded(self, out);
    }

    fn write_json_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"items\":")?;
            self.items.json_serialize_to(out)?;
            out.push_str(",\"next_cursor\":")?;
            self.next_cursor.json_serialize_to(out)?;
            if let Some(total) = self.total {
                out.push_str(",\"total\":")?;
                total.json_serialize_to(out)?;
            }
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl<T: JsonDeserialize> JsonDeserialize for Page<T> {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let Value::Object(mut map) = Value::json_deserialize(parser)? else {
            return Err(json::Error::Message("a page must be a JSON object".into()));
        };
        let items: Vec<T> = match map.remove("items") {
            Some(Value::Array(items)) => items
                .into_iter()
                .map(json::from_value::<T>)
                .collect::<Result<Vec<_>, _>>()?,
            _ => {
                return Err(json::Error::Message(
                    "a page must contain an `items` array".into(),
                ));
            }
        };
        let next_cursor = match map.remove("next_cursor") {
            Some(Value::Null) => None,
            Some(Value::String(cursor)) if !cursor.is_empty() => Some(cursor),
            _ => {
                return Err(json::Error::Message(
                    "a page must contain `next_cursor` as a nonempty string or null".into(),
                ));
            }
        };
        let total = match map.remove("total") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_u64().ok_or_else(|| {
                json::Error::Message("`total` must be a non-negative integer".into())
            })?),
        };
        if !map.is_empty() {
            return Err(json::Error::Message(
                "a page contains unknown envelope fields".into(),
            ));
        }
        if total.is_some_and(|total| total < items.len() as u64) {
            return Err(json::Error::Message(
                "a page total cannot be smaller than its items".into(),
            ));
        }
        Ok(Self {
            items,
            next_cursor,
            total,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn checked_query_and_page_writers_preserve_semantics_at_exact_boundary() {
        use super::*;
        let query = ListQuery::from_json_value(norito::json!({
            "filter": {"op":"and", "args":[
                {"op":"eq", "args":["metadata.label", "quoted \\\" text"]},
                {"op":"not", "args":[{"op":"in", "args":["id", ["a","b"]]}]}
            ]},
            "sort":["-id"],
            "include_total":true, "limit":2,
            "aggregate":{"group_by":["id"],"metrics":[{"alias":"count","fn":"count"}],"having":{"op":"gt","args":["count",0]}}
        })).unwrap();
        let expected = query.to_json_value();
        let body = json::to_json_bounded_boxed(&query, 16 * 1024).unwrap();
        assert_eq!(body.as_ref(), json::to_json(&query).unwrap().as_bytes());
        assert_eq!(json::from_slice::<Value>(&body).unwrap(), expected);
        assert_eq!(
            json::to_json_bounded_boxed(&query, body.len()).unwrap(),
            body
        );
        assert_eq!(
            json::to_json_bounded_boxed(&query, body.len() - 1),
            Err(json::BoundedJsonError::BodyTooLarge)
        );
        let page = Page {
            items: vec![expected],
            next_cursor: Some("position".to_owned()),
            total: Some(1),
        };
        let legacy = json::to_json(&page).unwrap();
        let body = json::to_json_bounded_boxed(&page, legacy.len()).unwrap();
        assert_eq!(body.as_ref(), legacy.as_bytes());
        assert_eq!(
            json::to_json_bounded_boxed(&page, body.len() - 1),
            Err(json::BoundedJsonError::BodyTooLarge)
        );
        let query = ListQuery::new()
            .select(["id", "metadata.label"])
            .cursor("position".to_owned())
            .limit(2);
        let ordinary = json::to_json(&query).unwrap();
        let body = json::to_json_bounded_boxed(&query, ordinary.len()).unwrap();
        assert_eq!(body.as_ref(), ordinary.as_bytes());
        assert_eq!(
            json::from_slice::<Value>(&body).unwrap(),
            query.to_json_value()
        );
        assert_eq!(
            json::to_json_bounded_boxed(&query, body.len() - 1),
            Err(json::BoundedJsonError::BodyTooLarge)
        );
    }

    use super::*;

    #[test]
    fn aggregates_are_bounded_and_their_paths_validated() {
        let metric = |alias: &str| AggregateMetric {
            alias: alias.into(),
            r#fn: AggregateFn::Count,
            field: None,
        };
        let query = |group_by: Vec<FieldPath>, metrics: Vec<AggregateMetric>| {
            ListQuery::new().aggregate(AggregateSpec {
                group_by,
                metrics,
                having: None,
            })
        };
        let wide_groups = (0..=AGGREGATE_MAX_GROUP_BY)
            .map(|index| FieldPath(format!("metadata.k{index}")))
            .collect();
        let err = query(wide_groups, vec![metric("n")])
            .validate()
            .expect_err("too many groups");
        assert_eq!(err.parameter, "aggregate");
        let many_metrics = (0..=AGGREGATE_MAX_METRICS)
            .map(|index| metric(&format!("m{index}")))
            .collect();
        assert!(query(Vec::new(), many_metrics).validate().is_err());
        let bad_path = query(vec![FieldPath("a..b".into())], vec![metric("n")]);
        assert!(bad_path.validate().is_err());
        let fine = query(vec![FieldPath("owned_by".into())], vec![metric("n")]);
        assert!(fine.validate().is_ok());
    }

    #[test]
    fn json_body_accepts_text_and_structured_filters() {
        let text: ListQuery = json::from_str(
            r#"{"filter": "owned_by = \"alice\" and quantity > 1", "sort": ["-quantity", "id"],
                "select": ["id", "quantity"], "limit": 25, "include_total": true}"#,
        )
        .expect("text filter body");
        let structured = ListQuery::new()
            .filter(field("owned_by").eq("alice") & field("quantity").gt(1))
            .sort_by(SortKey::desc("quantity"))
            .sort_by(SortKey::asc("id"))
            .select(["id", "quantity"])
            .limit(25)
            .include_total();
        assert_eq!(text, structured);
        let reencoded: ListQuery =
            json::from_value(structured.to_json_value()).expect("canonical body");
        assert_eq!(reencoded, structured);
    }

    #[test]
    fn json_body_rejects_unknown_and_malformed_members() {
        for (body, parameter, needle) in [
            (
                r#"{"pagination": {"limit": 1}}"#,
                "query",
                "unknown member `pagination`",
            ),
            (r#"{"filter": "a ="}"#, "filter", "expected a literal"),
            (
                r#"{"filter": {"op": "eq"}}"#,
                "filter",
                "takes [\"field\", value]",
            ),
            (r#"{"sort": "id"}"#, "sort", "must be an array"),
            (r#"{"sort": ["id:desc"]}"#, "sort", "`-field`"),
            (r#"{"sort": ["id", "-id"]}"#, "sort", "more than once"),
            (r#"{"select": []}"#, "select", "at least one field"),
            (
                r#"{"select": ["id"], "aggregate": {"metrics": [{"alias": "n", "fn": "count"}]}}"#,
                "select",
                "cannot be combined",
            ),
            (r#"{"limit": 0}"#, "limit", "at least 1"),
            (r#"{"limit": "10"}"#, "limit", "positive integer"),
            (r#"{"cursor": "has space"}"#, "cursor", "next_cursor"),
            (
                r#"{"include_total": "yes"}"#,
                "include_total",
                "true or false",
            ),
            ("[]", "query", "JSON object"),
        ] {
            let value = json::parse_value(body).expect("valid JSON");
            let err = ListQuery::from_json_value(value).expect_err(body);
            assert_eq!(err.parameter, parameter, "{body}: {err}");
            assert!(err.message.contains(needle), "{body}: {err}");
        }
    }

    #[test]
    fn query_pairs_roundtrip() {
        let query = ListQuery::new()
            .filter(FilterExpr::parse(r#"metadata.tier in [1, 2] or name = "x""#).unwrap())
            .sort_by(SortKey::desc("quantity"))
            .select(["id", "name"])
            .limit(10)
            .cursor("abc_DEF-1")
            .include_total();
        let pairs = query.to_query_pairs().expect("GET form");
        assert_eq!(
            pairs.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            [
                "filter",
                "sort",
                "select",
                "limit",
                "cursor",
                "include_total"
            ]
        );
        assert_eq!(ListQuery::from_query_pairs(pairs).expect("decode"), query);
    }

    #[test]
    fn query_pairs_reject_unknown_duplicate_and_malformed_parameters() {
        for (pairs, parameter, needle) in [
            (
                vec![("offset", "10")],
                "query",
                "unknown parameter `offset`",
            ),
            (vec![("count_mode", "exact")], "query", "unknown parameter"),
            (vec![("aggregate", "x")], "query", "POST /query"),
            (vec![("limit", "ten")], "limit", "got `ten`"),
            (
                vec![("limit", "1"), ("limit", "2")],
                "limit",
                "at most once",
            ),
            (vec![("sort", "id:asc")], "sort", "`-field`"),
            (vec![("include_total", "1")], "include_total", "got `1`"),
            (vec![("select", "id,,name")], "select", "must not be empty"),
            (vec![("filter", "a = = 1")], "filter", "expected a literal"),
        ] {
            let err = ListQuery::from_query_pairs(pairs.clone()).expect_err("rejected");
            assert_eq!(err.parameter, parameter, "{pairs:?}: {err}");
            assert!(err.message.contains(needle), "{pairs:?}: {err}");
        }
        assert_eq!(ListQueryError::new("filter", "x").code(), "invalid_filter");
    }

    #[test]
    fn page_envelope_rejects_retired_or_ambiguous_continuation() {
        for value in [
            r#"{"items":[]}"#,
            r#"{"items":[],"next_cursor":""}"#,
            r#"{"items":[],"next_cursor":7}"#,
            r#"{"items":[],"has_more":false,"count_mode":"exact","total":0}"#,
            r#"{"items":[],"next_cursor":null,"has_more":false}"#,
            r#"{"items":[1],"next_cursor":null,"total":0}"#,
        ] {
            assert!(
                json::from_str::<Page<Value>>(value).is_err(),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn page_envelope_roundtrip() {
        let page = Page {
            items: vec![Value::from("a"), Value::from("b")],
            next_cursor: Some("c1".into()),
            total: Some(7),
        };
        let encoded = json::to_json(&page).expect("serialize");
        assert_eq!(
            encoded,
            r#"{"items":["a","b"],"next_cursor":"c1","total":7}"#
        );
        assert_eq!(
            json::from_str::<Page<Value>>(&encoded).expect("decode"),
            page
        );
        let last = Page::last(vec![Value::from(1u64)]);
        let encoded = json::to_json(&last).expect("serialize");
        assert_eq!(encoded, r#"{"items":[1],"next_cursor":null}"#);
        assert!(!json::from_str::<Page<Value>>(&encoded).unwrap().has_more());
        let query = ListQuery::new().limit(2);
        assert_eq!(
            query.next_page(&page).unwrap().cursor.as_deref(),
            Some("c1")
        );
        assert!(query.next_page(&last).is_none());
    }
}

#[cfg(test)]
mod vectors_tests;

#[cfg(test)]
mod service_depth_tests {
    //! Owning checked service writers keep the caller depth on exact refusals.
    use super::*;
    use crate::service_checked_writer_test_support::{RefusingLeaf, audit, byte_refusal, error};
    use norito::json::{BoundedJsonError, FastJsonWrite};

    #[test]
    fn original_list_query_keeps_optional_controls_and_refusal_depth() {
        let values = [
            ListQuery::default(),
            ListQuery {
                filter: Some(FilterExpr::Eq(FieldPath::from("name"), Value::from("é"))),
                sort: vec![SortKey::asc("name"), SortKey::desc("quantity")],
                limit: Some(7),
                cursor: Some("abc".into()),
                select: Some(vec![FieldPath::from("name")]),
                include_total: true,
                ..ListQuery::default()
            },
            ListQuery {
                aggregate: Some(AggregateSpec {
                    group_by: vec![FieldPath::from("name")],
                    metrics: vec![AggregateMetric {
                        alias: "accounts".into(),
                        r#fn: AggregateFn::Count,
                        field: None,
                    }],
                    having: Some(FilterExpr::Gt(
                        FieldPath::from("accounts"),
                        Value::from(1_u64),
                    )),
                }),
                ..ListQuery::default()
            },
        ];
        for source in &values {
            source
                .validate()
                .expect("original supported list-query controls");
            // Typed aggregate writers retain declaration order; materializing a
            // Value alphabetizes object keys and is only a semantic oracle.
            let expected = norito::json::to_json(source).unwrap();
            assert_eq!(
                norito::json::from_str::<Value>(&expected).unwrap(),
                source.to_json_value()
            );
            audit(&expected, |sink| source.write_json_to(sink));
        }
    }
    #[test]
    fn original_page_keeps_actual_items_optional_total_and_manual_leaf_refusal() {
        let values = [
            Page::last(vec![1_u64, 7]),
            Page {
                items: Vec::new(),
                next_cursor: Some("abc".into()),
                total: Some(9),
            },
        ];
        for source in &values {
            let expected = norito::json::to_json(source).unwrap();
            audit(&expected, |sink| source.write_json_to(sink));
        }
        let source = Page::last(vec![RefusingLeaf {
            visits: std::cell::Cell::new(0),
        }]);
        byte_refusal(|sink| source.write_json_to(sink));
        assert_eq!(source.items[0].visits.get(), 0);
        error(BoundedJsonError::Unsupported, |sink| {
            source.write_json_to(sink)
        });
        assert_eq!(source.items[0].visits.get(), 1);
    }
}
