//! Schema-bound construction records for native Kotodama JSON expressions.
//!
//! A construction schema is emitted by the compiler in preorder. Object and array nodes describe
//! source structure, while value nodes reuse the exact aggregate-state schema for the corresponding
//! flattened VM words. This lets the host recursively convert bounded Lists and active-only Options
//! without guessing runtime types or serializing an intermediate projection.
use crate::state_value::{
    MAX_STATE_VALUE_NODES, MAX_STATE_VALUE_SCHEMA_BYTES, MAX_STATE_VALUE_WORDS, StateValueKindV1,
    StateValueNodeV1, StateValueSchemaV1,
};
use norito::{Decode, Encode};
use std::collections::BTreeSet;
/// Maximum number of construction nodes accepted by the V1 JSON builder.
pub const MAX_JSON_CONSTRUCTION_NODES_V1: usize = 256;
/// Maximum number of statically declared fields or elements in one JSON node.
pub const MAX_JSON_LITERAL_ITEMS_V1: usize = 64;
/// Maximum canonical encoded construction-schema size.
pub const MAX_JSON_CONSTRUCTION_SCHEMA_BYTES_V1: usize = MAX_STATE_VALUE_SCHEMA_BYTES;
/// One preorder node in a compiler-emitted native JSON construction schema.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::json::JsonConstructionNodeV1")]
pub enum JsonConstructionNodeV1 {
    /// JSON object. One child immediately follows for every key in source order.
    Object {
        /// Source keys. The host inserts them into a canonical ordered map.
        keys: Vec<String>,
    },
    /// JSON array. `arity` children immediately follow.
    Array {
        /// Statically known number of array elements.
        arity: u16,
    },
    /// One dynamic source value represented by flattened VM words.
    Value {
        /// Exact source-value schema used to interpret those words.
        schema: StateValueSchemaV1,
    },
}
/// Compiler-owned schema for one native `json { ... }` or `json [ ... ]` expression.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::json::JsonConstructionSchemaV1")]
pub struct JsonConstructionSchemaV1 {
    /// Preorder construction tree.
    pub nodes: Vec<JsonConstructionNodeV1>,
}
impl JsonConstructionSchemaV1 {
    /// Validate tree shape, duplicate keys, collection bounds, and source-value types.
    #[must_use]
    pub fn validate(&self) -> bool {
        self.analyze().is_some()
    }
    /// Return the exact number of flattened VM words consumed by this schema.
    #[must_use]
    pub fn word_count(&self) -> Option<usize> {
        self.analyze().map(|analysis| analysis.words)
    }
    fn analyze(&self) -> Option<JsonConstructionAnalysisV1> {
        if self.nodes.is_empty() || self.nodes.len() > MAX_JSON_CONSTRUCTION_NODES_V1 {
            return None;
        }
        let mut pending_depths = vec![1_usize];
        let mut analysis = JsonConstructionAnalysisV1 {
            nodes: 0,
            words: 0,
            depth: 0,
        };
        for node in &self.nodes {
            let depth = pending_depths.pop()?;
            if depth > MAX_JSON_CONSTRUCTION_NODES_V1 {
                return None;
            }
            analysis.nodes = analysis.nodes.checked_add(1)?;
            analysis.depth = analysis.depth.max(depth);
            let child_count = match node {
                JsonConstructionNodeV1::Object { keys } => {
                    if keys.len() > MAX_JSON_LITERAL_ITEMS_V1
                        || keys.iter().collect::<BTreeSet<_>>().len() != keys.len()
                    {
                        return None;
                    }
                    keys.len()
                }
                JsonConstructionNodeV1::Array { arity } => {
                    if usize::from(*arity) > MAX_JSON_LITERAL_ITEMS_V1 {
                        return None;
                    }
                    usize::from(*arity)
                }
                JsonConstructionNodeV1::Value { schema } => {
                    if !json_value_schema_is_supported(schema) {
                        return None;
                    }
                    analysis.words = analysis.words.checked_add(schema.word_count()?)?;
                    0
                }
            };
            if child_count != 0 {
                let child_depth = depth.checked_add(1)?;
                pending_depths.extend(std::iter::repeat_n(child_depth, child_count));
            }
        }
        (pending_depths.is_empty()
            && analysis.nodes <= MAX_JSON_CONSTRUCTION_NODES_V1
            && analysis.words <= MAX_STATE_VALUE_WORDS)
            .then_some(analysis)
    }
}
#[derive(Clone, Copy)]
struct JsonConstructionAnalysisV1 {
    nodes: usize,
    words: usize,
    depth: usize,
}
/// Return whether an aggregate-state schema belongs to the nested JSON-convertible V1 subset.
#[must_use]
pub fn json_value_schema_is_supported(schema: &StateValueSchemaV1) -> bool {
    const fn supported_leaf(kind: StateValueKindV1) -> bool {
        matches!(
            kind,
            StateValueKindV1::Int
                | StateValueKindV1::Decimal
                | StateValueKindV1::Quantity
                | StateValueKindV1::Bool
                | StateValueKindV1::String
                | StateValueKindV1::Json
                | StateValueKindV1::Bytes
                | StateValueKindV1::AccountId
                | StateValueKindV1::AssetDefinitionId
                | StateValueKindV1::AssetId
                | StateValueKindV1::DomainId
                | StateValueKindV1::NftId
                | StateValueKindV1::Name
                | StateValueKindV1::DataSpaceId
        )
    }
    if !schema.validate() {
        return false;
    }
    let mut pending = vec![(&schema.nodes[..], 1usize)];
    let mut visited_nodes = 0usize;
    while let Some((nodes, mut depth)) = pending.pop() {
        let mut index = 0usize;
        loop {
            if depth > MAX_STATE_VALUE_NODES {
                return false;
            }
            visited_nodes = match visited_nodes.checked_add(1) {
                Some(count) if count <= MAX_STATE_VALUE_NODES => count,
                _ => return false,
            };
            let Some(node) = nodes.get(index) else {
                return false;
            };
            index = match index.checked_add(1) {
                Some(index) => index,
                None => return false,
            };
            match node {
                StateValueNodeV1::Option => {
                    depth = match depth.checked_add(1) {
                        Some(depth) => depth,
                        None => return false,
                    };
                }
                StateValueNodeV1::List { element, .. } => {
                    if index != nodes.len() {
                        return false;
                    }
                    let child_depth = match depth.checked_add(1) {
                        Some(depth) => depth,
                        None => return false,
                    };
                    pending.push((&element.nodes, child_depth));
                    break;
                }
                StateValueNodeV1::Unit
                | StateValueNodeV1::Error(_)
                | StateValueNodeV1::Enum(_)
                | StateValueNodeV1::StateCursor(_) => {
                    if index != nodes.len() {
                        return false;
                    }
                    break;
                }
                StateValueNodeV1::Leaf(kind) => {
                    if index != nodes.len() || !supported_leaf(*kind) {
                        return false;
                    }
                    break;
                }
                StateValueNodeV1::Struct { .. }
                | StateValueNodeV1::Tuple { .. }
                | StateValueNodeV1::Result => return false,
            }
        }
    }
    true
}
#[cfg(test)]
mod tests {
    use super::*;
    use norito::{decode_from_bytes, to_bytes};
    fn leaf(kind: StateValueKindV1) -> StateValueSchemaV1 {
        StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Leaf(kind)],
        }
    }
    fn nested_list_schema(wrappers: usize) -> StateValueSchemaV1 {
        let mut schema = leaf(StateValueKindV1::Bool);
        for _ in 0..wrappers {
            schema = StateValueSchemaV1 {
                nodes: vec![StateValueNodeV1::List {
                    element: Box::new(schema),
                    capacity: 1,
                }],
            };
        }
        schema
    }
    fn nested_option_schema(wrappers: usize) -> StateValueSchemaV1 {
        let mut nodes = vec![StateValueNodeV1::Option; wrappers];
        nodes.push(StateValueNodeV1::Leaf(StateValueKindV1::Bool));
        StateValueSchemaV1 { nodes }
    }
    #[test]
    fn construction_schema_counts_words_and_rejects_duplicate_keys() {
        let schema = JsonConstructionSchemaV1 {
            nodes: vec![
                JsonConstructionNodeV1::Object {
                    keys: vec!["amount".into(), "labels".into()],
                },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Quantity),
                },
                JsonConstructionNodeV1::Array { arity: 2 },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::String),
                },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::String),
                },
            ],
        };
        assert!(schema.validate());
        assert_eq!(schema.word_count(), Some(3));
        let duplicate = JsonConstructionSchemaV1 {
            nodes: vec![
                JsonConstructionNodeV1::Object {
                    keys: vec!["same".into(), "same".into()],
                },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Int),
                },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Int),
                },
            ],
        };
        assert!(!duplicate.validate());
        assert_eq!(duplicate.word_count(), None);
    }
    #[test]
    fn supported_values_allow_nested_options_and_lists_but_reject_products_and_results() {
        let option_list = StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Option,
                StateValueNodeV1::List {
                    element: Box::new(leaf(StateValueKindV1::AccountId)),
                    capacity: 4,
                },
            ],
        };
        assert!(json_value_schema_is_supported(&option_list));
        for rejected in [
            StateValueSchemaV1 {
                nodes: vec![
                    StateValueNodeV1::Tuple { arity: 2 },
                    StateValueNodeV1::Leaf(StateValueKindV1::Int),
                    StateValueNodeV1::Leaf(StateValueKindV1::Int),
                ],
            },
            StateValueSchemaV1 {
                nodes: vec![
                    StateValueNodeV1::Result,
                    StateValueNodeV1::Leaf(StateValueKindV1::Int),
                    StateValueNodeV1::Leaf(StateValueKindV1::Int),
                ],
            },
        ] {
            assert!(!json_value_schema_is_supported(&rejected));
        }
    }
    #[test]
    fn supported_value_walker_honours_the_256_node_boundary_on_a_small_stack() {
        std::thread::Builder::new()
            .name("json-schema-small-stack".to_owned())
            .stack_size(128 * 1024)
            .spawn(|| {
                let lists = nested_list_schema(MAX_STATE_VALUE_NODES - 1);
                assert!(json_value_schema_is_supported(&lists));
                let options = nested_option_schema(MAX_STATE_VALUE_NODES - 1);
                assert!(json_value_schema_is_supported(&options));
                let too_deep = nested_list_schema(MAX_STATE_VALUE_NODES);
                assert!(!json_value_schema_is_supported(&too_deep));
                assert!(!json_value_schema_is_supported(&StateValueSchemaV1 {
                    nodes: vec![StateValueNodeV1::Option],
                }));
            })
            .expect("spawn small-stack JSON schema test")
            .join()
            .expect("small-stack JSON schema test");
    }
    #[test]
    fn construction_schema_analyzer_honours_the_256_node_boundary_on_a_small_stack() {
        std::thread::Builder::new()
            .name("json-construction-schema-small-stack".to_owned())
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut nodes = Vec::with_capacity(MAX_JSON_CONSTRUCTION_NODES_V1);
                nodes.extend(
                    (0..MAX_JSON_CONSTRUCTION_NODES_V1 - 1)
                        .map(|_| JsonConstructionNodeV1::Array { arity: 1 }),
                );
                nodes.push(JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Bool),
                });
                let boundary = JsonConstructionSchemaV1 { nodes };
                assert!(boundary.validate());
                assert_eq!(boundary.word_count(), Some(1));
                let mut too_many_nodes = Vec::with_capacity(MAX_JSON_CONSTRUCTION_NODES_V1 + 1);
                too_many_nodes.extend(
                    (0..MAX_JSON_CONSTRUCTION_NODES_V1)
                        .map(|_| JsonConstructionNodeV1::Array { arity: 1 }),
                );
                too_many_nodes.push(JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Bool),
                });
                let rejected = JsonConstructionSchemaV1 {
                    nodes: too_many_nodes,
                };
                assert!(!rejected.validate());
                assert_eq!(rejected.word_count(), None);
            })
            .expect("spawn small-stack JSON construction-schema test")
            .join()
            .expect("small-stack JSON construction-schema test");
    }
    #[test]
    fn construction_schema_roundtrips_canonically() {
        let schema = JsonConstructionSchemaV1 {
            nodes: vec![
                JsonConstructionNodeV1::Array { arity: 2 },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Quantity),
                },
                JsonConstructionNodeV1::Value {
                    schema: StateValueSchemaV1 {
                        nodes: vec![
                            StateValueNodeV1::Option,
                            StateValueNodeV1::Leaf(StateValueKindV1::Name),
                        ],
                    },
                },
            ],
        };
        let encoded = to_bytes(&schema).expect("encode JSON construction schema");
        let decoded: JsonConstructionSchemaV1 =
            decode_from_bytes(&encoded).expect("decode JSON construction schema");
        assert_eq!(decoded, schema);
        assert_eq!(to_bytes(&decoded).expect("re-encode schema"), encoded);
    }
}

#[cfg(test)]
mod captured_frame_identity_tests {
    #[test]
    fn observed_declared_identities() {
        crate::captured_identity_tests::assert_bidirectional::<super::JsonConstructionNodeV1>(
            "ivm_abi::json::JsonConstructionNodeV1",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::JsonConstructionSchemaV1>(
            "ivm_abi::json::JsonConstructionSchemaV1",
        );
    }
}
