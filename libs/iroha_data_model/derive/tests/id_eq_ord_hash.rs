//! Basic tests for traits derived by [`IdEqOrdHash`] macro

use std::collections::BTreeSet;

use iroha_data_model_derive::IdEqOrdHash;

/// fake `Identifiable` trait
///
/// Doesn't require `Into<IdBox>` implementation
pub trait Identifiable: Ord + Eq {
    /// Type of the entity identifier
    type Id: Ord + Eq + core::hash::Hash;

    /// Get reference to the type identifier
    fn id(&self) -> &Self::Id;
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct ObjectId(char);

#[derive(Debug, IdEqOrdHash)]
struct Object {
    id: ObjectId,
    #[allow(unused)]
    data: i32,
}
#[derive(Debug, IdEqOrdHash)]
struct ObjectWithExplicitId {
    #[id]
    definitely_not_id: ObjectId,
    #[allow(unused)]
    data: i32,
}
#[derive(Debug, IdEqOrdHash)]
struct ObjectWithTransparentId {
    #[id(transparent)] // delegate the id to `Object` type
    definitely_not_id: Object,
    #[allow(unused)]
    data: i32,
}

// some objects to play with in tests
const ID_A: ObjectId = ObjectId('A');
const ID_B: ObjectId = ObjectId('B');
const OBJECT_1A: Object = Object { id: ID_A, data: 1 };
const OBJECT_1B: Object = Object { id: ID_B, data: 1 };
const OBJECT_2A: Object = Object { id: ID_A, data: 2 };
const EXPLICIT_OBJECT_1A: ObjectWithExplicitId = ObjectWithExplicitId {
    definitely_not_id: ID_A,
    data: 1,
};
const EXPLICIT_OBJECT_1B: ObjectWithExplicitId = ObjectWithExplicitId {
    definitely_not_id: ID_B,
    data: 1,
};
const EXPLICIT_OBJECT_2A: ObjectWithExplicitId = ObjectWithExplicitId {
    definitely_not_id: ID_A,
    data: 2,
};
const TRANSPARENT_OBJECT_1A: ObjectWithTransparentId = ObjectWithTransparentId {
    definitely_not_id: OBJECT_1A,
    data: 1,
};
const TRANSPARENT_OBJECT_1B: ObjectWithTransparentId = ObjectWithTransparentId {
    definitely_not_id: OBJECT_1B,
    data: 1,
};
const TRANSPARENT_OBJECT_2A: ObjectWithTransparentId = ObjectWithTransparentId {
    definitely_not_id: OBJECT_2A,
    data: 2,
};

#[test]
fn id() {
    assert_eq!(OBJECT_1A.id(), &ID_A);
    assert_eq!(OBJECT_1B.id(), &ID_B);
    assert_eq!(EXPLICIT_OBJECT_1A.id(), &ID_A);
    assert_eq!(EXPLICIT_OBJECT_1B.id(), &ID_B);
    assert_eq!(TRANSPARENT_OBJECT_1A.id(), &ID_A);
    assert_eq!(TRANSPARENT_OBJECT_1B.id(), &ID_B);
}

#[test]
fn id_eq() {
    assert_eq!(OBJECT_1A, OBJECT_2A);
    assert_ne!(OBJECT_1B, OBJECT_2A);
    assert_eq!(EXPLICIT_OBJECT_1A, EXPLICIT_OBJECT_2A);
    assert_ne!(EXPLICIT_OBJECT_1B, EXPLICIT_OBJECT_2A);
    assert_eq!(TRANSPARENT_OBJECT_1A, TRANSPARENT_OBJECT_2A);
    assert_ne!(TRANSPARENT_OBJECT_1B, TRANSPARENT_OBJECT_2A);
}

#[test]
fn id_ord() {
    assert!(OBJECT_1A < OBJECT_1B);
    assert!(OBJECT_1B > OBJECT_1A);
    assert!(EXPLICIT_OBJECT_1A < EXPLICIT_OBJECT_1B);
    assert!(EXPLICIT_OBJECT_1B > EXPLICIT_OBJECT_1A);
    assert!(TRANSPARENT_OBJECT_1A < TRANSPARENT_OBJECT_1B);
    assert!(TRANSPARENT_OBJECT_1B > TRANSPARENT_OBJECT_1A);
}

#[test]
fn id_hash() {
    let mut set = BTreeSet::new();
    set.insert(OBJECT_1A);
    set.insert(OBJECT_2A);
    assert_eq!(set.len(), 1);
    assert!(set.contains(&OBJECT_1A));
    assert!(!set.contains(&OBJECT_1B));
    assert!(set.contains(&OBJECT_2A));
    set.insert(OBJECT_1B);
    assert_eq!(set.len(), 2);
    assert!(set.contains(&OBJECT_1A));
    assert!(set.contains(&OBJECT_1B));
    assert!(set.contains(&OBJECT_2A));
}
