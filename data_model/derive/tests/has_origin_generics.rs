use iroha_data_model::prelude::{HasOrigin, Identifiable};
use iroha_data_model_derive::{HasOrigin, IdEqOrdHash};

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct ObjectId(pub i32);

// fake impl for `#[derive(IdEqOrdHash)]`
impl From<ObjectId> for iroha_data_model::IdBox {
    fn from(_: ObjectId) -> Self {
        unimplemented!("fake impl")
    }
}

#[derive(Debug, IdEqOrdHash)]
struct Object {
    id: ObjectId,
}

impl Object {
    fn id(&self) -> &ObjectId {
        &self.id
    }
}

#[allow(clippy::enum_variant_names)] // it's a test, duh
#[derive(Debug, HasOrigin)]
#[has_origin(origin = Object)]
enum ObjectEvent<T: Identifiable<Id = ObjectId>> {
    EventWithId(ObjectId),
    #[has_origin(event => &event.0)]
    EventWithExtractor((ObjectId, i32)),
    #[has_origin(obj => obj.id())]
    EventWithAnotherExtractor(T),
}

#[test]
fn has_origin() {
    let events = vec![
        ObjectEvent::EventWithId(ObjectId(1)),
        ObjectEvent::EventWithExtractor((ObjectId(2), 2)),
        ObjectEvent::EventWithAnotherExtractor(Object { id: ObjectId(3) }),
    ];
    let expected_ids = vec![ObjectId(1), ObjectId(2), ObjectId(3)];

    for (event, expected_id) in events.into_iter().zip(expected_ids) {
        assert_eq!(
            event.origin_id(),
            &expected_id,
            "mismatched origin id for event {event:?}",
        );
    }
}
