//! A smoke-test for the `derive(Filter)`

use iroha_data_model::{
    prelude::{HasOrigin, Identifiable},
    IdBox,
};
use iroha_data_model_derive::{Filter, IdEqOrdHash};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

// These are dummy types for the FilterDerive to work
// They would not work with `feature = transparent_api`, but are enough for the smoke test
mod prelude {
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encode, Decode, IntoSchema)]
    pub struct FilterOpt<T>(T);

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encode, Decode, IntoSchema)]
    pub struct OriginFilter<T>(T);

    pub use super::LayerEvent;
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    IntoSchema,
)]
pub struct SubLayerEvent;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encode, Decode, IntoSchema)]
pub struct SubLayerFilter;

#[derive(
    Copy,
    Clone,
    IntoSchema,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    Decode,
    Encode,
    Debug,
    Hash,
)]
pub struct LayerId {
    name: u32,
}

impl HasOrigin for LayerEvent {
    type Origin = Layer;

    fn origin_id(&self) -> &<Self::Origin as Identifiable>::Id {
        todo!()
    }
}

#[derive(Debug, IdEqOrdHash)]
pub struct Layer {
    id: LayerId,
}

impl From<LayerId> for IdBox {
    fn from(_: LayerId) -> Self {
        unreachable!()
    }
}

/// The tested type
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    IntoSchema,
    Filter,
)]
pub enum LayerEvent {
    SubLayer(SubLayerEvent),
    Created(LayerId),
}

#[test]
fn filter() {
    // nothing much to test here...
    // I guess we do test that it compiles
}
