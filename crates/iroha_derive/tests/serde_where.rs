use iroha_derive::serde_where;
use serde::{Deserialize, Serialize};

trait Trait {
    type Assoc;
}

#[serde_where(T::Assoc)]
#[derive(Serialize, Deserialize)]
struct Type<T: Trait> {
    field: T::Assoc,
}
