#![deny(unused_must_use)]

use iroha_primitives::must_use::MustUse;

fn main() {
    MustUse::new(5);
}
