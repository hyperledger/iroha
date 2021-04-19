//! Proxy crate for easy changing and substituting other crates' data structures

pub use hashmap::HashMap;
pub use hashset::HashSet;
pub use rwlock::RwLock;

pub mod hashmap;
pub mod hashset;
pub mod rwlock;
