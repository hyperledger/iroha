//! Proxy crate for easy changing and substituting other crates' data structures

pub use hashmap::HashMap;
pub use hashset::HashSet;
pub use lockfree::queue::Queue;
pub use rwlock::RwLock;
pub use stack::Stack;

pub mod hashmap;
pub mod hashset;
pub mod rwlock;
pub mod stack;
