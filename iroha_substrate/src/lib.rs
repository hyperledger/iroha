#![warn(
    missing_docs,
    private_doc_tests,
    clippy::all,
    clippy::pedantic,
    clippy::nursery
)]
#![allow(
    clippy::use_self,
    clippy::implicit_return,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::enum_glob_use,
    clippy::wildcard_imports
)]
//! Bridge substrate `XClaim` external module.

#[cfg(test)]
mod tests {
    #[test]
    #[allow(clippy::eq_op)]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
