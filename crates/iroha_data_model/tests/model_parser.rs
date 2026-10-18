//! Tests for model parser module
use crate::support;
#[test]
fn parse_model_module_extracts_public_items() {
    let src = r"
        #[model]
        mod model {
            pub struct Foo;
            pub enum Bar {}
            pub union Baz {}
            pub type Alias = u32;
            pub const CONST: u32 = 0;
            pub fn function() {}
            pub trait Trait {}
            pub mod ignored {}
        }
    ";
    let mut names = support::parse_model_module(src);
    names.sort();
    assert_eq!(
        names,
        vec!["Alias", "Bar", "Baz", "CONST", "Foo", "Trait", "function",]
    );
}
