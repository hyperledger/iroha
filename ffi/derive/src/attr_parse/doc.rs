use darling::FromAttributes;
use syn2::Attribute;

pub struct DocAttrs {
    pub attrs: Vec<Attribute>,
}

impl FromAttributes for DocAttrs {
    fn from_attributes(attrs: &[Attribute]) -> darling::Result<Self> {
        let mut docs = Vec::new();
        for attr in attrs {
            if attr.path().is_ident("doc") {
                docs.push(attr.clone());
            }
        }
        Ok(DocAttrs { attrs: docs })
    }
}
