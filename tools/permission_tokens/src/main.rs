use std::collections::HashMap;

use iroha_permissions_validators::public_blockchain::DefaultPermissionToken;
use iroha_schema::{IntoSchema, Metadata};

#[allow(clippy::print_stdout, clippy::expect_used, clippy::panic)]
fn main() {
    let mut schema = DefaultPermissionToken::get_schema();

    let enum_variants = match schema
        .remove("iroha_permissions_validators::public_blockchain::DefaultPermissionToken")
        .expect("Token enum not in schema")
    {
        Metadata::Enum(meta) => meta.variants,
        _ => panic!("Expected enum"),
    };

    let token_map = enum_variants
        .into_iter()
        .map(|variant| {
            let ty = variant.ty.expect("Empty enum variant");
            let fields = match schema.remove(&ty).expect("Token not in schema") {
                Metadata::Struct(meta) => meta
                    .declarations
                    .into_iter()
                    .map(|decl| (decl.name, decl.ty))
                    .collect::<HashMap<_, _>>(),
                _ => panic!("Token is not a struct"),
            };
            (ty, fields)
        })
        .collect::<HashMap<_, _>>();

    println!(
        "{}",
        serde_json::to_string_pretty(&token_map).expect("Serialization error")
    );
}
