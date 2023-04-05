use iroha_schema::IntoSchema;

#[derive(IntoSchema)]
enum EnumWithExplicitDiscriminant {
    A = 1,
    B,
    C,
    D,
}

fn main() {}
