struct Variant1;
struct Variant2;

#[derive(iroha_derive::FromVariant)]
enum Enum {
    #[skip_from]
    Variant1(Variant1),
    Variant2(Variant2),
}

fn main() {}
