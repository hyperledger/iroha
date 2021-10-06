struct Variant1;
struct Variant2;
struct Variant3;
struct Variant4;
struct Variant5;
struct Variant6;
struct Variant7;
struct Variant8;
struct Variant9;

#[derive(iroha_derive::FromVariant)]
enum Enum {
    Variant1(Variant1),
    Variant2(Variant2),
    Variant3(Variant3),
    Variant4(Variant4),
    Variant5(Variant5),
    Variant6(Variant6),
    Variant7(Variant7),
    Variant8(Variant8),
    Variant9(Variant9),
}

fn main() {}
