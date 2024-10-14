use iroha_schema::IntoSchema;

#[derive(IntoSchema)]
pub struct Foo1<T> {
    _value1: T,
}

#[derive(IntoSchema)]
pub struct Foo2<T, K> {
    _value1: T,
    _value2: K,
}

#[derive(IntoSchema)]
pub struct Foo3<T: Clone> {
    _value1: T,
}

#[derive(IntoSchema)]
pub struct Foo4<T: iroha_schema::IntoSchema> {
    _value1: T,
}

#[derive(IntoSchema)]
pub struct Foo5<T: IntoSchema> {
    _value1: T,
}

#[derive(IntoSchema)]
#[schema(transparent)]
pub struct AutoTransparent(u32);

#[derive(IntoSchema)]
#[schema(transparent = "String")]
pub struct FakeString {}

#[derive(IntoSchema)]
pub enum Enum {
    Zero,
    One,
    #[codec(index = 42)]
    FortyTwo,
}

pub trait Trait {
    type Assoc;
}

#[derive(IntoSchema)]
pub struct WithComplexGeneric<T: Trait> {
    _value: T::Assoc,
}

pub fn main() {}
