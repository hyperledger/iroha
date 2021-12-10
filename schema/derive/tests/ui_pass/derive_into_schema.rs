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

pub fn main() {}
