#![allow(unused)]
use std::{fmt::Debug, ops::Deref};

#[derive(iroha_derive::VariantCount)]
enum Simple {
    Unit,
    Tuple(u32),
    Struct { a: u32, b: u32 },
}

#[derive(iroha_derive::VariantCount)]
enum Empty {}

#[derive(iroha_derive::VariantCount)]
enum Generic<T1: Copy + Debug, T2>
where
    T2: ?Sized + Clone + Deref<Target = T1>,
{
    Unit,
    TupleA(Box<T1>),
    TupleB(T2),
    Struct { a: T1, b: T2 },
}

const _: () = {
    if Simple::VARIANT_COUNT != 3
        || Empty::VARIANT_COUNT != 0
        || Generic::<(), &()>::VARIANT_COUNT != 4
    {
        panic!("Derived wrong variant count")
    }
};

fn main() {}
