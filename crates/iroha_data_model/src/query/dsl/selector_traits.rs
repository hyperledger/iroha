#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use crate::{
    prelude::SelectorTuple,
    query::dsl::{HasProjection, SelectorMarker},
};

pub trait IntoSelector {
    type SelectingType: HasProjection<SelectorMarker, AtomType = ()>;
    type SelectedType;
    fn into_selector(self) -> <Self::SelectingType as HasProjection<SelectorMarker>>::Projection;
}

pub trait IntoSelectorTuple {
    type SelectingType: HasProjection<SelectorMarker, AtomType = ()>;
    type SelectedTuple;
    fn into_selector_tuple(self) -> SelectorTuple<Self::SelectingType>;
}

impl<T: IntoSelector> IntoSelectorTuple for T {
    type SelectingType = T::SelectingType;
    type SelectedTuple = T::SelectedType;

    fn into_selector_tuple(self) -> SelectorTuple<Self::SelectingType> {
        SelectorTuple::new(vec![self.into_selector()])
    }
}

impl<T1: IntoSelector> IntoSelectorTuple for (T1,) {
    type SelectingType = T1::SelectingType;
    type SelectedTuple = (T1::SelectedType,);

    fn into_selector_tuple(self) -> SelectorTuple<Self::SelectingType> {
        SelectorTuple::new(vec![self.0.into_selector()])
    }
}

macro_rules! impl_into_selector_tuple {
    ($t1_name:ident, $($t_name:ident),*) => {
        impl<$t1_name: IntoSelector, $($t_name: IntoSelector<SelectingType = T1::SelectingType>),*> IntoSelectorTuple for ($t1_name, $($t_name),*)
        {
            type SelectingType = $t1_name::SelectingType;
            type SelectedTuple = ($t1_name::SelectedType, $($t_name::SelectedType),*);

            #[allow(non_snake_case)] // we re-use the type names as variable names to not require the user to come up with new ones in the macro invocation
            fn into_selector_tuple(self) -> SelectorTuple<Self::SelectingType> {
                let ($t1_name, $($t_name),*) = self;
                SelectorTuple::new(vec![
                    $t1_name.into_selector(),
                    $($t_name.into_selector(),)*
                ])
            }
        }
    };
}
impl_into_selector_tuple!(T1, T2);
impl_into_selector_tuple!(T1, T2, T3);
impl_into_selector_tuple!(T1, T2, T3, T4);
impl_into_selector_tuple!(T1, T2, T3, T4, T5);
impl_into_selector_tuple!(T1, T2, T3, T4, T5, T6);
impl_into_selector_tuple!(T1, T2, T3, T4, T5, T6, T7);
impl_into_selector_tuple!(T1, T2, T3, T4, T5, T6, T7, T8);
