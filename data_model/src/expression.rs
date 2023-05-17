//! Expressions to use inside of ISIs.

#![allow(
    // Because of `codec(skip)`
    clippy::default_trait_access,
    // Because of length on instructions and expressions (can't be 0)
    clippy::len_without_is_empty,
    // Because of length on instructions and expressions (XXX: Should it be trait?)
    clippy::unused_self
)]

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections::btree_map, format, string::String, vec, vec::Vec};
use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::collections::btree_map;

use derive_more::{Constructor, DebugCustom, Display};
use getset::Getters;
use iroha_data_model_derive::{model, PartiallyTaggedDeserialize, PartiallyTaggedSerialize};
use iroha_macro::FromVariant;
use iroha_schema::{IntoSchema, TypeId};
use operation::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use super::{query::QueryBox, Name, Value};
use crate::NumericValue;

/// Generate expression structure and basic impls for it.
///
/// # Syntax
///
/// Basic syntax:
///
/// ```ignore
/// gen_expr_and_impls! {
///     /// Comment
///     #[derive(Derives)]
///     pub Expr(param1: Type1, param2: Type2, param3: Type3, ...) -> OutputType
/// }
/// ```
///
/// The macro has three syntax forms to specify parameters:
/// - One unnamed parameter. In that case, the parameter name will be `expression`.
/// - Two unnamed parameters.
///   In that case, the parameter names will be `left` and `right` respectively.
/// - Any number of named parameters.
///
/// The macro has two syntax forms to specify result:
/// - With the actual result type after the arrow (`->`).
///   In that case, `impl From<$i> for EvaluatesTo<$result_type>` will be generated.
/// - With `?` sign as a result type.
///   In that case `impl From<$i> for EvaluatesTo<$result_type>` **won't** be generated.
///
/// See the example and further usage for more details.
///
/// # Example
///
/// ```ignore
/// gen_expr_and_impls! {
///     /// Evaluates to the sum of left and right expressions.
///     #[derive(Debug)]
///     pub Add(u32, u32) -> u32
/// }
///
/// // Will generate the following code:
///
/// /// Evaluates to the sum of left and right expressions.
/// iroha_data_model_derive::model_single! {
///     #[derive(Debug)]
///     pub struct Add {
///         #[allow(missing_docs)]
///         pub left: EvaluatesTo<u32>,
///         #[allow(missing_docs)]
///         pub right: EvaluatesTo<u32>,
///     }
/// }
///
/// impl Add {
///     /// Construct new [`Add`] expression
///     pub fn new(left: impl Into<EvaluatesTo<u32>>, right: impl Into<EvaluatesTo<u32>>) -> Self {
///         Self {
///             left: left.into(),
///             right: right.into(),
///         }
///     }
/// }
///
/// impl From<Add> for EvaluatesTo<u32> {
///     fn from(expression: Add) -> Self {
///         EvaluatesTo::new_unchecked(expression)
///     }
/// }
/// ```
macro_rules! gen_expr_and_impls {
    // Case: one unnamed parameter
    ($(#[$me:meta])* $v:vis $i:ident($first_type:ty $(,)?) -> $($result:tt)*) => {
        gen_expr_and_impls!($(#[$me])* $v $i(expression: $first_type) -> $($result)*);
    };
    // Case: two unnamed parameters
    ($(#[$me:meta])* $v:vis $i:ident($first_type:ty, $second_type:ty $(,)?) -> $($result:tt)*) => {
        gen_expr_and_impls!($(#[$me])* $v $i(left: $first_type, right: $second_type) -> $($result)*);
    };
    // Case: any number of named parameters
    ($(#[$me:meta])* $v:vis $i:ident($($param_name:ident: $param_type:ty),* $(,)?) -> $($result:tt)*) => {
        gen_expr_and_impls!(impl_basic $(#[$me])* $v $i($($param_name: $param_type),*));
        gen_expr_and_impls!(impl_extra_convert $i $($result)*);
    };
    // Internal usage: generate basic code for the expression
    (impl_basic $(#[$me:meta])* $v:vis $i:ident($($param_name:ident: $param_type:ty),* $(,)?)) => {
        iroha_data_model_derive::model_single! {
            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema)]
            #[getset(get = "pub")]
            $(#[$me])*
            $v struct $i { $(
                ///
                #[allow(missing_docs)]
                pub $param_name: EvaluatesTo<$param_type>, )*
            }
        }

        impl $i {
            #[doc = concat!(" Construct new [`", stringify!($i), "`] expression")]
            pub fn new(
                $($param_name: impl Into<EvaluatesTo<$param_type>>),*
            ) -> Self {
                Self {
                    $($param_name: $param_name.into()),*
                }
            }
        }
    };
    // Internal usage: do nothing for expressions with unknown result type
    (impl_extra_convert $i:ident ?) => {
    };
    // Internal usage: generate extra `From` impl for expressions with known result type
    (impl_extra_convert $i:ident $result_type:ty) => {
        impl From<$i> for EvaluatesTo<$result_type> {
            fn from(expression: $i) -> Self {
                EvaluatesTo::new_unchecked(expression)
            }
        }
    };
}

#[model]
pub mod model {
    use super::*;

    /// Struct for type checking and converting expression results.
    #[derive(
        DebugCustom,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        TypeId,
    )]
    // As this structure exists only for type checking
    // it makes sense to display `expression` directly
    #[display(fmt = "{expression}")]
    #[debug(fmt = "{expression:?}")]
    #[serde(transparent)]
    #[repr(transparent)]
    // SAFETY: `EvaluatesTo` has no trap representation in `Box<Expression>`
    #[ffi_type(unsafe {robust})]
    pub struct EvaluatesTo<V> {
        /// Expression.
        #[serde(flatten)]
        pub expression: Box<Expression>,
        #[codec(skip)]
        pub(super) _value_type: PhantomData<V>,
    }

    /// Represents all possible expressions.
    #[derive(
        DebugCustom,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        Decode,
        Encode,
        PartiallyTaggedDeserialize,
        PartiallyTaggedSerialize,
        IntoSchema,
    )]
    #[ffi_type(opaque)]
    pub enum Expression {
        /// Add expression.
        Add(Add),
        /// Subtract expression.
        Subtract(Subtract),
        /// Multiply expression.
        Multiply(Multiply),
        /// Divide expression.
        Divide(Divide),
        /// Module expression.
        Mod(Mod),
        /// Raise to power expression.
        RaiseTo(RaiseTo),
        /// Greater expression.
        Greater(Greater),
        /// Less expression.
        Less(Less),
        /// Equal expression.
        Equal(Equal),
        /// Not expression.
        Not(Not),
        /// And expression.
        And(And),
        /// Or expression.
        Or(Or),
        /// If expression.
        If(If),
        /// Raw value.
        #[serde_partially_tagged(untagged)]
        #[debug(fmt = "{_0:?}")]
        Raw(#[skip_from] Value),
        /// Query to Iroha state.
        Query(QueryBox),
        /// Contains expression for vectors.
        Contains(Contains),
        /// Contains all expression for vectors.
        ContainsAll(ContainsAll),
        /// Contains any expression for vectors.
        ContainsAny(ContainsAny),
        /// Where expression to supply temporary values to local context.
        Where(Where),
        /// Get a temporary value by name
        ContextValue(ContextValue),
    }

    /// Get a temporary value by name. The values are brought into [`Context`] by [`Where`] expression.
    // NOTE: Can't use `gen_expr_and_impls!` here because we need special type for `value_name`
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Constructor,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[display(fmt = "CONTEXT `{value_name}`")]
    #[getset(get = "pub")]
    #[serde(transparent)]
    #[repr(transparent)]
    // SAFETY: `ContextValue` has no trap representation in `Name`
    #[ffi_type(unsafe {robust})]
    pub struct ContextValue {
        /// Name bound to the value.
        pub value_name: Name,
    }

    gen_expr_and_impls! {
        /// Evaluates to the multiplication of left and right expressions.
        #[derive(Display)]
        #[display(fmt = "{}*{}", // Keep without spaces
            "self.left.parenthesise(Operation::Multiply)",
            "self.right.parenthesise(Operation::Multiply)"
        )]
        #[ffi_type]
        pub Multiply(NumericValue, NumericValue) -> NumericValue
    }

    gen_expr_and_impls! {
        /// Evaluates to the left expression divided by the right expression.
        #[derive(Display)]
        #[display(fmt = "{}/{}", // Keep without spaces
            "self.left.parenthesise(Operation::Divide)",
            "self.right.parenthesise(Operation::Divide)"
        )]
        #[ffi_type]
        pub Divide(NumericValue, NumericValue) -> NumericValue
    }

    gen_expr_and_impls! {
        /// Evaluates to the left expression modulo the right expression.
        #[derive(Display)]
        #[display(fmt = "{} % {}",
            "self.left.parenthesise(Operation::Mod)",
            "self.right.parenthesise(Operation::Mod)"
        )]
        #[ffi_type]
        pub Mod(NumericValue, NumericValue) -> NumericValue
    }

    gen_expr_and_impls! {
        /// Evaluates to the left expression in the power of right expression.
        /// Currently does not support [`NumericValue::Fixed`].
        #[derive(Display)]
        #[display(fmt = "{}**{}",
            "self.left.parenthesise(Operation::RaiseTo)",
            "self.right.parenthesise(Operation::RaiseTo)"
        )]
        #[ffi_type]
        pub RaiseTo(NumericValue, NumericValue) -> NumericValue
    }

    gen_expr_and_impls! {
        /// Evaluates to the sum of left and right expressions.
        #[derive(Display)]
        #[display(fmt = "{}+{}",
            "self.left.parenthesise(Operation::Add)",
            "self.right.parenthesise(Operation::Add)"
        )]
        #[ffi_type]
        pub Add(NumericValue, NumericValue) -> NumericValue
    }

    gen_expr_and_impls! {
        /// Evaluates to the left expression minus the right expression.
        #[derive(Display)]
        #[display(fmt = "{}-{}",
            "self.left.parenthesise(Operation::Subtract)",
            "self.right.parenthesise(Operation::Subtract)"
        )]
        #[ffi_type]
        pub Subtract(NumericValue, NumericValue) -> NumericValue
    }

    gen_expr_and_impls! {
        /// Returns whether the `left` expression is greater than the `right`.
        #[derive(Display)]
        #[display(fmt = "{} > {}",
            "self.left.parenthesise(Operation::Greater)",
            "self.right.parenthesise(Operation::Greater)"
        )]
        #[ffi_type]
        pub Greater(NumericValue, NumericValue) -> bool
    }

    gen_expr_and_impls! {
        /// Returns whether the `left` expression is less than the `right`.
        #[derive(Display)]
        #[display(fmt = "{} < {}",
            "self.left.parenthesise(Operation::Less)",
            "self.right.parenthesise(Operation::Less)"
        )]
        #[ffi_type]
        pub Less(NumericValue, NumericValue) -> bool
    }

    gen_expr_and_impls! {
        /// Negates the result of the `expression`.
        /// Works only for `Value::Bool`.
        #[derive(Display)]
        #[display(fmt = "!{}", "self.expression.parenthesise(Operation::Not)")]
        #[serde(transparent)]
        #[repr(transparent)]
        // SAFETY: `Not` has no trap representation in `bool`
        #[ffi_type(unsafe {robust})]
        pub Not(bool) -> bool
    }

    gen_expr_and_impls! {
        /// Applies the logical `and` to two `Value::Bool` operands.
        #[derive(Display)]
        #[display(fmt = "{} && {}",
            "self.left.parenthesise(Operation::And)",
            "self.right.parenthesise(Operation::And)"
        )]
        #[ffi_type]
        pub And(bool, bool) -> bool
    }

    gen_expr_and_impls! {
        /// Applies the logical `or` to two `Value::Bool` operands.
        #[derive(Display)]
        #[display(fmt = "{} || {}",
            "self.left.parenthesise(Operation::Or)",
            "self.right.parenthesise(Operation::Or)"
        )]
        #[ffi_type]
        pub Or(bool, bool) -> bool
    }

    gen_expr_and_impls! {
        /// If expression. Based on the `condition`, returns the result of either `then` or `otherwise`.
        #[derive(Display)]
        #[display(fmt = "if {condition} {{ {then} }} else {{ {otherwise} }}")]
        #[ffi_type]
        pub If(condition: bool, then: Value, otherwise: Value) -> ?
    }

    gen_expr_and_impls! {
        /// `Contains` expression.
        /// Returns `true` if `collection` contains an `element`, `false` otherwise.
        #[derive(Display)]
        #[display(fmt = "{}.contains({})", "collection.parenthesise(Operation::MethodCall)", "element")]
        #[ffi_type]
        pub Contains(collection: Vec<Value>, element: Value) -> bool
    }

    gen_expr_and_impls! {
        /// `ContainsAll` expression.
        /// Returns `true` if `collection` contains all `elements`, `false` otherwise.
        #[derive(Display)]
        #[display(fmt = "{}.contains_all({})", "collection.parenthesise(Operation::MethodCall)", "elements")]
        #[ffi_type]
        pub ContainsAll(collection: Vec<Value>, elements: Vec<Value>) -> bool
    }

    gen_expr_and_impls! {
        /// `ContainsAny` expression.
        /// Returns `true` if `collection` contains any element out of the `elements`, `false` otherwise.
        #[derive(Display)]
        #[display(fmt = "{}.contains_any({})", "collection.parenthesise(Operation::MethodCall)", "elements")]
        #[ffi_type]
        pub ContainsAny(collection: Vec<Value>, elements: Vec<Value>) -> bool
    }

    gen_expr_and_impls! {
        /// Returns `true` if `left` operand is equal to the `right` operand.
        #[derive(Display)]
        #[display(fmt = "{} == {}",
            "self.left.parenthesise(Operation::Equal)",
            "self.right.parenthesise(Operation::Equal)"
        )]
        #[ffi_type]
        pub Equal(Value, Value) -> bool
    }

    /// Adds a local context of `values` for the `expression`.
    /// It is similar to **where** syntax in *Haskell* although evaluated eagerly.
    // NOTE: Can't use `gen_expr_and_impls!` here because we need special type for `values`
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type]
    pub struct Where {
        /// Expression to be evaluated.
        #[getset(get = "pub")]
        pub expression: EvaluatesTo<Value>,
        /// Context values for the context bonded to their `String` names.
        pub values: btree_map::BTreeMap<Name, EvaluatesTo<Value>>,
    }
}

impl<V: Into<Value>> From<V> for Expression {
    fn from(value: V) -> Self {
        Self::Raw(value.into())
    }
}

impl<V: TryFrom<Value>, E: Into<Expression> + Into<V>> From<E> for EvaluatesTo<V> {
    fn from(expression: E) -> Self {
        Self::new_unchecked(expression)
    }
}

impl<V> EvaluatesTo<V> {
    /// Expression
    #[inline]
    // NOTE: getset would return &Box<Expression>
    pub fn expression(&self) -> &Expression {
        &self.expression
    }

    /// Construct new [`EvaluatesTo`] from [`Expression`] without type checking.
    ///
    /// # Warning
    /// Prefer using [`Into`] conversions rather than this method,
    /// because it does not check the value type at compile-time.
    #[inline]
    pub fn new_unchecked(expression: impl Into<Expression>) -> Self {
        Self {
            expression: Box::new(expression.into()),
            _value_type: PhantomData::default(),
        }
    }

    fn operation(&self) -> Operation {
        use Expression::*;

        match self.expression.as_ref() {
            Add(_) => Operation::Add,
            Subtract(_) => Operation::Subtract,
            Multiply(_) => Operation::Multiply,
            Divide(_) => Operation::Divide,
            Mod(_) => Operation::Mod,
            RaiseTo(_) => Operation::RaiseTo,
            Greater(_) => Operation::Greater,
            Less(_) => Operation::Less,
            Equal(_) => Operation::Equal,
            Not(_) => Operation::Not,
            And(_) => Operation::And,
            Or(_) => Operation::Or,
            Contains(_) | ContainsAll(_) | ContainsAny(_) => Operation::MethodCall,
            If(_) | Raw(_) | Query(_) | Where(_) | ContextValue(_) => Operation::Other,
        }
    }

    /// Wrap expression into parentheses depending on `operation` and get the resulting string.
    fn parenthesise(&self, operation: Operation) -> String {
        if self.operation().priority() < operation.priority()
            && !matches!(self.expression.as_ref(), Expression::Raw(_))
        {
            format!("({})", self.expression)
        } else {
            format!("{}", self.expression)
        }
    }
}

impl EvaluatesTo<Value> {
    /// Construct `EvaluatesTo<Value>` from any `expression`
    /// because all of them evaluate to [`Value`].
    #[inline]
    pub fn new_evaluates_to_value(expression: impl Into<Expression>) -> Self {
        Self::new_unchecked(expression)
    }
}

impl<V: TryFrom<Value> + IntoSchema> IntoSchema for EvaluatesTo<V> {
    fn type_name() -> String {
        format!("EvaluatesTo<{}>", V::type_name())
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        const EXPRESSION: &str = "expression";

        if !map.contains_key::<Self>() {
            map.insert::<Self>(iroha_schema::Metadata::Struct(
                iroha_schema::NamedFieldsMeta {
                    declarations: vec![iroha_schema::Declaration {
                        name: String::from(EXPRESSION),
                        ty: core::any::TypeId::of::<Expression>(),
                    }],
                },
            ));

            Expression::update_schema_map(map);
        }
    }
}

impl core::fmt::Display for Where {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "`{} where: [", self.expression)?;

        let mut first = true;
        for (key, value) in &self.values {
            if !first {
                write!(f, ", ")?;
            }
            first = false;
            write!(f, "`{key}` : `{value}`")?;
        }

        write!(f, "]")
    }
}

impl Where {
    /// Construct [`Where`] expression
    #[must_use]
    pub fn new(expression: impl Into<EvaluatesTo<Value>>) -> Self {
        Self {
            expression: expression.into(),
            values: Default::default(),
        }
    }

    /// Get an iterator over the values of [`Where`] clause
    #[inline]
    pub fn values(&self) -> impl ExactSizeIterator<Item = (&Name, &EvaluatesTo<Value>)> {
        self.values.iter()
    }

    /// Binds `expression` result to a `value_name`, by which it will be reachable from the main expression.
    #[must_use]
    pub fn with_value<E: Into<EvaluatesTo<Value>>>(
        mut self,
        value_name: Name,
        expression: E,
    ) -> Self {
        self.values.insert(value_name, expression.into());
        self
    }
}

mod operation {
    //! Module containing operations and their priorities.

    /// Type of expression operation.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Operation {
        MethodCall,
        RaiseTo,
        Multiply,
        Divide,
        Mod,
        Add,
        Subtract,
        Greater,
        Less,
        Equal,
        Not,
        And,
        Or,
        Other,
    }

    /// Priority of operation.
    ///
    /// [`First`](Operation::First) is the highest priority
    /// and [`Ninth`](Operation::Ninth) is the lowest.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Priority {
        First = 1,
        Second = 2,
        Third = 3,
        Fourth = 4,
        Fifth = 5,
        Sixth = 6,
        Seventh = 7,
        Eighth = 8,
        Ninth = 9,
    }

    impl Operation {
        /// Get the priority of the operation.
        ///
        /// Ordering is the same as in Python code.
        /// See [`here`](https://docs.python.org/3/reference/expressions.html#operator-precedence)
        /// for more details.
        pub fn priority(self) -> Priority {
            use Operation::*;

            match self {
                MethodCall => Priority::First,
                RaiseTo => Priority::Second,
                Multiply | Divide | Mod => Priority::Third,
                Add | Subtract => Priority::Fourth,
                Greater | Less | Equal => Priority::Fifth,
                Not => Priority::Sixth,
                And => Priority::Seventh,
                Or => Priority::Eighth,
                Other => Priority::Ninth,
            }
        }
    }

    impl PartialOrd for Priority {
        #[inline]
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for Priority {
        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            use core::cmp::Ordering::*;

            let lhs = *self as u8;
            let rhs = *other as u8;

            match lhs.cmp(&rhs) {
                Less => Greater,
                Equal => Equal,
                Greater => Less,
            }
        }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        Add, And, Contains, ContainsAll, ContainsAny, ContextValue, Divide, Equal, EvaluatesTo,
        Expression, Greater, If, Less, Mod, Multiply, Not, Or, RaiseTo, Subtract, Where,
    };
}
