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

use derive_more::Display;
use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use operation::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::{query::QueryBox, Value, ValueBox};

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
/// #[derive(Debug)]
/// pub struct Add {
///     #[allow(missing_docs)]
///     pub left: EvaluatesTo<u32>,
///     #[allow(missing_docs)]
///     pub right: EvaluatesTo<u32>,
/// }
///
/// impl Add {
///     /// Number of underneath expressions
///     #[inline]
///     pub fn len(&self) -> usize {
///         self.left.len() + self.right.len() + 1
///     }
///     /// Construct new [`Add`] expression
///     pub fn new(left: impl Into<EvaluatesTo<u32>>, right: impl Into<EvaluatesTo<u32>>) -> Self {
///         Self {
///             left: left.into(),
///             right: right.into(),
///         }
///     }
/// }
///
/// impl From<Add> for ExpressionBox {
///     fn from(expression: Add) -> Self {
///         Expression::Add(expression).into()
///     }
/// }
///
/// impl From<Add> for EvaluatesTo<u32> {
///     fn from(expression: Add) -> Self {
///         EvaluatesTo::new_unchecked(expression.into())
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
        $(#[$me])*
        $v struct $i {
            $(
                #[allow(missing_docs)]
                pub $param_name: EvaluatesTo<$param_type>,
            )*
        }

        impl $i {
            /// Number of underneath expressions.
            #[inline]
            pub fn len(&self) -> usize {
                $(self.$param_name.len() +)* 1
            }

            #[doc = concat!(" Construct new [`", stringify!($i), "`] expression")]
            pub fn new(
                $($param_name: impl Into<EvaluatesTo<$param_type>>),*
            ) -> Self {
                Self {
                    $($param_name: $param_name.into()),*
                }
            }
        }

        impl From<$i> for ExpressionBox {
            fn from(expression: $i) -> Self {
                Expression::$i(expression).into()
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
                EvaluatesTo::new_unchecked(expression.into())
            }
        }
    };
}

/// Bound name for a value.
pub type ValueName = String;

/// Context, composed of (name, value) pairs.
pub type Context = btree_map::BTreeMap<ValueName, Value>;

/// Boxed expression.
pub type ExpressionBox = Box<Expression>;

/// Struct for type checking and converting expression results.
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, PartialOrd, Ord,
)]
#[serde(transparent)]
// As this structure exists only for type checking
// it makes sense to display `expression` directly
#[display(fmt = "{}", expression)]
pub struct EvaluatesTo<V: TryFrom<Value>> {
    /// Expression.
    #[serde(flatten)]
    pub expression: ExpressionBox,
    #[codec(skip)]
    _value_type: PhantomData<V>,
}

impl<V: TryFrom<Value>, E: Into<ExpressionBox> + Into<V>> From<E> for EvaluatesTo<V> {
    fn from(expression: E) -> Self {
        Self::new_unchecked(expression.into())
    }
}

impl<V: TryFrom<Value>> EvaluatesTo<V> {
    /// Number of underneath expressions.
    #[inline]
    pub fn len(&self) -> usize {
        self.expression.len()
    }

    /// Construct new [`EvaluatesTo`] from [`ExpressionBox`] without type checking.
    ///
    /// # Warning
    /// Prefer using [`Into`] conversions rather than this method,
    /// because it does not check the value type at compile-time.
    #[inline]
    pub fn new_unchecked(expression: ExpressionBox) -> Self {
        Self {
            expression,
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
    ///
    /// # Panics
    /// - If `operation` has [`Other`](Operation::Other) value.
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
    pub fn new_evaluates_to_value(expression: ExpressionBox) -> Self {
        Self::new_unchecked(expression)
    }
}

impl<V: IntoSchema + TryFrom<Value>> IntoSchema for EvaluatesTo<V> {
    fn type_name() -> String {
        format!("{}::EvaluatesTo<{}>", module_path!(), V::type_name())
    }

    fn schema(map: &mut MetaMap) {
        ExpressionBox::schema(map);

        map.entry(Self::type_name()).or_insert_with(|| {
            const EXPRESSION: &str = "expression";

            Metadata::Struct(NamedFieldsMeta {
                declarations: vec![Declaration {
                    name: String::from(EXPRESSION),
                    ty: ExpressionBox::type_name(),
                }],
            })
        });
    }
}

mod operation {
    //! Module containing operations and their priorities.

    /// Type of expression operation.
    #[derive(Copy, Clone, PartialEq, Eq)]
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
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

/// Represents all possible expressions.
#[derive(
    Debug,
    Display,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FromVariant,
    IntoSchema,
    PartialOrd,
    Ord,
)]
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
    Raw(ValueBox),
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

impl Expression {
    /// Number of underneath expressions.
    #[inline]
    pub fn len(&self) -> usize {
        use Expression::*;

        match self {
            Add(add) => add.len(),
            Subtract(subtract) => subtract.len(),
            Greater(greater) => greater.len(),
            Less(less) => less.len(),
            Equal(equal) => equal.len(),
            Not(not) => not.len(),
            And(and) => and.len(),
            Or(or) => or.len(),
            If(if_expression) => if_expression.len(),
            Raw(raw) => raw.len(),
            Query(query) => query.len(),
            Contains(contains) => contains.len(),
            ContainsAll(contains_all) => contains_all.len(),
            ContainsAny(contains_any) => contains_any.len(),
            Where(where_expression) => where_expression.len(),
            ContextValue(context_value) => context_value.len(),
            Multiply(multiply) => multiply.len(),
            Divide(divide) => divide.len(),
            Mod(modulus) => modulus.len(),
            RaiseTo(raise_to) => raise_to.len(),
        }
    }
}

impl<T: Into<Value>> From<T> for ExpressionBox {
    fn from(value: T) -> Self {
        Expression::Raw(Box::new(value.into())).into()
    }
}

/// Get a temporary value by name.
/// The values are brought into [`Context`] by [`Where`] expression.
//
// Can't use `gen_expr_and_impls!` here because we need special type for `value_name`
#[derive(
    Debug,
    Display,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
    PartialOrd,
    Ord,
)]
#[display(fmt = "CONTEXT `{}`", value_name)]
pub struct ContextValue {
    /// Name bound to the value.
    pub value_name: String,
}

impl ContextValue {
    /// Number of underneath expressions.
    #[inline]
    pub const fn len(&self) -> usize {
        1
    }

    /// Constructs `ContextValue`.
    #[inline]
    pub fn new(value_name: &str) -> Self {
        Self {
            value_name: String::from(value_name),
        }
    }
}

impl From<ContextValue> for ExpressionBox {
    #[inline]
    fn from(expression: ContextValue) -> Self {
        Expression::ContextValue(expression).into()
    }
}

gen_expr_and_impls! {
    /// Evaluates to the multiplication of left and right expressions.
    /// Works only for [`Value::U32`]
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
    fmt = "{}*{}", // Keep without spaces
        "self.left.parenthesise(Operation::Multiply)",
        "self.right.parenthesise(Operation::Multiply)"
    )]
    pub Multiply(u32, u32) -> u32
}

gen_expr_and_impls! {
    /// Evaluates to the left expression divided by the right expression.
    /// Works only for [`Value::U32`]
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "{}/{}", // Keep without spaces
        "self.left.parenthesise(Operation::Divide)",
        "self.right.parenthesise(Operation::Divide)"
    )]
    pub Divide(u32, u32) -> u32
}

gen_expr_and_impls! {
    /// Evaluates to the left expression modulo the right expression.
    /// Works only for [`Value::U32`]
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "{} % {}",
        "self.left.parenthesise(Operation::Mod)",
        "self.right.parenthesise(Operation::Mod)"
    )]
    pub Mod(u32, u32) -> u32
}

gen_expr_and_impls! {
    /// Evaluates to the left expression in the power of right expression.
    /// Works only for [`Value::U32`]
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "{}**{}",
        "self.left.parenthesise(Operation::RaiseTo)",
        "self.right.parenthesise(Operation::RaiseTo)"
    )]
    pub RaiseTo(u32, u32) -> u32
}

gen_expr_and_impls! {
    /// Evaluates to the sum of left and right expressions.
    /// Works only for [`Value::U32`]
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "{}+{}",
        "self.left.parenthesise(Operation::Add)",
        "self.right.parenthesise(Operation::Add)"
    )]
    pub Add(u32, u32) -> u32
}

gen_expr_and_impls! {
    /// Evaluates to the left expression minus the right expression.
    /// Works only for [`Value::U32`]
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "{}-{}",
        "self.left.parenthesise(Operation::Subtract)",
        "self.right.parenthesise(Operation::Subtract)"
    )]
    pub Subtract(u32, u32) -> u32
}

gen_expr_and_impls! {
    /// Returns whether the `left` expression is greater than the `right`.
    /// Works only for [`Value::U32`].
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "{} > {}",
        "self.left.parenthesise(Operation::Greater)",
        "self.right.parenthesise(Operation::Greater)"
    )]
    pub Greater(u32, u32) -> bool
}

gen_expr_and_impls! {
    /// Returns whether the `left` expression is less than the `right`.
    /// Works only for [`Value::U32`].
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "{} < {}",
        "self.left.parenthesise(Operation::Less)",
        "self.right.parenthesise(Operation::Less)"
    )]
    pub Less(u32, u32) -> bool
}

gen_expr_and_impls! {
    /// Negates the result of the `expression`.
    /// Works only for `Value::Bool`.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(fmt = "!{}", "self.expression.parenthesise(Operation::Not)")]
    pub Not(bool) -> bool
}

gen_expr_and_impls! {
    /// Applies the logical `and` to two `Value::Bool` operands.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "{} && {}",
        "self.left.parenthesise(Operation::And)",
        "self.right.parenthesise(Operation::And)"
    )]
    pub And(bool, bool) -> bool
}

gen_expr_and_impls! {
    /// Applies the logical `or` to two `Value::Bool` operands.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "{} || {}",
        "self.left.parenthesise(Operation::Or)",
        "self.right.parenthesise(Operation::Or)"
    )]
    pub Or(bool, bool) -> bool
}

/// Builder for [`If`] expression.
#[derive(Debug)]
#[must_use = ".build() not used"]
pub struct IfBuilder {
    /// Condition expression, which should evaluate to `Value::Bool`.
    /// If it is `true`, then the evaluated `then_expression` is returned.
    /// Otherwise, the evaluated `else_expression` is returned.
    pub condition: EvaluatesTo<bool>,
    /// Expression evaluated and returned if the condition is `true`.
    pub then_expression: Option<EvaluatesTo<Value>>,
    /// Expression evaluated and returned if the condition is `false`.
    pub else_expression: Option<EvaluatesTo<Value>>,
}

impl IfBuilder {
    /// Sets the `condition`.
    pub fn condition<C: Into<EvaluatesTo<bool>>>(condition: C) -> Self {
        IfBuilder {
            condition: condition.into(),
            then_expression: None,
            else_expression: None,
        }
    }

    /// Sets `then_expression`.
    pub fn then_expression<E: Into<EvaluatesTo<Value>>>(self, expression: E) -> Self {
        IfBuilder {
            then_expression: Some(expression.into()),
            ..self
        }
    }

    /// Sets `else_expression`.
    pub fn else_expression<E: Into<EvaluatesTo<Value>>>(self, expression: E) -> Self {
        IfBuilder {
            else_expression: Some(expression.into()),
            ..self
        }
    }

    /// Returns [`If`] expression if all the fields are filled.
    ///
    /// # Errors
    ///
    /// Fails if some of the fields are not filled.
    pub fn build(self) -> Result<If, &'static str> {
        if let (Some(then_expression), Some(else_expression)) =
            (self.then_expression, self.else_expression)
        {
            return Ok(If::new(self.condition, then_expression, else_expression));
        }

        Err("Not all fields filled")
    }
}

gen_expr_and_impls! {
    /// If expression. Based on the `condition`, returns the result of
    /// either `then_expression`  or `else_expression`.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "if {} {{ {} }} else {{ {} }}",
        condition,
        then_expression,
        else_expression
    )]
    pub If(condition: bool, then_expression: Value, else_expression: Value) -> ?
}

gen_expr_and_impls! {
    /// `Contains` expression.
    /// Returns `true` if `collection` contains an `element`, `false` otherwise.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "{}.contains({})",
        "collection.parenthesise(Operation::MethodCall)",
        "element"
    )]
    pub Contains(collection: Vec<Value>, element: Value) -> bool
}

gen_expr_and_impls! {
    /// `ContainsAll` expression.
    /// Returns `true` if `collection` contains all `elements`, `false` otherwise.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "{}.contains_all({})",
        "collection.parenthesise(Operation::MethodCall)",
        "elements"
    )]

    pub ContainsAll(collection: Vec<Value>, elements: Vec<Value>) -> bool
}

gen_expr_and_impls! {
    /// `ContainsAny` expression.
    /// Returns `true` if `collection` contains any element out of the `elements`, `false` otherwise.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "{}.contains_any({})",
        "collection.parenthesise(Operation::MethodCall)",
        "elements"
    )]
    pub ContainsAny(collection: Vec<Value>, elements: Vec<Value>) -> bool
}

gen_expr_and_impls! {
    /// Returns `true` if `left` operand is equal to the `right` operand.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        PartialOrd,
        Ord,
    )]
    #[display(
        fmt = "{} == {}",
        "self.left.parenthesise(Operation::Equal)",
        "self.right.parenthesise(Operation::Equal)"
    )]
    pub Equal(Value, Value) -> bool
}

/// [`Where`] builder.
#[derive(Debug)]
pub struct WhereBuilder {
    /// Expression to be evaluated.
    expression: EvaluatesTo<Value>,
    /// Context values for the context binded to their `String` names.
    values: btree_map::BTreeMap<ValueName, EvaluatesTo<Value>>,
}

impl WhereBuilder {
    /// Sets the `expression` to be evaluated.
    #[must_use]
    pub fn evaluate<E: Into<EvaluatesTo<Value>>>(expression: E) -> Self {
        Self {
            expression: expression.into(),
            values: btree_map::BTreeMap::new(),
        }
    }

    /// Binds `expression` result to a `value_name`, by which it will be reachable from the main expression.
    #[must_use]
    pub fn with_value<E: Into<EvaluatesTo<Value>>>(
        mut self,
        value_name: ValueName,
        expression: E,
    ) -> Self {
        let _result = self.values.insert(value_name, expression.into());
        self
    }

    /// Returns a [`Where`] expression.
    #[inline]
    #[must_use]
    pub fn build(self) -> Where {
        Where::new(self.expression, self.values)
    }
}

/// Adds a local context of `values` for the `expression`.
/// It is similar to **where** syntax in *Haskell* although evaluated eagerly.
//
// Can't use `gen_expr_and_impls!` here because we need special type for `values`
#[derive(
    Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema, PartialOrd, Ord,
)]
pub struct Where {
    /// Expression to be evaluated.
    pub expression: EvaluatesTo<Value>,
    /// Context values for the context bonded to their `String` names.
    pub values: btree_map::BTreeMap<ValueName, EvaluatesTo<Value>>,
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
            write!(f, "`{}` : `{}`", key, value)?;
        }

        write!(f, "]")
    }
}

impl Where {
    /// Number of underneath expressions.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.expression.len() + self.values.values().map(EvaluatesTo::len).sum::<usize>() + 1
    }

    /// Construct [`Where`] expression
    #[must_use]
    pub fn new<E: Into<EvaluatesTo<Value>>>(
        expression: E,
        values: btree_map::BTreeMap<ValueName, EvaluatesTo<Value>>,
    ) -> Self {
        Self {
            expression: expression.into(),
            values,
        }
    }
}

impl From<Where> for ExpressionBox {
    fn from(where_expression: Where) -> Self {
        Expression::Where(where_expression).into()
    }
}

impl QueryBox {
    /// Number of underneath expressions.
    #[inline]
    pub const fn len(&self) -> usize {
        1
    }
}

impl From<QueryBox> for ExpressionBox {
    fn from(query: QueryBox) -> Self {
        Expression::Query(query).into()
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        Add, And, Contains, ContainsAll, ContainsAny, Context, ContextValue, Divide, Equal,
        EvaluatesTo, Expression, ExpressionBox, Greater, If as IfExpression, IfBuilder, Less, Mod,
        Multiply, Not, Or, RaiseTo, Subtract, ValueName, Where, WhereBuilder,
    };
}
