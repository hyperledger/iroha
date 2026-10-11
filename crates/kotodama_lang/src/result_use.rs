//! Definite-use checking for recoverable results before executable lowering.
//!
//! A result obligation follows a local binding until the value is read, passed,
//! matched, propagated, returned, or explicitly discarded. Branch joins retain
//! obligations from every reachable path; a read on only one path is insufficient.
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

use crate::{
    semantic_diagnostics::{SemanticDiagnostic, SemanticFix},
    source::SourceRange,
};

use crate::semantic::{
    CallTarget, CompilerIntrinsic, ExprKind, SemanticError, Type, TypedBlock, TypedExpr,
    TypedParam, TypedStatement, TypedSumPattern, aggregate_binding_origin, resolve_struct_type,
};

/// A fixed product field or a compact set of possible bounded-list slots.
/// Unknown nested lists add one segment each, never a capacity cross-product.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Part {
    Field(usize),
    Slots(u64),
}
impl Part {
    fn slot(index: usize) -> Self {
        Self::Slots(
            u32::try_from(index)
                .ok()
                .and_then(|index| 1_u64.checked_shl(index))
                .unwrap_or(0),
        )
    }
    fn intersects(self, other: Self) -> bool {
        match (self, other) {
            (Self::Field(a), Self::Field(b)) => a == b,
            (Self::Slots(a), Self::Slots(b)) => a & b != 0,
            _ => false,
        }
    }
}
type Path = Vec<Part>;
fn under(path: &[Part], prefix: &[Part]) -> bool {
    path.len() >= prefix.len() && path.iter().zip(prefix).all(|(a, b)| a.intersects(*b))
}
/// Subtract only the selected subtree, retaining other slots symbolically.
fn remainder(path: &[Part], prefix: &[Part]) -> Vec<Path> {
    if prefix.is_empty() {
        return Vec::new();
    }
    if path.is_empty() || !path[0].intersects(prefix[0]) {
        return vec![path.to_vec()];
    }
    let mut output = Vec::new();
    let selected = match (path[0], prefix[0]) {
        (Part::Slots(all), Part::Slots(selected)) => {
            let remaining = all & !selected;
            if remaining != 0 {
                let mut rest = path.to_vec();
                rest[0] = Part::Slots(remaining);
                output.push(rest);
            }
            Part::Slots(all & selected)
        }
        (part, _) => part,
    };
    output.extend(
        remainder(&path[1..], &prefix[1..])
            .into_iter()
            .map(|mut rest| {
                rest.insert(0, selected);
                rest
            }),
    );
    output
}
type Paths = BTreeSet<Path>;

/// At a control-flow join, masks which differ along one list axis have an exact
/// union. Bound harder multidimensional correlations per Result leaf: widening
/// retains every possible obligation and can only require an explicit whole-
/// value read/discard, never silently accept an unhandled Result.
const MAX_PATH_ALTERNATIVES: usize = 128;
fn normalize(paths: Paths) -> Paths {
    let mut leaves: BTreeMap<Path, Vec<Path>> = BTreeMap::new();
    for path in paths {
        let key = path
            .iter()
            .map(|part| match part {
                Part::Slots(_) => Part::Slots(0),
                field => *field,
            })
            .collect();
        leaves.entry(key).or_default().push(path);
    }
    let mut output = Paths::new();
    for (skeleton, mut alternatives) in leaves {
        if alternatives.len() > MAX_PATH_ALTERNATIVES {
            let mut widened = skeleton;
            for path in alternatives {
                for (target, part) in widened.iter_mut().zip(path) {
                    if let (Part::Slots(all), Part::Slots(slots)) = (target, part) {
                        *all |= slots;
                    }
                }
            }
            output.insert(widened);
            continue;
        }
        loop {
            let before = alternatives.len();
            for (axis, part) in skeleton.iter().enumerate() {
                if !matches!(part, Part::Slots(_)) {
                    continue;
                }
                let mut merged: BTreeMap<Path, u64> = BTreeMap::new();
                for mut path in alternatives {
                    let Part::Slots(slots) = path[axis] else {
                        unreachable!("same leaf skeleton")
                    };
                    path[axis] = Part::Slots(0);
                    *merged.entry(path).or_default() |= slots;
                }
                alternatives = merged
                    .into_iter()
                    .map(|(mut path, slots)| {
                        path[axis] = Part::Slots(slots);
                        path
                    })
                    .collect();
            }
            if alternatives.len() == before {
                break;
            }
        }
        output.extend(alternatives);
    }
    output
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Place {
    name: String,
    path: Path,
}
/// Potentially active Result leaves, with known list lengths when syntax proves
/// them. Unknown lengths retain every possible slot; they are never guessed.
#[derive(Clone, Default)]
struct Shape {
    results: Paths,
    lengths: BTreeMap<Path, usize>,
    escaped_lists: bool,
}
impl Shape {
    fn typed(ty: &Type) -> Self {
        match resolve_struct_type(ty) {
            Type::Result(ok, error) => {
                let mut shape = Self::product([Self::typed(&ok), Self::typed(&error)]);
                shape.results.insert(Vec::new());
                shape
            }
            Type::Tuple(items) => Self::product(items.iter().map(Self::typed)),
            Type::Struct { fields, .. } => {
                Self::product(fields.iter().map(|(_, ty)| Self::typed(ty)))
            }
            Type::Option(item) => Self::product([Self::typed(&item)]),
            Type::List(item, capacity) => {
                let mut shape = Self::default();
                let mask = if capacity == 64 {
                    u64::MAX
                } else {
                    (1_u64 << capacity) - 1
                };
                shape.insert(Part::Slots(mask), Self::typed(&item));
                shape
            }
            _ => Self::default(),
        }
    }
    fn product(items: impl IntoIterator<Item = Self>) -> Self {
        let mut shape = Self::default();
        for (index, item) in items.into_iter().enumerate() {
            shape.insert(Part::Field(index), item);
        }
        shape
    }
    fn insert(&mut self, index: Part, item: Self) {
        self.escaped_lists |= item.escaped_lists;
        self.results
            .extend(item.results.into_iter().map(|mut path| {
                path.insert(0, index);
                path
            }));
        self.lengths
            .extend(item.lengths.into_iter().map(|(mut path, len)| {
                path.insert(0, index);
                (path, len)
            }));
    }
    fn project(&self, prefix: &[Part]) -> Self {
        Self {
            escaped_lists: self.escaped_lists,
            results: self
                .results
                .iter()
                .filter(|path| under(path, prefix))
                .map(|path| path[prefix.len()..].to_vec())
                .collect(),
            lengths: self
                .lengths
                .iter()
                .filter(|(path, _)| under(path, prefix))
                .map(|(path, len)| (path[prefix.len()..].to_vec(), *len))
                .collect(),
        }
    }
    fn remove(&mut self, prefix: &[Part]) {
        self.results = std::mem::take(&mut self.results)
            .into_iter()
            .flat_map(|path| remainder(&path, prefix))
            .collect();
        self.lengths.retain(|path, _| !under(path, prefix));
    }
    fn merge(&mut self, other: Self) {
        self.escaped_lists |= other.escaped_lists;
        self.results.extend(other.results);
        self.results = normalize(std::mem::take(&mut self.results));
        self.lengths
            .retain(|path, len| other.lengths.get(path) == Some(len));
    }
}

#[derive(Default)]
struct Flow {
    pending: BTreeSet<Place>,
    shapes: BTreeMap<String, Shape>,
    list_epoch: u64,
    names: BTreeSet<String>,
    durable: BTreeSet<String>,
    returned: bool,
    exits: Vec<LoopExit>,
    /// Diagnostic-only source sites shared by every fork of one check.
    sites: Rc<RefCell<MustUseSites>>,
}
/// Source locations observed while checking one function body.
#[derive(Default)]
struct MustUseSites {
    /// Innermost statement currently being checked.
    current: Option<SourceRange>,
    /// Innermost statement that observed the first failure.
    failure: Option<SourceRange>,
    /// Whether that statement discarded the value of an expression statement.
    expression_statement: bool,
    /// Statement that declared each tracked Result binding.
    bindings: BTreeMap<String, SourceRange>,
    /// Binding named by the first failure, when it names one.
    failed_binding: Option<String>,
}
struct LoopExit {
    pending: BTreeSet<Place>,
    shapes: BTreeMap<String, Shape>,
    list_epoch: u64,
    continuing: bool,
}
fn failure_message(name: &str, reason: &str) -> SemanticError {
    SemanticError {
        code: "E_RESULT_MUST_USE",
        message: format!(
            "Result binding `{name}` is {reason}; handle it or explicitly discard it with `let _ = {name};`"
        ),
    }
}
fn discarded() -> SemanticError {
    SemanticError {
        code: "E_RESULT_MUST_USE",
        message: "Result values, including values inside aggregates, must be handled; write `let _ = ...;` to deliberately discard the whole value".into(),
    }
}
fn contains_list(ty: &Type) -> bool {
    let mut pending = vec![ty];
    while let Some(ty) = pending.pop() {
        match ty {
            Type::List(..) => return true,
            Type::Option(inner) | Type::Secret(inner) => pending.push(inner),
            Type::Result(ok, error) => pending.extend([ok.as_ref(), error.as_ref()]),
            Type::Tuple(items) => pending.extend(items.iter()),
            Type::Struct { fields, .. } => pending.extend(fields.iter().map(|(_, ty)| ty)),
            _ => {}
        }
    }
    false
}
fn constant_index(value: &TypedExpr) -> Option<usize> {
    if let ExprKind::IntLiteral(index) = &value.expr {
        // Every non-addressable literal is a known out-of-bounds index, not a
        // dynamic index. The sentinel is outside 0..64 on every host width.
        Some(
            index
                .try_to_u64()
                .and_then(|index| usize::try_from(index).ok())
                .unwrap_or(usize::MAX),
        )
    } else {
        None
    }
}
fn place(value: &TypedExpr) -> Option<Place> {
    match &value.expr {
        ExprKind::Ident(name) => {
            let (root, path, _) = aggregate_binding_origin(name);
            Some(Place {
                name: root.to_owned(),
                path: path.into_iter().map(Part::Field).collect(),
            })
        }
        ExprKind::Member { object, field } => {
            let mut base = place(object)?;
            base.path.push(Part::Field(field.parse().ok()?));
            Some(base)
        }
        ExprKind::Index { target, index } => {
            let mut base = place(target)?;
            base.path.push(Part::slot(constant_index(index)?));
            Some(base)
        }
        _ => None,
    }
}
impl Flow {
    /// Fork only the path still executing. Earlier break/continue paths belong
    /// to their enclosing flow: they neither execute later branches nor exit a
    /// subsequently entered inner loop. `join` retains them exactly once.
    fn fork(&self) -> Self {
        Self {
            pending: self.pending.clone(),
            shapes: self.shapes.clone(),
            list_epoch: self.list_epoch,
            names: self.names.clone(),
            durable: self.durable.clone(),
            returned: self.returned,
            exits: Vec::new(),
            sites: Rc::clone(&self.sites),
        }
    }
    /// Report that the obligation of binding `name` was not met.
    fn failure(&self, name: &str, reason: &str) -> SemanticError {
        let mut sites = self.sites.borrow_mut();
        if sites.failed_binding.is_none() && sites.failure.is_none() {
            sites.failed_binding = Some(name.to_owned());
        }
        failure_message(name, reason)
    }
    fn bind(&mut self, name: &str, shape: Shape) -> Result<(), SemanticError> {
        let (_, path, capture) = aggregate_binding_origin(name);
        if name == "_" || !path.is_empty() || self.durable.contains(name) {
            return Ok(());
        }
        // Captures exist only for validated destructuring. Unselected fields
        // correspond to explicit `_` or `..`; selected fields get source Lets.
        if !capture {
            if let Some(old) = self.pending.iter().find(|old| old.name == name) {
                return Err(self.failure(&old.name, "overwritten before being consumed"));
            }
            if !shape.results.is_empty() {
                let mut sites = self.sites.borrow_mut();
                if let Some(current) = sites.current {
                    sites.bindings.entry(name.to_owned()).or_insert(current);
                }
            }
            self.names.insert(name.to_owned());
            self.pending
                .extend(shape.results.iter().cloned().map(|path| Place {
                    name: name.to_owned(),
                    path,
                }));
        }
        self.shapes.insert(name.to_owned(), shape);
        Ok(())
    }
    fn consume(&mut self, selected: &Place) {
        self.pending = std::mem::take(&mut self.pending)
            .into_iter()
            .flat_map(|pending| {
                if pending.name != selected.name {
                    return vec![pending];
                }
                remainder(&pending.path, &selected.path)
                    .into_iter()
                    .map(|path| Place {
                        name: pending.name.clone(),
                        path,
                    })
                    .collect()
            })
            .collect();
        self.normalize_pending();
    }
    fn consume_tag(&mut self, selected: &Place) {
        self.pending = std::mem::take(&mut self.pending)
            .into_iter()
            .flat_map(|pending| {
                if pending.name != selected.name || pending.path.len() != selected.path.len() {
                    return vec![pending];
                }
                remainder(&pending.path, &selected.path)
                    .into_iter()
                    .map(|path| Place {
                        name: pending.name.clone(),
                        path,
                    })
                    .collect()
            })
            .collect();
        self.normalize_pending();
    }
    fn normalize_pending(&mut self) {
        let mut bindings: BTreeMap<String, Paths> = BTreeMap::new();
        for pending in std::mem::take(&mut self.pending) {
            bindings
                .entry(pending.name)
                .or_default()
                .insert(pending.path);
        }
        for (name, paths) in bindings {
            self.pending
                .extend(normalize(paths).into_iter().map(|path| Place {
                    name: name.clone(),
                    path,
                }));
        }
    }
    fn stored_shape(&self, value: &TypedExpr) -> Shape {
        if let Some(selected) = place(value)
            && let Some(shape) = self.shapes.get(&selected.name)
        {
            if shape.escaped_lists && contains_list(&value.ty) {
                let mut unknown = Shape::typed(&value.ty);
                unknown.escaped_lists = true;
                return unknown;
            }
            return shape.project(&selected.path);
        }
        Shape::typed(&value.ty)
    }
    /// Copies share List handles. Invalidate precise facts only in values that
    /// escaped, including through aggregate fields; unrelated fresh lists retain
    /// their proven shape. Unknown alias correlations are intentionally widened.
    fn escape_lists(&mut self, value: &TypedExpr) {
        if let Some(selected) = place(value)
            && let Some(shape) = self.shapes.get_mut(&selected.name)
        {
            shape.escaped_lists = true;
        }
    }
    /// Evaluate a receiver once without interpreting observation as consuming
    /// its contained Results. The caller accounts for the exact inspected part.
    fn observe(&mut self, value: &TypedExpr) -> Result<Shape, SemanticError> {
        if place(value).is_some() {
            Ok(self.stored_shape(value))
        } else {
            self.expression(value)
        }
    }
    fn select(&mut self, value: &TypedExpr, prefix: &[Part]) -> Result<Shape, SemanticError> {
        let shape = self.observe(value)?;
        self.select_evaluated(value, &shape, prefix)?;
        Ok(shape.project(prefix))
    }
    fn select_evaluated(
        &mut self,
        value: &TypedExpr,
        shape: &Shape,
        prefix: &[Part],
    ) -> Result<(), SemanticError> {
        if let Some(mut selected) = place(value) {
            selected.path.extend_from_slice(prefix);
            self.consume(&selected);
        } else if shape
            .results
            .iter()
            .any(|path| !remainder(path, prefix).is_empty())
        {
            return Err(discarded());
        }
        Ok(())
    }
    fn call(
        &mut self,
        target: &CallTarget,
        args: &[TypedExpr],
        order: &[usize],
        result_ty: &Type,
    ) -> Result<Shape, SemanticError> {
        if target.is_lazy_sum_error() {
            self.expression(&args[0])?;
            let success = self.fork();
            let mut failure = self.fork();
            failure.expression(&args[1])?;
            if target.intrinsic() == Some(CompilerIntrinsic::Expect) {
                // The failing branch ends in a contract rejection, not a
                // recoverable return. Only the success path continues.
                failure.returned = true;
            }
            self.join([success, failure]);
            return Ok(Shape::typed(result_ty));
        }
        let intrinsic = target.intrinsic();
        let receiver_observed = matches!(
            intrinsic,
            Some(
                CompilerIntrinsic::IsSome
                    | CompilerIntrinsic::IsNone
                    | CompilerIntrinsic::IsOk
                    | CompilerIntrinsic::IsErr
                    | CompilerIntrinsic::UnwrapErrOr
                    | CompilerIntrinsic::ListLen
                    | CompilerIntrinsic::ListGet
                    | CompilerIntrinsic::ListContains
                    | CompilerIntrinsic::ListTake
                    | CompilerIntrinsic::ListWiden
                    | CompilerIntrinsic::ListEnumerate
                    | CompilerIntrinsic::ListSet
                    | CompilerIntrinsic::ListTrySet
                    | CompilerIntrinsic::ListPush
                    | CompilerIntrinsic::ListTryPush
                    | CompilerIntrinsic::ListPop
            )
        );
        let mut evaluated = vec![Shape::default(); args.len()];
        for index in order {
            evaluated[*index] = if *index == 0 && receiver_observed {
                self.observe(&args[0])?
            } else {
                self.expression(&args[*index])?
            };
        }
        if !receiver_observed {
            return Ok(Shape::typed(result_ty));
        }
        let name = intrinsic.expect("observed compiler intrinsic");
        // Lists are mutable pointer values. Later argument evaluation can mutate
        // the same receiver; runtime loads its length only after all arguments.
        let source = if place(&args[0]).is_some() {
            self.stored_shape(&args[0])
        } else {
            evaluated[0].clone()
        };
        let mut result = Shape::typed(result_ty);
        match name {
            CompilerIntrinsic::IsOk | CompilerIntrinsic::IsErr | CompilerIntrinsic::UnwrapErrOr => {
                if let Some(selected) = place(&args[0]) {
                    self.consume_tag(&selected); // Only the outer Result tag.
                } else if source.results.iter().any(|path| !path.is_empty()) {
                    return Err(discarded());
                }
            }
            CompilerIntrinsic::ListContains => {
                // Canonical equality observes complete structured values, like
                // comparing or passing the aggregate as a whole.
                self.select_evaluated(&args[0], &source, &[])?;
            }
            CompilerIntrinsic::IsSome | CompilerIntrinsic::IsNone | CompilerIntrinsic::ListLen => {
                if place(&args[0]).is_none() && !source.results.is_empty() {
                    return Err(discarded());
                }
            }
            CompilerIntrinsic::ListGet => {
                if let Some(index) = constant_index(&args[1]) {
                    self.select_evaluated(&args[0], &source, &[Part::slot(index)])?;
                    result = Shape::product([source.project(&[Part::slot(index)])]);
                } else if place(&args[0]).is_none() && !source.results.is_empty() {
                    return Err(discarded());
                }
            }
            CompilerIntrinsic::ListWiden => {
                self.select_evaluated(&args[0], &source, &[])?;
                result = source.clone();
            }
            CompilerIntrinsic::ListTake => {
                let length = constant_index(&args[1]).expect("typed take bound");
                let mask = if length == 64 {
                    u64::MAX
                } else {
                    (1_u64 << length) - 1
                };
                self.select_evaluated(&args[0], &source, &[Part::Slots(mask)])?;
                result = source.clone();
                result.remove(&[Part::Slots(!mask)]);
                if let Some(known) = source.lengths.get(&Vec::new()) {
                    result.lengths.insert(Vec::new(), (*known).min(length));
                } else if length == 0 {
                    result.lengths.insert(Vec::new(), 0);
                }
            }
            CompilerIntrinsic::ListEnumerate => {
                self.select_evaluated(&args[0], &source, &[])?;
                result = Shape::default();
                result.results = source
                    .results
                    .iter()
                    .map(|path| {
                        let mut path = path.clone();
                        path.insert(1, Part::Field(1));
                        path
                    })
                    .collect();
                result.lengths = source
                    .lengths
                    .iter()
                    .map(|(path, length)| {
                        let mut path = path.clone();
                        if !path.is_empty() {
                            path.insert(1, Part::Field(1));
                        }
                        (path, *length)
                    })
                    .collect();
            }
            CompilerIntrinsic::ListPop => {
                if let Some(length) = source.lengths.get(&Vec::new()) {
                    if let Some(index) = length.checked_sub(1) {
                        self.select_evaluated(&args[0], &source, &[Part::slot(index)])?;
                        result = Shape::product([source.project(&[Part::slot(index)])]);
                    } else {
                        result = Shape::default();
                    }
                }
                self.mutate_list(name, args, source, Shape::default())?;
            }
            CompilerIntrinsic::ListSet
            | CompilerIntrinsic::ListTrySet
            | CompilerIntrinsic::ListPush
            | CompilerIntrinsic::ListTryPush => {
                self.mutate_list(
                    name,
                    args,
                    source,
                    evaluated.last().cloned().expect("typed mutation value"),
                )?;
            }
            _ => unreachable!("observed intrinsic registry"),
        }
        let shares_elements = match resolve_struct_type(&args[0].ty) {
            Type::List(element, _) => contains_list(&element),
            _ => false,
        };
        if shares_elements
            && matches!(
                name,
                CompilerIntrinsic::ListGet
                    | CompilerIntrinsic::ListTake
                    | CompilerIntrinsic::ListWiden
                    | CompilerIntrinsic::ListEnumerate
            )
        {
            self.escape_lists(&args[0]);
            result.escaped_lists = true;
        }
        Ok(result)
    }
    fn mutate_list(
        &mut self,
        name: CompilerIntrinsic,
        args: &[TypedExpr],
        mut shape: Shape,
        replacement: Shape,
    ) -> Result<(), SemanticError> {
        let Some(base) = place(&args[0]) else {
            unreachable!("typed mutable list receiver")
        };
        let Type::List(_, capacity) = resolve_struct_type(&args[0].ty) else {
            unreachable!("typed list receiver")
        };
        let length = shape.lengths.get(&Vec::new()).copied();
        if name == CompilerIntrinsic::ListPop {
            if let Some(length) = length {
                if let Some(index) = length.checked_sub(1) {
                    shape.remove(&[Part::slot(index)]);
                    shape.lengths.insert(Vec::new(), index);
                }
            } else {
                shape.lengths.clear();
            }
        } else {
            let setting = matches!(
                name,
                CompilerIntrinsic::ListSet | CompilerIntrinsic::ListTrySet
            );
            let known_index = if setting {
                constant_index(&args[1])
            } else {
                length
            };
            let indices: Vec<_> = match known_index {
                Some(index)
                    if index < usize::from(capacity)
                        && (!setting || length.is_none_or(|length| index < length)) =>
                {
                    vec![index]
                }
                Some(_) => Vec::new(),
                None => (0..usize::from(capacity)).collect(),
            };
            if setting {
                if shape.escaped_lists
                    && !indices.is_empty()
                    && let Some(old) = self
                        .pending
                        .iter()
                        .find(|old| old.path.iter().any(|part| matches!(part, Part::Slots(_))))
                {
                    return Err(self.failure(
                        &old.name,
                        "possibly overwritten through a shared List handle before being consumed",
                    ));
                }
                for index in &indices {
                    let mut selected = base.clone();
                    selected.path.push(Part::slot(*index));
                    if let Some(old) = self
                        .pending
                        .iter()
                        .find(|old| old.name == selected.name && under(&old.path, &selected.path))
                    {
                        return Err(self.failure(&old.name, "overwritten before being consumed"));
                    }
                }
            }
            for index in &indices {
                // An unknown index describes alternatives; retain every possibly
                // untouched slot and only union the new obligations.
                if known_index.is_some() {
                    shape.remove(&[Part::slot(*index)]);
                }
                shape.insert(Part::slot(*index), replacement.clone());
                if !self.durable.contains(&base.name) {
                    self.pending.extend(replacement.results.iter().map(|path| {
                        let mut selected = base.clone();
                        selected.path.push(Part::slot(*index));
                        selected.path.extend(path);
                        selected
                    }));
                }
            }
            if !setting && let Some(length) = length {
                shape
                    .lengths
                    .insert(Vec::new(), (length + 1).min(usize::from(capacity)));
            }
        }
        // Replace only the selected list subtree. Sibling product fields retain
        // their lengths and Result obligations; nested receiver paths are fixed
        // struct/tuple projections validated by semantic analysis.
        let root = self.shapes.entry(base.name).or_default();
        root.remove(&base.path);
        root.escaped_lists |= shape.escaped_lists;
        root.results.extend(shape.results.into_iter().map(|path| {
            let mut selected = base.path.clone();
            selected.extend(path);
            selected
        }));
        root.lengths
            .extend(shape.lengths.into_iter().map(|(path, length)| {
                let mut selected = base.path.clone();
                selected.extend(path);
                (selected, length)
            }));
        self.list_epoch = self.list_epoch.saturating_add(1);
        Ok(())
    }
    fn check_exit(&self) -> Result<(), SemanticError> {
        if let Some(name) = self.pending.first() {
            return Err(self.failure(&name.name, "unread when this path exits"));
        }
        Ok(())
    }
    fn pattern(&mut self, pattern: &TypedSumPattern) -> Result<(), SemanticError> {
        if let (Some(crate::ast::PatternBinding::Name(name)), Some(ty)) =
            (&pattern.pattern.binding, &pattern.payload_type)
        {
            self.bind(name, Shape::typed(ty))?;
        }
        Ok(())
    }
    fn join(&mut self, paths: impl IntoIterator<Item = Self>) {
        self.pending.clear();
        let mut shapes: Option<BTreeMap<String, Shape>> = None;
        self.returned = true;
        // Forks own only exits reached within that fork. Preserve exits from
        // earlier statements without cloning them into every later branch.
        for path in paths {
            self.exits.extend(path.exits);
            if !path.returned {
                self.list_epoch = self.list_epoch.max(path.list_epoch);
                self.returned = false;
                self.pending.extend(path.pending);
                if let Some(merged) = &mut shapes {
                    for (name, shape) in path.shapes {
                        if let Some(current) = merged.get_mut(&name) {
                            current.merge(shape);
                        } else {
                            merged.insert(name, shape);
                        }
                    }
                } else {
                    shapes = Some(path.shapes);
                }
            }
        }
        if let Some(shapes) = shapes {
            self.shapes = shapes;
        }
        self.normalize_pending();
    }
    fn block(&mut self, block: &TypedBlock, tail_used: bool) -> Result<Shape, SemanticError> {
        let outer = self.names.clone();
        let mut tail_shape = Shape::default();
        for (index, statement) in block.statements.iter().enumerate() {
            if self.returned {
                break;
            }
            let source = block.statement_source(index);
            let enclosing = std::mem::replace(&mut self.sites.borrow_mut().current, source);
            let result = self.statement(statement);
            let mut sites = self.sites.borrow_mut();
            sites.current = enclosing;
            if result.is_err() && sites.failure.is_none() {
                sites.failure = source;
                sites.expression_statement = matches!(statement, TypedStatement::Expr(_));
            }
            drop(sites);
            result?;
        }
        if !self.returned {
            if let Some(tail) = &block.tail {
                tail_shape = self.expression(tail)?;
                if !tail_used && !tail_shape.results.is_empty() {
                    let mut sites = self.sites.borrow_mut();
                    if sites.failure.is_none() {
                        sites.failure = block.tail_source();
                    }
                    return Err(discarded());
                }
            }
            if let Some(name) = self.pending.iter().find(|name| !outer.contains(&name.name)) {
                return Err(self.failure(&name.name, "unread at the end of its scope"));
            }
        }
        for exit in &self.exits {
            if let Some(name) = exit.pending.iter().find(|name| !outer.contains(&name.name)) {
                return Err(self.failure(&name.name, "unread before leaving its scope"));
            }
        }
        self.names = outer;
        Ok(tail_shape)
    }
    fn loop_paths(
        &mut self,
        initial: Self,
        mut iteration: Self,
        body: &TypedBlock,
    ) -> Result<(), SemanticError> {
        let mut paths = vec![initial];
        for exit in std::mem::take(&mut iteration.exits) {
            let path = Self {
                pending: exit.pending,
                shapes: exit.shapes,
                list_epoch: exit.list_epoch,
                names: self.names.clone(),
                durable: self.durable.clone(),
                returned: false,
                exits: Vec::new(),
                sites: Rc::clone(&self.sites),
            };
            if exit.continuing {
                let mut repeated = path.fork();
                repeated.block(body, false)?;
            }
            paths.push(path);
        }
        paths.push(iteration);
        self.join(paths);
        Ok(())
    }
    fn branches(
        &mut self,
        left: &TypedBlock,
        right: Option<&TypedBlock>,
        pattern: Option<&TypedSumPattern>,
        tail_used: bool,
    ) -> Result<Shape, SemanticError> {
        let mut a = self.fork();
        let mut b = self.fork();
        let left_shape;
        if let Some(pattern) = pattern {
            let outer = a.names.clone();
            a.pattern(pattern)?;
            left_shape = a.block(left, tail_used)?;
            if !a.returned
                && let Some(name) = a.pending.iter().find(|name| !outer.contains(&name.name))
            {
                return Err(self.failure(&name.name, "unread in this pattern arm"));
            }
            a.names = outer;
        } else {
            left_shape = a.block(left, tail_used)?;
        }
        let right_shape = if let Some(right) = right {
            b.block(right, tail_used)?
        } else {
            Shape::default()
        };
        let mut output = if a.returned {
            Shape::default()
        } else {
            left_shape
        };
        if !b.returned {
            output.merge(right_shape);
        }
        self.join([a, b]);
        Ok(output)
    }
    fn if_let(
        &mut self,
        value: &TypedExpr,
        pattern: &TypedSumPattern,
        left: &TypedBlock,
        right: Option<&TypedBlock>,
        tail_used: bool,
    ) -> Result<Shape, SemanticError> {
        let shape = self.observe(value)?;
        let unmatched_payload = match pattern.pattern.variant {
            crate::ast::SumVariant::OptionNone => !shape.results.is_empty(),
            crate::ast::SumVariant::ResultErr => {
                !shape.project(&[Part::Field(0)]).results.is_empty()
            }
            _ => false,
        };
        if unmatched_payload {
            let Some(selected) = place(value) else {
                return Err(discarded());
            };
            if pattern.pattern.variant == crate::ast::SumVariant::ResultErr {
                self.consume_tag(&selected);
            }
            let mut matched = self.fork();
            matched.consume(&selected);
            matched.pattern(pattern)?;
            let left_shape = matched.block(left, tail_used)?;
            let mut unmatched = self.fork();
            let right_shape = if let Some(right) = right {
                unmatched.block(right, tail_used)?
            } else {
                Shape::default()
            };
            let mut output = if matched.returned {
                Shape::default()
            } else {
                left_shape
            };
            if !unmatched.returned {
                output.merge(right_shape);
            }
            self.join([matched, unmatched]);
            Ok(output)
        } else {
            if let Some(selected) = place(value) {
                self.consume(&selected);
            }
            self.branches(left, right, Some(pattern), tail_used)
        }
    }
    fn statement(&mut self, statement: &TypedStatement) -> Result<(), SemanticError> {
        match statement {
            TypedStatement::Let { name, value } => {
                let (_, path, _) = aggregate_binding_origin(name);
                if !path.is_empty() {
                    // Flattened field aliases materialize an existing binding;
                    // generating them is not a source-level read or transfer.
                    return Ok(());
                }
                let shape = self.expression(value)?;
                self.bind(name, shape)?;
            }
            TypedStatement::Expr(value) => {
                if !self.expression(value)?.results.is_empty() {
                    return Err(discarded());
                }
            }
            TypedStatement::Return(value) => {
                if let Some(value) = value {
                    self.expression(value)?;
                }
                self.check_exit()?;
                self.returned = true;
            }
            TypedStatement::If {
                cond,
                then_branch,
                else_branch,
            } => {
                self.expression(cond)?;
                self.branches(then_branch, else_branch.as_ref(), None, false)?;
            }
            TypedStatement::IfLet {
                pattern,
                value,
                then_branch,
                else_branch,
            } => {
                self.if_let(value, pattern, then_branch, else_branch.as_ref(), false)?;
            }
            TypedStatement::While { cond, body } => {
                self.expression(cond)?;
                let initial = self.fork();
                let mut iteration = self.fork();
                iteration.block(body, false)?;
                if !iteration.returned {
                    // A second iteration exposes unconsumed overwrites on backedges.
                    let mut repeat = iteration.fork();
                    repeat.expression(cond)?;
                    repeat.block(body, false)?;
                }
                self.loop_paths(initial, iteration, body)?;
            }
            TypedStatement::For {
                init,
                cond,
                step,
                body,
                ..
            } => {
                if let Some(init) = init {
                    self.statement(init)?;
                }
                if let Some(cond) = cond {
                    self.expression(cond)?;
                }
                let initial = self.fork();
                let mut iteration = self.fork();
                iteration.block(body, false)?;
                if !iteration.returned {
                    if let Some(step) = step {
                        iteration.statement(step)?;
                    }
                    let mut repeat = iteration.fork();
                    if let Some(cond) = cond {
                        repeat.expression(cond)?;
                    }
                    repeat.block(body, false)?;
                }
                self.loop_paths(initial, iteration, body)?;
            }
            TypedStatement::ForEachMap { map, body, .. } => {
                // Iteration reads each item only on paths which visit it. A
                // break/return must not silently drop unvisited Result items.
                let temporary = place(map).is_none();
                let source = if let Some(source) = place(map) {
                    source
                } else {
                    let shape = self.expression(map)?;
                    let name = format!("\0result_iteration{}", self.names.len());
                    self.bind(&name, shape)?;
                    Place {
                        name,
                        path: Vec::new(),
                    }
                };
                let entry_epoch = self.list_epoch;
                let mut empty = self.fork();
                empty.consume(&source);
                let mut iteration = self.fork();
                iteration.block(body, false)?;
                let mut paths = vec![empty];
                for exit in std::mem::take(&mut iteration.exits) {
                    let mut path = Self {
                        pending: exit.pending,
                        shapes: exit.shapes,
                        list_epoch: exit.list_epoch,
                        names: self.names.clone(),
                        durable: self.durable.clone(),
                        returned: false,
                        exits: Vec::new(),
                        sites: Rc::clone(&self.sites),
                    };
                    if exit.continuing {
                        let mut repeat = path.fork();
                        repeat.block(body, false)?;
                        if path.list_epoch == entry_epoch {
                            path.consume(&source);
                        }
                    }
                    paths.push(path);
                }
                if !iteration.returned {
                    let mut repeat = iteration.fork();
                    repeat.block(body, false)?;
                    if iteration.list_epoch == entry_epoch {
                        iteration.consume(&source);
                    }
                }
                paths.push(iteration);
                self.join(paths);
                if temporary {
                    if self
                        .pending
                        .iter()
                        .any(|pending| pending.name == source.name)
                    {
                        return Err(discarded());
                    }
                    self.names.remove(&source.name);
                    self.shapes.remove(&source.name);
                }
            }
            TypedStatement::MapSet { map, key, value } => {
                self.expression(map)?;
                self.expression(key)?;
                self.expression(value)?;
            }
            TypedStatement::Break | TypedStatement::Continue => {
                self.exits.push(LoopExit {
                    pending: std::mem::take(&mut self.pending),
                    shapes: self.shapes.clone(),
                    list_epoch: self.list_epoch,
                    continuing: matches!(statement, TypedStatement::Continue),
                });
                self.returned = true;
            }
        }
        Ok(())
    }
    fn expression(&mut self, value: &TypedExpr) -> Result<Shape, SemanticError> {
        match &value.expr {
            ExprKind::Ident(_) => {
                let list_value = contains_list(&value.ty);
                if list_value {
                    self.escape_lists(value);
                }
                let mut shape = self.stored_shape(value);
                shape.escaped_lists |= list_value;
                self.consume(&place(value).expect("identifier place"));
                return Ok(shape);
            }
            ExprKind::Binary { op, left, right } => {
                self.expression(left)?;
                if matches!(op, crate::ast::BinaryOp::And | crate::ast::BinaryOp::Or) {
                    let skip = self.fork();
                    let mut active = self.fork();
                    active.expression(right)?;
                    self.join([skip, active]);
                } else {
                    self.expression(right)?;
                }
            }
            ExprKind::Unary { expr, .. }
            | ExprKind::NumericCast { expr }
            | ExprKind::NumericTryCast { expr } => {
                self.expression(expr)?;
            }
            ExprKind::OptionSome { value } => return Ok(Shape::product([self.expression(value)?])),
            ExprKind::ResultOk { value: payload } | ExprKind::ResultErr { error: payload } => {
                let mut shape = Shape::default();
                let payload = self.expression(payload)?;
                shape.insert(
                    Part::Field(usize::from(matches!(
                        &value.expr,
                        ExprKind::ResultErr { .. }
                    ))),
                    payload,
                );
                shape.results.insert(Vec::new());
                return Ok(shape);
            }
            ExprKind::Propagate { value } => {
                self.expression(value)?;
                self.check_exit()?;
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                self.expression(cond)?;
                let mut a = self.fork();
                let mut b = self.fork();
                let mut output = a.expression(then_expr)?;
                output.merge(b.expression(else_expr)?);
                self.join([a, b]);
                return Ok(output);
            }
            ExprKind::If {
                condition,
                then_branch,
                else_branch,
            } => {
                self.expression(condition)?;
                return self.branches(then_branch, Some(else_branch), None, true);
            }
            ExprKind::IfLet {
                value,
                pattern,
                then_branch,
                else_branch,
            } => {
                return self.if_let(value, pattern, then_branch, Some(else_branch), true);
            }
            ExprKind::Match { value, arms } => {
                self.expression(value)?;
                let mut paths = Vec::with_capacity(arms.len());
                let mut output: Option<Shape> = None;
                for arm in arms {
                    let mut path = self.fork();
                    path.pattern(&arm.pattern)?;
                    let shape = path.block(&arm.body, true)?;
                    if !path.returned {
                        if let Some(output) = &mut output {
                            output.merge(shape);
                        } else {
                            output = Some(shape);
                        }
                        if let Some(name) = path
                            .pending
                            .iter()
                            .find(|name| !self.names.contains(&name.name))
                        {
                            return Err(self.failure(&name.name, "unread in this match arm"));
                        }
                    }
                    paths.push(path);
                }
                self.join(paths);
                return Ok(output.unwrap_or_default());
            }
            ExprKind::Call { target: name, args } => {
                return self.call(name, args, &(0..args.len()).collect::<Vec<_>>(), &value.ty);
            }
            ExprKind::NamedCall {
                target: name,
                args,
                evaluation_order,
            } => return self.call(name, args, evaluation_order, &value.ty),
            ExprKind::StructLiteral { fields, .. } => {
                let Type::Struct {
                    fields: declared, ..
                } = resolve_struct_type(&value.ty)
                else {
                    unreachable!("typed struct literal")
                };
                let mut shape = Shape::default();
                for (name, field) in fields {
                    let index = declared
                        .iter()
                        .position(|(field, _)| field == name)
                        .expect("typed field");
                    shape.insert(Part::Field(index), self.expression(field)?);
                }
                return Ok(shape);
            }
            ExprKind::Tuple(items) | ExprKind::List(items) => {
                let mut shape = Shape::default();
                for (index, item) in items.iter().enumerate() {
                    let part = if matches!(&value.expr, ExprKind::List(_)) {
                        Part::slot(index)
                    } else {
                        Part::Field(index)
                    };
                    shape.insert(part, self.expression(item)?);
                }
                if matches!(&value.expr, ExprKind::List(_)) {
                    shape.lengths.insert(Vec::new(), items.len());
                }
                return Ok(shape);
            }
            ExprKind::JsonObject(fields) => {
                for (_, item) in fields {
                    self.expression(item)?;
                }
            }
            ExprKind::JsonArray(items) => {
                for item in items {
                    self.expression(item)?;
                }
            }
            ExprKind::ListComprehension {
                source,
                expression,
                condition,
                item: name,
            } => {
                let temporary = place(source).is_none();
                let selected = if let Some(source) = place(source) {
                    source
                } else {
                    let shape = self.expression(source)?;
                    let name = format!("\0result_comprehension{}", self.names.len());
                    self.bind(&name, shape)?;
                    Place {
                        name,
                        path: Vec::new(),
                    }
                };
                let entry_epoch = self.list_epoch;
                let mut initial = self.fork();
                initial.consume(&selected); // The zero-element path is exhaustive.
                let mut item = self.fork();
                let Type::List(element, _) = resolve_struct_type(&source.ty) else {
                    unreachable!("typed comprehension")
                };
                item.bind(name, Shape::typed(&element))?;
                if let Some(condition) = condition {
                    item.expression(condition)?;
                    if let Some(pending) = item.pending.iter().find(|pending| pending.name == *name)
                    {
                        return Err(self.failure(
                            &pending.name,
                            "unread when the comprehension filter excludes it",
                        ));
                    }
                }
                item.expression(expression)?;
                if let Some(pending) = item.pending.iter().find(|pending| pending.name == *name) {
                    return Err(self.failure(&pending.name, "unread by the comprehension"));
                }
                if item.list_epoch == entry_epoch {
                    item.consume(&selected);
                }
                item.names.remove(name);
                item.shapes.remove(name);
                self.join([initial, item]);
                if temporary {
                    if self
                        .pending
                        .iter()
                        .any(|pending| pending.name == selected.name)
                    {
                        return Err(discarded());
                    }
                    self.names.remove(&selected.name);
                    self.shapes.remove(&selected.name);
                }
            }
            ExprKind::Member { object, field } => {
                let shape = self.select(
                    object,
                    &[Part::Field(field.parse().expect("typed projection"))],
                )?;
                if contains_list(&value.ty) {
                    self.escape_lists(object);
                    let mut unknown = Shape::typed(&value.ty);
                    unknown.escaped_lists = true;
                    return Ok(unknown);
                }
                return Ok(shape);
            }
            ExprKind::Index { target, index } => {
                let shape = self.observe(target)?;
                self.expression(index)?;
                let source = if place(target).is_some() {
                    self.stored_shape(target)
                } else {
                    shape
                };
                if let Some(index) = constant_index(index) {
                    self.select_evaluated(target, &source, &[Part::slot(index)])?;
                } else if place(target).is_none() && !source.results.is_empty() {
                    return Err(discarded());
                }
            }
            ExprKind::OptionNone => return Ok(Shape::default()),
            ExprKind::VariantCode(_)
            | ExprKind::IntLiteral(_)
            | ExprKind::DecimalLiteral { .. }
            | ExprKind::Bool(_)
            | ExprKind::String(_)
            | ExprKind::Bytes(_) => {}
        }
        Ok(Shape::typed(&value.ty))
    }
}
/// Check result obligations and locate the first failure in source.
///
/// A failure that names a binding points at the statement that declared the
/// binding. A discarded value points at the innermost statement that dropped
/// it; a discarded expression statement also receives a `let _ = ...;` fix.
pub(crate) fn check_with_diagnostic(
    parameters: &[TypedParam],
    body: &TypedBlock,
    durable: BTreeSet<String>,
) -> Result<(), Box<(SemanticError, Option<SemanticDiagnostic>)>> {
    // Publishing a Result to durable state consumes the local value. State
    // names cannot be shadowed, so these resolver-owned names are unambiguous.
    let mut flow = Flow {
        durable,
        ..Flow::default()
    };
    let result = (|| {
        for parameter in parameters {
            flow.bind(&parameter.name, Shape::typed(&parameter.ty))?;
        }
        flow.block(body, true)?;
        flow.check_exit()
    })();
    result.map_err(|error| {
        let sites = flow.sites.borrow();
        let diagnostic = if let Some(name) = &sites.failed_binding {
            sites.bindings.get(name).map(|binding| {
                SemanticDiagnostic::at(*binding, None)
                    .with_label(
                        sites.failure.filter(|failure| failure != binding),
                        format!("`{name}` is still unhandled here"),
                    )
                    .with_help(format!(
                        "Read `{name}` with `match`, `if let`, or `?`, pass or return it, or discard it explicitly with `let _ = {name};`."
                    ))
            })
        } else {
            sites.failure.map(|failure| {
                SemanticDiagnostic::at(
                    failure,
                    sites
                        .expression_statement
                        .then_some(SemanticFix::DiscardStatement),
                )
                .with_help(
                    "This expression produces a Result whose failure would be silently lost. \
                     Handle it with `match`, `if let`, or `?`, or discard it explicitly with `let _ = ...;`.",
                )
            })
        };
        Box::new((error, diagnostic))
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn lazy_sum_errors_do_not_consume_results_on_the_success_path() {
        for bridge in [
            "value.ok_or(fallback(pending))",
            "value.expect(fallback(pending))",
        ] {
            let source = format!(
                "error enum Failure {{ Missing = 1 }} \
                 fn fallback(Result<int, Failure> input) -> Failure {{ let _ = input; Failure::Missing }} \
                 fn run(Option<int> value) {{ let Result<int, Failure> pending = Result::err(Failure::Missing); \
                 let _ = {bridge}; }}"
            );
            assert_eq!(
                analyze(&source)
                    .expect_err("success never consumes pending")
                    .code(),
                "E_RESULT_MUST_USE"
            );
            let repaired = source.replace(
                &format!("let _ = {bridge};"),
                &format!("let _ = {bridge}; let _ = pending;"),
            );
            analyze(&repaired).expect("explicit discard handles the continuing success path");
        }
    }
    use super::*;
    fn analyze(source: &str) -> Result<crate::semantic::TypedProgram, SemanticError> {
        crate::semantic::analyze(&crate::parser::parse_test_fragment(source).expect("valid source"))
    }
    #[test]
    fn results_require_handling_and_explicit_discard_is_allowed() {
        for source in [
            "fn f() { quantity::try_from_int(-1); }",
            "fn f() { let result = quantity::try_from_int(-1); }",
            "fn f() { var result = quantity::try_from_int(1); result = quantity::try_from_int(2); let _ = result; }",
        ] {
            assert_eq!(analyze(source).unwrap_err().code(), "E_RESULT_MUST_USE");
        }
        analyze("fn f() { let _ = quantity::try_from_int(-1); }").unwrap();
        analyze("fn f() { let result = quantity::try_from_int(-1); let _ = result; }").unwrap();
    }
    #[test]
    fn every_reachable_branch_must_consume_a_result() {
        assert_eq!(analyze("fn f(bool flag) { let result = quantity::try_from_int(1); if flag { let _ = result; } }").unwrap_err().code(), "E_RESULT_MUST_USE");
        analyze("fn f(bool flag) { let result = quantity::try_from_int(1); if flag { let _ = result; } else { let _ = result; } }").unwrap();
    }
    fn reject(source: &str) {
        let error = analyze(source).expect_err(source);
        assert_eq!(error.code(), "E_RESULT_MUST_USE", "{source}: {error:?}");
    }
    #[test]
    fn aggregate_results_cannot_be_hidden_by_construction_or_scalar_projection() {
        for body in [
            "(quantity::try_from_int(-1), 0);",
            "let bundle = (quantity::try_from_int(-1), 0);",
            "Option::some(quantity::try_from_int(-1));",
            "[quantity::try_from_int(-1)];",
            "let bundle = (quantity::try_from_int(-1), 0); let scalar = bundle.1;",
            "let scalar = (quantity::try_from_int(-1), 0).1;",
            "let _ = (quantity::try_from_int(-1), 0).1;",
            "let __kotodama_hidden = quantity::try_from_int(-1);",
        ] {
            reject(&format!("fn f() {{ {body} }}"));
        }
        analyze("fn f() { let _ = (quantity::try_from_int(-1), 0); let _ = Option::some(quantity::try_from_int(-1)); let __kotodama_hidden = quantity::try_from_int(-1); let _ = __kotodama_hidden; }").unwrap();
    }
    #[test]
    fn projection_transfers_only_selected_obligations_and_overwrites_check_siblings() {
        for body in [
            "let pair = (quantity::try_from_int(1), quantity::try_from_int(2)); let _ = pair.0;",
            "var pair = (quantity::try_from_int(1), quantity::try_from_int(2)); let _ = pair.0; pair = (quantity::try_from_int(3), quantity::try_from_int(4)); let _ = pair;",
            "let pair = (quantity::try_from_int(1), 0); let next = pair;",
            "let pair = (quantity::try_from_int(1), 0); let checked = pair.0;",
        ] {
            reject(&format!("fn f() {{ {body} }}"));
        }
        analyze("fn f() { let pair = (quantity::try_from_int(1), quantity::try_from_int(2)); let first = pair.0; let _ = first; let _ = pair.1; }").unwrap();
        analyze("fn f() { var pair = (quantity::try_from_int(1), 0); let _ = pair.0; pair = (quantity::try_from_int(2), 0); let _ = pair; }").unwrap();
    }
    #[test]
    fn named_and_tuple_patterns_preserve_explicit_discard_intent() {
        let declaration = "struct Bundle { Result<quantity, NumericError> checked, int number }";
        for pattern in [
            "let Bundle { checked, .. } = bundle;",
            "let Bundle { checked: renamed, number: _ } = bundle;",
        ] {
            reject(&format!(
                "{declaration} fn f() {{ let bundle = Bundle {{ number: 0, checked: quantity::try_from_int(-1) }}; {pattern} }}"
            ));
        }
        for pattern in [
            "let Bundle { checked: _, number } = bundle;",
            "let Bundle { number, .. } = bundle;",
            "let Bundle { checked, .. } = bundle; let _ = checked;",
        ] {
            analyze(&format!("{declaration} fn f() {{ let bundle = Bundle {{ number: 0, checked: quantity::try_from_int(-1) }}; {pattern} }}")).unwrap();
        }
        reject("fn f() { let (checked, _) = (quantity::try_from_int(-1), 0); }");
        analyze("fn f() { let (_, number) = (quantity::try_from_int(-1), 0); }").unwrap();
    }
    #[test]
    fn aggregate_function_and_durable_publication_transfer_all_obligations() {
        analyze("fn accept((Result<quantity, NumericError>, int) pair) { let _ = pair; } fn f() { let pair = (quantity::try_from_int(-1), 0); accept(pair: pair); }").unwrap();
        analyze("fn f() -> (Result<quantity, NumericError>, int) { let pair = (quantity::try_from_int(-1), 0); return pair; }").unwrap();
        analyze("fn f() -> Option<Result<quantity, NumericError>> { Option::some(quantity::try_from_int(-1)) }").unwrap();
        analyze("seiyaku Publish { permission Writer;  state (Result<quantity, NumericError>, int) saved; state StateMap<int, Option<Result<quantity, NumericError>>> entries; hajimari() { saved = (quantity::try_from_int(0), 0); } kotoage fn save() authorize(Writer) { let pair = (quantity::try_from_int(-1), 0); saved = pair; let optional = Option::some(quantity::try_from_int(-1)); entries[0] = optional; } }").unwrap();
    }
    #[test]
    fn container_observation_does_not_handle_nested_results() {
        for body in [
            "let optional = Option::some(quantity::try_from_int(-1)); let present = optional.is_some();",
            "let present = Option::some(quantity::try_from_int(-1)).is_none();",
            "let values = [quantity::try_from_int(-1)]; let length = values.len();",
            "let length = [quantity::try_from_int(-1)].len();",
            "let optional = Option::some(quantity::try_from_int(-1)); if let Option::none = optional { }",
            "if let Option::none = Option::some(quantity::try_from_int(-1)) { }",
            "let values = [quantity::try_from_int(-1), quantity::try_from_int(2)]; let _ = values.get(0);",
            "let _ = [quantity::try_from_int(-1), quantity::try_from_int(2)].get(0);",
            "let values = [quantity::try_from_int(-1)]; let _ = values.get(64);",
            "let values = [quantity::try_from_int(-1)]; let _ = values.get(4294967296);",
        ] {
            reject(&format!("fn f() {{ {body} }}"));
        }
        analyze("fn f() { let result = quantity::try_from_int(-1); let failed = result.is_err(); let optional = Option::some(quantity::try_from_int(-1)); let present = optional.is_some(); let _ = optional; }").unwrap();
        analyze("fn f() { let values = [quantity::try_from_int(-1), quantity::try_from_int(2)]; let _ = values.get(0); let _ = values.get(1); }").unwrap();
        analyze("fn f() { let optional = Option::some(quantity::try_from_int(-1)); if let Option::none = optional { } else { let _ = optional; } }").unwrap();
        analyze("fn f() { let Option<Result<quantity, NumericError>> optional = Option::none; let List<Result<quantity, NumericError>, 2> values = []; let present = optional.is_some(); let length = values.len(); }").unwrap();
    }
    #[test]
    fn canonical_contains_is_a_whole_value_read_of_result_elements() {
        analyze("fn f() { let values = [quantity::try_from_int(1), quantity::try_from_int(-1)]; let found = values.contains(quantity::try_from_int(-1)); }").unwrap();
        analyze("fn f() { let values = [(quantity::try_from_int(1), 0), (quantity::try_from_int(-1), 1)]; values.contains((quantity::try_from_int(-1), 1)); }").unwrap();
        reject(
            "fn f() { let values = [quantity::try_from_int(1), quantity::try_from_int(-1)]; let length = values.len(); }",
        );
    }
    #[test]
    fn mutable_product_list_fields_preserve_sibling_and_slot_obligations() {
        let declarations =
            "struct Holder { Result<int, bool> sibling; List<Result<int, bool>, 2> items; }";
        for body in [
            "var holder = Holder { sibling: Result::ok(9), items: [] }; holder.items.push(Result::ok(1)); let _ = holder.items.pop();",
            "var holder = Holder { sibling: Result::ok(9), items: [] }; let _ = holder.sibling; holder.items.push(Result::ok(1));",
            "var holder = Holder { sibling: Result::ok(9), items: [] }; holder.items.push(Result::ok(1)); holder.items.set(0, Result::ok(2)); let _ = holder;",
        ] {
            reject(&format!("{declarations} fn f() {{ {body} }}"));
        }
        analyze(&format!("{declarations} fn f() {{ var pair = (0, Holder {{ sibling: Result::ok(9), items: [] }}); pair.1.items.push(Result::ok(1)); let _ = pair.1.items.pop(); let _ = pair.1.sibling; }}")).unwrap();
    }
    #[test]
    fn list_mutation_retains_new_and_untouched_result_elements() {
        for body in [
            "var values = [quantity::try_from_int(1)]; values.set(index: 0, value: quantity::try_from_int(2)); let _ = values;",
            "var List<Result<quantity, NumericError>, 2> values = []; values.push(quantity::try_from_int(1));",
            "var values = [quantity::try_from_int(1), quantity::try_from_int(2)]; let _ = values.pop();",
        ] {
            reject(&format!("fn f() {{ {body} }}"));
        }
        analyze("fn f() { var values = [quantity::try_from_int(1), quantity::try_from_int(2)]; let _ = values.get(0); values.set(index: 0, value: quantity::try_from_int(3)); let _ = values.get(0); let _ = values.get(1); }").unwrap();
        analyze("fn f() { var values = [quantity::try_from_int(1), quantity::try_from_int(2)]; let _ = values.pop(); let _ = values.pop(); }").unwrap();
        analyze("fn f() { var List<Result<quantity, NumericError>, 2> values = []; let _ = values.try_push(quantity::try_from_int(1)); let _ = values; }").unwrap();
    }
    #[test]
    fn branches_loops_and_discarded_block_tails_retain_obligations() {
        for source in [
            "fn f() { if true { quantity::try_from_int(-1) } }",
            "fn f(bool flag) { let pair = (quantity::try_from_int(-1), 0); if flag { let _ = pair.0; } }",
            "fn f(bool flag) { let pair = (quantity::try_from_int(-1), 0); for i in range(1) { if flag { let _ = pair.0; } } }",
            "fn f() { let values = [quantity::try_from_int(-1)]; for value in values { let _ = value; break; } }",
            "fn f() { for value in [quantity::try_from_int(-1)] { let _ = value; break; } }",
            "fn f() { let values = [quantity::try_from_int(-1)]; let _ = [0 for value in values]; }",
            "fn f() { let values = [quantity::try_from_int(-1)]; let _ = [value for value in values if true]; }",
            "fn f() { var List<Result<quantity, NumericError>, 2> values = [quantity::try_from_int(1)]; for value in values { let _ = value; values.push(quantity::try_from_int(2)); } }",
            "fn f(bool stop) { let values = [quantity::try_from_int(1), quantity::try_from_int(2)]; let _ = [if stop { let _ = value; return; } else { value.is_ok() } for value in values]; }",
        ] {
            reject(source);
        }
        analyze("fn f(bool flag) { let pair = (quantity::try_from_int(-1), 0); if flag { let _ = pair.0; } else { let _ = pair; } }").unwrap();
        analyze("fn f() { let values = [quantity::try_from_int(-1)]; for value in values { let _ = value; } }").unwrap();
        analyze("fn f() { let values = [quantity::try_from_int(-1)]; let forwarded = [value for value in values]; let _ = forwarded; }").unwrap();
        analyze("fn f() { let values = [quantity::try_from_int(-1)]; let flags = [value.is_ok() for value in values]; }").unwrap();
    }
    #[test]
    fn nested_result_status_does_not_consume_its_success_payload() {
        reject(
            "fn f() { let Result<Result<quantity, NumericError>, NumericError> nested = Result::ok(quantity::try_from_int(-1)); let flag = nested.is_ok(); }",
        );
        reject(
            "fn f() { let Result<Result<quantity, NumericError>, NumericError> nested = Result::ok(quantity::try_from_int(-1)); if let Result::err(_) = nested { } }",
        );
        analyze("fn f() { let Result<Result<quantity, NumericError>, NumericError> nested = Result::ok(quantity::try_from_int(-1)); let flag = nested.is_ok(); let _ = nested; }").unwrap();
    }
    #[test]
    fn error_only_projection_retains_nested_success_results() {
        reject(
            "error enum E { Nope = 1 } fn f() { let Result<Result<quantity, NumericError>, E> nested = Result::ok(quantity::try_from_int(-1)); let rejected = nested.unwrap_err_or(E::Nope); }",
        );
        analyze("error enum E { Nope = 1 } fn f() { let Result<Result<quantity, NumericError>, E> nested = Result::ok(quantity::try_from_int(-1)); let rejected = nested.unwrap_err_or(E::Nope); let _ = nested; }").unwrap();
        analyze("error enum E { Nope = 1 } fn f() { let Result<quantity, E> checked = Result::err(E::Nope); let rejected = checked.unwrap_err_or(E::Nope); }").unwrap();
    }
    #[test]
    fn mutation_results_follow_evaluation_order_and_shared_list_handles() {
        for body in [
            "var values = [Option::some(quantity::try_from_int(-1)), Option::none]; (values.pop(), values.pop());",
            "var values = [Option::some(quantity::try_from_int(-1)), Option::none]; let pair = (values.pop(), values.pop());",
            "var List<Option<Result<quantity, NumericError>>, 2> values = [Option::none, Option::some(quantity::try_from_int(-1))]; let Option<Result<quantity, NumericError>> absent = Option::none; values.push(values.pop().unwrap_or(absent));",
            "var values = [Option::some(quantity::try_from_int(-1)), Option::none]; var alias = values; values.pop(); alias.pop(); let _ = alias;",
            "var values = [Option::some(quantity::try_from_int(-1)), Option::none]; let bundle = (values, 0); var alias = bundle.0; values.pop(); alias.pop(); let _ = alias;",
            "var values = [quantity::try_from_int(-1)]; var alias = values; values.set(index: 0, value: quantity::try_from_int(2)); let _ = values; let _ = alias;",
        ] {
            reject(&format!("fn f() {{ {body} }}"));
        }
        analyze("fn f() { var values = [Option::some(quantity::try_from_int(-1)), Option::none]; let _ = (values.pop(), values.pop()); }").unwrap();
        analyze("fn f() { var List<Option<Result<quantity, NumericError>>, 2> values = [Option::none, Option::some(quantity::try_from_int(-1))]; let Option<Result<quantity, NumericError>> absent = Option::none; values.push(values.pop().unwrap_or(absent)); let _ = values; }").unwrap();
        analyze("fn f() { var values = [Option::some(quantity::try_from_int(-1)), Option::none]; var alias = values; let _ = values.pop(); let _ = alias.pop(); let _ = alias; }").unwrap();
        analyze("fn f() { var values = [quantity::try_from_int(-1)]; var alias = values; let _ = alias; values.set(index: 0, value: quantity::try_from_int(2)); let _ = values; }").unwrap();
    }
    #[test]
    fn take_and_enumerate_preserve_proven_empty_and_short_shapes() {
        analyze("fn f() { let List<Result<quantity, NumericError>, 2> empty = []; let copied = empty.take(0); let length = copied.len(); let indexed = empty.enumerate(); let count = indexed.len(); }").unwrap();
        analyze("fn f() { let ints = [0]; let _ = ints; let List<Result<quantity, NumericError>, 2> empty = []; let copied = empty.take(2); let count = copied.len(); }").unwrap();
        analyze("fn f(bool flag) { let Option<Result<quantity, NumericError>> empty = if flag { Option::none } else { Option::none }; let absent = empty.is_none(); }").unwrap();
        analyze("fn f() { let List<Result<quantity, NumericError>, 2> values = [quantity::try_from_int(1)]; let copied = values.take(2); let _ = copied.get(0); }").unwrap();
    }
    fn boolean(value: bool) -> TypedExpr {
        TypedExpr {
            expr: ExprKind::Bool(value),
            ty: Type::Bool,
        }
    }
    fn statements(statements: Vec<TypedStatement>) -> TypedBlock {
        TypedBlock::new(statements, None)
    }
    #[test]
    fn sequential_forks_retain_each_loop_exit_once() {
        let mut flow = Flow::default();
        let result = Type::Result(Box::new(Type::Unit), Box::new(Type::Int));
        flow.bind("result", Shape::typed(&result)).unwrap();
        let optional = Type::Option(Box::new(result));
        flow.bind("optional", Shape::typed(&optional)).unwrap();
        let optional_value = TypedExpr {
            expr: ExprKind::Ident("optional".into()),
            ty: optional,
        };
        let none = TypedSumPattern {
            pattern: crate::ast::SumPattern {
                variant: crate::ast::SumVariant::OptionNone,
                binding: None,
            },
            variant_code: None,
            payload_type: None,
        };
        let empty = statements(Vec::new());
        let consume_optional = statements(vec![TypedStatement::Let {
            name: "_".into(),
            value: optional_value.clone(),
        }]);
        let expression_branches = [
            TypedExpr {
                expr: ExprKind::Binary {
                    op: crate::ast::BinaryOp::And,
                    left: Box::new(boolean(true)),
                    right: Box::new(boolean(false)),
                },
                ty: Type::Bool,
            },
            TypedExpr {
                expr: ExprKind::Conditional {
                    cond: Box::new(boolean(true)),
                    then_expr: Box::new(boolean(true)),
                    else_expr: Box::new(boolean(false)),
                },
                ty: Type::Bool,
            },
            TypedExpr {
                expr: ExprKind::Match {
                    value: Box::new(TypedExpr {
                        expr: ExprKind::OptionNone,
                        ty: Type::Option(Box::new(Type::Bool)),
                    }),
                    arms: vec![
                        crate::semantic::TypedMatchArm {
                            pattern: none.clone(),
                            body: empty.clone(),
                        },
                        crate::semantic::TypedMatchArm {
                            pattern: TypedSumPattern {
                                pattern: crate::ast::SumPattern {
                                    variant: crate::ast::SumVariant::OptionSome,
                                    binding: Some(crate::ast::PatternBinding::Wildcard),
                                },
                                variant_code: None,
                                payload_type: Some(Type::Bool),
                            },
                            body: empty.clone(),
                        },
                    ],
                },
                ty: Type::Unit,
            },
            TypedExpr {
                expr: ExprKind::ListComprehension {
                    source: Box::new(TypedExpr {
                        expr: ExprKind::List(Vec::new()),
                        ty: Type::List(Box::new(Type::Bool), 1),
                    }),
                    expression: Box::new(boolean(true)),
                    condition: None,
                    item: "item".into(),
                },
                ty: Type::List(Box::new(Type::Bool), 1),
            },
        ];
        for index in 0..96 {
            let exit = if index % 2 == 0 {
                TypedStatement::Break
            } else {
                TypedStatement::Continue
            };
            flow.branches(&statements(vec![exit]), None, None, false)
                .unwrap();
            assert_eq!(flow.exits.len(), index + 1);
            flow.branches(&empty, Some(&empty), None, false).unwrap();
            flow.if_let(
                &optional_value,
                &none,
                &empty,
                Some(&consume_optional),
                false,
            )
            .unwrap();
            for expression in &expression_branches {
                flow.expression(expression).unwrap();
                assert_eq!(flow.exits.len(), index + 1);
            }
            assert!(
                flow.exits
                    .iter()
                    .all(|exit| { exit.pending.iter().any(|pending| pending.name == "result") })
            );
        }
        assert_eq!(flow.exits.iter().filter(|exit| exit.continuing).count(), 48);
        assert_eq!(flow.check_exit().unwrap_err().code(), "E_RESULT_MUST_USE");
    }
    #[test]
    fn inner_loops_do_not_reinterpret_outer_break_or_continue_paths() {
        let empty = statements(Vec::new());
        let inner_loops = [
            TypedStatement::While {
                cond: boolean(true),
                body: empty.clone(),
            },
            TypedStatement::For {
                line: 1,
                init: None,
                cond: Some(boolean(true)),
                step: None,
                body: empty.clone(),
            },
            TypedStatement::ForEachMap {
                key: "item".into(),
                value: None,
                map: TypedExpr {
                    expr: ExprKind::List(Vec::new()),
                    ty: Type::List(Box::new(Type::Bool), 1),
                },
                body: empty,
            },
        ];
        for continuing in [false, true] {
            for inner in &inner_loops {
                let mut flow = Flow::default();
                flow.bind(
                    "result",
                    Shape::typed(&Type::Result(Box::new(Type::Unit), Box::new(Type::Int))),
                )
                .unwrap();
                let exit = if continuing {
                    TypedStatement::Continue
                } else {
                    TypedStatement::Break
                };
                flow.branches(&statements(vec![exit]), None, None, false)
                    .unwrap();
                flow.consume(&Place {
                    name: "result".into(),
                    path: Vec::new(),
                });
                flow.statement(inner).unwrap();
                flow.check_exit()
                    .expect("the live path consumed its Result");
                assert_eq!(flow.exits.len(), 1);
                assert_eq!(flow.exits[0].continuing, continuing);
                assert_eq!(flow.exits[0].pending.len(), 1);
                assert_eq!(flow.exits[0].pending.first().unwrap().name, "result");
            }
        }
    }
    #[test]
    fn earlier_loop_exits_still_reject_unread_scoped_and_pattern_results() {
        for exit in ["break", "continue", "return"] {
            reject(&format!(
                "fn f(bool stop) {{ for i in range(2) {{ let result = quantity::try_from_int(i); if stop {{ {exit}; }} for j in range(1) {{ }} let _ = result; }} }}"
            ));
            reject(&format!(
                "fn f(bool stop) {{ for i in range(2) {{ let optional = Option::some(quantity::try_from_int(i)); if let Option::some(result) = optional {{ if stop {{ {exit}; }} for j in range(1) {{ }} let _ = result; }} }} }}"
            ));
            analyze(&format!(
                "fn f(bool stop) {{ for i in range(2) {{ let result = quantity::try_from_int(i); if stop {{ let _ = result; {exit}; }} for j in range(1) {{ }} let _ = result; }} }}"
            ))
            .unwrap();
        }
        let branches = "if stop { continue; } if stop { break; } ".repeat(64);
        analyze(&format!(
            "fn f(bool stop) {{ for i in range(2) {{ {branches} let _ = quantity::try_from_int(i); }} }}"
        ))
        .unwrap();
    }
    #[test]
    fn sequential_joins_do_not_enumerate_combinations_of_unread_slots() {
        let mut flow = Flow::default();
        flow.bind(
            "values",
            Shape::typed(&Type::List(
                Box::new(Type::Result(Box::new(Type::Unit), Box::new(Type::Int))),
                64,
            )),
        )
        .unwrap();
        for pair in 0..32 {
            let mut left = flow.fork();
            let mut right = flow.fork();
            left.consume(&Place {
                name: "values".into(),
                path: vec![Part::slot(pair * 2)],
            });
            right.consume(&Place {
                name: "values".into(),
                path: vec![Part::slot(pair * 2 + 1)],
            });
            flow.join([left, right]);
            assert_eq!(flow.pending.len(), 1);
            assert_eq!(
                flow.pending.first().unwrap().path,
                vec![Part::Slots(u64::MAX)]
            );
        }
        for index in 0..64 {
            flow.consume(&Place {
                name: "values".into(),
                path: vec![Part::slot(index)],
            });
        }
        flow.check_exit().unwrap();
        let diagonal = BTreeSet::from([
            vec![Part::slot(0), Part::slot(0)],
            vec![Part::slot(1), Part::slot(1)],
        ]);
        assert_eq!(
            normalize(diagonal.clone()),
            diagonal,
            "exact small correlations survive"
        );
        let many = (0..129)
            .map(|index| vec![Part::slot(index % 64), Part::slot(index / 64)])
            .collect();
        let widened = normalize(many);
        assert_eq!(widened.len(), 1);
        for index in 0..129 {
            assert!(under(
                widened.first().unwrap(),
                &[Part::slot(index % 64), Part::slot(index / 64)]
            ));
        }
    }
    #[test]
    fn nested_list_obligations_have_symbolic_bounded_size() {
        let mut result = Type::Result(Box::new(Type::Unit), Box::new(Type::Int));
        let mut scalar = Type::Int;
        for _ in 0..24 {
            result = Type::List(Box::new(result), 64);
            scalar = Type::List(Box::new(scalar), 64);
        }
        let shape = Shape::typed(&result);
        assert_eq!(shape.results.len(), 1);
        assert_eq!(shape.results.first().unwrap().len(), 24);
        assert!(Shape::typed(&scalar).results.is_empty());
        let selected = vec![Part::slot(0); 24];
        let remaining = remainder(shape.results.first().unwrap(), &selected);
        assert_eq!(remaining.len(), 24);
        assert!(remaining.iter().all(|path| path.len() == 24));
        assert!(remaining.iter().all(|path| !under(path, &selected)));
        assert!(remainder(shape.results.first().unwrap(), &[]).is_empty());
        let mut source_type = "Result<quantity, NumericError>".to_owned();
        for _ in 0..8 {
            source_type = format!("List<{source_type}, 64>");
        }
        analyze(&format!("fn f({source_type} values) {{ let _ = values; }}")).unwrap();
        assert_eq!(Part::slot(64), Part::Slots(0));
        assert_eq!(Part::slot(4_294_967_296), Part::Slots(0));
        let huge = TypedExpr {
            expr: ExprKind::IntLiteral("340282366920938463463374607431768211455".parse().unwrap()),
            ty: Type::Int,
        };
        assert_eq!(constant_index(&huge), Some(usize::MAX));
    }
    #[test]
    fn only_compiler_owned_binding_names_are_classified_as_synthetic() {
        assert_eq!(
            aggregate_binding_origin("__kotodama_hidden"),
            ("__kotodama_hidden", vec![], false)
        );
        assert_eq!(
            aggregate_binding_origin("\0aggregate_capture#12"),
            ("\0aggregate_capture#12", vec![], true)
        );
        assert_eq!(
            aggregate_binding_origin("\0aggregate_capture#12#2#0"),
            ("\0aggregate_capture#12", vec![2, 0], true)
        );
        assert_eq!(
            aggregate_binding_origin("bundle#1#0"),
            ("bundle", vec![1, 0], false)
        );
    }
}
