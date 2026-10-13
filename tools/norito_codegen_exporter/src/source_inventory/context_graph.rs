//! Physical module/include ownership contexts, never canonical schema names.
//!
//! Module directories follow the [Rust Reference](https://doc.rust-lang.org/reference/items/modules.html#the-path-attribute).
//! In particular, explicit file paths and item includes reset the default child
//! directory to the loaded file's parent. Small rustc fixtures test these rules.

use std::{collections::BTreeMap, rc::Rc};

use super::*;
use syn::ext::IdentExt as _;

const MAX_CONTEXTS: usize = 50_000;
const MAX_DEPTH: usize = 128;

/// A bounded source-access graph for explicitly selected crate roots.
#[derive(JsonSerialize)]
pub struct ContextGraph {
    schema: u32,
    qualification: &'static str,
    source_set_sha256: String,
    roots: Vec<String>,
    /// Physical syntax records occur once even when a file has several owners.
    pub files: Vec<FileInventory>,
    contexts: Vec<Context>,
    edges: Vec<Edge>,
    review: Vec<Review>,
    /// Syntax errors in roots or ordinary modules, excluding include fragments.
    pub invalid_sources: bool,
}

#[derive(Clone, JsonSerialize)]
struct Site {
    file: String,
    span: SourceSpan,
}

#[derive(Clone, JsonSerialize)]
struct Context {
    id: usize,
    root: usize,
    parent: Option<usize>,
    kind: String,
    file: String,
    /// Lexical labels only; neither crate names nor compiler nominal names.
    lexical_modules: Vec<String>,
    origin: Option<Site>,
    module_directory: String,
    path_attribute_directory: String,
    conditions: Vec<String>,
    local_block: bool,
    state: String,
}

#[derive(JsonSerialize)]
struct Edge {
    from: usize,
    to: Option<usize>,
    kind: String,
    site: Site,
    literal: Option<String>,
    candidates: Vec<String>,
    conditions: Vec<String>,
    state: String,
}

#[derive(JsonSerialize)]
struct Review {
    kind: String,
    context: usize,
    site: Option<Site>,
    related_contexts: Vec<usize>,
    reason: String,
}

struct Loaded {
    source: String,
    syntax: Option<syn::File>,
    record: FileInventory,
}

struct Builder {
    root: PathBuf,
    loaded: BTreeMap<String, Rc<Loaded>>,
    contexts: Vec<Context>,
    edges: Vec<Edge>,
    review: Vec<Review>,
    active_files: Vec<(String, usize)>,
    inclusions: BTreeMap<String, Vec<usize>>,
    lookups: BTreeMap<PathBuf, bool>,
    invalid_sources: bool,
}

fn spelling(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("graph paths must be UTF-8")?
        .replace('\\', "/"))
}

fn predicates(source: &str, attrs: &[Attribute]) -> Result<Vec<String>> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
        .map(|attr| source_span(source, attr.span()).map(|span| span.source))
        .collect()
}

/// None means an ordinary lookup; Err retains dynamic/conditional paths for review.
fn explicit_path(attrs: &[Attribute]) -> Result<Option<String>> {
    let mut paths = Vec::new();
    for attr in attrs {
        if attr.path().is_ident("cfg_attr") {
            // A cfg_attr can itself expand to another cfg_attr, path or macro.
            // Do not choose a current path by pretending configuration is known.
            bail!("conditional module attributes require an explicit configuration review");
        }
        if attr.path().is_ident("path") {
            if let Meta::NameValue(pair) = &attr.meta
                && let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(value),
                    ..
                }) = &pair.value
            {
                paths.push(value.value());
                continue;
            }
            bail!("module path is not one string literal");
        }
    }
    match paths.as_slice() {
        [] => Ok(None),
        [path] if !path.is_empty() => Ok(Some(path.clone())),
        _ => bail!("module has empty or multiple path attributes"),
    }
}

impl Builder {
    fn note(&mut self, kind: &str, context: usize, site: Option<Site>, reason: impl Into<String>) {
        self.review.push(Review {
            kind: kind.to_owned(),
            context,
            site,
            related_contexts: Vec::new(),
            reason: reason.into(),
        });
    }

    fn site(file: &Loaded, span: Span) -> Result<Site> {
        Ok(Site {
            file: file.record.path.clone(),
            span: source_span(&file.source, span)?,
        })
    }

    fn resolve(&self, base: &Path, literal: &str) -> Result<PathBuf> {
        let input = Path::new(literal);
        if input.is_absolute() || literal.is_empty() {
            bail!("path must be nonempty and repository-relative");
        }
        let mut resolved = PathBuf::new();
        // Inspect symlinks before reducing '..', including base components.
        for part in base.components().chain(input.components()) {
            match part {
                Component::Normal(value) => resolved.push(value),
                Component::CurDir => continue,
                Component::ParentDir => {
                    if !self.root.join(&resolved).is_dir() {
                        bail!("parent traversal requires an existing directory");
                    }
                    if !resolved.pop() {
                        bail!("path escapes the repository");
                    }
                    continue;
                }
                _ => bail!("path escapes the repository"),
            }
            match fs::symlink_metadata(self.root.join(&resolved)) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    bail!("source symlinks require explicit review")
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(resolved)
    }

    fn exists(&mut self, path: &Path) -> Result<bool> {
        let present = match fs::symlink_metadata(self.root.join(path)) {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => true,
            Ok(_) => bail!("source candidate is not a regular file: {}", path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if self
            .lookups
            .insert(path.to_owned(), present)
            .is_some_and(|before| before != present)
        {
            bail!("module candidates changed during graph traversal");
        }
        Ok(present)
    }

    fn load(&mut self, path: &Path) -> Result<Rc<Loaded>> {
        let name = spelling(path)?;
        if let Some(loaded) = self.loaded.get(&name) {
            return Ok(Rc::clone(loaded));
        }
        let path = self.resolve(Path::new(""), &name)?;
        let metadata = fs::symlink_metadata(self.root.join(&path))?;
        if !metadata.is_file() {
            bail!("source must be a regular file: {name}");
        }
        let source = fs::read_to_string(self.root.join(path))?;
        let syntax = syn::parse_file(&source).ok();
        let record = inspect_source(&name, &source)?;
        let loaded = Rc::new(Loaded {
            source,
            syntax,
            record,
        });
        self.loaded.insert(name, Rc::clone(&loaded));
        Ok(loaded)
    }

    fn new_context(&mut self, mut context: Context) -> Result<usize> {
        if self.contexts.len() >= MAX_CONTEXTS {
            bail!("source context count exceeds {MAX_CONTEXTS}; narrow crate-root selections");
        }
        context.id = self.contexts.len();
        let id = context.id;
        self.contexts.push(context);
        Ok(id)
    }

    fn enter_file(&mut self, id: usize, allow_items: bool) -> Result<()> {
        let context = self.contexts[id].clone();
        let loaded = self.load(Path::new(&context.file))?;
        if let Some(syntax) = &loaded.syntax {
            self.contexts[id]
                .conditions
                .extend(predicates(&loaded.source, &syntax.attrs)?);
        }
        let prior = self.inclusions.entry(context.file.clone()).or_default();
        if !prior.is_empty() {
            self.review.push(Review { kind: "multiple_inclusion".to_owned(), context: id,
                site: context.origin.clone(), related_contexts: prior.clone(),
                reason: "one physical source has several access contexts; capture selection must name the intended context, not deduplicate owners".to_owned() });
        }
        prior.push(id);
        if let Some((_, ancestor)) = self
            .active_files
            .iter()
            .find(|(file, _)| *file == context.file)
        {
            "cycle".clone_into(&mut self.contexts[id].state);
            self.review.push(Review { kind: "cycle".to_owned(), context: id, site: context.origin,
                related_contexts: vec![*ancestor], reason: "source is already active on this inclusion path; traversal stops without expanding the cycle".to_owned() });
            return Ok(());
        }
        if !allow_items || loaded.syntax.is_none() {
            "parse_review".clone_into(&mut self.contexts[id].state);
            self.note("parse_fragment", id, context.origin,
                "this source has no supported item-file parse in this position; expression/statement/type fragments and macro expansion require separate review");
            if context.kind == "crate_root" || context.kind == "external_module" {
                self.invalid_sources = true;
            }
            return Ok(());
        }
        if self.active_files.len() >= MAX_DEPTH {
            "depth_limit".clone_into(&mut self.contexts[id].state);
            self.note(
                "depth_limit",
                id,
                context.origin,
                "source access depth exceeds the bounded traversal limit",
            );
            return Ok(());
        }
        self.active_files.push((context.file, id));
        "visited".clone_into(&mut self.contexts[id].state);
        let mut visitor = AccessVisitor {
            builder: self,
            loaded: Rc::clone(&loaded),
            context: id,
            conditions: Vec::new(),
            local_depth: usize::from(context.local_block),
            error: None,
        };
        visitor.conditions = visitor.builder.contexts[id].conditions.clone();
        visitor.visit_file(loaded.syntax.as_ref().expect("item-file parse checked"));
        let error = visitor.error.take();
        self.active_files.pop();
        error.map_or(Ok(()), Err)
    }

    fn module(
        &mut self,
        parent: usize,
        loaded: Rc<Loaded>,
        item: &syn::ItemMod,
        conditions: &[String],
        local: bool,
    ) -> Result<()> {
        let owner = self.contexts[parent].clone();
        let site = Self::site(&loaded, item.span())?;
        let kind = if item.content.is_some() {
            "inline_module"
        } else {
            "external_module"
        };
        let filename = item.ident.unraw().to_string();
        let mut edge = Edge {
            from: parent,
            to: None,
            kind: kind.to_owned(),
            site: site.clone(),
            literal: None,
            candidates: Vec::new(),
            conditions: conditions.to_vec(),
            state: "review".to_owned(),
        };
        let mut names = owner.lexical_modules.clone();
        names.push(item.ident.to_string());
        let result = (|| -> Result<(PathBuf, bool)> {
            let explicit = explicit_path(&item.attrs)?;
            edge.literal.clone_from(&explicit);
            if local && item.content.is_none() && explicit.is_none() {
                bail!(
                    "an ordinary external module in a local block has no unambiguous file ownership"
                );
            }
            if let Some(path) = explicit {
                let candidate = self.resolve(Path::new(&owner.path_attribute_directory), &path)?;
                edge.candidates.push(spelling(&candidate)?);
                if item.content.is_none() && !self.exists(&candidate)? {
                    bail!("literal module file is missing");
                }
                Ok((candidate, true))
            } else if item.content.is_some() {
                Ok((
                    self.resolve(Path::new(&owner.module_directory), &filename)?,
                    false,
                ))
            } else {
                let base = Path::new(&owner.module_directory);
                let flat = self.resolve(base, &format!("{filename}.rs"))?;
                let nested = self.resolve(base, &format!("{filename}/mod.rs"))?;
                edge.candidates = vec![spelling(&flat)?, spelling(&nested)?];
                match (self.exists(&flat)?, self.exists(&nested)?) {
                    (true, false) => Ok((flat, false)),
                    (false, true) => Ok((nested, false)),
                    (true, true) => bail!("both name.rs and name/mod.rs exist"),
                    (false, false) => bail!("neither name.rs nor name/mod.rs exists"),
                }
            }
        })();
        let (path, explicit) = match result {
            Ok(result) => result,
            Err(error) => {
                self.note("module_path", parent, Some(site), error.to_string());
                self.edges.push(edge);
                return Ok(());
            }
        };
        let inline = item.content.is_some();
        let module_dir = if inline {
            path.clone()
        } else if explicit || path.file_name().is_some_and(|name| name == "mod.rs") {
            path.parent().unwrap_or_else(|| Path::new("")).to_owned()
        } else {
            path.with_extension("")
        };
        let path_dir = if inline {
            module_dir.clone()
        } else {
            path.parent().unwrap_or_else(|| Path::new("")).to_owned()
        };
        let id = self.new_context(Context {
            id: 0,
            root: owner.root,
            parent: Some(parent),
            kind: kind.to_owned(),
            file: if inline { owner.file } else { spelling(&path)? },
            lexical_modules: names,
            origin: Some(site),
            module_directory: spelling(&module_dir)?,
            path_attribute_directory: spelling(&path_dir)?,
            conditions: conditions.to_vec(),
            local_block: local,
            state: "visited".to_owned(),
        })?;
        edge.to = Some(id);
        "resolved".clone_into(&mut edge.state);
        self.edges.push(edge);
        if let Some((_, items)) = &item.content {
            let mut visitor = AccessVisitor {
                builder: self,
                loaded,
                context: id,
                conditions: conditions.to_vec(),
                local_depth: usize::from(local),
                error: None,
            };
            for child in items {
                visitor.visit_item(child);
            }
            if let Some(error) = visitor.error {
                return Err(error);
            }
            Ok(())
        } else {
            self.enter_file(id, true)
        }
    }

    fn inclusion(
        &mut self,
        parent: usize,
        loaded: &Loaded,
        value: &syn::Macro,
        conditions: &[String],
        items: bool,
        local: bool,
    ) -> Result<()> {
        let owner = self.contexts[parent].clone();
        let site = Self::site(loaded, value.span())?;
        let mut edge = Edge {
            from: parent,
            to: None,
            kind: "include".to_owned(),
            site: site.clone(),
            literal: None,
            candidates: Vec::new(),
            conditions: conditions.to_vec(),
            state: "review".to_owned(),
        };
        let result = (|| -> Result<PathBuf> {
            let literal = value
                .parse_body::<syn::LitStr>()
                .context("include argument is not one string literal")?
                .value();
            edge.literal = Some(literal.clone());
            let path = self.resolve(
                Path::new(&owner.file)
                    .parent()
                    .unwrap_or_else(|| Path::new("")),
                &literal,
            )?;
            edge.candidates.push(spelling(&path)?);
            if !self.exists(&path)? {
                bail!("literal include file is missing");
            }
            Ok(path)
        })();
        match result {
            Err(error) => {
                self.note("include_path", parent, Some(site), error.to_string());
                self.edges.push(edge);
            }
            Ok(path) => {
                let directory = spelling(path.parent().unwrap_or_else(|| Path::new("")))?;
                let id = self.new_context(Context {
                    id: 0,
                    root: owner.root,
                    parent: Some(parent),
                    kind: "include".to_owned(),
                    file: spelling(&path)?,
                    lexical_modules: owner.lexical_modules,
                    origin: Some(site),
                    module_directory: directory.clone(),
                    path_attribute_directory: directory,
                    conditions: conditions.to_vec(),
                    local_block: local,
                    state: "pending".to_owned(),
                })?;
                edge.to = Some(id);
                "resolved".clone_into(&mut edge.state);
                self.edges.push(edge);
                self.enter_file(id, items)?;
            }
        }
        Ok(())
    }
}

struct AccessVisitor<'a> {
    builder: &'a mut Builder,
    loaded: Rc<Loaded>,
    context: usize,
    conditions: Vec<String>,
    local_depth: usize,
    error: Option<anyhow::Error>,
}

impl AccessVisitor<'_> {
    fn scoped_attributes(&mut self, attrs: &[Attribute], visit: impl FnOnce(&mut Self)) {
        if self.error.is_some() {
            return;
        }
        let previous = self.conditions.len();
        match self.attributes(attrs) {
            Ok(()) => visit(self),
            Err(error) => self.error = Some(error),
        }
        self.conditions.truncate(previous);
    }

    fn attributes(&mut self, attrs: &[Attribute]) -> Result<()> {
        self.conditions
            .extend(predicates(&self.loaded.source, attrs)?);
        for attr in attrs {
            if !matches!(
                path_text(attr.path()).as_str(),
                "cfg"
                    | "doc"
                    | "allow"
                    | "warn"
                    | "deny"
                    | "forbid"
                    | "expect"
                    | "path"
                    | "derive"
                    | "repr"
                    | "inline"
                    | "test"
                    | "must_use"
                    | "non_exhaustive"
                    | "deprecated"
            ) {
                let site = Builder::site(&self.loaded, attr.span())?;
                self.builder.note("unexpanded_attribute", self.context, Some(site), "conditional/helper/procedural attributes remain source evidence, not evaluated ownership");
            }
        }
        Ok(())
    }

    fn mac(&mut self, value: &syn::Macro, items: bool) -> Result<()> {
        if value.path.is_ident("include") {
            self.builder.inclusion(
                self.context,
                &self.loaded,
                value,
                &self.conditions,
                items,
                self.local_depth > 0,
            )
        } else {
            let site = Builder::site(&self.loaded, value.span())?;
            self.builder.note("macro_expansion", self.context, Some(site), "macro tokens may generate access paths; no module/include ownership is inferred from their bodies");
            Ok(())
        }
    }
}

impl<'ast> Visit<'ast> for AccessVisitor<'_> {
    fn visit_expr(&mut self, value: &'ast syn::Expr) {
        self.scoped_attributes(expression_attributes(value), |this| {
            syn::visit::visit_expr(this, value)
        });
    }

    fn visit_local(&mut self, value: &'ast syn::Local) {
        self.scoped_attributes(&value.attrs, |this| syn::visit::visit_local(this, value));
    }

    fn visit_stmt_macro(&mut self, value: &'ast syn::StmtMacro) {
        self.scoped_attributes(&value.attrs, |this| {
            syn::visit::visit_stmt_macro(this, value)
        });
    }

    fn visit_field(&mut self, value: &'ast syn::Field) {
        self.scoped_attributes(&value.attrs, |this| syn::visit::visit_field(this, value));
    }

    fn visit_variant(&mut self, value: &'ast syn::Variant) {
        self.scoped_attributes(&value.attrs, |this| syn::visit::visit_variant(this, value));
    }

    fn visit_impl_item(&mut self, value: &'ast syn::ImplItem) {
        let attrs = match value {
            syn::ImplItem::Const(value) => &value.attrs,
            syn::ImplItem::Fn(value) => &value.attrs,
            syn::ImplItem::Type(value) => &value.attrs,
            syn::ImplItem::Macro(value) => &value.attrs,
            _ => &Vec::new(),
        };
        self.scoped_attributes(attrs, |this| syn::visit::visit_impl_item(this, value));
    }

    fn visit_trait_item(&mut self, value: &'ast syn::TraitItem) {
        let attrs = match value {
            syn::TraitItem::Const(value) => &value.attrs,
            syn::TraitItem::Fn(value) => &value.attrs,
            syn::TraitItem::Type(value) => &value.attrs,
            syn::TraitItem::Macro(value) => &value.attrs,
            _ => &Vec::new(),
        };
        self.scoped_attributes(attrs, |this| syn::visit::visit_trait_item(this, value));
    }

    fn visit_item(&mut self, item: &'ast Item) {
        if self.error.is_some() {
            return;
        }
        let previous = self.conditions.len();
        let result = self
            .attributes(item_attributes(item))
            .and_then(|()| match item {
                Item::Mod(value) => self.builder.module(
                    self.context,
                    Rc::clone(&self.loaded),
                    value,
                    &self.conditions,
                    self.local_depth > 0,
                ),
                Item::Macro(value) => self.mac(&value.mac, self.local_depth == 0),
                _ => {
                    syn::visit::visit_item(self, item);
                    Ok(())
                }
            });
        if let Err(error) = result {
            self.error = Some(error);
        }
        self.conditions.truncate(previous);
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.local_depth += 1;
        syn::visit::visit_block(self, block);
        self.local_depth -= 1;
    }

    fn visit_macro(&mut self, value: &'ast syn::Macro) {
        if self.error.is_none()
            && let Err(error) = self.mac(value, false)
        {
            self.error = Some(error);
        }
    }
}

fn expression_attributes(value: &syn::Expr) -> &[Attribute] {
    match value {
        syn::Expr::Array(value) => &value.attrs,
        syn::Expr::Assign(value) => &value.attrs,
        syn::Expr::Async(value) => &value.attrs,
        syn::Expr::Await(value) => &value.attrs,
        syn::Expr::Binary(value) => &value.attrs,
        syn::Expr::Block(value) => &value.attrs,
        syn::Expr::Break(value) => &value.attrs,
        syn::Expr::Call(value) => &value.attrs,
        syn::Expr::Cast(value) => &value.attrs,
        syn::Expr::Closure(value) => &value.attrs,
        syn::Expr::Const(value) => &value.attrs,
        syn::Expr::Continue(value) => &value.attrs,
        syn::Expr::Field(value) => &value.attrs,
        syn::Expr::ForLoop(value) => &value.attrs,
        syn::Expr::Group(value) => &value.attrs,
        syn::Expr::If(value) => &value.attrs,
        syn::Expr::Index(value) => &value.attrs,
        syn::Expr::Infer(value) => &value.attrs,
        syn::Expr::Let(value) => &value.attrs,
        syn::Expr::Lit(value) => &value.attrs,
        syn::Expr::Loop(value) => &value.attrs,
        syn::Expr::Macro(value) => &value.attrs,
        syn::Expr::Match(value) => &value.attrs,
        syn::Expr::MethodCall(value) => &value.attrs,
        syn::Expr::Paren(value) => &value.attrs,
        syn::Expr::Path(value) => &value.attrs,
        syn::Expr::Range(value) => &value.attrs,
        syn::Expr::RawAddr(value) => &value.attrs,
        syn::Expr::Reference(value) => &value.attrs,
        syn::Expr::Repeat(value) => &value.attrs,
        syn::Expr::Return(value) => &value.attrs,
        syn::Expr::Struct(value) => &value.attrs,
        syn::Expr::Try(value) => &value.attrs,
        syn::Expr::TryBlock(value) => &value.attrs,
        syn::Expr::Tuple(value) => &value.attrs,
        syn::Expr::Unary(value) => &value.attrs,
        syn::Expr::Unsafe(value) => &value.attrs,
        syn::Expr::While(value) => &value.attrs,
        syn::Expr::Yield(value) => &value.attrs,
        _ => &[],
    }
}

/// Traverse physical access from crate roots without selecting cfgs or expanding macros.
pub fn inventory_contexts(root: &Path, roots: &[PathBuf]) -> Result<ContextGraph> {
    if roots.is_empty() {
        bail!("at least one crate root is required");
    }
    let mut builder = Builder {
        root: root.canonicalize()?,
        loaded: BTreeMap::new(),
        contexts: Vec::new(),
        edges: Vec::new(),
        review: Vec::new(),
        active_files: Vec::new(),
        inclusions: BTreeMap::new(),
        lookups: BTreeMap::new(),
        invalid_sources: false,
    };
    let mut selections = Vec::new();
    for (index, root) in roots.iter().enumerate() {
        normalized_relative(root)?;
        let root = builder.resolve(Path::new(""), &spelling(root)?)?;
        let file = spelling(&root)?;
        selections.push(file.clone());
        let directory = spelling(root.parent().unwrap_or_else(|| Path::new("")))?;
        let context = builder.new_context(Context {
            id: 0,
            root: index,
            parent: None,
            kind: "crate_root".to_owned(),
            file,
            lexical_modules: Vec::new(),
            origin: None,
            module_directory: directory.clone(),
            path_attribute_directory: directory,
            conditions: Vec::new(),
            local_block: false,
            state: "pending".to_owned(),
        })?;
        builder.enter_file(context, true)?;
    }
    for (path, expected) in &builder.lookups {
        let resolved = builder.resolve(Path::new(""), &spelling(path)?)?;
        if builder.root.join(resolved).is_file() != *expected {
            bail!("module candidates changed during graph traversal");
        }
    }
    let mut files = Vec::new();
    let mut hash = Sha256::new();
    let loaded_files = std::mem::take(&mut builder.loaded);
    for (path, loaded) in loaded_files {
        let resolved = builder.resolve(Path::new(""), &path)?;
        let source = fs::read(builder.root.join(resolved))?;
        if hex::encode(Sha256::digest(&source)) != loaded.record.sha256 {
            bail!("source changed during graph traversal: {path}");
        }
        hash.update((path.len() as u64).to_le_bytes());
        hash.update(path.as_bytes());
        hash.update(Sha256::digest(&source));
        let loaded = Rc::try_unwrap(loaded)
            .map_err(|_| anyhow::anyhow!("source visitor retained a live file context"))?;
        files.push(loaded.record);
    }
    Ok(ContextGraph {
        schema: 1,
        qualification: "unexpanded source ownership/access graph; lexical module labels are not canonical schema names; cfg evaluation, fragment/macro expansion, semantic resolution and compiler closure remain pending",
        source_set_sha256: hex::encode(hash.finalize()),
        roots: selections,
        files,
        contexts: builder.contexts,
        edges: builder.edges,
        review: builder.review,
        invalid_sources: builder.invalid_sources,
    })
}

#[cfg(test)]
mod tests;
