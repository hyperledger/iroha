//! Source-bound syntax inventory, deliberately separate from compiler capture.

pub mod context_graph;

use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use norito::derive::JsonSerialize;
use proc_macro2::Span;
use sha2::{Digest, Sha256};
use syn::{
    Attribute, GenericParam, Item, Meta, Path as SynPath, Stmt, Token, UseTree, parse::Parser as _,
    punctuated::Punctuated, spanned::Spanned as _, visit::Visit,
};

/// Physical source inventory; this never asserts expanded codec closure.
#[derive(JsonSerialize)]
pub struct Inventory {
    schema: u32,
    qualification: &'static str,
    source_set_sha256: String,
    selections: Vec<String>,
    excluded_directories: Vec<String>,
    /// Parsed and explicitly unparsed selected source files.
    pub files: Vec<FileInventory>,
}

/// Exact UTF-8 bytes represented by a source span, excluding any inferred name.
#[derive(Clone, Debug, JsonSerialize)]
struct SourceSpan {
    start_byte: usize,
    end_byte: usize,
    source: String,
}

#[derive(Clone, Debug, JsonSerialize)]
struct SourceRange {
    start_byte: usize,
    end_byte: usize,
}

impl From<&SourceSpan> for SourceRange {
    fn from(span: &SourceSpan) -> Self {
        Self {
            start_byte: span.start_byte,
            end_byte: span.end_byte,
        }
    }
}

/// One lexical enclosure, including function/block scopes and unexpanded attributes.
#[derive(Clone, Debug, JsonSerialize)]
struct Scope {
    kind: String,
    identifier: Option<String>,
    span: SourceRange,
    attributes: Vec<SourceSpan>,
}

#[derive(Clone, Debug, JsonSerialize)]
struct GenericSlot {
    kind: String,
    identifier: String,
    span: SourceSpan,
}

/// Span fields can seed the patch helper after independent compiler capture/review.
#[derive(Clone, Debug, JsonSerialize)]
struct MappingAnchor {
    start_byte: usize,
    end_byte: usize,
    anchor: String,
    kind: String,
    identifier: String,
}

#[derive(Clone, Debug, JsonSerialize)]
struct IdentityLiteral {
    kind: String,
    nominal: Option<String>,
    frame: Option<String>,
    span: SourceSpan,
    conditions: Vec<String>,
}

#[derive(Clone, Debug, JsonSerialize)]
struct TypeDeclaration {
    kind: String,
    identifier: String,
    span: SourceSpan,
    mapping_anchor: Option<MappingAnchor>,
    generics: Vec<GenericSlot>,
    where_clause: Option<SourceSpan>,
    attributes: Vec<SourceSpan>,
    conditions: Vec<String>,
    scopes: Vec<Scope>,
    derives: Vec<PathSite>,
    declared_literals: Vec<IdentityLiteral>,
}

#[derive(Clone, Debug, JsonSerialize)]
struct Binding {
    local_name: String,
    written_path: String,
    conditions: Vec<String>,
    span: SourceSpan,
}

#[derive(Clone, Debug, JsonSerialize)]
struct PathSite {
    written_path: String,
    span: SourceSpan,
    candidate_families: Vec<String>,
    lexical_import_candidates: Vec<Binding>,
    resolution: String,
    conditions: Vec<String>,
}

#[derive(Clone, Debug, JsonSerialize)]
struct ManualImpl {
    span: SourceSpan,
    self_type: SourceSpan,
    generics: Vec<GenericSlot>,
    where_clause: Option<SourceSpan>,
    trait_site: Option<PathSite>,
    attributes: Vec<SourceSpan>,
    conditions: Vec<String>,
    scopes: Vec<Scope>,
}

#[derive(Clone, Debug, JsonSerialize)]
struct Reference {
    kind: String,
    written_path: String,
    literal_path: Option<String>,
    span: SourceSpan,
    conditions: Vec<String>,
    scopes: Vec<Scope>,
}

#[derive(Clone, Debug, JsonSerialize)]
struct AttributeSite {
    span: SourceSpan,
    conditions: Vec<String>,
    scopes: Vec<Scope>,
}

#[derive(Clone, Debug, JsonSerialize)]
struct Unresolved {
    kind: String,
    reason: String,
    span: SourceSpan,
    conditions: Vec<String>,
    scopes: Vec<Scope>,
}

/// One selected physical file, including parse errors rather than partial success.
#[derive(JsonSerialize)]
pub struct FileInventory {
    path: String,
    sha256: String,
    bytes: usize,
    /// A file-level syntax error prevents declaration coverage for this file.
    pub parse_error: Option<String>,
    declarations: Vec<TypeDeclaration>,
    implementations: Vec<ManualImpl>,
    imports: Vec<Binding>,
    attributes: Vec<AttributeSite>,
    references: Vec<Reference>,
    unresolved: Vec<Unresolved>,
}

fn source_span(source: &str, span: Span) -> Result<SourceSpan> {
    let range = span.byte_range();
    let text = source
        .get(range.clone())
        .context("parser span is not a UTF-8 source range")?;
    Ok(SourceSpan {
        start_byte: range.start,
        end_byte: range.end,
        source: text.to_owned(),
    })
}

fn path_text(path: &SynPath) -> String {
    let mut result = if path.leading_colon.is_some() {
        "::".to_owned()
    } else {
        String::new()
    };
    result.push_str(
        &path
            .segments
            .iter()
            .map(|part| part.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
    );
    result
}

fn family(path: &str) -> Option<&'static str> {
    match path.rsplit("::").next()? {
        "Encode" | "NoritoSerialize" => Some("serialize"),
        "Decode" | "NoritoDeserialize" => Some("deserialize"),
        "NoritoSchema" => Some("identity"),
        _ => None,
    }
}

fn item_attributes(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn cfg_conditions(source: &str, attrs: &[Attribute]) -> Result<Vec<String>> {
    attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("cfg"))
        .map(|attribute| source_span(source, attribute.span()).map(|span| span.source))
        .collect()
}

fn flatten_use(
    source: &str,
    tree: &UseTree,
    prefix: &str,
    conditions: &[String],
    out: &mut Vec<Binding>,
) -> Result<()> {
    let target = |name: &str| {
        if prefix.is_empty() {
            name.to_owned()
        } else if prefix == "::" {
            format!("::{name}")
        } else {
            format!("{prefix}::{name}")
        }
    };
    match tree {
        UseTree::Path(path) => flatten_use(
            source,
            &path.tree,
            &target(&path.ident.to_string()),
            conditions,
            out,
        )?,
        UseTree::Group(group) => {
            for tree in &group.items {
                flatten_use(source, tree, prefix, conditions, out)?;
            }
        }
        UseTree::Name(name) => {
            let (local_name, written_path) = if name.ident == "self" {
                (
                    prefix.rsplit("::").next().unwrap_or("self").to_owned(),
                    prefix.to_owned(),
                )
            } else {
                (name.ident.to_string(), target(&name.ident.to_string()))
            };
            out.push(Binding {
                local_name,
                written_path,
                conditions: conditions.to_vec(),
                span: source_span(source, tree.span())?,
            });
        }
        UseTree::Rename(rename) => out.push(Binding {
            local_name: rename.rename.to_string(),
            written_path: if rename.ident == "self" {
                prefix.to_owned()
            } else {
                target(&rename.ident.to_string())
            },
            conditions: conditions.to_vec(),
            span: source_span(source, tree.span())?,
        }),
        UseTree::Glob(_) => out.push(Binding {
            local_name: "*".to_owned(),
            written_path: target("*"),
            conditions: conditions.to_vec(),
            span: source_span(source, tree.span())?,
        }),
    }
    Ok(())
}

fn collect_imports<'a>(
    source: &'a str,
    items: impl Iterator<Item = &'a Item>,
    inherited: &[String],
) -> Result<Vec<Binding>> {
    let mut bindings = Vec::new();
    for item in items {
        if let Item::Use(item) = item {
            let mut conditions = inherited.to_vec();
            for condition in cfg_conditions(source, &item.attrs)? {
                if !conditions.contains(&condition) {
                    conditions.push(condition);
                }
            }
            // cfg_attr can change import availability; retain it as explicit unresolved evidence.
            for attribute in &item.attrs {
                if attribute.path().is_ident("cfg_attr") {
                    let condition = source_span(source, attribute.span())?.source;
                    if !conditions.contains(&condition) {
                        conditions.push(condition);
                    }
                }
            }
            flatten_use(
                source,
                &item.tree,
                if item.leading_colon.is_some() {
                    "::"
                } else {
                    ""
                },
                &conditions,
                &mut bindings,
            )?;
        } else if let Item::ExternCrate(item) = item {
            let mut conditions = inherited.to_vec();
            for condition in cfg_conditions(source, &item.attrs)? {
                if !conditions.contains(&condition) {
                    conditions.push(condition);
                }
            }
            bindings.push(Binding {
                local_name: item
                    .rename
                    .as_ref()
                    .map_or_else(|| item.ident.to_string(), |(_, name)| name.to_string()),
                written_path: item.ident.to_string(),
                conditions,
                span: source_span(source, item.span())?,
            });
        }
    }
    Ok(bindings)
}

struct Walker<'source> {
    source: &'source str,
    report: FileInventory,
    scopes: Vec<Scope>,
    conditions: Vec<String>,
    imports: Vec<Vec<Binding>>,
    module_floor: usize,
    error: Option<anyhow::Error>,
}

impl Walker<'_> {
    fn unresolved(&mut self, kind: &str, reason: &str, span: Span) -> Result<()> {
        self.report.unresolved.push(Unresolved {
            kind: kind.to_owned(),
            reason: reason.to_owned(),
            span: source_span(self.source, span)?,
            conditions: self.conditions.clone(),
            scopes: self.scopes.clone(),
        });
        Ok(())
    }

    fn site(&mut self, path: &SynPath, conditions: &[String]) -> Result<PathSite> {
        let written_path = path_text(path);
        let first = path
            .segments
            .first()
            .context("empty Rust path")?
            .ident
            .to_string();
        let suffix = written_path.strip_prefix(&first).unwrap_or("");
        let candidates: Vec<_> = if path.leading_colon.is_some() {
            Vec::new()
        } else {
            self.imports[self.module_floor..]
                .iter()
                .rev()
                .flatten()
                .filter(|binding| binding.local_name == first)
                .cloned()
                .collect()
        };
        let mut families = BTreeSet::new();
        if let Some(candidate) = family(&written_path) {
            families.insert(candidate.to_owned());
        }
        for binding in &candidates {
            if let Some(candidate) = family(&format!("{}{suffix}", binding.written_path)) {
                families.insert(candidate.to_owned());
            }
        }
        let resolution = if candidates.len() > 1 {
            "ambiguous_lexical_imports"
        } else if !candidates.is_empty() {
            "lexical_import_evidence_only"
        } else if written_path
            .trim_start_matches("::")
            .starts_with("norito::")
        {
            "canonical_path_spelling_only"
        } else {
            "requires_semantic_resolution"
        };
        if resolution == "ambiguous_lexical_imports"
            || (!families.is_empty() && resolution == "requires_semantic_resolution")
        {
            self.unresolved("path_resolution", resolution, path.span())?;
        }
        Ok(PathSite {
            written_path,
            span: source_span(self.source, path.span())?,
            candidate_families: families.into_iter().collect(),
            lexical_import_candidates: candidates,
            resolution: resolution.to_owned(),
            conditions: conditions.to_vec(),
        })
    }

    fn generics(&self, generics: &syn::Generics) -> Result<Vec<GenericSlot>> {
        generics
            .params
            .iter()
            .map(|parameter| {
                let (kind, identifier) = match parameter {
                    GenericParam::Lifetime(value) => ("lifetime", value.lifetime.to_string()),
                    GenericParam::Type(value) => ("type", value.ident.to_string()),
                    GenericParam::Const(value) => ("const", value.ident.to_string()),
                };
                Ok(GenericSlot {
                    kind: kind.to_owned(),
                    identifier,
                    span: source_span(self.source, parameter.span())?,
                })
            })
            .collect()
    }

    fn attribute_meta(
        &mut self,
        meta: &Meta,
        conditions: &[String],
        derives: &mut Vec<PathSite>,
        literals: &mut Vec<IdentityLiteral>,
    ) -> Result<()> {
        if meta.path().is_ident("cfg_attr") {
            self.unresolved(
                "conditional_attribute",
                "conditional attributes are retained without evaluating configuration or expansion",
                meta.span(),
            )?;
            if let Meta::List(list) = meta {
                match Punctuated::<Meta, Token![,]>::parse_terminated.parse2(list.tokens.clone()) {
                    Ok(parts) if parts.len() >= 2 => {
                        let mut nested = conditions.to_vec();
                        nested.push(
                            source_span(
                                self.source,
                                parts.first().expect("length checked").span(),
                            )?
                            .source,
                        );
                        for attribute in parts.iter().skip(1) {
                            self.attribute_meta(attribute, &nested, derives, literals)?;
                        }
                    }
                    _ => self.unresolved(
                        "cfg_attr",
                        "conditional attributes could not be inspected",
                        meta.span(),
                    )?,
                }
            }
        } else if meta.path().is_ident("derive") {
            if let Meta::List(list) = meta {
                match Punctuated::<SynPath, Token![,]>::parse_terminated.parse2(list.tokens.clone())
                {
                    Ok(paths) => {
                        for path in paths {
                            let site = self.site(&path, conditions)?;
                            if site.candidate_families.is_empty()
                                && !matches!(
                                    site.written_path.as_str(),
                                    "Clone"
                                        | "Copy"
                                        | "Debug"
                                        | "Default"
                                        | "Eq"
                                        | "PartialEq"
                                        | "Ord"
                                        | "PartialOrd"
                                        | "Hash"
                                )
                            {
                                self.unresolved(
                                    "derive_expansion",
                                    "derive output and external aliases require compiler review",
                                    path.span(),
                                )?;
                            }
                            derives.push(site);
                        }
                    }
                    Err(_) => self.unresolved(
                        "derive",
                        "derive paths could not be inspected",
                        meta.span(),
                    )?,
                }
            }
        } else if meta.path().is_ident("norito_schema") || meta.path().is_ident("norito") {
            if let Meta::List(list) = meta {
                let identity = meta.path().is_ident("norito_schema");
                let mut nominal = None;
                let mut frame = None;
                if let Ok(parts) =
                    Punctuated::<Meta, Token![,]>::parse_terminated.parse2(list.tokens.clone())
                {
                    for part in parts {
                        if let Meta::NameValue(pair) = &part {
                            let target = if (identity && pair.path.is_ident("name"))
                                || (!identity && pair.path.is_ident("schema_name"))
                            {
                                Some(&mut nominal)
                            } else if identity && pair.path.is_ident("frame") {
                                Some(&mut frame)
                            } else {
                                None
                            };
                            if let Some(target) = target {
                                if let syn::Expr::Lit(syn::ExprLit {
                                    lit: syn::Lit::Str(value),
                                    ..
                                }) = &pair.value
                                {
                                    if target.replace(value.value()).is_some() {
                                        self.unresolved(
                                            "identity_attribute",
                                            "duplicate explicit literal requires compiler review",
                                            part.span(),
                                        )?;
                                    }
                                } else {
                                    self.unresolved(
                                        "identity_attribute",
                                        "identity is not a string literal",
                                        part.span(),
                                    )?;
                                }
                            }
                        }
                    }
                } else {
                    self.unresolved(
                        "identity_attribute",
                        "attribute grammar requires separate review",
                        meta.span(),
                    )?;
                }
                if identity || nominal.is_some() {
                    literals.push(IdentityLiteral {
                        kind: if identity {
                            "declared_identity"
                        } else {
                            "active_schema_name"
                        }
                        .to_owned(),
                        nominal,
                        frame,
                        span: source_span(self.source, meta.span())?,
                        conditions: conditions.to_vec(),
                    });
                }
            }
        } else if !matches!(
            meta.path().get_ident().map(ToString::to_string).as_deref(),
            Some(
                "cfg"
                    | "doc"
                    | "allow"
                    | "warn"
                    | "deny"
                    | "forbid"
                    | "expect"
                    | "repr"
                    | "non_exhaustive"
                    | "must_use"
                    | "deprecated"
            )
        ) {
            self.unresolved(
                "attribute",
                "attribute macro/helper semantics are unexpanded",
                meta.span(),
            )?;
        }
        Ok(())
    }

    fn declaration(
        &mut self,
        kind: &str,
        identifier: &syn::Ident,
        generics: &syn::Generics,
        attrs: &[Attribute],
        span: Span,
        anchor_start: Option<Span>,
    ) -> Result<()> {
        let full = source_span(self.source, span)?;
        let mapping_anchor = anchor_start
            .map(|start| -> Result<_> {
                let start = source_span(self.source, start)?.start_byte;
                Ok(MappingAnchor {
                    start_byte: start,
                    end_byte: full.end_byte,
                    anchor: self
                        .source
                        .get(start..full.end_byte)
                        .context("invalid declaration anchor")?
                        .to_owned(),
                    kind: kind.to_owned(),
                    identifier: identifier.to_string(),
                })
            })
            .transpose()?;
        let mut derives = Vec::new();
        let mut declared_literals = Vec::new();
        let conditions = self.conditions.clone();
        for attribute in attrs {
            self.attribute_meta(
                &attribute.meta,
                &conditions,
                &mut derives,
                &mut declared_literals,
            )?;
        }
        self.report.declarations.push(TypeDeclaration {
            kind: kind.to_owned(),
            identifier: identifier.to_string(),
            span: full,
            mapping_anchor,
            generics: self.generics(generics)?,
            where_clause: generics
                .where_clause
                .as_ref()
                .map(|clause| source_span(self.source, clause.span()))
                .transpose()?,
            attributes: attrs
                .iter()
                .map(|attr| source_span(self.source, attr.span()))
                .collect::<Result<_>>()?,
            conditions,
            scopes: self.scopes.clone(),
            derives,
            declared_literals,
        });
        Ok(())
    }

    fn inspect_item(&mut self, item: &Item) -> Result<()> {
        // Type declarations retain their parsed attribute evidence below. Other
        // items can also be rewritten by attributes, so expose that uncertainty.
        if !matches!(
            item,
            Item::Struct(_)
                | Item::Enum(_)
                | Item::Union(_)
                | Item::Type(_)
                | Item::Trait(_)
                | Item::TraitAlias(_)
                | Item::Mod(_)
        ) {
            for attr in item_attributes(item) {
                self.attribute_meta(
                    &attr.meta,
                    &self.conditions.clone(),
                    &mut Vec::new(),
                    &mut Vec::new(),
                )?;
            }
        }
        let start = |visibility: &syn::Visibility, keyword: Span| {
            if matches!(visibility, syn::Visibility::Inherited) {
                keyword
            } else {
                visibility.span()
            }
        };
        match item {
            Item::Struct(value) => self.declaration(
                "struct",
                &value.ident,
                &value.generics,
                &value.attrs,
                value.span(),
                Some(start(&value.vis, value.struct_token.span)),
            )?,
            Item::Enum(value) => self.declaration(
                "enum",
                &value.ident,
                &value.generics,
                &value.attrs,
                value.span(),
                Some(start(&value.vis, value.enum_token.span)),
            )?,
            Item::Union(value) => self.declaration(
                "union",
                &value.ident,
                &value.generics,
                &value.attrs,
                value.span(),
                None,
            )?,
            Item::Type(value) => self.declaration(
                "type_alias",
                &value.ident,
                &value.generics,
                &value.attrs,
                value.span(),
                None,
            )?,
            Item::Trait(value) => self.declaration(
                "trait",
                &value.ident,
                &value.generics,
                &value.attrs,
                value.span(),
                None,
            )?,
            Item::TraitAlias(value) => self.declaration(
                "trait_alias",
                &value.ident,
                &value.generics,
                &value.attrs,
                value.span(),
                None,
            )?,
            Item::Impl(value) => {
                let conditions = self.conditions.clone();
                let trait_site = value
                    .trait_
                    .as_ref()
                    .map(|(_, path, _)| self.site(path, &conditions))
                    .transpose()?;
                self.report.implementations.push(ManualImpl {
                    span: source_span(self.source, value.span())?,
                    self_type: source_span(self.source, value.self_ty.span())?,
                    generics: self.generics(&value.generics)?,
                    where_clause: value
                        .generics
                        .where_clause
                        .as_ref()
                        .map(|clause| source_span(self.source, clause.span()))
                        .transpose()?,
                    trait_site,
                    attributes: value
                        .attrs
                        .iter()
                        .map(|attr| source_span(self.source, attr.span()))
                        .collect::<Result<_>>()?,
                    conditions,
                    scopes: self.scopes.clone(),
                });
            }
            Item::Use(value) => {
                let imports =
                    collect_imports(self.source, std::iter::once(item), &self.conditions)?;
                if imports.iter().any(|binding| binding.local_name == "*") {
                    self.unresolved(
                        "wildcard_import",
                        "wildcard exports require semantic resolution",
                        value.span(),
                    )?;
                }
                self.report.imports.extend(imports);
            }
            Item::ExternCrate(value) => {
                let imports =
                    collect_imports(self.source, std::iter::once(item), &self.conditions)?;
                self.report.imports.extend(imports);
                self.unresolved(
                    "external_crate",
                    "crate aliases and macro imports require compiler name resolution",
                    value.span(),
                )?;
            }
            Item::Mod(value) => {
                let mut derives = Vec::new();
                let mut literals = Vec::new();
                for attr in &value.attrs {
                    self.attribute_meta(
                        &attr.meta,
                        &self.conditions.clone(),
                        &mut derives,
                        &mut literals,
                    )?;
                }
                if value.content.is_none() {
                    let literal_path =
                        value
                            .attrs
                            .iter()
                            .find_map(|attribute| match &attribute.meta {
                                Meta::NameValue(pair) if pair.path.is_ident("path") => {
                                    match &pair.value {
                                        syn::Expr::Lit(syn::ExprLit {
                                            lit: syn::Lit::Str(value),
                                            ..
                                        }) => Some(value.value()),
                                        _ => None,
                                    }
                                }
                                _ => None,
                            });
                    self.report.references.push(Reference {
                        kind: "external_module".to_owned(),
                        written_path: value.ident.to_string(),
                        literal_path,
                        span: source_span(self.source, value.span())?,
                        conditions: self.conditions.clone(),
                        scopes: self.scopes.clone(),
                    });
                    self.unresolved(
                        "external_module",
                        "module ownership/path/cfg requires a reviewed compilation context",
                        value.span(),
                    )?;
                }
            }
            Item::Verbatim(tokens) => self.unresolved(
                "verbatim_item",
                "syn retained an unparsed item token stream",
                tokens.span(),
            )?,
            _ => {}
        }
        Ok(())
    }
}

impl<'ast> Visit<'ast> for Walker<'_> {
    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let (attrs, name) = match item {
            syn::ImplItem::Fn(value) => (&value.attrs, Some(value.sig.ident.to_string())),
            syn::ImplItem::Const(value) => (&value.attrs, Some(value.ident.to_string())),
            syn::ImplItem::Type(value) => (&value.attrs, Some(value.ident.to_string())),
            syn::ImplItem::Macro(value) => (&value.attrs, None),
            _ => {
                syn::visit::visit_impl_item(self, item);
                return;
            }
        };
        let previous_conditions = self.conditions.len();
        let previous_scopes = self.scopes.len();
        let result = (|| -> Result<()> {
            self.conditions.extend(cfg_conditions(self.source, attrs)?);
            if let syn::ImplItem::Type(value) = item {
                self.declaration(
                    "associated_type",
                    &value.ident,
                    &value.generics,
                    attrs,
                    value.span(),
                    None,
                )?;
            } else {
                for attr in attrs {
                    self.attribute_meta(
                        &attr.meta,
                        &self.conditions.clone(),
                        &mut Vec::new(),
                        &mut Vec::new(),
                    )?;
                }
            }
            self.scopes.push(Scope {
                kind: "associated_item".to_owned(),
                identifier: name,
                span: SourceRange::from(&source_span(self.source, item.span())?),
                attributes: attrs
                    .iter()
                    .map(|attr| source_span(self.source, attr.span()))
                    .collect::<Result<_>>()?,
            });
            Ok(())
        })();
        if let Err(error) = result {
            self.error = Some(error);
        } else {
            syn::visit::visit_impl_item(self, item);
        }
        self.conditions.truncate(previous_conditions);
        self.scopes.truncate(previous_scopes);
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let (attrs, name) = match item {
            syn::TraitItem::Fn(value) => (&value.attrs, Some(value.sig.ident.to_string())),
            syn::TraitItem::Const(value) => (&value.attrs, Some(value.ident.to_string())),
            syn::TraitItem::Type(value) => (&value.attrs, Some(value.ident.to_string())),
            syn::TraitItem::Macro(value) => (&value.attrs, None),
            _ => {
                syn::visit::visit_trait_item(self, item);
                return;
            }
        };
        let previous_conditions = self.conditions.len();
        let previous_scopes = self.scopes.len();
        let result = (|| -> Result<()> {
            self.conditions.extend(cfg_conditions(self.source, attrs)?);
            if let syn::TraitItem::Type(value) = item {
                self.declaration(
                    "associated_type",
                    &value.ident,
                    &value.generics,
                    attrs,
                    value.span(),
                    None,
                )?;
            } else {
                for attr in attrs {
                    self.attribute_meta(
                        &attr.meta,
                        &self.conditions.clone(),
                        &mut Vec::new(),
                        &mut Vec::new(),
                    )?;
                }
            }
            self.scopes.push(Scope {
                kind: "associated_item".to_owned(),
                identifier: name,
                span: SourceRange::from(&source_span(self.source, item.span())?),
                attributes: attrs
                    .iter()
                    .map(|attr| source_span(self.source, attr.span()))
                    .collect::<Result<_>>()?,
            });
            Ok(())
        })();
        if let Err(error) = result {
            self.error = Some(error);
        } else {
            syn::visit::visit_trait_item(self, item);
        }
        self.conditions.truncate(previous_conditions);
        self.scopes.truncate(previous_scopes);
    }

    fn visit_item(&mut self, item: &'ast Item) {
        if self.error.is_some() {
            return;
        }
        let previous_conditions = self.conditions.len();
        let previous_imports = self.imports.len();
        let previous_floor = self.module_floor;
        let previous_scopes = self.scopes.len();
        let result = (|| -> Result<()> {
            self.conditions
                .extend(cfg_conditions(self.source, item_attributes(item))?);
            self.inspect_item(item)?;
            let enclosure = match item {
                Item::Mod(value) => Some(("module", Some(value.ident.to_string()))),
                Item::Fn(value) => Some(("function", Some(value.sig.ident.to_string()))),
                Item::Impl(_) => Some(("implementation", None)),
                Item::Trait(value) => Some(("trait", Some(value.ident.to_string()))),
                _ => None,
            };
            if let Some((kind, identifier)) = enclosure {
                self.scopes.push(Scope {
                    kind: kind.to_owned(),
                    identifier,
                    span: SourceRange::from(&source_span(self.source, item.span())?),
                    attributes: item_attributes(item)
                        .iter()
                        .map(|attr| source_span(self.source, attr.span()))
                        .collect::<Result<_>>()?,
                });
            }
            if let Item::Mod(value) = item
                && let Some((_, items)) = &value.content
            {
                self.module_floor = self.imports.len();
                self.imports.push(collect_imports(
                    self.source,
                    items.iter(),
                    &self.conditions,
                )?);
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.error = Some(error);
        } else {
            syn::visit::visit_item(self, item);
        }
        self.conditions.truncate(previous_conditions);
        self.imports.truncate(previous_imports);
        self.module_floor = previous_floor;
        self.scopes.truncate(previous_scopes);
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        if self.error.is_some() {
            return;
        }
        let imports = collect_imports(
            self.source,
            block.stmts.iter().filter_map(|statement| {
                if let Stmt::Item(item) = statement {
                    Some(item)
                } else {
                    None
                }
            }),
            &self.conditions,
        );
        match imports.and_then(|imports| Ok((imports, source_span(self.source, block.span())?))) {
            Ok((imports, span)) => {
                self.imports.push(imports);
                self.scopes.push(Scope {
                    kind: "block".to_owned(),
                    identifier: None,
                    span: SourceRange::from(&span),
                    attributes: Vec::new(),
                });
                syn::visit::visit_block(self, block);
                self.scopes.pop();
                self.imports.pop();
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn visit_macro(&mut self, value: &'ast syn::Macro) {
        if self.error.is_some() {
            return;
        }
        let result = (|| -> Result<()> {
            let path = path_text(&value.path);
            let include = value.path.is_ident("include");
            self.report.references.push(Reference {
                kind: if include {
                    "include"
                } else if value.path.is_ident("macro_rules") {
                    "macro_definition"
                } else {
                    "macro_invocation"
                }
                .to_owned(),
                written_path: path,
                literal_path: if include {
                    value
                        .parse_body::<syn::LitStr>()
                        .ok()
                        .map(|value| value.value())
                } else {
                    None
                },
                span: source_span(self.source, value.span())?,
                conditions: self.conditions.clone(),
                scopes: self.scopes.clone(),
            });
            self.unresolved(
                if include {
                    "include"
                } else {
                    "macro_expansion"
                },
                "tokens are recorded without expansion or inferred generated declarations",
                value.span(),
            )
        })();
        if let Err(error) = result {
            self.error = Some(error);
        }
    }

    fn visit_attribute(&mut self, value: &'ast Attribute) {
        if self.error.is_some() {
            return;
        }
        match source_span(self.source, value.span()) {
            Ok(span) => self.report.attributes.push(AttributeSite {
                span,
                conditions: self.conditions.clone(),
                scopes: self.scopes.clone(),
            }),
            Err(error) => self.error = Some(error),
        }
        syn::visit::visit_attribute(self, value);
    }
}

fn inspect_source(path: &str, source: &str) -> Result<FileInventory> {
    let mut report = FileInventory {
        path: path.to_owned(),
        sha256: hex::encode(Sha256::digest(source.as_bytes())),
        bytes: source.len(),
        parse_error: None,
        declarations: Vec::new(),
        implementations: Vec::new(),
        imports: Vec::new(),
        attributes: Vec::new(),
        references: Vec::new(),
        unresolved: Vec::new(),
    };
    let parsed = match syn::parse_file(source) {
        Ok(parsed) => parsed,
        Err(error) => {
            report.parse_error = Some(format!("{error} at {:?}", error.span().byte_range()));
            return Ok(report);
        }
    };
    let conditions = cfg_conditions(source, &parsed.attrs)?;
    let imports = collect_imports(source, parsed.items.iter(), &conditions)?;
    let mut walker = Walker {
        source,
        report,
        scopes: vec![Scope {
            kind: "file".to_owned(),
            identifier: None,
            span: SourceRange {
                start_byte: 0,
                end_byte: source.len(),
            },
            attributes: parsed
                .attrs
                .iter()
                .map(|attr| source_span(source, attr.span()))
                .collect::<Result<_>>()?,
        }],
        conditions,
        imports: vec![imports],
        module_floor: 0,
        error: None,
    };
    walker.visit_file(&parsed);
    if let Some(error) = walker.error {
        return Err(error).context(format!("invalid parser span in {path}"));
    }
    Ok(walker.report)
}

fn normalized_relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        bail!("source selections must be normalized repository-relative paths");
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    relative: &Path,
    files: &mut BTreeSet<PathBuf>,
    exclusions: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    normalized_relative(relative)?;
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() {
        bail!(
            "source symlink requires explicit review: {}",
            relative.display()
        );
    }
    if metadata.is_dir() {
        for child in fs::read_dir(&path)? {
            let child = child?;
            let name = child.file_name();
            if (name == ".git" || name == "target") && child.file_type()?.is_dir() {
                exclusions.insert(relative.join(name));
                continue;
            }
            collect_files(root, &relative.join(name), files, exclusions)?;
        }
    } else if relative
        .extension()
        .is_some_and(|extension| extension == "rs")
    {
        if !metadata.is_file() {
            bail!("source must be a regular file: {}", relative.display());
        }
        files.insert(relative.to_owned());
    }
    Ok(())
}

/// Read selected physical source files, retaining all cfg branches and unresolved references.
pub fn inventory(root: &Path, selections: &[PathBuf]) -> Result<Inventory> {
    let root = root.canonicalize()?;
    let mut paths = BTreeSet::new();
    let mut exclusions = BTreeSet::new();
    for selection in selections {
        // Reject symlink parents too: checking only the selected leaf would
        // otherwise silently inventory a different physical source owner.
        let mut prefix = PathBuf::new();
        normalized_relative(selection)?;
        for component in selection.components() {
            prefix.push(component);
            if fs::symlink_metadata(root.join(&prefix))?
                .file_type()
                .is_symlink()
            {
                bail!(
                    "source symlink requires explicit review: {}",
                    prefix.display()
                );
            }
        }
        collect_files(&root, selection, &mut paths, &mut exclusions)?;
    }
    if paths.is_empty() {
        bail!("no Rust source files selected");
    }
    let mut files = Vec::new();
    let mut set_hash = Sha256::new();
    for path in &paths {
        let full = root.join(path);
        let metadata = fs::symlink_metadata(&full)?;
        if !metadata.is_file() {
            bail!("source must be a regular file: {}", path.display());
        }
        let bytes = fs::read(&full)?;
        let source = std::str::from_utf8(&bytes).context("Rust source must be UTF-8")?;
        let path = path
            .to_str()
            .context("source path must be UTF-8")?
            .replace('\\', "/");
        let report = inspect_source(&path, source)?;
        set_hash.update((path.len() as u64).to_le_bytes());
        set_hash.update(path.as_bytes());
        set_hash.update(Sha256::digest(&bytes));
        files.push(report);
    }
    for file in &files {
        if hex::encode(Sha256::digest(fs::read(root.join(&file.path))?)) != file.sha256 {
            bail!("source changed during inventory: {}", file.path);
        }
    }
    Ok(Inventory {
        schema: 1,
        qualification: "unexpanded physical-source syntax inventory; canonical capture, semantic resolution and compiler closure remain pending",
        source_set_sha256: hex::encode(set_hash.finalize()),
        selections: selections
            .iter()
            .map(|path| {
                path.to_str()
                    .map(str::to_owned)
                    .context("source selection must be UTF-8")
            })
            .collect::<Result<_>>()?,
        excluded_directories: exclusions
            .iter()
            .map(|path| {
                path.to_str()
                    .map(str::to_owned)
                    .context("excluded directory path must be UTF-8")
            })
            .collect::<Result<_>>()?,
        files,
    })
}

#[cfg(test)]
mod tests;
