use derive_more::Constructor;
use proc_macro2::Span;
use proc_macro_error::{abort, OptionExt};
use syn::{
    parse_quote,
    visit::{visit_signature, Visit},
    visit_mut::VisitMut,
    Attribute, Ident, Path, Type, Visibility,
};

#[derive(Constructor)]
pub struct Arg {
    self_ty: Option<Path>,
    name: Ident,
    type_: Type,
}

impl Arg {
    pub fn name(&self) -> &Ident {
        &self.name
    }
    pub fn src_type(&self) -> &Type {
        &self.type_
    }
    pub fn src_type_is_empty_tuple(&self) -> bool {
        matches!(self.src_type_resolved(), Type::Tuple(syn::TypeTuple { ref elems, .. }) if elems.is_empty())
    }
    pub fn src_type_resolved(&self) -> Type {
        resolve_type(self.self_ty.as_ref(), self.type_.clone())
    }
    pub fn ffi_type_resolved(&self) -> Type {
        let mut src_type = resolve_type(self.self_ty.as_ref(), self.type_.clone());

        if matches!(src_type, Type::Array(_)) {
            src_type = parse_quote! {Box<#src_type>}
        }

        parse_quote! {<#src_type as iroha_ffi::FfiType>::ReprC}
    }
    // TODO: Probably can be removed?
    pub fn wrapper_ffi_type_resolved(&self) -> Type {
        let mut src_type = resolve_type(self.self_ty.as_ref(), self.type_.clone());

        if matches!(src_type, Type::Array(_)) {
            src_type = parse_quote! {Box<#src_type>}
        }

        parse_quote! {<<#src_type as iroha_ffi::FfiWrapperType>::InputType as iroha_ffi::FfiType>::ReprC}
    }
}

fn resolve_type(self_type: Option<&Path>, mut arg_type: Type) -> Type {
    TypeImplTraitResolver.visit_type_mut(&mut arg_type);

    if let Some(self_ty) = self_type {
        SelfResolver::new(self_ty).visit_type_mut(&mut arg_type);
    }
    if let Some((ok, _)) = unwrap_result_type(&arg_type) {
        arg_type = ok.clone();
    }

    arg_type
}

pub struct ImplDescriptor<'ast> {
    /// Attributes of the impl block
    pub attrs: Vec<&'ast Attribute>,
    /// Trait name
    pub trait_name: Option<&'ast Path>,
    /// Associated types
    pub associated_types: Vec<(&'ast Ident, &'ast Type)>,
    /// Functions in the impl block
    pub fns: Vec<FnDescriptor<'ast>>,
}

pub struct FnDescriptor<'ast> {
    /// Function attributes
    pub attrs: Vec<&'ast Attribute>,
    /// Resolved type of the `Self` type
    pub self_ty: Option<Path>,

    /// Function documentation
    // TODO: Could just be a part of all attrs?
    pub doc: Vec<&'ast syn::Attribute>,
    /// Original signature of the method
    pub sig: syn::Signature,

    /// Receiver argument, i.e. `self`
    pub receiver: Option<Arg>,
    /// Input fn arguments
    pub input_args: Vec<Arg>,
    /// Output fn argument
    pub output_arg: Option<Arg>,
}

struct ImplVisitor<'ast> {
    attrs: Vec<&'ast Attribute>,
    trait_name: Option<&'ast Path>,
    /// Resolved type of the `Self` type
    self_ty: Option<&'ast Path>,
    associated_types: Vec<(&'ast Ident, &'ast Type)>,
    fns: Vec<FnDescriptor<'ast>>,
}

struct FnVisitor<'ast> {
    attrs: Vec<&'ast Attribute>,
    doc: Vec<&'ast syn::Attribute>,
    trait_name: Option<&'ast Path>,
    /// Resolved type of the `Self` type
    self_ty: Option<&'ast Path>,

    /// Original signature of the method
    sig: Option<&'ast syn::Signature>,

    /// Receiver argument, i.e. `self`
    receiver: Option<Arg>,
    /// Input fn arguments
    input_args: Vec<Arg>,
    /// Output fn argument
    output_arg: Option<Arg>,

    /// Name of the argument being visited
    curr_arg_name: Option<&'ast Ident>,
}

impl<'ast> ImplDescriptor<'ast> {
    pub fn from_impl(node: &'ast syn::ItemImpl) -> Self {
        let mut visitor = ImplVisitor::new();
        visitor.visit_item_impl(node);

        ImplDescriptor::from_visitor(visitor)
    }

    fn from_visitor(visitor: ImplVisitor<'ast>) -> Self {
        Self {
            attrs: visitor.attrs,
            trait_name: visitor.trait_name,
            associated_types: visitor.associated_types,
            fns: visitor.fns,
        }
    }

    pub fn trait_name(&self) -> Option<&Ident> {
        self.trait_name.map(last_seg_ident)
    }
}

impl<'ast> FnDescriptor<'ast> {
    pub fn from_impl_method(
        self_ty: &'ast Path,
        trait_name: Option<&'ast Path>,
        node: &'ast syn::ImplItemMethod,
    ) -> Self {
        let mut visitor = FnVisitor::new(Some(self_ty), trait_name);

        visitor.visit_impl_item_method(node);
        FnDescriptor::from_visitor(visitor)
    }

    pub fn from_fn(node: &'ast syn::ItemFn) -> Self {
        let mut visitor = FnVisitor::new(None, None);

        visitor.visit_item_fn(node);
        Self::from_visitor(visitor)
    }

    fn from_visitor(visitor: FnVisitor<'ast>) -> Self {
        Self {
            attrs: visitor.attrs,
            doc: visitor.doc,
            self_ty: visitor.self_ty.map(Clone::clone),

            sig: visitor.sig.expect_or_abort("Missing signature").clone(),

            receiver: visitor.receiver,
            input_args: visitor.input_args,
            output_arg: visitor.output_arg,
        }
    }

    pub fn self_ty_name(&self) -> Option<&Ident> {
        self.self_ty.as_ref().map(last_seg_ident)
    }
}

impl<'ast> ImplVisitor<'ast> {
    const fn new() -> Self {
        Self {
            attrs: Vec::new(),
            trait_name: None,
            self_ty: None,
            associated_types: Vec::new(),
            fns: vec![],
        }
    }

    fn visit_self_type(&mut self, node: &'ast Type) {
        if let Type::Path(self_ty) = node {
            if self_ty.qself.is_some() {
                abort!(self_ty, "Qualified types are not supported as self type");
            }

            self.self_ty = Some(&self_ty.path);
        } else {
            abort!(node, "Only nominal types are supported as self type");
        }
    }
}

impl<'ast> FnVisitor<'ast> {
    pub const fn new(self_ty: Option<&'ast Path>, trait_name: Option<&'ast Path>) -> Self {
        Self {
            attrs: Vec::new(),
            doc: Vec::new(),
            trait_name,
            self_ty,

            sig: None,

            receiver: None,
            input_args: vec![],
            output_arg: None,

            curr_arg_name: None,
        }
    }

    fn add_input_arg(&mut self, src_type: &'ast Type) {
        let arg_name = self.curr_arg_name.take().expect_or_abort("Defined").clone();
        self.input_args.push(Arg::new(
            self.self_ty.map(Clone::clone),
            arg_name,
            src_type.clone(),
        ));
    }

    fn add_output_arg(&mut self, src_type: &'ast Type) {
        assert!(self.curr_arg_name.is_none());
        assert!(self.output_arg.is_none());

        let output_arg = Arg::new(
            self.self_ty.map(Clone::clone),
            Ident::new("__output", Span::call_site()),
            src_type.clone(),
        );

        self.output_arg = Some(output_arg);
    }
}

impl<'ast> Visit<'ast> for ImplVisitor<'ast> {
    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        self.attrs.push(node);
    }
    fn visit_generic_param(&mut self, node: &'ast syn::GenericParam) {
        abort!(node, "Generics are not supported");
    }
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if node.unsafety.is_some() {
            abort!(node.generics, "Unsafe impl not supported");
        }
        if node.defaultness.is_some() {
            abort!(node.generics, "Default impl not supported");
        }

        for it in &node.attrs {
            self.visit_attribute(it);
        }

        self.visit_generics(&node.generics);
        self.trait_name = node.trait_.as_ref().map(|(_, trait_, _)| trait_);
        self.visit_self_type(&node.self_ty);

        let self_ty = self.self_ty.expect_or_abort("Defined");
        self.associated_types
            .extend(node.items.iter().filter_map(|item| match item {
                syn::ImplItem::Type(associated_type) => {
                    Some((&associated_type.ident, &associated_type.ty))
                }
                _ => None,
            }));
        self.fns
            .extend(node.items.iter().filter_map(|item| match item {
                syn::ImplItem::Method(method) => {
                    // NOTE: private methods in inherent impl are skipped
                    if self.trait_name.is_none() && !matches!(method.vis, Visibility::Public(_)) {
                        return None;
                    }
                    Some(FnDescriptor::from_impl_method(
                        self_ty,
                        self.trait_name,
                        method,
                    ))
                }
                _ => None,
            }));
    }
}

impl<'ast> Visit<'ast> for FnVisitor<'ast> {
    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        if is_doc_attr(node) {
            self.doc.push(node);
        } else {
            self.attrs.push(node);
        }
    }

    fn visit_abi(&mut self, node: &'ast syn::Abi) {
        abort!(node, "You shouldn't specify function ABI");
    }
    fn visit_generic_param(&mut self, node: &'ast syn::GenericParam) {
        abort!(node, "Generics are not supported");
    }
    fn visit_impl_item_method(&mut self, node: &'ast syn::ImplItemMethod) {
        for attr in &node.attrs {
            self.visit_attribute(attr);
        }

        self.sig = Some(&node.sig);
        self.visit_visibility(&node.vis);
        self.visit_signature(&node.sig);
    }
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        for attr in &node.attrs {
            self.visit_attribute(attr);
        }

        self.sig = Some(&node.sig);
        self.visit_visibility(&node.vis);
        self.visit_signature(&node.sig);
    }
    fn visit_visibility(&mut self, node: &'ast syn::Visibility) {
        if self.trait_name.is_none() && !matches!(node, Visibility::Public(_)) {
            abort!(node, "Private methods should not be exported");
        }
    }
    fn visit_signature(&mut self, node: &'ast syn::Signature) {
        if node.constness.is_some() {
            abort!(node.constness, "Const functions not supported");
        }
        if node.asyncness.is_some() {
            abort!(node.asyncness, "Async functions not supported");
        }
        if node.unsafety.is_some() {
            abort!(node.unsafety, "You shouldn't specify function unsafety");
        }
        if node.abi.is_some() {
            abort!(node.abi, "Extern fn declarations not supported")
        }
        if node.variadic.is_some() {
            abort!(node.variadic, "Variadic arguments not supported")
        }

        visit_signature(self, node);
    }

    fn visit_receiver(&mut self, node: &'ast syn::Receiver) {
        for it in &node.attrs {
            self.visit_attribute(it);
        }
        if let Some((_, lifetime)) = &node.reference {
            if lifetime.is_some() {
                abort!(lifetime, "Explicit lifetimes not supported");
            }
        }

        let src_type: Type = node.reference.as_ref().map_or_else(
            || parse_quote! {Self},
            |it| {
                if it.1.is_some() {
                    abort!(it.1, "Explicit lifetime not supported");
                }

                if node.mutability.is_some() {
                    parse_quote! {&mut Self}
                } else {
                    parse_quote! {&Self}
                }
            },
        );

        let handle_name = Ident::new("__handle", Span::call_site());
        self.receiver = Some(Arg::new(
            self.self_ty.map(Clone::clone),
            handle_name,
            src_type,
        ));
    }

    fn visit_pat_type(&mut self, node: &'ast syn::PatType) {
        for it in &node.attrs {
            self.visit_attribute(it);
        }

        if let syn::Pat::Ident(ident) = &*node.pat {
            self.visit_pat_ident(ident);
        } else {
            abort!(node.pat, "Unsupported pattern in variable name binding");
        }

        self.add_input_arg(&node.ty);
    }

    fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
        for it in &node.attrs {
            self.visit_attribute(it);
        }
        if node.by_ref.is_some() {
            abort!(node.by_ref, "ref patterns not supported in argument name");
        }
        if node.mutability.is_some() {
            // NOTE: It's irrelevant
        }
        if node.subpat.is_some() {
            abort!(node, "Subpatterns not supported in argument name");
        }

        self.curr_arg_name = Some(&node.ident);
    }

    fn visit_return_type(&mut self, node: &'ast syn::ReturnType) {
        match node {
            syn::ReturnType::Default => {}
            syn::ReturnType::Type(_, src_type) => {
                self.add_output_arg(src_type);
            }
        }
    }
}

pub fn is_doc_attr(attr: &syn::Attribute) -> bool {
    if let Ok(meta) = attr.parse_meta() {
        if meta.path().is_ident("doc") {
            return true;
        }
    }

    false
}

/// Visitor replaces all occurrences of `Self` in a path type with a fully qualified type
struct SelfResolver<'ast> {
    self_ty: &'ast Path,
}

impl<'ast> SelfResolver<'ast> {
    fn new(self_ty: &'ast Path) -> Self {
        Self { self_ty }
    }
}

impl VisitMut for SelfResolver<'_> {
    fn visit_path_mut(&mut self, node: &mut Path) {
        if node.leading_colon.is_some() {
            // NOTE: It's irrelevant
        }
        for segment in &mut node.segments {
            self.visit_path_arguments_mut(&mut segment.arguments);
        }

        if node.segments[0].ident == "Self" {
            let mut node_segments = self.self_ty.segments.clone();

            for segment in core::mem::take(&mut node.segments).into_iter().skip(1) {
                node_segments.push(segment);
            }

            node.segments = node_segments;
        }
    }
}

pub struct TypeImplTraitResolver;
impl VisitMut for TypeImplTraitResolver {
    fn visit_type_mut(&mut self, node: &mut Type) {
        let mut new_node = None;

        if let Type::ImplTrait(impl_trait) = node {
            for bound in &impl_trait.bounds {
                if let syn::TypeParamBound::Trait(trait_) = bound {
                    let trait_ = trait_.path.segments.last().expect_or_abort("Defined");

                    if trait_.ident == "IntoIterator" || trait_.ident == "ExactSizeIterator" {
                        if let syn::PathArguments::AngleBracketed(args) = &trait_.arguments {
                            for arg in &args.args {
                                if let syn::GenericArgument::Binding(binding) = arg {
                                    if binding.ident == "Item" {
                                        let mut ty = binding.ty.clone();
                                        TypeImplTraitResolver.visit_type_mut(&mut ty);
                                        new_node = Some(parse_quote! { Vec<#ty> });
                                    }
                                }
                            }
                        }
                    } else if trait_.ident == "Into" {
                        if let syn::PathArguments::AngleBracketed(args) = &trait_.arguments {
                            for arg in &args.args {
                                if let syn::GenericArgument::Type(type_) = arg {
                                    new_node = Some(type_.clone());
                                }
                            }
                        }
                    } else if trait_.ident == "AsRef" {
                        if let syn::PathArguments::AngleBracketed(args) = &trait_.arguments {
                            for arg in &args.args {
                                if let syn::GenericArgument::Type(type_) = arg {
                                    new_node = Some(syn::parse_quote!(&#type_));
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(new_node) = new_node {
            *node = new_node;
        }
    }
}

fn last_seg_ident(path: &syn::Path) -> &Ident {
    &path.segments.last().expect_or_abort("Defined").ident
}

pub fn unwrap_result_type(node: &Type) -> Option<(&Type, &Type)> {
    if let Type::Path(type_) = node {
        let last_seg = type_.path.segments.last().expect_or_abort("Defined");

        if last_seg.ident == "Result" {
            if let syn::PathArguments::AngleBracketed(args) = &last_seg.arguments {
                if let (syn::GenericArgument::Type(ok), syn::GenericArgument::Type(err)) =
                    (&args.args[0], &args.args[1])
                {
                    return Some((ok, err));
                }
            }
        }
    }

    None
}
