use derive_more::Constructor;
use proc_macro2::Span;
use proc_macro_error::{abort, OptionExt};
use syn::{parse_quote, visit::Visit, visit_mut::VisitMut, Ident, Type};

#[derive(Constructor)]
pub struct Arg {
    self_ty: Option<syn::Path>,
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
    pub fn src_type_resolved(&self) -> Type {
        resolve_type(self.self_ty.as_ref(), self.type_.clone())
    }
    pub fn ffi_type_resolved(&self, is_output: bool) -> Type {
        let src_type = if let Type::Array(array) = &self.type_ {
            if is_output {
                self.type_.clone()
            } else {
                let elem = &array.elem;
                parse_quote! {&mut #elem}
            }
        } else {
            self.type_.clone()
        };

        let arg_type = resolve_type(self.self_ty.as_ref(), src_type);
        parse_quote! {<#arg_type as iroha_ffi::FfiType>::ReprC}
    }
}

fn resolve_type(self_type: Option<&syn::Path>, mut arg_type: Type) -> Type {
    ImplTraitResolver.visit_type_mut(&mut arg_type);

    if let Some(self_ty) = self_type {
        SelfResolver::new(self_ty).visit_type_mut(&mut arg_type);
    }
    if let Some(result_type) = unwrap_result_type(&arg_type) {
        arg_type = result_type.clone();
    }

    arg_type
}

pub struct ImplDescriptor {
    /// Functions in the impl block
    pub fns: Vec<FnDescriptor>,
}

pub struct FnDescriptor {
    /// Resolved type of the `Self` type
    pub self_ty: Option<syn::Path>,
    /// Trait name
    pub trait_name: Option<syn::Path>,

    /// Function documentation
    pub doc: Option<syn::Attribute>,
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
    /// Trait name
    trait_name: Option<&'ast syn::Path>,
    /// Resolved type of the `Self` type
    self_ty: Option<&'ast syn::Path>,
    /// Collection of FFI functions
    pub fns: Vec<FnDescriptor>,
}

struct FnVisitor<'ast> {
    /// Resolved type of the `Self` type
    self_ty: Option<&'ast syn::Path>,
    /// Trait name
    trait_name: Option<&'ast syn::Path>,

    /// Function documentation
    doc: Option<syn::Attribute>,
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

impl ImplDescriptor {
    pub fn from_impl(node: &syn::ItemImpl) -> Self {
        let mut visitor = ImplVisitor::new();
        visitor.visit_item_impl(node);

        ImplDescriptor::from_visitor(visitor)
    }

    fn from_visitor(visitor: ImplVisitor) -> Self {
        Self { fns: visitor.fns }
    }
}

impl FnDescriptor {
    pub fn from_impl_method(
        self_ty: &syn::Path,
        trait_name: Option<&syn::Path>,
        node: &syn::ImplItemMethod,
    ) -> Self {
        let mut visitor = FnVisitor::new(Some(self_ty), trait_name);

        visitor.visit_impl_item_method(node);
        FnDescriptor::from_visitor(visitor)
    }

    pub fn from_fn(node: &syn::ItemFn) -> Self {
        let mut visitor = FnVisitor::new(None, None);

        visitor.visit_item_fn(node);
        Self::from_visitor(visitor)
    }

    fn from_visitor(visitor: FnVisitor) -> Self {
        Self {
            self_ty: visitor.self_ty.map(Clone::clone),
            trait_name: visitor.trait_name.map(Clone::clone),

            doc: visitor.doc,
            sig: visitor.sig.expect_or_abort("Missing signature").clone(),

            receiver: visitor.receiver,
            input_args: visitor.input_args,
            output_arg: visitor.output_arg,
        }
    }

    pub fn self_ty_name(&self) -> Option<&Ident> {
        self.self_ty.as_ref().map(get_ident)
    }

    pub fn trait_name(&self) -> Option<&Ident> {
        self.trait_name.as_ref().map(get_ident)
    }
}

impl<'ast> ImplVisitor<'ast> {
    const fn new() -> Self {
        Self {
            trait_name: None,
            self_ty: None,
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
    pub const fn new(
        self_ty: Option<&'ast syn::Path>,
        trait_name: Option<&'ast syn::Path>,
    ) -> Self {
        Self {
            self_ty,
            trait_name,

            doc: None,
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
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        for it in &node.attrs {
            self.visit_attribute(it);
        }
        if node.defaultness.is_some() {
            // NOTE: Its's irrelevant
        }
        if node.unsafety.is_some() {
            // NOTE: Its's irrelevant
        }
        self.trait_name = node.trait_.as_ref().map(|(_, trait_, _)| trait_);
        self.visit_self_type(&node.self_ty);

        let self_ty = self.self_ty.expect_or_abort("Defined");
        self.fns
            .extend(node.items.iter().filter_map(|item| match item {
                syn::ImplItem::Method(method) => {
                    // NOTE: private methods in inherent impl are skipped
                    if self.trait_name.is_none()
                        && !matches!(method.vis, syn::Visibility::Public(_))
                    {
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
    fn visit_impl_item_method(&mut self, node: &'ast syn::ImplItemMethod) {
        self.doc = find_doc_attr(&node.attrs).cloned();

        if self.trait_name.is_none() && !matches!(node.vis, syn::Visibility::Public(_)) {
            abort!(
                node.vis,
                "Private methods defined in an inherent `impl` block should not be exported, this is a bug in the library",
            );
        }

        self.sig = Some(&node.sig);
        self.visit_signature(&node.sig);
    }
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.doc = find_doc_attr(&node.attrs).cloned();

        if !matches!(node.vis, syn::Visibility::Public(_)) {
            abort!(node.vis, "Exported functions must be public");
        }

        self.sig = Some(&node.sig);
        self.visit_signature(&node.sig);
    }
    fn visit_signature(&mut self, node: &'ast syn::Signature) {
        if node.constness.is_some() {
            // NOTE: It's irrelevant
        }
        if node.asyncness.is_some() {
            abort!(node.asyncness, "Async functions not supported");
        }
        if node.unsafety.is_some() {
            // NOTE: It's irrelevant
        }
        if node.abi.is_some() {
            abort!(node.abi, "Extern fn declarations not supported")
        }
        for fn_input_arg in &node.inputs {
            self.visit_fn_arg(fn_input_arg);
        }
        if node.variadic.is_some() {
            abort!(node.variadic, "Variadic arguments not supported")
        }
        self.visit_return_type(&node.output);
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

pub fn find_doc_attr(attrs: &[syn::Attribute]) -> Option<&syn::Attribute> {
    for attr in attrs {
        if let Ok(meta) = attr.parse_meta() {
            if !meta.path().is_ident("doc") {
                continue;
            }

            return Some(attr);
        }
    }

    None
}

/// Visitor replaces all occurrences of `Self` in a path type with a fully qualified type
struct SelfResolver<'ast> {
    self_ty: &'ast syn::Path,
}

impl<'ast> SelfResolver<'ast> {
    fn new(self_ty: &'ast syn::Path) -> Self {
        Self { self_ty }
    }
}

impl VisitMut for SelfResolver<'_> {
    fn visit_path_mut(&mut self, node: &mut syn::Path) {
        if node.leading_colon.is_some() {
            // NOTE: It's irrelevant
        }
        for segment in &mut node.segments {
            self.visit_path_arguments_mut(&mut segment.arguments);
        }

        if node.segments[0].ident == "Self" {
            #[allow(clippy::expect_used)]
            let mut node_segments = self.self_ty.segments.clone();

            for segment in core::mem::take(&mut node.segments).into_iter().skip(1) {
                node_segments.push(segment);
            }

            node.segments = node_segments;
        }
    }
}

struct ImplTraitResolver;
impl VisitMut for ImplTraitResolver {
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
                                        ImplTraitResolver.visit_type_mut(&mut ty);
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
                    }
                }
            }
        }

        if let Some(new_node) = new_node {
            *node = new_node;
        }
    }
}

fn get_ident(path: &syn::Path) -> &Ident {
    &path.segments.last().expect_or_abort("Defined").ident
}

pub fn unwrap_result_type(node: &Type) -> Option<&Type> {
    if let Type::Path(type_) = node {
        let last_seg = type_.path.segments.last().expect_or_abort("Defined");

        if last_seg.ident == "Result" {
            if let syn::PathArguments::AngleBracketed(args) = &last_seg.arguments {
                if let syn::GenericArgument::Type(result_type) = &args.args[0] {
                    return Some(result_type);
                }
            }
        }
    }

    None
}

pub fn ffi_output_arg(fn_descriptor: &FnDescriptor) -> Option<&Arg> {
    fn_descriptor.output_arg.as_ref().and_then(|output_arg| {
        if let Some(receiver) = &fn_descriptor.receiver {
            if receiver.name() == output_arg.name() {
                return None;
            }
        }

        Some(output_arg)
    })
}
