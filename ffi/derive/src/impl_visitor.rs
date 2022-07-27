use derive_more::Constructor;
use proc_macro2::Span;
use proc_macro_error::{abort, OptionExt};
use syn::{parse_quote, visit::Visit, visit_mut::VisitMut, Ident, Type};

pub trait Arg {
    fn name(&self) -> &Ident;
    fn src_type(&self) -> &Type;
    fn src_type_resolved(&self) -> Type;
    fn ffi_type_resolved(&self) -> Type;
}

#[derive(Constructor)]
pub struct Receiver<'ast> {
    self_ty: Option<&'ast syn::Path>,
    name: Ident,
    type_: Type,
}

pub struct InputArg<'ast> {
    self_ty: Option<&'ast syn::Path>,
    name: &'ast Ident,
    type_: &'ast Type,
}

pub struct ReturnArg<'ast> {
    self_ty: Option<&'ast syn::Path>,
    name: Ident,
    type_: &'ast Type,
}

pub struct ImplDescriptor<'ast> {
    /// Associated types in the impl block
    pub associated_types: Vec<(&'ast Ident, &'ast Type)>,
    /// Functions in the impl block
    pub fns: Vec<FnDescriptor<'ast>>,
}

impl<'ast> InputArg<'ast> {
    pub fn new(self_ty: Option<&'ast syn::Path>, name: &'ast Ident, type_: &'ast Type) -> Self {
        Self {
            self_ty,
            name,
            type_,
        }
    }
}

impl<'ast> ReturnArg<'ast> {
    pub fn new(self_ty: Option<&'ast syn::Path>, name: Ident, type_: &'ast Type) -> Self {
        Self {
            self_ty,
            name,
            type_,
        }
    }
}

impl Arg for Receiver<'_> {
    fn name(&self) -> &Ident {
        &self.name
    }
    fn src_type(&self) -> &Type {
        &self.type_
    }
    fn src_type_resolved(&self) -> Type {
        resolve_src_type(self.self_ty, self.type_.clone())
    }
    fn ffi_type_resolved(&self) -> Type {
        resolve_ffi_type(self.self_ty, self.type_.clone(), false)
    }
}

impl Arg for InputArg<'_> {
    fn name(&self) -> &Ident {
        self.name
    }
    fn src_type(&self) -> &Type {
        self.type_
    }
    fn src_type_resolved(&self) -> Type {
        resolve_src_type(self.self_ty, self.type_.clone())
    }
    fn ffi_type_resolved(&self) -> Type {
        resolve_ffi_type(self.self_ty, self.type_.clone(), false)
    }
}

impl Arg for ReturnArg<'_> {
    fn name(&self) -> &Ident {
        &self.name
    }
    fn src_type(&self) -> &Type {
        self.type_
    }
    fn src_type_resolved(&self) -> Type {
        resolve_src_type(self.self_ty, self.type_.clone())
    }
    fn ffi_type_resolved(&self) -> Type {
        resolve_ffi_type(self.self_ty, self.type_.clone(), true)
    }
}

fn resolve_src_type(self_ty: Option<&syn::Path>, mut arg_type: Type) -> Type {
    SelfResolver::new(self_ty).visit_type_mut(&mut arg_type);
    ImplTraitResolver.visit_type_mut(&mut arg_type);

    arg_type
}

fn resolve_ffi_type(self_ty: Option<&syn::Path>, mut arg_type: Type, is_output: bool) -> Type {
    SelfResolver::new(self_ty).visit_type_mut(&mut arg_type);
    ImplTraitResolver.visit_type_mut(&mut arg_type);

    if is_output {
        if let Some(result_type) = unwrap_result_type(&arg_type) {
            return parse_quote! {<#result_type as iroha_ffi::IntoFfi>::Target};
        }

        return parse_quote! {<#arg_type as iroha_ffi::IntoFfi>::Target};
    }

    if let Type::Reference(ref_type) = &arg_type {
        let elem = &ref_type.elem;

        return if ref_type.mutability.is_some() {
            parse_quote! {<&'itm mut #elem as iroha_ffi::TryFromReprC<'itm>>::Source}
        } else {
            parse_quote! {<&'itm #elem as iroha_ffi::TryFromReprC<'itm>>::Source}
        };
    }

    parse_quote! {<#arg_type as iroha_ffi::TryFromReprC<'itm>>::Source}
}

pub struct FnDescriptor<'ast> {
    /// Resolved type of the `Self` type
    pub self_ty: Option<&'ast syn::Path>,

    /// Function documentation
    pub doc: syn::LitStr,
    /// Name of the method in the original implementation
    pub method_name: &'ast Ident,
    /// Receiver argument, i.e. `self`
    pub receiver: Option<Receiver<'ast>>,
    /// Input fn arguments
    pub input_args: Vec<InputArg<'ast>>,
    /// Output fn argument
    pub output_arg: Option<ReturnArg<'ast>>,
}

struct ImplVisitor<'ast> {
    trait_name: Option<&'ast syn::Path>,
    /// Associated types in the impl block
    associated_types: Vec<(&'ast Ident, &'ast Type)>,
    /// Resolved type of the `Self` type
    self_ty: Option<&'ast syn::Path>,
    /// Collection of FFI functions
    pub fns: Vec<FnDescriptor<'ast>>,
}

struct FnVisitor<'ast> {
    /// Resolved type of the `Self` type
    self_ty: Option<&'ast syn::Path>,

    /// Function documentation
    doc: Option<syn::LitStr>,
    /// Name of the method in the original implementation
    method_name: Option<&'ast Ident>,
    /// Receiver argument, i.e. `self`
    receiver: Option<Receiver<'ast>>,
    /// Input fn arguments
    input_args: Vec<InputArg<'ast>>,
    /// Output fn argument
    output_arg: Option<ReturnArg<'ast>>,

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
            fns: visitor.fns,
            associated_types: visitor.associated_types,
        }
    }
}

impl<'ast> FnDescriptor<'ast> {
    pub fn from_impl_method(self_ty: &'ast syn::Path, node: &'ast syn::ImplItemMethod) -> Self {
        let mut visitor = FnVisitor::new(Some(self_ty));

        visitor.visit_impl_item_method(node);
        FnDescriptor::from_visitor(visitor)
    }

    fn from_visitor(visitor: FnVisitor<'ast>) -> Self {
        Self {
            self_ty: visitor.self_ty,
            doc: visitor.doc.expect_or_abort("Missing documentation"),
            method_name: visitor.method_name.expect_or_abort("Defined"),
            receiver: visitor.receiver,
            input_args: visitor.input_args,
            output_arg: visitor.output_arg,
        }
    }

    pub fn self_ty_name(&self) -> Option<&Ident> {
        self.self_ty.map(get_ident)
    }
}

impl<'ast> From<&'ast syn::ItemFn> for FnDescriptor<'ast> {
    fn from(item: &'ast syn::ItemFn) -> Self {
        let mut visitor = FnVisitor::new(None);

        visitor.visit_item_fn(item);
        Self::from_visitor(visitor)
    }
}

impl<'ast> ImplVisitor<'ast> {
    const fn new() -> Self {
        Self {
            trait_name: None,
            associated_types: Vec::new(),
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
    pub const fn new(self_ty: Option<&'ast syn::Path>) -> Self {
        Self {
            self_ty,

            doc: None,
            method_name: None,
            receiver: None,
            input_args: vec![],
            output_arg: None,

            curr_arg_name: None,
        }
    }

    fn add_input_arg(&mut self, src_type: &'ast Type) {
        let arg_name = self.curr_arg_name.take().expect_or_abort("Defined");
        self.input_args
            .push(InputArg::new(self.self_ty, arg_name, src_type));
    }

    /// Produces name of the return type. Name of the self argument is used for dummy
    /// output type which is not present in the FFI function signature. Dummy type is
    /// used to signal that the self type passes through the method being transcribed
    fn gen_output_arg_name(&mut self, output_src_type: &Type) -> Ident {
        if let Some(receiver) = &mut self.receiver {
            let self_src_ty = &mut receiver.type_;

            if *self_src_ty == *output_src_type {
                if matches!(self_src_ty, Type::Path(_)) {
                    // NOTE: `Self` is first consumed and then returned in the same method
                    let name = core::mem::replace(&mut receiver.name, parse_quote! {irrelevant});
                    *receiver = Receiver::new(self.self_ty, name, parse_quote! {#self_src_ty});
                }

                return receiver.name.clone();
            }
        }

        Ident::new("__output", Span::call_site())
    }

    fn add_output_arg(&mut self, src_type: &'ast Type) {
        assert!(self.curr_arg_name.is_none());
        assert!(self.output_arg.is_none());

        self.output_arg = Some(ReturnArg::new(
            self.self_ty,
            self.gen_output_arg_name(src_type),
            src_type,
        ));
    }

    fn visit_impl_item_method_attribute(&mut self, node: &'ast syn::Attribute) {
        if let Ok(meta) = node.parse_meta() {
            if !meta.path().is_ident("doc") {
                return;
            }

            self.doc = if let syn::Meta::NameValue(doc) = meta {
                let lit = doc.lit;
                Some(parse_quote! {#lit})
            } else {
                unreachable!()
            };
        }
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
        self.trait_name = node.trait_.as_ref().map(|trait_| &trait_.1);
        self.visit_self_type(&*node.self_ty);

        for it in &node.items {
            match it {
                syn::ImplItem::Method(method) => {
                    let self_ty = self.self_ty.expect_or_abort("Defined");
                    self.fns
                        .push(FnDescriptor::from_impl_method(self_ty, method))
                }
                syn::ImplItem::Type(type_) => {
                    self.associated_types.push((&type_.ident, &type_.ty));
                }
                _ => abort!(
                    node,
                    "Only methods or types are supported inside impl blocks"
                ),
            }
        }
    }
}

impl<'ast> Visit<'ast> for FnVisitor<'ast> {
    fn visit_impl_item_method(&mut self, node: &'ast syn::ImplItemMethod) {
        for attr in &node.attrs {
            self.visit_impl_item_method_attribute(attr);
        }
        if !matches!(node.vis, syn::Visibility::Public(_)) {
            abort!(node.vis, "Methods defined in the impl block must be public");
        }

        self.visit_signature(&node.sig);
    }
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        for attr in &node.attrs {
            self.visit_impl_item_method_attribute(attr);
        }

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
        self.method_name = Some(&node.ident);
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
        self.receiver = Some(Receiver::new(self.self_ty, handle_name, src_type));
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

        self.add_input_arg(&*node.ty);
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
                self.add_output_arg(&**src_type);
            }
        }
    }
}

/// Visitor replaces all occurrences of `Self` in a path type with a fully qualified type
struct SelfResolver<'ast> {
    self_ty: Option<&'ast syn::Path>,
}

impl<'ast> SelfResolver<'ast> {
    fn new(self_ty: Option<&'ast syn::Path>) -> Self {
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
            let mut node_segments = self
                .self_ty
                .expect("Self type path expected")
                .segments
                .clone();

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

                                        new_node = Some(parse_quote! {
                                            Vec<#ty>
                                        });
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
