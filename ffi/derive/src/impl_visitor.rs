#![allow(clippy::unimplemented)]

use proc_macro2::Span;
use proc_macro_error::{abort, OptionExt};
use syn::{
    parse_quote, visit::Visit, visit_mut::VisitMut, Ident, PathArguments::AngleBracketed, Type,
};

use crate::get_ident;

pub struct ImplDescriptor<'ast> {
    /// Functions in the impl block
    pub fns: Vec<FnDescriptor<'ast>>,
}

pub struct FnDescriptor<'ast> {
    /// Resolved type of the `Self` type
    pub self_ty: &'ast syn::Path,

    /// Function documentation
    pub doc: syn::LitStr,
    /// Name of the method in the original implementation
    pub method_name: &'ast Ident,
    /// Receiver argument, i.e. `self`
    pub receiver: Option<FnArgDescriptor>,
    /// Input fn arguments
    pub input_args: Vec<FnArgDescriptor>,
    /// Output fn argument
    pub output_arg: Option<FnArgDescriptor>,
}

#[derive(Debug)]
pub struct FnArgDescriptor {
    /// Name of the argument in an FFI function
    pub ffi_name: Ident,
    /// Type of the argument in a method implementation
    pub src_type: Type,
    /// Type of the argument in an FFI function
    pub ffi_type: Type,
}

struct ImplVisitor<'ast> {
    /// Resolved type of the `Self` type
    self_ty: Option<&'ast syn::Path>,
    /// Collection of FFI functions
    pub fns: Vec<FnDescriptor<'ast>>,
}

struct FnVisitor<'ast> {
    /// Resolved type of the `Self` type
    self_ty: &'ast syn::Path,

    /// Function documentation
    doc: Option<syn::LitStr>,
    /// Name of the method in the original implementation
    method_name: Option<&'ast Ident>,
    /// Receiver argument, i.e. `self`
    receiver: Option<FnArgDescriptor>,
    /// Input fn arguments
    input_args: Vec<FnArgDescriptor>,
    /// Output fn argument
    output_arg: Option<FnArgDescriptor>,

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
        Self { fns: visitor.fns }
    }
}

impl<'ast> FnDescriptor<'ast> {
    fn from_impl_method(self_ty: &'ast syn::Path, node: &'ast syn::ImplItemMethod) -> Self {
        let mut visitor = FnVisitor::new(self_ty);
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

    pub fn self_ty_name(&self) -> &Ident {
        get_ident(self.self_ty)
    }
}

impl<'ast> ImplVisitor<'ast> {
    const fn new() -> Self {
        Self {
            self_ty: None,
            fns: vec![],
        }
    }

    fn visit_self_type(&mut self, node: &'ast Type) {
        if let Type::Path(self_ty) = node {
            if self_ty.qself.is_some() {
                abort!(self_ty, "Qualified types not supported as self type");
            }

            self.self_ty = Some(&self_ty.path);
        } else {
            abort!(node, "Only nominal types supported as self type");
        }
    }
}

impl FnArgDescriptor {
    /// Returns true if this argument is a shared slice reference
    pub fn is_slice_ref(&self) -> bool {
        match &self.src_type {
            Type::Reference(type_) => {
                return type_.mutability.is_none() && matches!(*type_.elem, Type::Slice(_));
            }
            Type::ImplTrait(type_) => {
                assert_eq!(type_.bounds.len(), 1);

                if let syn::TypeParamBound::Trait(trait_) = &type_.bounds[0] {
                    let trait_name = get_ident(&trait_.path);
                    return trait_name == "IntoIterator";
                }
            }
            _ => return false,
        }

        false
    }

    /// Returns true if this argument is a mutable slice reference
    pub fn is_slice_ref_mut(&self) -> bool {
        match &self.src_type {
            Type::Reference(type_) => {
                return type_.mutability.is_some() && matches!(*type_.elem, Type::Slice(_));
            }
            Type::ImplTrait(type_) => {
                assert_eq!(type_.bounds.len(), 1);

                if let syn::TypeParamBound::Trait(trait_) = &type_.bounds[0] {
                    let trait_name = get_ident(&trait_.path);
                    return trait_name == "ExactSizeIterator";
                }
            }
            _ => return false,
        }

        false
    }

    pub const fn is_ffi_ptr(&self) -> bool {
        matches!(self.ffi_type, Type::Ptr(_))
    }
}

impl<'ast> FnVisitor<'ast> {
    pub const fn new(self_ty: &'ast syn::Path) -> Self {
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

    fn gen_self_arg_name() -> Ident {
        Ident::new("handle", Span::call_site())
    }

    fn add_input_arg(&mut self, src_type: Type, ffi_type: Type) {
        let ffi_name = self.curr_arg_name.take().expect_or_abort("Defined").clone();

        self.input_args.push(FnArgDescriptor {
            ffi_name,
            src_type,
            ffi_type,
        });
    }

    /// Produces name of the return type. Name of the self argument is used for dummy
    /// output type which is not present in the FFI function signature. Dummy type is
    /// used to signal that the self type passes through the method being transcribed
    fn gen_output_arg_name(&self, output_ffi_type: &Type) -> Ident {
        if let Some(receiver) = &self.receiver {
            if &receiver.ffi_type == output_ffi_type {
                return receiver.ffi_name.clone();
            }
        }

        Ident::new("output", Span::call_site())
    }

    fn add_output_arg(&mut self, src_type: Type, mut ffi_type: Type) {
        assert!(self.curr_arg_name.is_none());
        assert!(self.output_arg.is_none());

        let ffi_name = self.gen_output_arg_name(&ffi_type);
        if !matches!(src_type, Type::ImplTrait(_)) {
            ffi_type = parse_quote! { *mut #ffi_type };
        }

        self.output_arg = Some(FnArgDescriptor {
            ffi_name,
            src_type,
            ffi_type,
        });
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
        if let Some(trait_) = &node.trait_ {
            abort!(trait_.1, "Only inherent impls are supported");
        }
        self.visit_self_type(&*node.self_ty);

        for it in &node.items {
            self.visit_impl_item(it);
        }
    }
    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        let self_ty = self.self_ty.expect_or_abort("Defined");

        match node {
            syn::ImplItem::Method(method) => {
                self.fns
                    .push(FnDescriptor::from_impl_method(self_ty, method));
            }
            _ => abort!(node, "Only methods are supported inside impl blocks"),
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

        let self_type = self.self_ty;
        let (src_type, ffi_type) = node.reference.as_ref().map_or_else(
            || {
                (
                    syn::TypePath {
                        qself: None,
                        path: self_type.clone(),
                    }
                    .into(),
                    parse_quote! { *mut #self_type },
                )
            },
            |it| {
                if it.1.is_some() {
                    abort!(it.1, "Explicit lifetime not supported");
                }

                if node.mutability.is_some() {
                    (
                        parse_quote! { &mut #self_type },
                        parse_quote! { *mut #self_type },
                    )
                } else {
                    (
                        parse_quote! { & #self_type },
                        parse_quote! { *const #self_type },
                    )
                }
            },
        );

        self.receiver = Some(FnArgDescriptor {
            ffi_name: Self::gen_self_arg_name(),
            src_type,
            ffi_type,
        });
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

        self.add_input_arg(
            *node.ty.clone(),
            TypeVisitor::resolve_ffi_type(self.self_ty, *node.ty.clone()),
        );
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
                let mut ffi_type = TypeVisitor::resolve_ffi_type(self.self_ty, *src_type.clone());

                // NOTE: Transcribe owned output types to *mut ptr
                if let (Type::Path(src_ty), Type::Ptr(ffi_ty)) = (*src_type.clone(), &mut ffi_type)
                {
                    let ffi_ptr_subty = &ffi_ty.elem;

                    if get_ident(&src_ty.path) != "Option" {
                        *ffi_ty = parse_quote! { *mut #ffi_ptr_subty };
                    }
                }

                self.add_output_arg(*src_type.clone(), ffi_type);
            }
        }

        if let Some(receiver) = &self.receiver {
            let self_src_type = &receiver.src_type;

            if matches!(self_src_type, Type::Path(_)) {
                let output_arg = self.output_arg.as_ref();

                if output_arg.map_or(true, |out_arg| receiver.ffi_name != out_arg.ffi_name) {
                    abort!(self_src_type, "Methods which consume self not supported");
                }
            }
        }
    }
}

struct TypeVisitor {
    ffi_type: Option<Type>,
}
impl TypeVisitor {
    fn resolve_ffi_type(self_ty: &syn::Path, mut src_type: Type) -> Type {
        SelfResolver::new(self_ty).visit_type_mut(&mut src_type);
        let mut visitor = Self { ffi_type: None };
        visitor.visit_type(&src_type);
        visitor.ffi_type.expect_or_abort("Defined")
    }

    fn visit_item_binding(&mut self, seg: &syn::PathSegment) {
        let bindings = generic_arg_bindings(seg);

        if bindings.is_empty() {
            abort!(seg, "Missing generic argument `Item`");
        }
        if bindings[0].ident != "Item" {
            abort!(seg, "Unknown binding");
        }

        self.visit_type(&bindings[0].ty);
    }
}

impl<'ast> Visit<'ast> for TypeVisitor {
    fn visit_type_array(&mut self, _: &'ast syn::TypeArray) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_bare_fn(&mut self, _: &'ast syn::TypeBareFn) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_group(&mut self, _: &'ast syn::TypeGroup) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_impl_trait(&mut self, node: &'ast syn::TypeImplTrait) {
        if node.bounds.len() > 1 {
            abort!(
                node.bounds,
                "Only one trait is allowed for the `impl trait` argument"
            );
        }

        if let syn::TypeParamBound::Trait(trait_) = &node.bounds[0] {
            let last_seg = trait_.path.segments.last().expect_or_abort("Defined");

            if trait_.lifetimes.is_some() {
                abort!(last_seg, "Lifetime bound not supported in `impl Trait`");
            }

            match last_seg.ident.to_string().as_str() {
                "IntoIterator" => {
                    self.visit_item_binding(last_seg);

                    self.ffi_type = {
                        let ffi_subty = &self.ffi_type;
                        Some(parse_quote! { *const #ffi_subty })
                    };
                }
                "ExactSizeIterator" => {
                    self.visit_item_binding(last_seg);

                    self.ffi_type = {
                        let ffi_subty = &self.ffi_type;
                        Some(parse_quote! { *mut #ffi_subty })
                    };
                }
                "Into" => {
                    self.visit_type(generic_arg_types(last_seg)[0]);
                }
                _ => abort!(trait_, "Unsupported `impl trait`"),
            }
        }
    }
    fn visit_type_infer(&mut self, _: &'ast syn::TypeInfer) {
        unreachable!("Infer type not possible in a declaration")
    }
    fn visit_type_macro(&mut self, _: &'ast syn::TypeMacro) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_never(&mut self, _: &'ast syn::TypeNever) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_param(&mut self, _: &'ast syn::TypeParam) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_param_bound(&mut self, _: &'ast syn::TypeParamBound) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_paren(&mut self, _: &'ast syn::TypeParen) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        let last_seg = node.path.segments.last().expect_or_abort("Defined");

        match last_seg.ident.to_string().as_str() {
            "bool" => self.ffi_type = Some(parse_quote! { u8 }),
            "u8" | "u16" => self.ffi_type = Some(parse_quote! { u32 }),
            "i8" | "i16" => self.ffi_type = Some(parse_quote! { i32 }),
            "u32" | "i32" | "u64" | "i64" | "f32" | "f64" => {
                self.ffi_type = Some(node.clone().into())
            }
            "Option" => {
                let option_ty = generic_arg_types(last_seg)[0];

                match option_ty {
                    Type::Reference(type_) => self.visit_type_reference(type_),
                    _ => abort!(option_ty, "Unsupported Option type"),
                }
            }
            "Result" => {
                let args = generic_arg_types(last_seg);
                let (ok_type, _) = (args[0], args[1]);

                match ok_type {
                    Type::Path(type_) => self.visit_type_path(type_),
                    Type::Reference(type_) => self.visit_type_reference(type_),
                    _ => abort!(ok_type, "Unsupported Result::Ok type"),
                }
            }
            _ => self.ffi_type = Some(parse_quote! { *const #node }),
        }
    }
    fn visit_type_ptr(&mut self, node: &'ast syn::TypePtr) {
        abort!(node, "Raw pointers not supported")
    }
    fn visit_type_reference(&mut self, node: &'ast syn::TypeReference) {
        if let Some(li) = &node.lifetime {
            abort!(li, "Explicit lifetime not supported in reference types");
        }

        if node.mutability.is_some() {
            abort!(node, "Mutable references not supported");
        }

        self.visit_type(&*node.elem);

        // NOTE: Owned opaque pointers produce double indirection
        let mut ffi_type = self.ffi_type.take().expect_or_abort("Defined");
        if let (Type::Path(_), Type::Ptr(ffi_ptr_ty)) = (&*node.elem, &ffi_type) {
            ffi_type = *ffi_ptr_ty.elem.clone();
        }

        self.ffi_type = Some(parse_quote! { *const #ffi_type });
    }

    fn visit_type_slice(&mut self, _: &'ast syn::TypeSlice) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_trait_object(&mut self, _: &'ast syn::TypeTraitObject) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_tuple(&mut self, node: &'ast syn::TypeTuple) {
        if node.elems.len() != 2 {
            abort!(node, "Only tuple pairs supported as of yet");
        }

        self.visit_type(&node.elems[0]);
        let key = self.ffi_type.take();
        self.visit_type(&node.elems[1]);
        let val = self.ffi_type.take();

        self.ffi_type = Some(parse_quote! { iroha_ffi::Pair<#key, #val> });
    }
}

/// Visitor for path types which replaces all occurrences of `Self` with a fully qualified type
pub struct SelfResolver<'ast> {
    self_ty: &'ast syn::Path,
}

impl<'ast> SelfResolver<'ast> {
    pub const fn new(self_ty: &'ast syn::Path) -> Self {
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
            let mut node_segments = self.self_ty.segments.clone();

            for segment in core::mem::take(&mut node.segments).into_iter().skip(1) {
                node_segments.push(segment);
            }

            node.segments = node_segments;
        }
    }
}

pub fn generic_arg_types(seg: &syn::PathSegment) -> Vec<&Type> {
    if let AngleBracketed(arguments) = &seg.arguments {
        let mut args = vec![];

        for arg in &arguments.args {
            if let syn::GenericArgument::Type(ty) = &arg {
                args.push(ty);
            }
        }

        return args;
    };

    abort!(seg, "Type not found in the given path segment")
}

fn generic_arg_bindings(seg: &syn::PathSegment) -> Vec<&syn::Binding> {
    if let AngleBracketed(arguments) = &seg.arguments {
        let mut bindings = vec![];

        for arg in &arguments.args {
            if let syn::GenericArgument::Binding(binding) = arg {
                bindings.push(binding);
            }
        }

        return bindings;
    };

    abort!(seg, "Binding not found in the given path segment")
}
