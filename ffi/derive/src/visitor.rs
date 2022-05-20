#![allow(clippy::unimplemented)]

use heck::ToSnakeCase;
use proc_macro2::Span;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{
    parse_quote, visit::Visit, visit_mut::VisitMut, Ident, PathArguments::AngleBracketed, Type,
};

pub struct ImplDescriptor<'ast> {
    /// Whether current impl is a trait impl
    is_inherent_impl: bool,
    /// Resolved type of the `Self` type
    self_ty: Option<&'ast syn::Path>,

    /// Collection of FFI functions
    pub fns: Vec<FfiFnDescriptor<'ast>>,
}

#[derive(Debug)]
pub struct FfiFnDescriptor<'ast> {
    /// Whether currently visited method is a trait method
    is_inherent_method: bool,

    /// Resolved type of the `Self` type
    self_ty: &'ast syn::Path,

    /// Name of the method in the original implementation
    method_name: Option<&'ast Ident>,
    /// Receiver argument
    self_arg: Option<FfiFnArgDescriptor>,
    /// Input fn arguments
    input_args: Vec<FfiFnArgDescriptor>,
    /// Output fn argument
    output_arg: Option<FfiFnArgDescriptor>,

    /// Name of the argument being visited
    curr_arg_name: Option<&'ast Ident>,
}

#[derive(Debug)]
pub struct FfiFnArgDescriptor {
    /// Name of the argument in an FFI function
    ffi_name: Ident,
    /// Type of the argument in a method implementation
    src_type: Type,
    /// Type of the argument in an FFI function
    ffi_type: Type,
}

impl quote::ToTokens for FfiFnDescriptor<'_> {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let ffi_fn_name = self.get_ffi_fn_name();

        let self_arg = self
            .self_arg
            .as_ref()
            .map_or_else(Vec::new, |self_arg| vec![self_arg]);

        let fn_args = &self.input_args;
        let ret_arg = self.output_arg();
        let fn_body = self.get_fn_body();

        let ffi_fn_doc = format!(
            " FFI function equivalent of [`{}::{}`]",
            self.self_ty.get_ident().expect_or_abort("Defined"),
            self.method_name.expect_or_abort("Defined")
        );

        tokens.extend(quote! {
            #[doc = #ffi_fn_doc]
            #[no_mangle]
            pub unsafe extern "C" fn #ffi_fn_name(#(#self_arg,)* #(#fn_args,)* #ret_arg) -> iroha_ffi::FfiResult {
                #fn_body
            }
        });
    }
}

impl quote::ToTokens for FfiFnArgDescriptor {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let ffi_name = &self.ffi_name;
        let src_type = &self.src_type;
        let ffi_type = &self.ffi_type;

        if self.is_slice_ref() || self.is_slice_ref_mut() {
            tokens.extend(quote! { mut #ffi_name: #ffi_type, });
            slice_len_arg_to_tokens(src_type, self, tokens);
        } else {
            tokens.extend(quote! { #ffi_name: #ffi_type });
        };
    }
}

fn slice_len_arg_to_tokens(
    src_type: &Type,
    ffi_fn_arg: &FfiFnArgDescriptor,
    tokens: &mut proc_macro2::TokenStream,
) {
    let mut slice_len_to_tokens = || {
        let slice_len_arg_name = ffi_fn_arg.get_slice_len_arg_name();
        tokens.extend(quote! { #slice_len_arg_name: usize });
    };

    match &src_type {
        Type::Reference(type_) => {
            if matches!(*type_.elem, Type::Slice(_)) {
                slice_len_to_tokens();
            }
        }
        Type::ImplTrait(type_) => {
            assert_eq!(type_.bounds.len(), 1);

            if let syn::TypeParamBound::Trait(trait_) = &type_.bounds[0] {
                let last_seg = &trait_.path.segments.last().expect_or_abort("Defined");

                if last_seg.ident == "IntoIterator" {
                    slice_len_to_tokens();
                } else if last_seg.ident == "ExactSizeIterator" {
                    slice_len_to_tokens();
                    let slice_elems_arg_name = ffi_fn_arg.get_slice_elems_arg_name();
                    tokens.extend(quote! {, #slice_elems_arg_name: *mut usize });
                } else {
                    abort!(src_type, "Unsupported impl trait slice type")
                }
            }
        }
        _ => {}
    }
}

impl<'ast> ImplDescriptor<'ast> {
    pub fn new() -> Self {
        Self {
            is_inherent_impl: true,
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

impl<'ast> FfiFnDescriptor<'ast> {
    pub fn new(self_ty: &'ast syn::Path, is_inherent_method: bool) -> Self {
        Self {
            is_inherent_method,
            self_ty,

            method_name: None,
            self_arg: None,
            input_args: vec![],
            output_arg: None,

            curr_arg_name: None,
        }
    }

    fn get_ffi_fn_name(&self) -> Ident {
        let self_ty_name = self
            .self_ty
            .segments
            .last()
            .expect_or_abort("Path must have at least one segment")
            .ident
            .to_string()
            .to_snake_case();

        Ident::new(
            &format!(
                "{}_{}",
                self_ty_name,
                self.method_name
                    .as_ref()
                    .expect_or_abort("Method name must be defined")
            ),
            Span::call_site(),
        )
    }

    fn get_self_arg_name() -> Ident {
        Ident::new("handle", Span::call_site())
    }

    fn add_input_arg(&mut self, src_type: Type, ffi_type: Type) {
        let ffi_name = self.curr_arg_name.take().expect_or_abort("Defined").clone();

        self.input_args.push(FfiFnArgDescriptor {
            ffi_name,
            src_type,
            ffi_type,
        });
    }

    /// Produces name of the return type. Name of the self argument is used for dummy output type.
    /// Dummy output type is a type which is not present in the FFI function signature. Dummy
    /// type is used to signal that the self type passes through the method being transcribed
    fn get_output_arg_name(&self, output_ffi_type: &Type) -> Ident {
        if let Some(self_arg) = &self.self_arg {
            if &self_arg.ffi_type == output_ffi_type {
                return self_arg.ffi_name.clone();
            }
        }

        Ident::new("output", Span::call_site())
    }

    fn add_output_arg(&mut self, src_type: Type, mut ffi_type: Type) {
        assert!(self.curr_arg_name.is_none());
        assert!(self.output_arg.is_none());

        let ffi_name = self.get_output_arg_name(&ffi_type);
        if !matches!(src_type, Type::ImplTrait(_)) {
            ffi_type = parse_quote! { *mut #ffi_type };
        }

        self.output_arg = Some(FfiFnArgDescriptor {
            ffi_name,
            src_type,
            ffi_type,
        });
    }

    fn get_type_check_stmts(&self) -> Vec<syn::Stmt> {
        let mut stmts = vec![];

        self.self_arg.as_ref().map(|self_arg| {
            self_arg
                .get_ptr_null_check_stmt()
                .map(|stmt| stmts.push(stmt))
        });

        for arg in &self.input_args {
            if arg.is_slice_ref() {
                stmts.push(arg.get_dangling_ptr_assignment());
            } else if let Some(stmt) = arg.get_ptr_null_check_stmt() {
                stmts.push(stmt);
            }
        }

        if let Some(output_arg) = self.output_arg() {
            if output_arg.is_slice_ref_mut() {
                let slice_elems_arg_name = output_arg.get_slice_elems_arg_name();

                stmts.push(parse_quote! {
                    if #slice_elems_arg_name.is_null() {
                        return iroha_ffi::FfiResult::ArgIsNull;
                    }
                });

                stmts.push(output_arg.get_dangling_ptr_assignment());
            } else if let Some(stmt) = output_arg.get_ptr_null_check_stmt() {
                stmts.push(stmt);
            }
        }

        stmts
    }

    /// Return output argument if present and not dummy
    fn output_arg(&self) -> Option<&FfiFnArgDescriptor> {
        self.output_arg.as_ref().and_then(|output_arg| {
            if let Some(self_arg) = &self.self_arg {
                if self_arg.ffi_name == output_arg.ffi_name {
                    return None;
                }
            }

            Some(output_arg)
        })
    }

    fn get_ffi_to_src_conversion_stmts(&self) -> Vec<syn::Stmt> {
        let mut stmts = vec![];

        if let Some(self_arg) = &self.self_arg {
            let arg_name = &self_arg.ffi_name;

            match &self_arg.src_type {
                Type::Path(_) => stmts.push(parse_quote! {
                    let _handle = #arg_name.read();
                }),
                Type::Reference(type_) => {
                    stmts.push(if type_.mutability.is_some() {
                        parse_quote! { let #arg_name = &mut *#arg_name; }
                    } else {
                        parse_quote! { let #arg_name = &*#arg_name; }
                    });
                }
                _ => unreachable!("Self can only be taken by value or by reference"),
            }
        }

        for arg in &self.input_args {
            stmts.extend(arg.get_ffi_to_src_conversion_stmts());
        }

        stmts
    }

    fn get_method_call_stmt(&self) -> syn::Stmt {
        let method_name = &self.method_name;
        let self_type = &self.self_ty;

        let self_arg_name = self.self_arg.as_ref().map_or_else(Vec::new, |self_arg| {
            if matches!(self_arg.src_type, Type::Path(_)) {
                return vec![Ident::new("_handle", Span::call_site())];
            }

            vec![self_arg.ffi_name.clone()]
        });

        let fn_arg_names = self.input_args.iter().map(|arg| &arg.ffi_name);
        parse_quote! { let method_res = #self_type::#method_name(#(#self_arg_name,)* #(#fn_arg_names),*); }
    }

    fn get_src_to_ffi_conversion_stmts(&self) -> Vec<syn::Stmt> {
        if let Some(output_arg) = self.output_arg() {
            return output_arg.get_src_to_ffi_conversion_stmts();
        }

        vec![]
    }

    fn get_output_assignment_stmts(&self) -> Vec<syn::Stmt> {
        let mut stmts = vec![];

        if let Some(output_arg) = &self.output_arg {
            let output_arg_name = &output_arg.ffi_name;

            if output_arg.is_slice_ref_mut() {
                let (slice_len_arg_name, slice_elems_arg_name) = (
                    output_arg.get_slice_len_arg_name(),
                    output_arg.get_slice_elems_arg_name(),
                );

                stmts.push(parse_quote! {{
                    let #output_arg_name = core::slice::from_raw_parts_mut(#output_arg_name, #slice_len_arg_name);

                    #slice_elems_arg_name.write(method_res.len());
                    for (i, elem) in method_res.take(#slice_len_arg_name).enumerate() {
                        #output_arg_name[i] = elem;
                    }
                }});
            } else {
                assert!(matches!(output_arg.ffi_type, Type::Ptr(_)));
                stmts.push(parse_quote! { #output_arg_name.write(method_res); });
            }
        }

        stmts
    }

    fn get_fn_body(&self) -> syn::Block {
        let checks = self.get_type_check_stmts();
        let input_conversions = self.get_ffi_to_src_conversion_stmts();
        let method_call_stmt = self.get_method_call_stmt();
        let output_conversions = self.get_src_to_ffi_conversion_stmts();
        let output_assignment = self.get_output_assignment_stmts();

        parse_quote! {{
            #( #checks )*
            #( #input_conversions )*

            #method_call_stmt

            #( #output_conversions )*
            #( #output_assignment )*

            iroha_ffi::FfiResult::Ok
        }}
    }
}

impl FfiFnArgDescriptor {
    /// Returns true if this argument is a shared slice reference
    fn is_slice_ref(&self) -> bool {
        match &self.src_type {
            Type::Reference(type_) => {
                return type_.mutability.is_none() && matches!(*type_.elem, Type::Slice(_));
            }
            Type::ImplTrait(type_) => {
                assert_eq!(type_.bounds.len(), 1);

                if let syn::TypeParamBound::Trait(trait_) = &type_.bounds[0] {
                    let trait_name = &trait_.path.segments.last().expect_or_abort("Defined").ident;
                    return trait_name == "IntoIterator";
                }
            }
            _ => return false,
        }

        false
    }

    /// Returns true if this argument is a mutable slice reference
    fn is_slice_ref_mut(&self) -> bool {
        match &self.src_type {
            Type::Reference(type_) => {
                return type_.mutability.is_some() && matches!(*type_.elem, Type::Slice(_));
            }
            Type::ImplTrait(type_) => {
                assert_eq!(type_.bounds.len(), 1);

                if let syn::TypeParamBound::Trait(trait_) = &type_.bounds[0] {
                    let trait_name = &trait_.path.segments.last().expect_or_abort("Defined").ident;
                    return trait_name == "ExactSizeIterator";
                }
            }
            _ => return false,
        }

        false
    }

    fn is_ffi_ptr(&self) -> bool {
        matches!(self.ffi_type, Type::Ptr(_))
    }

    /// Returns a null check statement for this argument if it's FFI type is [`Type::Ptr`]
    fn get_ptr_null_check_stmt(&self) -> Option<syn::Stmt> {
        let arg_name = &self.ffi_name;

        if self.is_ffi_ptr() {
            return Some(parse_quote! {
                if #arg_name.is_null() {
                    return iroha_ffi::FfiResult::ArgIsNull;
                }
            });
        }

        None
    }

    fn get_dangling_ptr_assignment(&self) -> syn::Stmt {
        let (arg_name, slice_len_arg_name) = (&self.ffi_name, self.get_slice_len_arg_name());

        parse_quote! {
            if #slice_len_arg_name == 0_usize {
                // NOTE: `slice::from_raw_parts` takes a non-null aligned pointer
                #arg_name = core::ptr::NonNull::dangling().as_ptr();
            }
        }
    }

    fn get_slice_elems_arg_name(&self) -> Ident {
        Ident::new(&format!("{}_elems", self.ffi_name), Span::call_site())
    }

    fn get_slice_len_arg_name(&self) -> Ident {
        Ident::new(&format!("{}_len", self.ffi_name), Span::call_site())
    }

    fn get_ffi_to_src_impl_into_iterator_conversion_stmts(
        &self,
        ffi_type: &syn::TypePtr,
    ) -> Vec<syn::Stmt> {
        let slice_len_arg_name = self.get_slice_len_arg_name();

        let arg_name = &self.ffi_name;
        let mut stmts = vec![parse_quote! {
            let #arg_name = core::slice::from_raw_parts(#arg_name, #slice_len_arg_name).into_iter();
        }];

        match &*ffi_type.elem {
            Type::Path(type_) => {
                let last_seg = type_.path.segments.last().expect_or_abort("Defined");

                if last_seg.ident == "Pair" {
                    stmts.push(parse_quote! {
                        let #arg_name = #arg_name.map(|iroha_ffi::Pair(key, val)| {
                            (key.read(), val.read())
                        });
                    });
                } else {
                    abort!(last_seg, "Collection item not supported in FFI")
                }
            }
            Type::Ptr(_) => {
                stmts.push(parse_quote! {
                    let #arg_name = #arg_name.map(|ptr| ptr.read());
                });
            }
            _ => abort!(self, "Unsupported FFI type conversion"),
        }

        stmts
    }

    fn get_ffi_to_src_conversion_stmts(&self) -> Vec<syn::Stmt> {
        let mut stmts = vec![];

        let arg_name = &self.ffi_name;
        match (&self.src_type, &self.ffi_type) {
            (Type::Reference(src_ty), Type::Ptr(_)) => {
                if matches!(*src_ty.elem, Type::Slice(_)) {
                    // TODO: slice is here
                } else {
                    stmts.push(parse_quote! { let #arg_name = &*#arg_name; });
                }
            }
            (Type::ImplTrait(src_ty), Type::Ptr(ffi_ty)) => {
                if let syn::TypeParamBound::Trait(trait_) = &src_ty.bounds[0] {
                    let last_seg = &trait_.path.segments.last().expect_or_abort("Defined");

                    match last_seg.ident.to_string().as_ref() {
                        "IntoIterator" => stmts.extend(
                            self.get_ffi_to_src_impl_into_iterator_conversion_stmts(ffi_ty),
                        ),
                        "Into" => stmts.push(parse_quote! {
                            let #arg_name = #arg_name.read();
                        }),
                        _ => abort!(last_seg, "impl Trait type not supported"),
                    }
                }
            }
            (Type::Path(_), Type::Ptr(_)) => {
                stmts.push(parse_quote! { let #arg_name = #arg_name.read(); });
            }
            (Type::Path(src_ty), Type::Path(_)) => {
                let last_seg = src_ty.path.segments.last().expect_or_abort("Defined");

                match last_seg.ident.to_string().as_ref() {
                    "bool" => stmts.push(parse_quote! { let #arg_name = #arg_name != 0; }),
                    // TODO: Wasm conversions?
                    _ => unreachable!("Unsupported FFI conversion"),
                }
            }
            _ => abort!(self, "Unsupported FFI type conversion"),
        }

        stmts
    }

    fn get_src_to_ffi_conversion_stmts(&self) -> Vec<syn::Stmt> {
        let ffi_type = if let Type::Ptr(ffi_type) = &self.ffi_type {
            &*ffi_type.elem
        } else {
            unreachable!("Output must be an out-pointer")
        };

        let mut stmts = vec![];
        match (&self.src_type, ffi_type) {
            (Type::Reference(src_ty), Type::Ptr(_)) => {
                stmts.push(if src_ty.mutability.is_some() {
                    parse_quote! { let method_res: *mut _ = method_res; }
                } else {
                    parse_quote! { let method_res: *const _ = method_res; }
                });
            }
            (Type::ImplTrait(_), Type::Path(ffi_ty)) => {
                if ffi_ty.path.segments.last().expect_or_abort("Defined").ident != "Pair" {
                    abort!(self, "Unsupported FFI type conversion");
                }

                stmts.push(parse_quote! {
                    let method_res = method_res.into_iter().map(|(key, val)| {
                        iroha_ffi::Pair(key as *const _, val as *const _)
                    });
                });
            }
            (Type::ImplTrait(_), Type::Ptr(ffi_ty)) => {
                stmts.push(parse_quote! { let method_res = method_res.into_iter(); });

                if !matches!(*ffi_ty.elem, Type::Path(_)) {
                    abort!(self, "Unsupported FFI type conversion");
                }

                stmts.push(if ffi_ty.mutability.is_some() {
                    parse_quote! { let method_res = method_res.map(|arg| arg as *mut _); }
                } else {
                    parse_quote! { let method_res = method_res.map(|arg| arg as *const _); }
                });
            }
            (Type::Path(src_ty), Type::Ptr(ffi_ty)) => {
                let is_option_type = is_option_type(src_ty);

                stmts.push(if is_option_type && ffi_ty.mutability.is_some() {
                    parse_quote! {
                        let method_res = method_res.map_or(core::ptr::null_mut(), |elem| elem as *mut _);
                    }
                } else if is_option_type && ffi_ty.mutability.is_none() {
                    parse_quote! {
                        let method_res = method_res.map_or(core::ptr::null(), |elem| elem as *const _);
                    }
                } else {
                    parse_quote! { let method_res = Box::into_raw(Box::new(method_res)); }
                });
            }
            (Type::Path(src_ty), Type::Path(_)) => {
                let last_seg = src_ty.path.segments.last().expect_or_abort("Defined");

                match last_seg.ident.to_string().as_ref() {
                    "bool" => stmts.push(parse_quote! { let method_res = method_res as u8; }),
                    "Result" => stmts.push(parse_quote! {
                        let method_res = match method_res {
                            Ok(method_res) => method_res,
                            Err(method_res) => {
                                return iroha_ffi::FfiResult::ExecutionFail;
                            }
                        };
                    }),
                    // TODO: Wasm conversions?
                    _ => unreachable!("Unsupported FFI conversion"),
                }
            }
            _ => abort!(self, "Unsupported FFI type conversion"),
        }

        stmts
    }
}

impl<'ast> Visit<'ast> for ImplDescriptor<'ast> {
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
        // TODO: What to do about generics?
        //self.visit_generics(&node.generics);
        self.is_inherent_impl = node.trait_.is_none();
        self.visit_self_type(&*node.self_ty);

        for it in &node.items {
            self.visit_impl_item(it);
        }
    }
    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        let mut ffi_fn_descriptor = FfiFnDescriptor::new(
            self.self_ty.expect_or_abort("Defined"),
            self.is_inherent_impl,
        );

        match node {
            syn::ImplItem::Method(method) => {
                ffi_fn_descriptor.visit_impl_item_method(method);
                self.fns.push(ffi_fn_descriptor);
            }
            _ => abort!(node, "Only methods are supported inside impl blocks"),
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

impl<'ast> Visit<'ast> for FfiFnDescriptor<'ast> {
    fn visit_impl_item_method(&mut self, node: &'ast syn::ImplItemMethod) {
        for it in &node.attrs {
            self.visit_attribute(it);
        }
        if self.is_inherent_method && !matches!(node.vis, syn::Visibility::Public(_)) {
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
        // TODO: Support generics
        //self.visit_generics(&node.generics);
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

        self.self_arg = Some(FfiFnArgDescriptor {
            ffi_name: Self::get_self_arg_name(),
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

                    if !is_option_type(&src_ty) {
                        *ffi_ty = parse_quote! { *mut #ffi_ptr_subty };
                    }
                }

                self.add_output_arg(*src_type.clone(), ffi_type);
            }
        }

        if let Some(self_arg) = &self.self_arg {
            let self_src_type = &self_arg.src_type;

            if matches!(self_src_type, Type::Path(_)) {
                let output_arg = self.output_arg.as_ref();

                if output_arg.map_or(true, |out_arg| self_arg.ffi_name != out_arg.ffi_name) {
                    abort!(self_src_type, "Methods which consume self not supported");
                }
            }
        }
    }
}

/// Visitor for path types which replaces all occurrences of `Self` with a fully qualified type
pub struct SelfResolver<'ast> {
    self_ty: &'ast syn::Path,
}

impl<'ast> SelfResolver<'ast> {
    pub fn new(self_ty: &'ast syn::Path) -> Self {
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

fn is_option_type(type_: &syn::TypePath) -> bool {
    type_.path.segments.last().expect_or_abort("Defined").ident == "Option"
}

fn generic_arg_types(seg: &syn::PathSegment) -> Vec<&Type> {
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
