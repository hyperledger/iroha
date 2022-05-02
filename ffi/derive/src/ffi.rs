#![allow(clippy::unimplemented)]

use heck::ToSnakeCase;
use proc_macro2::Span;
use proc_macro_error::{abort, abort_call_site, OptionExt};
use quote::quote;
use syn::{parse_quote, visit::Visit, visit_mut::VisitMut, Ident, Type};

pub struct ImplDescriptor {
    /// Resolved type of the `Self` type
    self_ty: Option<syn::Path>,

    /// Collection of FFI functions
    pub fns: Vec<FfiFnDescriptor>,
}

#[derive(Debug)]
pub struct FfiFnDescriptor {
    /// Resolved type of the `Self` type
    self_ty: syn::Path,

    /// Name of the method in the original implementation
    method_name: Option<Ident>,
    /// Receiver argument
    self_arg: Option<FfiFnArgDescriptor>,
    /// Input fn arguments
    input_args: Vec<FfiFnArgDescriptor>,
    /// Output fn argument
    output_arg: Option<FfiFnArgDescriptor>,

    /// Name of the argument being visited
    curr_arg_name: Option<Ident>,
    /// Source and FFI (sub)type of the argument being visited.
    curr_arg_ty: Option<(Type, Type)>,
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

impl quote::ToTokens for FfiFnDescriptor {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let ffi_fn_name = self.get_ffi_fn_name();

        let self_arg = self
            .self_arg
            .as_ref()
            .map_or_else(Vec::new, |self_arg| vec![self_arg]);

        let fn_args = &self.input_args;
        let ret_arg = &self.output_arg;
        let fn_body = self.get_fn_body();

        tokens.extend(quote! {
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

        tokens.extend(if self.is_slice_ref() {
            quote! { mut #ffi_name: #ffi_type }
        } else {
            quote! { #ffi_name: #ffi_type}
        });

        let mut slice_len_to_tokens = |mutability| {
            let ffi_slice_len_arg_name = self.get_slice_len_arg_name();

            if mutability {
                tokens.extend(quote! {, #ffi_slice_len_arg_name: *mut usize });
            } else {
                tokens.extend(quote! {, #ffi_slice_len_arg_name: usize });
            }
        };

        // TODO: Use newly defined functions
        if let Type::Reference(type_) = &src_type {
            if matches!(*type_.elem, Type::Slice(_)) {
                slice_len_to_tokens(type_.mutability.is_some());
            }
        } else if matches!(src_type, Type::ImplTrait(_)) {
            match ffi_type {
                Type::Ptr(ptr_ty) => {
                    slice_len_to_tokens(ptr_ty.mutability.is_some());
                }
                _ => unreachable!("Incorrectly transcribed type -> {:?}", ffi_type),
            }
        }
    }
}

impl ImplDescriptor {
    pub fn new() -> Self {
        Self {
            self_ty: None,
            fns: vec![],
        }
    }

    fn visit_self_type(&mut self, node: &Type) {
        if let Type::Path(self_ty) = node {
            if self_ty.qself.is_some() {
                abort_call_site!("Qualified types not supported as self type");
            }

            self.self_ty = Some(self_ty.path.clone());
        } else {
            abort_call_site!("Only nominal types supported as self type");
        }
    }
}

impl FfiFnDescriptor {
    pub fn new(self_ty: syn::Path) -> Self {
        Self {
            self_ty,

            method_name: None,
            self_arg: None,
            input_args: vec![],
            output_arg: None,

            curr_arg_name: None,
            curr_arg_ty: None,
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

    /// Produces name of the return type argument from a set of predefined conventions
    fn get_output_arg_name() -> Ident {
        Ident::new("output", Span::call_site())
    }

    fn add_input_arg(&mut self) {
        let ffi_name = self.curr_arg_name.take().expect_or_abort("Defined");
        let (src_type, ffi_type) = self.curr_arg_ty.take().expect_or_abort("Defined");

        self.input_args.push(FfiFnArgDescriptor {
            ffi_name,
            src_type,
            ffi_type,
        });
    }

    fn add_output_arg(&mut self) {
        let (src_type, ffi_type) = self.curr_arg_ty.take().expect_or_abort("Defined");

        assert!(self.curr_arg_name.is_none());
        assert!(self.output_arg.is_none());

        self.output_arg = Some(FfiFnArgDescriptor {
            ffi_name: Self::get_output_arg_name(),
            src_type,
            ffi_type: parse_quote! { *mut #ffi_type },
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
            if let Some(stmt) = arg.get_ptr_null_check_stmt() {
                stmts.push(stmt);
            }

            let arg_name = &arg.ffi_name;
            if arg.is_slice_ref() {
                let slice_len_arg_name = arg.get_slice_len_arg_name();

                stmts.push(parse_quote! {
                    if #slice_len_arg_name == 0_usize {
                        // NOTE: `slice::from_raw_parts` takes a non-null aligned pointer
                        #arg_name = core::ptr::NonNull::dangling().as_ptr();
                    }
                });
            }
        }

        if let Some(output_arg) = &self.output_arg {
            if let Some(stmt) = output_arg.get_ptr_null_check_stmt() {
                stmts.push(stmt);
            }

            if output_arg.is_slice_ref_mut() {
                let slice_len_arg_name = output_arg.get_slice_len_arg_name();

                stmts.push(parse_quote! {
                    if #slice_len_arg_name.is_null() {
                        return iroha_ffi::FfiResult::ArgIsNull;
                    }
                });
            }
        }

        stmts
    }

    fn get_input_conversion_stmts(&self) -> Vec<syn::Stmt> {
        let mut stmts = vec![];

        if let Some(self_arg) = &self.self_arg {
            let arg_name = &self_arg.ffi_name;

            stmts.push(match self_arg.src_type {
                Type::Reference(_) => parse_quote! { let #arg_name = &*#arg_name; },
                Type::Path(_) => unimplemented!("Should transfter ownership"),
                _ => unreachable!("Self can only be taken by ref or by value"),
            });
        }

        for arg in &self.input_args {
            let arg_name = &arg.ffi_name;

            if arg.is_slice_ref() {
                let slice_len_arg_name = arg.get_slice_len_arg_name();

                if let Type::Ptr(ptr) = &arg.ffi_type {
                    if ptr.mutability.is_some() {
                        abort_call_site!("Input arguments mutability not supported");
                    }

                    stmts.push(parse_quote! {
                        let #arg_name = core::slice::from_raw_parts(#arg_name, #slice_len_arg_name);
                    });

                    // NOTE: This is a slice of pointers
                    if matches!(*ptr.elem, Type::Ptr(_)) {
                        stmts.push(
                            parse_quote! { let #arg_name = #arg_name.into_iter().map(|ptr| ptr.read()); },
                        );
                    }
                } else {
                    unreachable!("FFI type is pointer for a slice")
                }
            } else if matches!(arg.ffi_type, Type::Ptr(_)) {
                stmts.push(match &arg.src_type {
                    Type::Reference(_) => parse_quote! {
                        let #arg_name = &*#arg_name;
                    },
                    Type::Path(_) => parse_quote! {
                        let #arg_name = #arg_name.read();
                    },
                    _ => unreachable!("Either slice, reference or owned type expected"),
                });
            }
        }

        stmts
    }

    fn get_method_call_stmt(&self) -> syn::Stmt {
        let method_name = &self.method_name;
        let self_type = &self.self_ty;

        let self_arg_name = self
            .self_arg
            .as_ref()
            .map_or_else(Vec::new, |self_arg| vec![&self_arg.ffi_name]);

        let fn_arg_names = self.input_args.iter().map(|arg| &arg.ffi_name);
        parse_quote! { let method_res = #self_type::#method_name(#(#self_arg_name,)* #(#fn_arg_names),*); }
    }

    fn get_output_conversion_stmts(&self) -> Vec<syn::Stmt> {
        let mut stmts = vec![];

        if let Some(output_arg) = &self.output_arg {
            if !matches!(output_arg.ffi_type, Type::Ptr(_)) {
                unreachable!("Must be a pointer");
            }

            if let Type::Reference(type_) = &output_arg.src_type {
                stmts.push(if type_.mutability.is_some() {
                    parse_quote! { let method_res: *mut _ = method_res; }
                } else {
                    parse_quote! { let method_res: *const _ = method_res; }
                });
            } else if output_arg.is_collection() {
                stmts.push(parse_quote! { let method_res = method_res.into_iter(); });

                let src_type = output_arg.src_collection_item();
                if let Type::Reference(src_ptr_ty) = src_type {
                    stmts.push(if src_ptr_ty.mutability.is_some() {
                        parse_quote! { let method_res = method_res.map(|arg| arg as *mut _); }
                    } else {
                        parse_quote! { let method_res = method_res.map(|arg| arg as *const _); }
                    });
                } else {
                    abort_call_site!("Only references supported for collections");
                }

                stmts.push(parse_quote! {
                    // TODO: Seems that the implementation reallocates even for `ExactSizeIterator`
                    // Optimize collecting to avoid reallocation in case of `ExactSizeIterator`
                    let mut method_res = core::mem::ManuallyDrop::new(method_res.collect::<Box<[_]>>());
                });
            } else if let Type::Path(src_type_path) = &output_arg.src_type {
                // NOTE: Transcribe owned type into opaque raw pointer type

                if !is_repr_c(&src_type_path) {
                    stmts.push(parse_quote! {
                        let method_res = Box::into_raw(Box::new(method_res));
                    });
                }
            }
        }

        stmts
    }

    fn get_output_assignment_stmts(&self) -> Vec<syn::Stmt> {
        let mut stmts = vec![];

        if let Some(output_arg) = &self.output_arg {
            let output_arg_name = &output_arg.ffi_name;

            if output_arg.is_slice_ref_mut() {
                let slice_len_arg_name = output_arg.get_slice_len_arg_name();

                stmts.extend([
                    parse_quote! { #output_arg_name.write(method_res.as_mut_ptr()); },
                    parse_quote! { #slice_len_arg_name.write(method_res.len()); },
                ]);
            } else {
                assert!(matches!(output_arg.ffi_type, Type::Ptr(_)));
                stmts.push(parse_quote! { #output_arg_name.write(method_res); });
            }
        }

        stmts
    }

    fn get_fn_body(&self) -> syn::Block {
        let checks = self.get_type_check_stmts();
        let input_conversions = self.get_input_conversion_stmts();
        let method_call_stmt = self.get_method_call_stmt();
        let output_conversions = self.get_output_conversion_stmts();
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
    fn src_collection_item(&self) -> &Type {
        match &self.src_type {
            Type::ImplTrait(type_) => {
                assert_eq!(type_.bounds.len(), 1);

                if let syn::TypeParamBound::Trait(trait_) = &type_.bounds[0] {
                    let last_seg = &trait_.path.segments.last().expect_or_abort("Defined");
                    return if let syn::PathArguments::AngleBracketed(arguments) =
                        &last_seg.arguments
                    {
                        if arguments.args.is_empty() {
                            abort_call_site!("{} missing generic argument `Item`", last_seg.ident);
                        }
                        if let syn::GenericArgument::Binding(arg) = &arguments.args[0] {
                            if arg.ident != "Item" {
                                abort_call_site!(
                                    "Only `Item` supported in arguments to {}",
                                    last_seg.ident
                                );
                            }

                            &arg.ty
                        } else {
                            abort_call_site!(
                                "Only `Item` supported in arguments to {}",
                                last_seg.ident
                            );
                        }
                    } else {
                        abort_call_site!("{} must be parametrized with `Item`", last_seg.ident);
                    };
                } else {
                    abort_call_site!("Not a collection");
                }
            }
            _ => abort_call_site!("Not a collection"),
        }
    }

    fn is_collection(&self) -> bool {
        self.is_slice_ref_mut()
    }

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

    fn get_slice_len_arg_name(&self) -> Ident {
        Ident::new(&format!("{}_len", self.ffi_name), Span::call_site())
    }
}

impl<'ast> Visit<'ast> for ImplDescriptor {
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
        if node.trait_.is_some() {
            // TODO: Can they be supported?
            unimplemented!("Not yet supported")
        }
        self.visit_self_type(&*node.self_ty);

        for it in &node.items {
            self.visit_impl_item(it);
        }
    }
    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        let mut ffi_fn_descriptor =
            FfiFnDescriptor::new(self.self_ty.as_ref().expect_or_abort("Defined").clone());

        match node {
            syn::ImplItem::Method(method) => {
                ffi_fn_descriptor.visit_impl_item_method(method);
            }
            _ => abort_call_site!("Only methods are supported inside impl blocks"),
        }

        self.fns.push(ffi_fn_descriptor);
    }
}

impl<'ast> syn::visit::Visit<'ast> for FfiFnDescriptor {
    fn visit_impl_item_method(&mut self, node: &'ast syn::ImplItemMethod) {
        for it in &node.attrs {
            self.visit_attribute(it);
        }
        if !matches!(node.vis, syn::Visibility::Public(_)) {
            abort_call_site!("Methods defined in the impl block must be public");
        }

        self.visit_signature(&node.sig);
    }
    fn visit_signature(&mut self, node: &'ast syn::Signature) {
        if node.constness.is_some() {
            // NOTE: It's irrelevant
        }
        if node.asyncness.is_some() {
            abort_call_site!("Async functions not supported");
        }
        if node.unsafety.is_some() {
            // NOTE: It's irrelevant
        }
        if node.abi.is_some() {
            abort_call_site!("Extern fn declarations not supported")
        }
        self.method_name = Some(node.ident.clone());
        // TODO: Support generics
        //self.visit_generics(&node.generics);
        for fn_input_arg in &node.inputs {
            self.visit_fn_arg(fn_input_arg);
        }
        if node.variadic.is_some() {
            abort_call_site!("Variadic arguments not supported")
        }
        self.visit_return_type(&node.output);
    }

    fn visit_receiver(&mut self, node: &'ast syn::Receiver) {
        for it in &node.attrs {
            self.visit_attribute(it);
        }
        if let Some((_, lifetime)) = &node.reference {
            if lifetime.is_some() {
                abort_call_site!("Explicit lifetimes not supported");
            }
        }

        let self_type = &self.self_ty;
        let (src_type, ffi_type) = node.reference.as_ref().map_or_else(
            || {
                (
                    Type::Path(syn::TypePath {
                        qself: None,
                        path: self_type.clone(),
                    }),
                    parse_quote! { *mut #self_type },
                )
            },
            |it| {
                if it.1.is_some() {
                    abort_call_site!("Explicit lifetime not supported");
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
            abort_call_site!("Only ident patterns are supported in variable name bindings");
        }

        self.visit_type(&*node.ty);
        self.add_input_arg();
    }

    fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
        for it in &node.attrs {
            self.visit_attribute(it);
        }
        if node.by_ref.is_some() {
            abort_call_site!("ref patterns not supported in argument name");
        }
        if node.mutability.is_some() {
            // NOTE: It's irrelevant
        }
        if node.subpat.is_some() {
            abort_call_site!("Subpatterns not supported in argument name");
        }

        self.curr_arg_name = Some(node.ident.clone());
    }

    fn visit_return_type(&mut self, node: &'ast syn::ReturnType) {
        match node {
            syn::ReturnType::Default => {}
            syn::ReturnType::Type(_, type_) => {
                self.visit_type(&**type_);

                // NOTE: Transcribe owned output types to *mut ptr
                self.curr_arg_ty.as_mut().map(|(src_ty, ffi_ty)| {
                    if !matches!(src_ty, Type::Path(_)) {
                        return;
                    }

                    if let Type::Ptr(ffi_ptr_ty) = ffi_ty {
                        let ffi_ptr_subty = &ffi_ptr_ty.elem;

                        *ffi_ty = parse_quote! {
                            *mut #ffi_ptr_subty
                        };
                    }
                });

                self.add_output_arg();
            }
        }
    }

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
            abort_call_site!("Only one trait is allowed for the `impl trait` argument");
        }

        if let syn::TypeParamBound::Trait(trait_) = &node.bounds[0] {
            let is_output_arg = self.curr_arg_name.is_none();

            if trait_.lifetimes.is_some() {
                abort_call_site!("Lifetime bound not supported for the `impl trait` argument");
            }

            let last_seg = trait_.path.segments.last().expect_or_abort("Defined");
            let is_into_iterator = !is_output_arg && last_seg.ident == "IntoIterator";
            let is_exact_size_iterator = is_output_arg && last_seg.ident == "ExactSizeIterator";

            if !is_into_iterator && !is_exact_size_iterator {
                abort_call_site!(
                    "Only IntoIterator and ExactSizeIterator supported in `impl trait`"
                );
            }

            let item = if let syn::PathArguments::AngleBracketed(arguments) = &last_seg.arguments {
                if arguments.args.is_empty() {
                    abort_call_site!("{} missing generic argument `Item`", last_seg.ident);
                }
                if let syn::GenericArgument::Binding(arg) = &arguments.args[0] {
                    if arg.ident != "Item" {
                        abort_call_site!(
                            "Only `Item` supported in arguments to {}",
                            last_seg.ident
                        );
                    }

                    &arg.ty
                } else {
                    abort_call_site!("Only `Item` supported in arguments to {}", last_seg.ident);
                }
            } else {
                abort_call_site!("{} must be parametrized with `Item`", last_seg.ident);
            };

            self.visit_type(item);
            self.curr_arg_ty = {
                let ffi_subty = self.curr_arg_ty.as_ref().map(|ty| &ty.1);

                Some((
                    Type::ImplTrait(node.clone()),
                    if is_output_arg {
                        parse_quote! { *mut #ffi_subty }
                    } else {
                        parse_quote! { *const #ffi_subty }
                    },
                ))
            };
        } else {
            abort_call_site!("Lifetime bound not supported for the `impl trait` argument");
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
        let self_ty = self.self_ty.clone();
        let mut ffi_type = node.clone();

        FfiTypePath::new(self_ty).visit_type_path_mut(&mut ffi_type);

        self.curr_arg_ty = Some((
            Type::Path(node.clone()),
            if is_repr_c(node) {
                Type::Path(ffi_type)
            } else {
                // TODO: Could take ownership here, but avoiding at the moment because it seems more safe.
                // The problem is that calling destructor will be another FFI call if not taking ownership.
                // However, if taking ownership there is a whole issue of pointer aliasing where we have to
                // trust the caller of the function to not make use of the given pointers anymore
                // NOTE: T -> *const T (opaque ptr)
                parse_quote! { *const #ffi_type }
            },
        ));
    }
    fn visit_type_ptr(&mut self, _: &'ast syn::TypePtr) {
        abort_call_site!("Raw pointers not supported")
    }
    fn visit_type_reference(&mut self, node: &'ast syn::TypeReference) {
        if let Some(li) = &node.lifetime {
            abort!(li, "Explicit lifetime not supported in reference types");
        }

        self.visit_type(&*node.elem);
        if node.mutability.is_some() {
            abort!(node.mutability, "Mutable references not supported");
        }

        // NOTE: Owned opaque types make double indirection
        self.curr_arg_ty.as_mut().map(|(src_ty, ffi_ty)| {
            if matches!(src_ty, Type::Path(_)) {
                // TODO: Don't accept references to owned collections like `Vec`

                if let Type::Ptr(ffi_ptr_ty) = ffi_ty {
                    *ffi_ty = *ffi_ptr_ty.elem.clone();
                }
            }
        });

        self.curr_arg_ty.as_mut().map(|(src_ty, ffi_ty)| {
            *src_ty = Type::Reference(node.clone());
            *ffi_ty = parse_quote! { *const #ffi_ty };
        });
    }

    fn visit_type_slice(&mut self, _: &'ast syn::TypeSlice) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_trait_object(&mut self, _: &'ast syn::TypeTraitObject) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_tuple(&mut self, _: &'ast syn::TypeTuple) {
        unimplemented!("Not needed as of yet")
    }
}

/// Visitor for path types which replaces all occurrences of `Self` with a fully qualified type
/// Additionally, visitor expands the integers to fit the size of WebAssembly defined types
struct FfiTypePath {
    self_ty: syn::Path,
}

impl FfiTypePath {
    fn new(self_ty: syn::Path) -> Self {
        Self { self_ty }
    }
}

impl VisitMut for FfiTypePath {
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

        node.segments.last_mut().map(|seg| {
            // NOTE: In Wasm only `u32/i32`, `u64/i64`, `f32/f64` are supported

            match seg.ident.to_string().as_str() {
                "u8" | "u16" => *seg = parse_quote! { u32 },
                "i8" | "i16" => *seg = parse_quote! { i32 },
                _ => {}
            };
        });
    }
}

// NOTE: Only supporting ints and floats
/// Returns true if the given type is repr(C)
fn is_repr_c(type_: &syn::TypePath) -> bool {
    let repr_c_types = [
        parse_quote! {u8},
        parse_quote! {i8},
        parse_quote! {u16},
        parse_quote! {i16},
        parse_quote! {u32},
        parse_quote! {i32},
        parse_quote! {u64},
        parse_quote! {i64},
        parse_quote! {f32},
        parse_quote! {f64},
    ];

    for repr_c_type in repr_c_types {
        if *type_ == repr_c_type {
            return true;
        }
    }

    false
}
