#![allow(clippy::unimplemented)]

use proc_macro2::Span;
use proc_macro_error::{abort, OptionExt};
use syn::{
    parse_quote, visit::Visit, visit_mut::VisitMut, Ident, Path, PathArguments::AngleBracketed,
    Type,
};

use crate::get_ident;

/// Struct representing a method/function argument
#[derive(Clone)]
pub struct Arg {
    /// Name of the function/method argument
    pub name: Ident,

    /// Rust type
    pub src_type: Type,
    /// FFI compliant type
    pub ffi_type: Type,

    /// Conversion statement from rust to FFI compliant type
    pub src_to_ffi: syn::Stmt,
    /// Conversion statement from FFI compliant to rust type
    pub ffi_to_src: syn::Stmt,
}

impl Arg {
    pub fn handle(self_ty: &Path, src_type: Type) -> Self {
        let handle_name = Ident::new("__handle", Span::call_site());
        Self::new(self_ty, handle_name, src_type, true)
    }

    pub fn input(self_ty: &Path, name: Ident, src_type: Type) -> Self {
        Self::new(self_ty, name, src_type, true)
    }

    pub fn output(self_ty: &Path, name: Ident, src_type: Type) -> Self {
        Self::new(self_ty, name, src_type, false)
    }

    fn new(self_ty: &Path, name: Ident, src_type: Type, is_input: bool) -> Self {
        let mut visitor: TypeVisitor = TypeVisitor::new(self_ty, &name, is_input);
        visitor.visit_type(&src_type);
        let mut ffi_type = visitor.ffi_type.expect_or_abort("Defined");
        SelfResolver::new(self_ty).visit_type_mut(&mut ffi_type);

        let src_to_ffi = visitor.src_to_ffi.expect_or_abort("Defined");
        let ffi_to_src = visitor.ffi_to_src.expect_or_abort("Defined");

        Self {
            name,
            src_type,
            ffi_type,
            src_to_ffi,
            ffi_to_src,
        }
    }

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
}

/// Struct representing a method/function argument
struct TypeVisitor<'ast> {
    self_ty: &'ast Path,
    name: &'ast Ident,
    is_input: bool,
    ffi_type: Option<Type>,
    src_to_ffi: Option<syn::Stmt>,
    ffi_to_src: Option<syn::Stmt>,
}

impl<'ast> TypeVisitor<'ast> {
    fn new(self_ty: &'ast Path, name: &'ast Ident, is_input: bool) -> Self {
        Self {
            self_ty,
            name,
            is_input,
            ffi_type: None,
            src_to_ffi: None,
            ffi_to_src: None,
        }
    }
    fn visit_item_binding(&mut self, seg: &'ast syn::PathSegment) {
        let bindings = generic_arg_bindings(seg);

        if bindings.is_empty() {
            abort!(seg, "Missing generic argument `Item`");
        }
        if bindings[0].ident != "Item" {
            abort!(seg, "Unknown binding");
        }

        let binding = Arg::input(self.self_ty, parse_quote! {arg}, bindings[0].ty.clone());

        self.ffi_type = Some(binding.ffi_type);
        self.src_to_ffi = Some(binding.src_to_ffi);
        self.ffi_to_src = Some(binding.ffi_to_src);
    }

    fn visit_type_option(&mut self, item: &'ast Type) {
        let arg_name = self.name;

        match item {
            Type::Reference(ref_ty) => {
                let elem = &ref_ty.elem;

                if ref_ty.mutability.is_some() {
                    self.ffi_type = Some(parse_quote! {*mut #elem});
                    self.src_to_ffi = Some(parse_quote! {
                        let #arg_name = match #arg_name {
                            Some(item) => item as *mut _,
                            None => core::ptr::null_mut(),
                        };
                    });
                    self.ffi_to_src = Some(parse_quote! {
                        let #arg_name = if !#arg_name.is_null() {
                            Some(&mut *#arg_name)
                        } else {
                            None
                        };
                    });
                } else {
                    self.ffi_type = Some(parse_quote! {*const #elem});
                    self.src_to_ffi = Some(parse_quote! {
                        let #arg_name = match #arg_name {
                            Some(item) => item as *const _,
                            None => core::ptr::null(),
                        };
                    });
                    self.ffi_to_src = Some(parse_quote! {
                        let #arg_name = if !#arg_name.is_null() {
                            Some(&*#arg_name)
                        } else {
                            None
                        };
                    });
                }
            }
            Type::Path(ty) => self.visit_type_path(ty),
            _ => abort!(item, "Unsupported Option type"),
        }
    }
}

impl<'ast> Visit<'ast> for TypeVisitor<'ast> {
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

            let arg_name = self.name;
            match last_seg.ident.to_string().as_str() {
                "IntoIterator" => {
                    if !self.is_input {
                        abort!(node, "Type not supported as output type")
                    }

                    self.visit_item_binding(last_seg);
                    let binding_ffi_type = &self.ffi_type;
                    let binding_src_to_ffi = &self.src_to_ffi;
                    let binding_ffi_to_src = &self.ffi_to_src;

                    let slice_len_arg_name = crate::bindgen::gen_slice_len_arg_name(arg_name);
                    self.ffi_type = Some(parse_quote! {*const #binding_ffi_type});
                    self.src_to_ffi = Some(parse_quote! {
                        let #arg_name = #arg_name.into_iter().map(|arg| {
                            #binding_src_to_ffi
                            arg
                        });
                    });
                    self.ffi_to_src = Some(parse_quote! {
                        let #arg_name = core::slice::from_raw_parts(#arg_name, #slice_len_arg_name)
                            .into_iter().map(|&arg| {
                                #binding_ffi_to_src
                                arg
                            });
                    });
                }
                "ExactSizeIterator" => {
                    if self.is_input {
                        abort!(node, "Type not supported as input type")
                    }

                    self.visit_item_binding(last_seg);
                    let binding_ffi_type = &self.ffi_type;
                    let binding_src_to_ffi = &self.src_to_ffi;
                    let binding_ffi_to_src = &self.ffi_to_src;

                    let slice_len_arg_name = crate::bindgen::gen_slice_len_arg_name(arg_name);
                    self.ffi_type = Some(parse_quote! {*mut #binding_ffi_type});
                    self.src_to_ffi = Some(parse_quote! {
                        let #arg_name = #arg_name.into_iter().map(|arg| {
                            #binding_src_to_ffi
                            arg
                        });
                    });
                    self.ffi_to_src = Some(parse_quote! {
                        let #arg_name = core::slice::from_raw_parts_mut(#arg_name, #slice_len_arg_name)
                            .into_iter().map(|&mut arg| {
                                #binding_ffi_to_src
                                arg
                            });
                    });
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

        let arg_name = self.name;
        match last_seg.ident.to_string().as_str() {
            "bool" => {
                if self.is_input {
                    self.ffi_type = Some(parse_quote! { u8 });
                    self.src_to_ffi = Some(parse_quote! {let #arg_name = #arg_name as u8;});
                    self.ffi_to_src = Some(parse_quote! {let #arg_name = #arg_name != 0;});
                } else {
                    self.ffi_type = Some(node.clone().into());
                    self.src_to_ffi = Some(parse_quote! {();});
                    self.ffi_to_src = Some(parse_quote! {();});
                }
            }
            "u8" | "u16" => {
                self.ffi_type = Some(parse_quote! {u32});
                self.src_to_ffi = Some(parse_quote! {let #arg_name = #arg_name as u32;});
                self.ffi_to_src = Some(parse_quote! {
                    let #arg_name = match #arg_name.try_into() {
                        Err(err) => return iroha_ffi::FfiResult::ConversionError,
                        Ok(item) => item,
                    };
                });
            }
            "i8" | "i16" => {
                self.ffi_type = Some(parse_quote! {i32});
                self.src_to_ffi = Some(parse_quote! {let #arg_name = #arg_name as i32;});
                self.ffi_to_src = Some(parse_quote! {
                    let #arg_name = match #arg_name.try_into() {
                        Err(err) => return iroha_ffi::FfiResult::ConversionError,
                        Ok(item) => item,
                    };
                });
            }
            "u32" | "i32" | "f32" | "f64" => {
                self.ffi_type = Some(node.clone().into());
                self.src_to_ffi = Some(parse_quote! {();});
                self.ffi_to_src = Some(parse_quote! {();});
            }
            "Option" => self.visit_type_option(generic_arg_types(last_seg)[0]),
            "Result" => {
                if self.is_input {
                    abort!(node, "Type not supported as input type")
                }

                let args = generic_arg_types(last_seg);
                let (ok_type, _) = (args[0], args[1]);

                self.visit_type(ok_type);
                let ok_src_to_ffi = &self.src_to_ffi;
                let ok_ffi_to_src = &self.ffi_to_src;

                self.src_to_ffi = Some(parse_quote! {
                    let #arg_name = match #arg_name {
                        Ok(#arg_name) => {
                            #ok_src_to_ffi
                            #arg_name
                        },
                        Err(_) => {
                            // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                            return iroha_ffi::FfiResult::ExecutionFail;
                        }
                    };
                });
                self.ffi_to_src = Some(parse_quote! { #ok_ffi_to_src });
            }
            _ => {
                if self.is_input {
                    self.ffi_type = Some(parse_quote! { *const #node });
                    self.src_to_ffi = Some(parse_quote! {
                        let #arg_name: *const _ = #arg_name;
                    });
                    self.ffi_to_src = Some(parse_quote! {
                        let #arg_name = Clone::clone(&*#arg_name);
                    });
                } else {
                    self.ffi_type = Some(parse_quote! { *mut #node });
                    self.src_to_ffi = Some(parse_quote! {
                        let #arg_name = Box::into_raw(Box::new(#arg_name));
                    });
                    self.ffi_to_src = Some(parse_quote! {
                        let #arg_name = *Box::from_raw(#arg_name);
                    });
                }
            }
        }
    }
    fn visit_type_ptr(&mut self, node: &'ast syn::TypePtr) {
        abort!(node, "Raw pointers not supported")
    }
    fn visit_type_reference(&mut self, node: &'ast syn::TypeReference) {
        if let Some(li) = &node.lifetime {
            abort!(li, "Explicit lifetime not supported in reference types");
        }

        let elem = &*node.elem;
        if !matches!(*elem, Type::Path(_)) {
            abort!(elem, "Unsupported reference type");
        }

        let arg_name = self.name;
        if node.mutability.is_some() {
            self.ffi_type = Some(parse_quote! {*mut #elem});
            self.src_to_ffi = Some(parse_quote! {let #arg_name: *mut _ = #arg_name;});
            self.ffi_to_src = Some(parse_quote! {let #arg_name = &mut *#arg_name;});
        } else {
            self.ffi_type = Some(parse_quote! {*const #elem});
            self.src_to_ffi = Some(parse_quote! {let #arg_name: *const _ = #arg_name;});
            self.ffi_to_src = Some(parse_quote! {let #arg_name = &*#arg_name;});
        }
    }

    fn visit_type_slice(&mut self, _: &'ast syn::TypeSlice) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_trait_object(&mut self, _: &'ast syn::TypeTraitObject) {
        unimplemented!("Not needed as of yet")
    }
    fn visit_type_tuple(&mut self, node: &'ast syn::TypeTuple) {
        let arg_name = self.name;

        if node.elems.len() != 2 {
            abort!(node, "Only tuple pairs supported as of yet");
        }

        let ids: Vec<_> = (0..node.elems.len())
            .map(|i| syn::LitInt::new(&i.to_string(), Span::call_site()))
            .collect();
        let field_idents: Vec<_> = (0..node.elems.len())
            .into_iter()
            .map(|idx| Ident::new(&format!("{}__field_{}", arg_name, idx), Span::call_site()))
            .collect();

        let (elem_ffi_type, elem_src_to_ffi, elem_ffi_to_src) = node
            .elems
            .iter()
            .enumerate()
            .map(|(i, elem)| (field_idents[i].clone(), elem.clone()))
            .fold(
                <(Vec<_>, Vec<_>, Vec<_>)>::default(),
                |mut acc, (field_ident, elem)| {
                    let elem_mapper = Arg::new(self.self_ty, field_ident, elem, self.is_input);

                    acc.0.push(elem_mapper.ffi_type);
                    acc.1.push(elem_mapper.src_to_ffi);
                    acc.2.push(elem_mapper.ffi_to_src);

                    acc
                },
            );

        self.ffi_type = Some(parse_quote! {iroha_ffi::Pair<#( #elem_ffi_type ),*>});
        self.src_to_ffi = Some(parse_quote! {
            let #arg_name = {
                #( let #field_idents = arg.#ids; )*
                #( #elem_src_to_ffi )*
                iroha_ffi::Pair(#( #field_idents ),*)
            };
        });
        self.ffi_to_src = Some(parse_quote! {
            let #arg_name = {
                #( let #field_idents = arg.#ids; )*
                #( #elem_ffi_to_src )*
                (#( #field_idents ),*)
            };
        });
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
