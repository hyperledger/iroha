//! Logic related to FFI function argument. Visitor implementation visits the given type
//! and collects the FFI conversion information into the [`Arg`] struct
#![allow(clippy::unimplemented)]

use proc_macro2::Span;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{
    parse_quote, visit::Visit, visit_mut::VisitMut, Ident, Path, PathArguments::AngleBracketed,
    Type,
};

/// Struct representing a method/function argument
#[derive(Clone)]
pub struct Arg {
    /// Name of the function/method argument
    pub name: Ident,

    /// Rust type
    pub src_type: Type,
    /// FFI compliant type
    pub ffi_type: Type,

    /// Conversion statement from Rust to FFI compliant type
    pub src_to_ffi: syn::Stmt,
    /// Conversion statement from FFI compliant to Rust type
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
}

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

    fn visit_item_binding(&mut self, seg: &'ast syn::PathSegment, is_input: bool) {
        let bindings = generic_arg_bindings(seg);

        if bindings.is_empty() {
            abort!(seg, "Missing generic argument `Item`");
        }
        if bindings[0].ident != "Item" {
            abort!(seg, "Unknown binding");
        }

        let binding = Arg::new(
            self.self_ty,
            parse_quote! {arg},
            bindings[0].ty.clone(),
            is_input,
        );

        self.ffi_type = Some(binding.ffi_type);
        self.src_to_ffi = Some(binding.src_to_ffi);
        self.ffi_to_src = Some(binding.ffi_to_src);
    }

    fn visit_type_slice_ref(&mut self, node: &'ast syn::TypeSlice, mutability: bool) {
        let arg_name = self.name;

        let (ref_mutability, ptr_mutability, from_raw_parts) = if mutability {
            (quote! {&mut}, quote! {*mut}, quote! {from_raw_parts_mut})
        } else {
            (quote! {&}, quote! {*const}, quote! {from_raw_parts})
        };
        let elem = (*node.elem).clone();
        let elem = parse_quote! {#ref_mutability #elem};

        let binding = Arg::new(self.self_ty, parse_quote! {arg}, elem, self.is_input);

        let elem_ffi_type = &binding.ffi_type;
        let elem_src_to_ffi = &binding.src_to_ffi;
        let elem_ffi_to_src = &binding.ffi_to_src;

        let slice_len_arg_name = gen_slice_len_arg_name(arg_name);
        self.ffi_type = Some(parse_quote! {#ptr_mutability #elem_ffi_type});
        self.src_to_ffi = Some(parse_quote! {
            let #arg_name = #arg_name.into_iter().map(|arg| {
                #elem_src_to_ffi
                arg
            });
        });
        self.ffi_to_src = Some(parse_quote! {
            let #arg_name = core::slice::#from_raw_parts(#arg_name, #slice_len_arg_name)
                .into_iter().map(|#ref_mutability arg| {
                    #elem_ffi_to_src
                    arg
                });
        });
    }

    fn visit_type_option(&mut self, item: &'ast Type) {
        let arg_name = self.name;

        match item {
            Type::Reference(ref_ty) => {
                let elem = &ref_ty.elem;

                let (ptr_mutability, ref_mutability, null_ptr) = if ref_ty.mutability.is_some() {
                    (quote! {*mut}, quote! {&mut}, quote! {null_mut})
                } else {
                    (quote! {*const}, quote! {&}, quote! {null})
                };

                self.ffi_type = Some(parse_quote! {#ptr_mutability #elem});
                self.src_to_ffi = Some(parse_quote! {
                    let #arg_name = match #arg_name {
                        Some(item) => item as #ptr_mutability _,
                        None => core::ptr::#null_ptr(),
                    };
                });
                self.ffi_to_src = Some(parse_quote! {
                    let #arg_name = if !#arg_name.is_null() {
                        Some(#ref_mutability *#arg_name)
                    } else {
                        None
                    };
                });
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
        let arg_name = self.name;

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

            let is_input = self.is_input;
            let mut visit_iterator = || {
                let (ptr_mutability, ref_mutability, from_raw_parts) = if is_input {
                    (quote! {*const}, quote! {&}, quote! {from_raw_parts})
                } else {
                    (quote! {*mut}, quote! {&mut}, quote! {from_raw_parts_mut})
                };

                self.visit_item_binding(last_seg, is_input);
                let binding_ffi_type = &self.ffi_type;
                let binding_src_to_ffi = &self.src_to_ffi;
                let binding_ffi_to_src = &self.ffi_to_src;

                let slice_len_arg_name = gen_slice_len_arg_name(arg_name);
                self.ffi_type = Some(parse_quote! {#ptr_mutability #binding_ffi_type});
                self.src_to_ffi = Some(parse_quote! {
                    let #arg_name = #arg_name.into_iter().map(|arg| {
                        #binding_src_to_ffi
                        arg
                    });
                });
                self.ffi_to_src = Some(parse_quote! {
                    let #arg_name = core::slice::#from_raw_parts(#arg_name, #slice_len_arg_name)
                        // TODO: ref_mutability is suspicious
                        .into_iter().map(|#ref_mutability arg| {
                            #binding_ffi_to_src
                            arg
                        });
                });
            };

            match last_seg.ident.to_string().as_str() {
                "IntoIterator" => {
                    if !is_input {
                        abort!(node, "Type not supported as output type")
                    }

                    visit_iterator()
                }
                "ExactSizeIterator" => {
                    if is_input {
                        abort!(node, "Type not supported as input type")
                    }

                    visit_iterator()
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
        let mut to_int = |int| {
            self.src_to_ffi = Some(parse_quote! {let #arg_name = #arg_name as #int;});
            self.ffi_to_src = Some(parse_quote! {
                let #arg_name = match #arg_name.try_into() {
                    Err(err) => return iroha_ffi::FfiResult::ConversionError,
                    Ok(item) => item,
                };
            });
            self.ffi_type = Some(int);
        };

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
            "u8" | "u16" => to_int(parse_quote! {u32}),
            "i8" | "i16" => to_int(parse_quote! {i32}),
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
                self.ffi_to_src = Some(parse_quote! {
                    let #arg_name = {
                        #ok_ffi_to_src
                        Ok(#arg_name)
                    };
                });
            }
            _ => {
                if self.is_input {
                    self.ffi_type = Some(parse_quote! { *const #node });
                    self.src_to_ffi = Some(parse_quote! {
                        let #arg_name: *const _ = &#arg_name;
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

        match &*node.elem {
            Type::Slice(type_) => self.visit_type_slice_ref(type_, node.mutability.is_some()),
            Type::Path(elem) => {
                let arg_name = self.name;

                let (ptr_mutability, ref_mutability) = if node.mutability.is_some() {
                    (quote! {*mut}, quote! {&mut})
                } else {
                    (quote! {*const}, quote! {&})
                };

                self.ffi_type = Some(parse_quote! {#ptr_mutability #elem});
                self.src_to_ffi =
                    Some(parse_quote! {let #arg_name: #ptr_mutability _ = #arg_name;});
                self.ffi_to_src = Some(parse_quote! {let #arg_name = #ref_mutability *#arg_name;});
            }
            _ => abort!(node, "Unsupported reference type"),
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
        return arguments
            .args
            .iter()
            .filter_map(|arg| {
                if let syn::GenericArgument::Type(ty) = &arg {
                    Some(ty)
                } else {
                    None
                }
            })
            .collect();
    }

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

pub fn gen_slice_len_arg_name(arg_name: &Ident) -> Ident {
    Ident::new(&format!("{}_len", arg_name), Span::call_site())
}
