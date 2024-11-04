use iroha_macro_utils::Emitter;
use manyhow::emit;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{parse_quote, visit_mut::VisitMut, Attribute, Ident, Type};

use crate::{
    attr_parse::derive::{Derive, RustcDerive},
    convert::FfiTypeInput,
    ffi_fn,
    getset_gen::{gen_resolve_type, gen_store_name},
    impl_visitor::{unwrap_result_type, Arg, FnDescriptor, ImplDescriptor, TypeImplTraitResolver},
};

fn gen_lifetime_name_for_opaque() -> TokenStream {
    quote! {'a}
}
fn gen_ref_name(name: &Ident) -> Ident {
    Ident::new(&format!("Ref{name}"), Span::call_site())
}
fn gen_ref_mut_name(name: &Ident) -> Ident {
    Ident::new(&format!("RefMut{name}"), Span::call_site())
}

fn add_handle_bound(name: &Ident, generics: &mut syn::Generics) {
    let cloned_generics = generics.clone();
    let (_, ty_generics, _) = cloned_generics.split_for_impl();

    generics
        .make_where_clause()
        .predicates
        .push(parse_quote! {#name #ty_generics: iroha_ffi::Handle});
}

fn impl_clone_for_opaque(name: &Ident, generics: &syn::Generics) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics Clone for #name #ty_generics #where_clause {
            fn clone(&self) -> Self {
                let mut output = core::mem::MaybeUninit::uninit();

                let handle_id = iroha_ffi::FfiConvert::into_ffi(<#name #ty_generics as iroha_ffi::Handle>::ID, &mut ());
                let clone_result = unsafe { crate::__clone(handle_id, self.0, output.as_mut_ptr()) };

                if clone_result != iroha_ffi::FfiReturn::Ok  {
                    panic!("Clone returned: {}", clone_result);
                }

                unsafe {iroha_ffi::FfiOutPtrRead::try_read_out(output.assume_init()).expect("Invalid output")}
            }
        }
    }
}

fn impl_default_for_opaque(name: &Ident, generics: &syn::Generics) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics Default for #name #ty_generics #where_clause {
            fn default() -> Self {
                let mut output = core::mem::MaybeUninit::uninit();

                let handle_id = iroha_ffi::FfiConvert::into_ffi(<#name #ty_generics as iroha_ffi::Handle>::ID, &mut ());
                let default_result = unsafe { crate::__default(handle_id, output.as_mut_ptr()) };

                if default_result != iroha_ffi::FfiReturn::Ok  {
                    panic!("Default returned: {}", default_result);
                }

                unsafe {iroha_ffi::FfiOutPtrRead::try_read_out(output.assume_init()).expect("Invalid output")}
            }
        }
    }
}

fn impl_eq_for_opaque(name: &Ident, generics: &syn::Generics) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    quote! { impl #impl_generics Eq for #name #ty_generics #where_clause {} }
}
fn impl_partial_eq_for_opaque(name: &Ident, generics: &syn::Generics) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics PartialEq for #name #ty_generics #where_clause {
            fn eq(&self, other: &Self) -> bool {
                let mut output = core::mem::MaybeUninit::uninit();

                let handle_id = iroha_ffi::FfiConvert::into_ffi(<#name #ty_generics as iroha_ffi::Handle>::ID, &mut ());
                let eq_result = unsafe { crate::__eq(handle_id, self.0, other.0, output.as_mut_ptr()) };

                if eq_result != iroha_ffi::FfiReturn::Ok  {
                    panic!("Eq returned: {}", eq_result);
                }

                unsafe {iroha_ffi::FfiOutPtrRead::try_read_out(output.assume_init()).expect("Invalid output")}
            }
        }
    }
}

fn impl_partial_ord_for_opaque(name: &Ident, generics: &syn::Generics) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics PartialOrd for #name #ty_generics #where_clause {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
    }
}
fn impl_ord_for_opaque(name: &Ident, generics: &syn::Generics) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics Ord for #name #ty_generics #where_clause {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                let mut output = core::mem::MaybeUninit::uninit();

                let handle_id = iroha_ffi::FfiConvert::into_ffi(<#name #ty_generics as iroha_ffi::Handle>::ID, &mut ());
                let cmp_result = unsafe { crate::__ord(handle_id, self.0, other.0, output.as_mut_ptr()) };

                if cmp_result != iroha_ffi::FfiReturn::Ok  {
                    panic!("Ord returned: {}", cmp_result);
                }

                unsafe {iroha_ffi::FfiOutPtrRead::try_read_out(output.assume_init()).expect("Invalid output")}
            }
        }
    }
}

fn gen_shared_fns(emitter: &mut Emitter, input: &FfiTypeInput) -> Vec<TokenStream> {
    let name = &input.ident;

    let mut shared_fn_impls = Vec::new();
    for derive in &input.derive_attr.derives {
        match derive {
            Derive::Rustc(derive) => match derive {
                RustcDerive::Copy => {
                    emit!(
                        emitter,
                        name,
                        "Opaque type should not implement `Copy` trait"
                    );
                }
                RustcDerive::Clone => {
                    shared_fn_impls.push(impl_clone_for_opaque(name, &input.generics));
                }
                RustcDerive::Default => {
                    shared_fn_impls.push(impl_default_for_opaque(name, &input.generics));
                }
                RustcDerive::PartialEq => {
                    shared_fn_impls.push(impl_partial_eq_for_opaque(name, &input.generics));
                }
                RustcDerive::Eq => {
                    shared_fn_impls.push(impl_eq_for_opaque(name, &input.generics));
                }
                RustcDerive::PartialOrd => {
                    shared_fn_impls.push(impl_partial_ord_for_opaque(name, &input.generics));
                }
                RustcDerive::Ord => {
                    shared_fn_impls.push(impl_ord_for_opaque(name, &input.generics));
                }
                RustcDerive::Hash | RustcDerive::Debug => {
                    emit!(
                        emitter,
                        name,
                        "Opaque type should not implement `{:?}` trait",
                        derive
                    );
                }
            },
            Derive::GetSet(_) => {
                // handled by `getset_gen` module
            }
            Derive::Other(derive) => {
                emit!(
                    emitter,
                    name,
                    "Opaque type should not implement `{}` trait",
                    derive
                );
            }
        }
    }

    shared_fn_impls
}

pub fn wrap_as_opaque(emitter: &mut Emitter, mut input: FfiTypeInput) -> TokenStream {
    let name = &input.ident;
    let vis = &input.vis;

    add_handle_bound(name, &mut input.generics);
    let mut ref_generics = input.generics.clone();
    let lifetime = gen_lifetime_name_for_opaque();
    ref_generics.params.push(parse_quote!(#lifetime));

    let (impl_generics, ty_generics, handle_bounded_where_clause) = input.generics.split_for_impl();
    let (ref_impl_generics, ref_ty_generics, _) = ref_generics.split_for_impl();

    let phantom_data_type_defs: Vec<_> = input
        .generics
        .type_params()
        .map(|param| quote! {, core::marker::PhantomData<#param>})
        .collect();

    let new_phantom_data_types: Vec<_> = input
        .generics
        .type_params()
        .map(|_| quote! {, core::marker::PhantomData})
        .collect();

    let ref_name = gen_ref_name(name);
    let ref_mut_name = gen_ref_mut_name(name);
    let impl_ffi = gen_impl_ffi(name, &input.generics);

    let shared_fns = gen_shared_fns(emitter, &input);
    // TODO: which attributes do we need to keep?
    // in darling there is mechanism to forwards attrs, but it needs to be an whitelist
    // it seems that as of now no such forwarding needs to take place
    // so we just drop all attributes
    let attrs = Vec::<Attribute>::new();

    quote! {
        #(#attrs)*
        #[repr(transparent)]
        #vis struct #name #ty_generics(*mut iroha_ffi::Extern #(#phantom_data_type_defs)*) #handle_bounded_where_clause;

        #(#attrs)*
        #[derive(Clone, Copy)]
        #[repr(transparent)]
        #vis struct #ref_name #ref_ty_generics (*const iroha_ffi::Extern, core::marker::PhantomData<&#lifetime ()> #(#phantom_data_type_defs)*) #handle_bounded_where_clause;

        #(#attrs)*
        #[repr(transparent)]
        #vis struct #ref_mut_name #ref_ty_generics(*mut iroha_ffi::Extern, core::marker::PhantomData<&#lifetime mut ()> #(#phantom_data_type_defs)*) #handle_bounded_where_clause;

        impl #impl_generics Drop for #name #ty_generics #handle_bounded_where_clause {
            fn drop(&mut self) {
                let handle_id = iroha_ffi::FfiConvert::into_ffi(<#name #ty_generics as iroha_ffi::Handle>::ID, &mut ());
                let drop_result = unsafe { crate::__drop(handle_id, self.0) };

                if drop_result != iroha_ffi::FfiReturn::Ok  {
                    panic!("Drop returned: {}", drop_result);
                }
            }
        }

        impl #impl_generics #name #ty_generics #handle_bounded_where_clause {
            fn from_extern_ptr(opaque_ptr: *mut iroha_ffi::Extern) -> Self {
                Self(opaque_ptr #(#new_phantom_data_types)*)
            }
        }

        impl #ref_impl_generics #name #ty_generics #handle_bounded_where_clause {
            fn as_ref(&self) -> #ref_name #ref_ty_generics {
                #ref_name(self.0, core::marker::PhantomData #(#new_phantom_data_types)*)
            }
            fn as_mut(&mut self) -> #ref_mut_name #ref_ty_generics #handle_bounded_where_clause {
                #ref_mut_name(self.0, core::marker::PhantomData #(#new_phantom_data_types)*)
            }
        }
        impl #ref_impl_generics core::ops::Deref for #ref_name #ref_ty_generics #handle_bounded_where_clause {
            type Target = #name #ty_generics;

            fn deref(&self) -> &Self::Target {
                unsafe {&*(&self.0 as *const *const iroha_ffi::Extern).cast()}
            }
        }

        impl #ref_impl_generics core::ops::Deref for #ref_mut_name #ref_ty_generics #handle_bounded_where_clause {
            type Target = #ref_name #ref_ty_generics;

            fn deref(&self) -> &Self::Target {
                unsafe {&*(&self.0 as *const *mut iroha_ffi::Extern).cast()}
            }
        }

        impl #ref_impl_generics core::ops::DerefMut for #ref_mut_name #ref_ty_generics #handle_bounded_where_clause {
            fn deref_mut(&mut self) -> &mut Self::Target {
                unsafe {&mut *(&mut self.0 as *mut *mut iroha_ffi::Extern).cast()}
            }
        }

        #(#shared_fns)*
        #impl_ffi
    }
}

#[allow(clippy::too_many_lines)]
fn gen_impl_ffi(name: &Ident, generics: &syn::Generics) -> TokenStream {
    let mut ref_generics = generics.clone();

    let ref_name = gen_ref_name(name);
    let ref_mut_name = gen_ref_mut_name(name);

    let lifetime = gen_lifetime_name_for_opaque();
    ref_generics.params.push(parse_quote!(#lifetime));

    let lifetime_bounded_where_clause = generics
        .type_params()
        .map(|param| parse_quote! {#param: #lifetime})
        .collect::<Vec<syn::WherePredicate>>();

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let (ref_impl_generics, ref_ty_generics, _) = ref_generics.split_for_impl();
    let split_impl_generics: Vec<_> = generics.type_params().collect();

    quote! {
        // SAFETY: Type is a wrapper for `*mut Extern`
        unsafe impl #impl_generics iroha_ffi::ir::External for #name #ty_generics #where_clause {
            type RefType<#lifetime> = #ref_name #ref_ty_generics;
            type RefMutType<#lifetime> = #ref_mut_name #ref_ty_generics;

            fn as_extern_ptr(&self) -> *const iroha_ffi::Extern {
                self.0
            }
            fn as_extern_ptr_mut(&mut self) -> *mut iroha_ffi::Extern {
                self.0
            }
            unsafe fn from_extern_ptr(opaque_ptr: *mut iroha_ffi::Extern) -> Self {
                Self::from_extern_ptr(opaque_ptr)
            }
        }

        // SAFETY: Type is a wrapper for `*mut Extern`
        unsafe impl #impl_generics iroha_ffi::ir::Transmute for #name #ty_generics #where_clause {
            type Target = *mut iroha_ffi::Extern;

            #[inline]
            unsafe fn is_valid(target: &Self::Target) -> bool {
                !target.is_null()
            }
        }

        impl #impl_generics iroha_ffi::ir::Ir for #name #ty_generics #where_clause {
            type Type = Self;
        }

        impl #impl_generics iroha_ffi::repr_c::CType<Self> for #name #ty_generics #where_clause {
            type ReprC = *mut iroha_ffi::Extern;
        }
        impl #impl_generics iroha_ffi::repr_c::CTypeConvert<'_, Self, *mut iroha_ffi::Extern> for #name #ty_generics #where_clause {
            type RustStore = ();
            type FfiStore = ();

            fn into_repr_c(self, _: &mut ()) -> *mut iroha_ffi::Extern {
                core::mem::ManuallyDrop::new(self).0
            }

            unsafe fn try_from_repr_c(source: *mut iroha_ffi::Extern, _: &mut ()) -> iroha_ffi::Result<Self> {
                if source.is_null() {
                    return Err(iroha_ffi::FfiReturn::ArgIsNull);
                }

                Ok(Self::from_extern_ptr(source))
            }
        }

        impl #impl_generics iroha_ffi::repr_c::CWrapperType<Self> for #name #ty_generics #where_clause {
            type InputType = Self;
            type ReturnType = Self;
        }
        impl #impl_generics iroha_ffi::repr_c::COutPtr<Self> for #name #ty_generics #where_clause {
            type OutPtr = Self::ReprC;
        }
        impl #impl_generics iroha_ffi::repr_c::COutPtrRead<Self> for #name #ty_generics #where_clause {
            unsafe fn try_read_out(out_ptr: Self::OutPtr) -> iroha_ffi::Result<Self> {
                iroha_ffi::repr_c::read_non_local::<_, Self>(out_ptr)
            }
        }

        impl #impl_generics iroha_ffi::ir::IrTypeFamily for #name #ty_generics #where_clause {
            type Ref<#lifetime> = &#lifetime iroha_ffi::Extern where #(#lifetime_bounded_where_clause),*;
            type RefMut<#lifetime> = &#lifetime mut iroha_ffi::Extern where #(#lifetime_bounded_where_clause),*;
            type Box = Box<iroha_ffi::Extern>;
            type BoxedSlice = Box<[iroha_ffi::Extern]>;
            type RefSlice<#lifetime> = &#lifetime [iroha_ffi::ir::Transparent] where #(#lifetime_bounded_where_clause),*;
            type RefMutSlice<#lifetime> = &#lifetime mut [iroha_ffi::ir::Transparent] where #(#lifetime_bounded_where_clause),*;
            type Vec = Vec<iroha_ffi::ir::Transparent>;
            type Arr<const N: usize> = iroha_ffi::ir::Transparent;
        }

        // SAFETY: Type doesn't use store during conversion
        unsafe impl #impl_generics iroha_ffi::repr_c::NonLocal<Self> for #name #ty_generics #where_clause {}

        iroha_ffi::ffi_type! {
            unsafe impl<#lifetime #(, #split_impl_generics)*> Transparent for #ref_name #ref_ty_generics #where_clause {
                type Target = *const iroha_ffi::Extern;

                validation_fn=unsafe {|target: &*const iroha_ffi::Extern| !target.is_null()},
                niche_value=core::ptr::null()
            }
        }
        iroha_ffi::ffi_type! {
            unsafe impl <#lifetime #(, #split_impl_generics)*> Transparent for #ref_mut_name #ref_ty_generics #where_clause {
                type Target = *mut iroha_ffi::Extern;

                validation_fn=unsafe {|target: &*mut iroha_ffi::Extern| !target.is_null()},
                niche_value=core::ptr::null_mut()
            }
        }

        // SAFETY: Opaque pointer must never be dereferenced
        unsafe impl #impl_generics iroha_ffi::ir::InfallibleTransmute for #name #ty_generics #where_clause {}
        // SAFETY: Opaque pointer must never be dereferenced
        unsafe impl #ref_impl_generics iroha_ffi::ir::InfallibleTransmute for #ref_name #ref_ty_generics #where_clause {}
        // SAFETY: Opaque pointer must never be dereferenced
        unsafe impl #ref_impl_generics iroha_ffi::ir::InfallibleTransmute for #ref_mut_name #ref_ty_generics #where_clause {}

        impl #impl_generics iroha_ffi::WrapperTypeOf<Self> for #name #ty_generics #where_clause {
            type Type = Self;
        }
        impl #ref_impl_generics iroha_ffi::WrapperTypeOf<&#lifetime #name #ty_generics> for #ref_name #ref_ty_generics #where_clause {
            type Type = Self;
        }
        impl #ref_impl_generics iroha_ffi::WrapperTypeOf<&#lifetime mut #name #ty_generics> for #ref_mut_name #ref_ty_generics #where_clause {
            type Type = Self;
        }

        impl #impl_generics iroha_ffi::option::Niche<'_> for #name #ty_generics #where_clause {
            const NICHE_VALUE: *mut iroha_ffi::Extern = core::ptr::null_mut();
        }
    }
}

pub fn wrap_impl_items(impl_desc: &ImplDescriptor) -> TokenStream {
    let impl_attrs = &impl_desc.attrs;

    if impl_desc.fns.is_empty() {
        return quote! {};
    }
    let lifetime = gen_lifetime_name_for_opaque();
    let self_ty_name = impl_desc.fns[0].self_ty_name().expect("Defined");
    let self_ty = &impl_desc.fns[0].self_ty;
    let ref_self_ty_name = gen_ref_name(self_ty_name);
    let ref_mut_self_ty_name = gen_ref_mut_name(self_ty_name);

    let mut self_methods = Vec::new();
    let mut self_ref_methods = Vec::new();
    let mut self_ref_mut_methods = Vec::new();
    let impl_trait_for = impl_desc
        .trait_name
        .map(|trait_name| quote! { #trait_name for });
    let (associated_names, associated_types) = impl_desc.associated_types.iter().fold(
        (Vec::new(), Vec::new()),
        |(mut names, mut types), (name, ty)| {
            names.push(name);
            types.push(ty);
            (names, types)
        },
    );

    for fn_ in &impl_desc.fns {
        let trait_name = impl_desc.trait_name();

        if let Some(wrapped) = is_shared_fn(fn_, trait_name) {
            return wrapped;
        }

        if let Some(recv) = &fn_.receiver {
            if let Type::Reference(ref_ty) = recv.src_type() {
                let mutability = ref_ty.mutability.is_some();
                let ref_wrapped = wrap_ref_method(fn_, trait_name);

                if mutability {
                    self_ref_mut_methods.push(ref_wrapped);
                } else {
                    self_ref_methods.push(ref_wrapped);
                }

                self_methods.push(gen_self_ref_method(fn_, trait_name, mutability));
            } else {
                self_methods.push(wrap_method(fn_, trait_name));
            }
        } else {
            self_methods.push(wrap_method(fn_, trait_name));
        }
    }

    let mut result = Vec::new();
    if !self_methods.is_empty() {
        result.push(quote! {
            #(#impl_attrs)*
            impl #impl_trait_for #self_ty {
                #(type #associated_names = #associated_types;)*
                #(#self_methods)*
            }
        });
    }
    if !self_ref_methods.is_empty() {
        result.push(quote! {
            #(#impl_attrs)*
            impl<#lifetime> #impl_trait_for #ref_self_ty_name<#lifetime> {
                #(type #associated_names = #associated_types;)*
                #(#self_ref_methods)*
            }
        });
    }
    if !self_ref_mut_methods.is_empty() {
        result.push(quote! {
            #(#impl_attrs)*
            impl<#lifetime> #impl_trait_for #ref_mut_self_ty_name<#lifetime> {
                #(type #associated_names = #associated_types;)*
                #(#self_ref_mut_methods)*
            }
        });
    }

    quote! { #(#result)* }
}

fn gen_ref_wrapper_signature(fn_descriptor: &FnDescriptor) -> syn::Signature {
    let mut signature = gen_wrapper_signature(fn_descriptor);

    let add_lifetime = fn_descriptor
        .receiver
        .as_ref()
        .filter(|arg| matches!(arg.src_type(), Type::Reference(_)))
        .is_some();

    if fn_descriptor.self_ty.is_some() && add_lifetime {
        let mut lifetime_resolver = WrapperLifetimeResolver::new();
        lifetime_resolver.visit_signature_mut(&mut signature);
    }

    signature
}

fn gen_wrapper_signature(fn_descriptor: &FnDescriptor) -> syn::Signature {
    let mut signature = fn_descriptor.sig.clone();

    let mut type_impl_trait_resolver = TypeImplTraitResolver;
    type_impl_trait_resolver.visit_signature_mut(&mut signature);

    let mut type_resolver = WrapperTypeResolver::new();
    type_resolver.visit_signature_mut(&mut signature);

    signature
}

fn is_shared_fn(fn_descriptor: &FnDescriptor, trait_name: Option<&Ident>) -> Option<TokenStream> {
    let mut generics = parse_quote! {};

    if let Some(trait_name) = trait_name {
        let self_ty = fn_descriptor.self_ty_name().expect("Method without Self");
        add_handle_bound(self_ty, &mut generics);

        if trait_name == "Clone" {
            return Some(impl_clone_for_opaque(self_ty, &generics));
        }
        if trait_name == "Default" {
            return Some(impl_default_for_opaque(self_ty, &generics));
        }
        if trait_name == "PartialEq" {
            return Some(impl_partial_eq_for_opaque(self_ty, &generics));
        }
        if trait_name == "Eq" {
            return Some(impl_eq_for_opaque(self_ty, &generics));
        }
        if trait_name == "PartialOrd" {
            return Some(impl_partial_ord_for_opaque(self_ty, &generics));
        }
        if trait_name == "Ord" {
            return Some(impl_ord_for_opaque(self_ty, &generics));
        }
    }

    None
}

fn gen_self_ref_method(
    fn_descriptor: &FnDescriptor,
    trait_name: Option<&Ident>,
    mutability: bool,
) -> TokenStream {
    let fn_name = &fn_descriptor.sig.ident;

    let args = fn_descriptor.sig.inputs.iter().filter_map(|input| {
        if let syn::FnArg::Typed(arg) = input {
            return Some(&arg.pat);
        }

        None
    });

    let ref_ty = if mutability {
        quote! {as_mut}
    } else {
        quote! {as_ref}
    };

    let method_body = quote! {
        self.#ref_ty().#fn_name(#(#args),*)
    };

    let signature = gen_wrapper_signature(fn_descriptor);
    wrap_method_with_signature_and_body(fn_descriptor, trait_name, &signature, &method_body)
}

fn wrap_ref_method(fn_descriptor: &FnDescriptor, trait_name: Option<&Ident>) -> TokenStream {
    let signature = gen_ref_wrapper_signature(fn_descriptor);
    wrap_method_with_signature(fn_descriptor, trait_name, &signature)
}

pub fn wrap_method(fn_descriptor: &FnDescriptor, trait_name: Option<&Ident>) -> TokenStream {
    let signature = gen_wrapper_signature(fn_descriptor);
    wrap_method_with_signature(fn_descriptor, trait_name, &signature)
}

fn wrap_method_with_signature(
    fn_descriptor: &FnDescriptor,
    trait_name: Option<&Ident>,
    signature: &syn::Signature,
) -> TokenStream {
    let ffi_fn_name = ffi_fn::gen_fn_name(fn_descriptor, trait_name);
    let method_body = gen_wrapper_method_body(fn_descriptor, &ffi_fn_name);
    wrap_method_with_signature_and_body(fn_descriptor, trait_name, signature, &method_body)
}

fn wrap_method_with_signature_and_body(
    fn_descriptor: &FnDescriptor,
    trait_name: Option<&Ident>,
    signature: &syn::Signature,
    method_body: &TokenStream,
) -> TokenStream {
    let ffi_fn_attrs = &fn_descriptor.attrs;
    let method_doc = &fn_descriptor.doc;
    let visibility = if trait_name.is_none() {
        quote! { pub }
    } else {
        quote! {}
    };

    quote! {
        #(#method_doc)*
        #(#ffi_fn_attrs)*
        #visibility #signature {
            #method_body
        }
    }
}

fn gen_wrapper_method_body(fn_descriptor: &FnDescriptor, ffi_fn_name: &Ident) -> TokenStream {
    let input_conversions = gen_input_conversion_stmts(fn_descriptor);
    let ffi_fn_call_stmt = gen_ffi_fn_call_stmt(fn_descriptor, ffi_fn_name);
    let return_stmt = gen_return_stmt(fn_descriptor);

    quote! {
        #input_conversions

        // SAFETY:
        // 1. call to FFI function is safe, i.e. it's implementation is free from UBs.
        // 2. out-pointer is initialized, i.e. MaybeUninit::assume_init() is not UB
        unsafe {
            #ffi_fn_call_stmt
            #return_stmt
        }
    }
}

fn gen_input_conversion_stmts(fn_descriptor: &FnDescriptor) -> TokenStream {
    let mut stmts = quote! {};

    if let Some(arg) = &fn_descriptor.receiver {
        let arg_name = arg.name();

        stmts.extend(quote! {let #arg_name = self;});
        if matches!(arg.src_type(), Type::Reference(_)) {
            stmts.extend(quote! { let #arg_name = #arg_name.0; });
        }

        stmts.extend(gen_input_arg_src_to_ffi(arg));
    }
    for arg in &fn_descriptor.input_args {
        stmts.extend(gen_input_arg_src_to_ffi(arg));
    }
    if let Some(arg) = &fn_descriptor.output_arg {
        let name = &arg.name();

        if !arg.src_type_is_empty_tuple() {
            stmts.extend(quote! {
                let mut #name = core::mem::MaybeUninit::uninit();
            });
        }
    }

    stmts
}

fn gen_input_arg_src_to_ffi(arg: &Arg) -> TokenStream {
    let arg_name = arg.name();

    let resolve_impl_trait = gen_resolve_type(arg);
    let store_name = gen_store_name(arg_name);

    quote! {
        #resolve_impl_trait
        let mut #store_name = Default::default();
        let #arg_name = iroha_ffi::FfiConvert::into_ffi(#arg_name, &mut #store_name);
    }
}

fn gen_ffi_fn_call_stmt(fn_descriptor: &FnDescriptor, ffi_fn_name: &Ident) -> TokenStream {
    let mut arg_names = quote! {};
    if let Some(arg) = &fn_descriptor.receiver {
        let arg_name = &arg.name();

        arg_names.extend(quote! {
            #arg_name,
        });
    }
    for arg in &fn_descriptor.input_args {
        let arg_name = &arg.name();

        arg_names.extend(quote! {
            #arg_name,
        });
    }
    if let Some(arg) = &fn_descriptor.output_arg {
        let arg_name = &arg.name();

        if !arg.src_type_is_empty_tuple() {
            arg_names.extend(quote! {
                #arg_name.as_mut_ptr()
            });
        }
    }

    let execution_fail_arm = fn_descriptor.output_arg.as_ref().map_or_else(
        || quote! {},
        |output| {
            if unwrap_result_type(output.src_type()).is_some() {
                quote! {
                    iroha_ffi::FfiReturn::ExecutionFail => {
                        // TODO: Implement error handling (https://github.com/hyperledger-iroha/iroha/issues/2252)
                        //return Err(Default::default());
                        unimplemented!("Error handling is not properly implemented yet");
                    }
                }
            } else {
                quote! {}
            }
        },
    );

    quote! {
        let __ffi_return = #ffi_fn_name(#arg_names);

        match __ffi_return {
            iroha_ffi::FfiReturn::Ok => {},
            #execution_fail_arm
            _ => panic!(concat!(stringify!(#ffi_fn_name), " returned {}"), __ffi_return)
        }
    }
}

fn gen_return_stmt(fn_descriptor: &FnDescriptor) -> TokenStream {
    fn_descriptor.output_arg.as_ref().map_or_else(|| quote! {}, |output| {
        if output.src_type_is_empty_tuple() {
            return quote! {Ok(())};
        }

        let arg_name= output.name();

        let return_stmt = unwrap_result_type(output.src_type())
            .map_or_else(|| quote! {#arg_name}, |_| (quote! { Ok(#arg_name) }));

        quote! {
            let #arg_name = #arg_name.assume_init();
            let #arg_name = iroha_ffi::FfiOutPtrRead::try_read_out(#arg_name).expect("Invalid out-pointer value returned");
            #return_stmt
        }
    })
}

pub struct WrapperTypeResolver(bool);
impl WrapperTypeResolver {
    pub fn new() -> Self {
        Self(false)
    }
}
impl VisitMut for WrapperTypeResolver {
    fn visit_receiver_mut(&mut self, i: &mut syn::Receiver) {
        if i.reference.is_none() {
            i.mutability = None;
        }

        // we do NOT want to visit the type in the receiver:
        // 1. what can actually go in there is severely limited
        // 2. in syn 2.0 even &self has a reconstructed type &Self, which, when patched, leads to an incorrect rust syntax
        // syn::visit_mut::visit_receiver_mut(self, i);
    }

    fn visit_type_mut(&mut self, i: &mut syn::Type) {
        if self.0 {
            // Patch return type to facilitate returning types referencing local store
            *i = parse_quote! {<#i as iroha_ffi::FfiWrapperType>::ReturnType};
        } else {
            // Patch the type mainly to facilitate the use of opaque types
            *i = parse_quote! {<#i as iroha_ffi::FfiWrapperType>::InputType};
        }
    }
    fn visit_return_type_mut(&mut self, i: &mut syn::ReturnType) {
        self.0 = true;

        if let syn::ReturnType::Type(_, output) = i {
            if let Some((ok, err)) = unwrap_result_type(output) {
                let mut ok = ok.clone();
                self.visit_type_mut(&mut ok);

                **output = parse_quote! {core::result::Result<#ok, #err>}
            } else {
                self.visit_type_mut(output);
            }
        }
    }
}

struct WrapperLifetimeResolver(bool);
impl WrapperLifetimeResolver {
    fn new() -> Self {
        Self(false)
    }
}

impl VisitMut for WrapperLifetimeResolver {
    fn visit_type_reference_mut(&mut self, i: &mut syn::TypeReference) {
        let lifetime = gen_lifetime_name_for_opaque();

        if !self.0 || i.lifetime.is_some() {
            return;
        }

        i.lifetime = parse_quote! {#lifetime};
    }
    fn visit_return_type_mut(&mut self, i: &mut syn::ReturnType) {
        self.0 = true;
        syn::visit_mut::visit_return_type_mut(self, i);
    }
}
