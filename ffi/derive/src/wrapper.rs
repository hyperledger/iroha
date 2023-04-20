use proc_macro2::{Span, TokenStream};
use proc_macro_error::abort;
use quote::quote;
use syn::{visit_mut::VisitMut, Ident};

use crate::{
    ffi_fn,
    impl_visitor::{unwrap_result_type, Arg, FnDescriptor, TypeImplTraitResolver},
    util::{gen_resolve_type, gen_store_name},
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

fn gen_shared_fns(name: &Ident, attrs: &[syn::Attribute]) -> Vec<TokenStream> {
    let mut shared_fn_impls = Vec::new();

    for attr in attrs.iter() {
        if !attr.path.is_ident("derive") {
            // TODO: User should be warned?
            continue;
        }

        if let syn::Meta::List(derives) = attr.parse_meta().expect("Derive macro invalid") {
            let mut derive_eq = false;
            let mut derive_ord = false;

            for derive in derives.nested {
                if let syn::NestedMeta::Meta(meta) = &derive {
                    if let syn::Meta::Path(path) = meta {
                        if path.is_ident("Clone") {
                            shared_fn_impls.push(quote! {
                                impl Clone for #name {
                                    fn clone(&self) -> Self {
                                        let mut output = core::mem::MaybeUninit::uninit();

                                        let handle_id = iroha_ffi::FfiConvert::into_ffi(<#name as iroha_ffi::Handle>::ID, &mut ());
                                        let clone_result = unsafe { crate::__clone(handle_id, self.__opaque_ptr, output.as_mut_ptr()) };

                                        if clone_result != iroha_ffi::FfiReturn::Ok  {
                                            panic!("Clone returned: {}", clone_result);
                                        }

                                        unsafe {iroha_ffi::FfiOutPtrRead::try_read_out(output.assume_init()).expect("Invalid output")}
                                    }
                                }
                            });
                        } else if path.is_ident("Eq") {
                            derive_eq = true;
                        } else if path.is_ident("Ord") {
                            derive_ord = true;
                        } else if path.is_ident("PartialEq") || path.is_ident("PartialOrd") {
                            // NOTE: These should be skipped
                        } else {
                            abort!(path, "Unsupported derive for opaque type");
                        }
                    }
                } else {
                    unreachable!()
                }
            }

            if derive_eq {
                shared_fn_impls.push(quote! {
                    impl PartialEq for #name {
                        fn eq(&self, other: &Self) -> bool {
                            let mut output = core::mem::MaybeUninit::uninit();

                            let handle_id = iroha_ffi::FfiConvert::into_ffi(<#name as iroha_ffi::Handle>::ID, &mut ());
                            let eq_result = unsafe { crate::__eq(handle_id, self.__opaque_ptr, other.__opaque_ptr, output.as_mut_ptr()) };

                            if eq_result != iroha_ffi::FfiReturn::Ok  {
                                panic!("Eq returned: {}", eq_result);
                            }

                            unsafe {iroha_ffi::FfiOutPtrRead::try_read_out(output.assume_init()).expect("Invalid output")}
                        }
                    }
                    impl Eq for #name {}
                });
            }

            if derive_ord {
                shared_fn_impls.push(quote! {
                    impl PartialOrd for #name {
                        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                            Some(self.cmp(other))
                        }
                    }
                    impl Ord for #name {
                        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                            let mut output = core::mem::MaybeUninit::uninit();

                            let handle_id = iroha_ffi::FfiConvert::into_ffi(<#name as iroha_ffi::Handle>::ID, &mut ());
                            let cmp_result = unsafe { crate::__ord(handle_id, self.__opaque_ptr, other.__opaque_ptr, output.as_mut_ptr()) };

                            if cmp_result != iroha_ffi::FfiReturn::Ok  {
                                panic!("Ord returned: {}", cmp_result);
                            }

                            unsafe {iroha_ffi::FfiOutPtrRead::try_read_out(output.assume_init()).expect("Invalid output")}
                        }
                    }
                });
            }
        }
    }

    shared_fn_impls
}

pub fn wrap_as_opaque(input: &syn::DeriveInput) -> TokenStream {
    let vis = &input.vis;
    let name = &input.ident;

    let ref_name = gen_ref_name(name);
    let ref_mut_name = gen_ref_mut_name(name);
    let impl_ffi = gen_impl_ffi(name);

    let ref_inner = quote!(*const iroha_ffi::Extern);
    let ref_mut_inner = quote!(*mut iroha_ffi::Extern);

    let item_type = match input.data {
        syn::Data::Enum(_) => quote! {enum},
        syn::Data::Struct(_) => quote! {struct},
        syn::Data::Union(_) => quote! {union},
    };

    match &input.data {
        syn::Data::Enum(_) | syn::Data::Struct(_) => {
            let shared_fns = gen_shared_fns(name, &input.attrs);

            quote! {
                #(#shared_fns)*

                #[repr(transparent)]
                #vis #item_type #name {
                    __opaque_ptr: *mut iroha_ffi::Extern
                }

                #[derive(Clone, Copy)]
                #[repr(transparent)]
                #vis #item_type #ref_name<'itm>(#ref_inner, core::marker::PhantomData<&'itm ()>);

                #[repr(transparent)]
                #vis #item_type #ref_mut_name<'itm>(#ref_mut_inner, core::marker::PhantomData<&'itm mut ()>);

                impl Drop for #name {
                    fn drop(&mut self) {
                        let handle_id = iroha_ffi::FfiConvert::into_ffi(<#name as iroha_ffi::Handle>::ID, &mut ());
                        let drop_result = unsafe { crate::__drop(handle_id, self.__opaque_ptr) };

                        if drop_result != iroha_ffi::FfiReturn::Ok  {
                            panic!("Drop returned: {}", drop_result);
                        }
                    }
                }

                impl core::ops::Deref for #ref_name<'_> {
                    type Target = #name;

                    fn deref(&self) -> &Self::Target {
                        unsafe {&*(&self.0 as *const #ref_inner).cast()}
                    }
                }

                impl core::ops::Deref for #ref_mut_name<'_> {
                    type Target = #name;

                    fn deref(&self) -> &Self::Target {
                        unsafe {&*(&self.0 as *const #ref_mut_inner).cast()}
                    }
                }

                impl core::ops::DerefMut for #ref_mut_name<'_> {
                    fn deref_mut(&mut self) -> &mut Self::Target {
                        unsafe {&mut *(&mut self.0 as *mut #ref_mut_inner).cast()}
                    }
                }

                #impl_ffi
            }
        }
        syn::Data::Union(_) => {
            abort!(name, "Unions are not supported")
        }
    }
}

fn gen_impl_ffi(name: &Ident) -> TokenStream {
    let ref_name = gen_ref_name(name);
    let ref_mut_name = gen_ref_mut_name(name);
    let ref_inner = quote!(*const iroha_ffi::Extern);
    let ref_mut_inner = quote!(*mut iroha_ffi::Extern);

    quote! {
        // SAFETY: Type is a wrapper for `*mut Extern`
        unsafe impl iroha_ffi::ir::External for #name {
            type RefType<'itm> = #ref_name<'itm>;
            type RefMutType<'itm> = #ref_mut_name<'itm>;

            fn as_extern_ptr(&self) -> #ref_inner {
                self.__opaque_ptr
            }
            fn as_extern_ptr_mut(&mut self) -> #ref_mut_inner {
                self.__opaque_ptr
            }
            unsafe fn from_extern_ptr(__opaque_ptr: *mut iroha_ffi::Extern) -> Self {
                Self { __opaque_ptr }
            }
        }

        // SAFETY: Type is a wrapper for `*mut Extern`
        unsafe impl iroha_ffi::ir::Transmute for #name {
            type Target = *mut iroha_ffi::Extern;

            #[inline]
            unsafe fn is_valid(target: &Self::Target) -> bool {
                !target.is_null()
            }
        }

        impl iroha_ffi::ir::Ir for #name {
            type Type = Self;
        }

        impl iroha_ffi::repr_c::CType<Self> for #name {
            type ReprC = *mut iroha_ffi::Extern;
        }
        impl iroha_ffi::repr_c::CTypeConvert<'_, Self, *mut iroha_ffi::Extern> for #name {
            type RustStore = ();
            type FfiStore = ();

            fn into_repr_c(self, _: &mut ()) -> *mut iroha_ffi::Extern {
                core::mem::ManuallyDrop::new(self).__opaque_ptr
            }

            unsafe fn try_from_repr_c(source: *mut iroha_ffi::Extern, _: &mut ()) -> iroha_ffi::Result<Self> {
                if source.is_null() {
                    return Err(iroha_ffi::FfiReturn::ArgIsNull);
                }

                Ok(Self { __opaque_ptr: source })
            }
        }

        impl iroha_ffi::repr_c::CWrapperType<Self> for #name {
            type InputType = Self;
            type ReturnType = Self;
        }
        impl iroha_ffi::repr_c::COutPtr<Self> for #name {
            type OutPtr = Self::ReprC;
        }
        impl iroha_ffi::repr_c::COutPtrRead<Self> for #name {
            unsafe fn try_read_out(out_ptr: Self::OutPtr) -> iroha_ffi::Result<Self> {
                iroha_ffi::repr_c::read_non_local::<_, Self>(out_ptr)
            }
        }

        impl iroha_ffi::ir::IrTypeFamily for #name {
            type RefType<'itm> = &'itm iroha_ffi::Extern;
            type RefMutType<'itm> = &'itm mut iroha_ffi::Extern;
            type BoxType = Box<iroha_ffi::Extern>;
            type SliceRefType<'itm> = &'itm [iroha_ffi::ir::Transparent];
            type SliceRefMutType<'itm> = &'itm mut [iroha_ffi::ir::Transparent];
            type VecType = Vec<iroha_ffi::ir::Transparent>;
            type ArrType<const N: usize> = iroha_ffi::ir::Transparent;
        }

        // SAFETY: Type doesn't use store during conversion
        unsafe impl iroha_ffi::repr_c::NonLocal<Self> for #name {}

        iroha_ffi::ffi_type! {
            unsafe impl<'itm> Transparent for #ref_name<'itm> {
                type Target = #ref_inner;

                validation_fn=unsafe {|target: &#ref_inner| !target.is_null()},
                niche_value=core::ptr::null()
            }
        }
        iroha_ffi::ffi_type! {
            unsafe impl<'itm> Transparent for #ref_mut_name<'itm> {
                type Target = #ref_mut_inner;

                validation_fn=unsafe {|target: &#ref_mut_inner| !target.is_null()},
                niche_value=core::ptr::null_mut()
            }
        }

        // SAFETY: Opaque pointer must never be dereferenced
        unsafe impl iroha_ffi::ir::InfallibleTransmute for #name {}
        // SAFETY: Opaque pointer must never be dereferenced
        unsafe impl iroha_ffi::ir::InfallibleTransmute for #ref_name<'_> {}
        // SAFETY: Opaque pointer must never be dereferenced
        unsafe impl iroha_ffi::ir::InfallibleTransmute for #ref_mut_name<'_> {}

        impl<'itm> iroha_ffi::WrapperTypeOf<Self> for #name {
            type Type = Self;
        }
        impl<'itm> iroha_ffi::WrapperTypeOf<&'itm #name> for #ref_name<'itm> {
            type Type = Self;
        }
        impl<'itm> iroha_ffi::WrapperTypeOf<&'itm mut #name> for #ref_mut_name<'itm> {
            type Type = Self;
        }

        impl iroha_ffi::option::Niche<'_> for #name {
            const NICHE_VALUE: *mut iroha_ffi::Extern = core::ptr::null_mut();
        }
    }
}

#[allow(clippy::expect_used)]
pub fn wrap_impl_items(fns: &[FnDescriptor]) -> TokenStream {
    if fns.is_empty() {
        return quote! {};
    }

    let lifetime = gen_lifetime_name_for_opaque();
    let self_ty_name = fns[0].self_ty_name().expect("Defined");
    let ref_self_ty_name = gen_ref_name(self_ty_name);
    let ref_mut_self_ty_name = gen_ref_mut_name(self_ty_name);

    let mut self_methods = Vec::new();
    let mut self_ref_methods = Vec::new();
    let mut self_ref_mut_methods = Vec::new();

    for fn_ in fns {
        if let Some(recv) = &fn_.receiver {
            match recv.src_type() {
                syn::Type::Reference(ref_ty) => {
                    if ref_ty.mutability.is_some() {
                        self_ref_mut_methods.push(wrap_method(fn_));
                    } else {
                        self_ref_methods.push(wrap_method(fn_));
                    }
                }
                _ => self_methods.push(wrap_method(fn_)),
            }
        } else {
            self_methods.push(wrap_method(fn_));
        }
    }

    quote! {
        impl #self_ty_name {
            #(#self_methods)*
        }
        impl<#lifetime> #ref_self_ty_name<#lifetime> {
            #(#self_ref_methods)*
        }
        impl<#lifetime> #ref_mut_self_ty_name<#lifetime> {
            #(#self_ref_mut_methods)*
        }
    }
}

fn gen_wrapper_signature(fn_descriptor: &FnDescriptor) -> syn::Signature {
    let mut signature = fn_descriptor.sig.clone();

    let mut type_impl_trait_resolver = TypeImplTraitResolver;
    type_impl_trait_resolver.visit_signature_mut(&mut signature);

    let mut type_resolver = WrapperTypeResolver::new();
    type_resolver.visit_signature_mut(&mut signature);

    // TODO: Actually not correct
    let add_lifetime = fn_descriptor
        .receiver
        .as_ref()
        .filter(|arg| matches!(arg.src_type(), syn::Type::Reference(_)))
        .is_some();

    if fn_descriptor.self_ty.is_some() && add_lifetime {
        let mut lifetime_resolver = WrapperLifetimeResolver;
        lifetime_resolver.visit_signature_mut(&mut signature);
    }

    signature
}

pub fn wrap_method(fn_descriptor: &FnDescriptor) -> TokenStream {
    let signature = gen_wrapper_signature(fn_descriptor);
    let method_body = gen_wrapper_method_body(fn_descriptor);
    let method_doc = &fn_descriptor.doc;

    quote! {
        #method_doc
        pub #signature {
            #method_body
        }
    }
}

fn gen_wrapper_method_body(fn_descriptor: &FnDescriptor) -> TokenStream {
    let input_conversions = gen_input_conversion_stmts(fn_descriptor);
    let ffi_fn_call_stmt = gen_ffi_fn_call_stmt(fn_descriptor);
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
        stmts.extend(gen_input_arg_src_to_ffi(arg));
    }
    for arg in &fn_descriptor.input_args {
        stmts.extend(gen_input_arg_src_to_ffi(arg));
    }
    if let Some(arg) = &fn_descriptor.output_arg {
        let name = &arg.name();

        stmts.extend(quote! {
            let mut #name = core::mem::MaybeUninit::uninit();
        });
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

fn gen_ffi_fn_call_stmt(fn_descriptor: &FnDescriptor) -> TokenStream {
    let ffi_fn_name = ffi_fn::gen_fn_name(fn_descriptor);

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

        arg_names.extend(quote! {
            #arg_name.as_mut_ptr()
        });
    }

    let execution_fail_arm = fn_descriptor.output_arg.as_ref().map_or_else(
        || quote! {},
        |output| {
            if unwrap_result_type(output.src_type()).is_some() {
                quote! {
                    iroha_ffi::FfiReturn::ExecutionFail => {
                        // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                        return Err(Default::default());
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
    fn visit_type_mut(&mut self, i: &mut syn::Type) {
        if self.0 {
            // Patch return type to facilitate returning types referencing local store
            *i = syn::parse_quote! {<#i as iroha_ffi::FfiWrapperType>::ReturnType};
        } else {
            // Patch the type mainly to facilitate the use of opaque types
            *i = syn::parse_quote! {<#i as iroha_ffi::FfiWrapperType>::InputType};
        }
    }
    fn visit_return_type_mut(&mut self, i: &mut syn::ReturnType) {
        self.0 = true;

        if let syn::ReturnType::Type(_, output) = i {
            if let Some((ok, err)) = unwrap_result_type(output) {
                let mut ok = ok.clone();
                self.visit_type_mut(&mut ok);

                **output = syn::parse_quote! {core::result::Result<#ok, #err>}
            } else {
                self.visit_type_mut(output);
            }
        }
    }
}

struct WrapperLifetimeResolver;
impl VisitMut for WrapperLifetimeResolver {
    fn visit_receiver_mut(&mut self, i: &mut syn::Receiver) {
        // ```
        // impl Opaque {
        //     fn some_fn(&self) { /* */ }
        // }
        // ```
        // is converted into:
        // ```
        // impl RefOpaque {
        //     fn some_fn(self) { /* */ }
        // }
        // ```
        i.reference = None;
        i.mutability = None;
    }
    fn visit_type_reference_mut(&mut self, i: &mut syn::TypeReference) {
        if i.lifetime.is_some() {
            return;
        }

        let lifetime = gen_lifetime_name_for_opaque();
        i.lifetime = syn::parse_quote! {#lifetime};
    }
}
