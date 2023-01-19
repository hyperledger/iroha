use proc_macro2::{Span, TokenStream};
use proc_macro_error::abort;
use quote::quote;
use syn::{visit_mut::VisitMut, Ident, Type};

use crate::{
    ffi_fn,
    impl_visitor::{unwrap_result_type, Arg, FnDescriptor, ImplDescriptor, TypeImplTraitResolver},
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

fn impl_clone_for_opaque(name: &Ident) -> TokenStream {
    quote! {
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
    }
}

fn impl_eq_for_opaque(name: &Ident) -> TokenStream {
    quote! {
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
    }
}

fn impl_ord_for_opaque(name: &Ident) -> TokenStream {
    quote! {
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
    }
}

fn gen_shared_fns(name: &Ident, attrs: &[syn::Attribute]) -> Vec<TokenStream> {
    let mut shared_fn_impls = Vec::new();

    for attr in attrs.iter() {
        if !attr.path.is_ident("derive") {
            // TODO: User should be warned?
            continue;
        }

        if let syn::Meta::List(derives) = attr.parse_meta().expect("Derive macro invalid") {
            for derive in derives.nested {
                if let syn::NestedMeta::Meta(meta) = &derive {
                    if let syn::Meta::Path(path) = meta {
                        if path.is_ident("Clone") {
                            shared_fn_impls.push(impl_clone_for_opaque(name));
                        } else if path.is_ident("Eq") {
                            shared_fn_impls.push(impl_eq_for_opaque(name));
                        } else if path.is_ident("Ord") {
                            shared_fn_impls.push(impl_ord_for_opaque(name));
                            // TODO: What to do about getters/setters?
                        } else if path.is_ident("PartialEq")
                            || path.is_ident("PartialOrd")
                            || path.is_ident("Setters")
                            || path.is_ident("Getters")
                            || path.is_ident("MutGetters")
                        {
                            // NOTE: These should be skipped
                        } else {
                            abort!(path, "Unsupported derive for opaque type");
                        }
                    }
                } else {
                    unreachable!()
                }
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

    let item_type = match input.data {
        syn::Data::Enum(_) | syn::Data::Struct(_) => quote! {struct},
        syn::Data::Union(_) => quote! {union},
    };

    match &input.data {
        syn::Data::Enum(_) | syn::Data::Struct(_) => {
            let shared_fns = gen_shared_fns(name, &input.attrs);

            quote! {
                #(#shared_fns)*

                // TODO: Other attributes are missing!
                #[repr(transparent)]
                #vis #item_type #name {
                    __opaque_ptr: *mut iroha_ffi::Extern
                }

                // TODO: Other attributes are missing!
                #[derive(Clone, Copy)]
                #[repr(transparent)]
                #vis #item_type #ref_name<'itm>(*const iroha_ffi::Extern, core::marker::PhantomData<&'itm ()>);

                // TODO: Other attributes are missing!
                #[repr(transparent)]
                #vis #item_type #ref_mut_name<'itm>(*mut iroha_ffi::Extern, core::marker::PhantomData<&'itm mut ()>);

                impl Drop for #name {
                    fn drop(&mut self) {
                        let handle_id = iroha_ffi::FfiConvert::into_ffi(<#name as iroha_ffi::Handle>::ID, &mut ());
                        let drop_result = unsafe { crate::__drop(handle_id, self.__opaque_ptr) };

                        if drop_result != iroha_ffi::FfiReturn::Ok  {
                            panic!("Drop returned: {}", drop_result);
                        }
                    }
                }

                impl #name {
                    fn as_ref(&self) -> #ref_name<'_> {
                        #ref_name(self.__opaque_ptr, core::marker::PhantomData)
                    }
                    fn as_mut(&self) -> #ref_mut_name<'_> {
                        #ref_mut_name(self.__opaque_ptr, core::marker::PhantomData)
                    }
                }
                impl core::ops::Deref for #ref_name<'_> {
                    type Target = #name;

                    fn deref(&self) -> &Self::Target {
                        unsafe {&*(&self.0 as *const *const iroha_ffi::Extern).cast()}
                    }
                }

                impl core::ops::Deref for #ref_mut_name<'_> {
                    type Target = #name;

                    fn deref(&self) -> &Self::Target {
                        unsafe {&*(&self.0 as *const *mut iroha_ffi::Extern).cast()}
                    }
                }

                impl core::ops::DerefMut for #ref_mut_name<'_> {
                    fn deref_mut(&mut self) -> &mut Self::Target {
                        unsafe {&mut *(&mut self.0 as *mut *mut iroha_ffi::Extern).cast()}
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

    quote! {
        // SAFETY: Type is a wrapper for `*mut Extern`
        unsafe impl iroha_ffi::ir::External for #name {
            type RefType<'itm> = #ref_name<'itm>;
            type RefMutType<'itm> = #ref_mut_name<'itm>;

            fn as_extern_ptr(&self) -> *const iroha_ffi::Extern {
                self.__opaque_ptr
            }
            fn as_extern_ptr_mut(&mut self) -> *mut iroha_ffi::Extern {
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

        iroha_ffi::ffi_type! {unsafe impl<'itm> Transparent for #ref_name<'itm>[*const iroha_ffi::Extern] validated with {|target: &*const iroha_ffi::Extern| !target.is_null()} }
        iroha_ffi::ffi_type! {unsafe impl<'itm> Transparent for #ref_mut_name<'itm>[*mut iroha_ffi::Extern] validated with {|target: &*mut iroha_ffi::Extern| !target.is_null()} }

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

        impl iroha_ffi::option::Niche for #name {
            const NICHE_VALUE: *mut iroha_ffi::Extern = core::ptr::null_mut();
        }
        impl iroha_ffi::option::Niche for #ref_name<'_> {
            const NICHE_VALUE: *const iroha_ffi::Extern = core::ptr::null();
        }
        impl iroha_ffi::option::Niche for #ref_mut_name<'_> {
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
        let wrapped = wrap_method(fn_, impl_desc.trait_name());

        if let Some(recv) = &fn_.receiver {
            if let Type::Reference(ref_ty) = recv.src_type() {
                if ref_ty.mutability.is_some() {
                    self_ref_mut_methods.push(wrapped);
                } else {
                    self_ref_methods.push(wrapped);
                }
            } else {
                self_methods.push(wrapped);
            }
        } else {
            self_methods.push(wrapped);
        }
    }

    let mut result = Vec::new();
    if !self_methods.is_empty() {
        result.push(quote! {
            #(#impl_attrs)*
            impl #impl_trait_for #self_ty_name {
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
        .filter(|arg| matches!(arg.src_type(), Type::Reference(_)))
        .is_some();

    if fn_descriptor.self_ty.is_some() && add_lifetime {
        let mut lifetime_resolver = WrapperLifetimeResolver;
        lifetime_resolver.visit_signature_mut(&mut signature);
    }

    signature
}

pub fn wrap_method(fn_descriptor: &FnDescriptor, trait_name: Option<&Ident>) -> TokenStream {
    if let Some(trait_name) = trait_name {
        let self_ty = fn_descriptor.self_ty_name().expect("Method without Self");

        if trait_name == "PartialEq" || trait_name == "PartialOrd" {
            return quote! {};
        }
        if trait_name == "Clone" {
            return impl_clone_for_opaque(self_ty);
        }
        if trait_name == "Eq" {
            return impl_eq_for_opaque(self_ty);
        }
        if trait_name == "Ord" {
            return impl_ord_for_opaque(self_ty);
        }
    }

    let ffi_fn_attrs = &fn_descriptor.attrs;
    let signature = gen_wrapper_signature(fn_descriptor);
    let ffi_fn_name = ffi_fn::gen_fn_name(fn_descriptor, trait_name);
    let method_body = gen_wrapper_method_body(fn_descriptor, &ffi_fn_name);
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
                        // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
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
