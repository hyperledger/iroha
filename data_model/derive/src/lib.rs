use proc_macro::{bridge::server::Ident, TokenStream};
use quote::{format_ident, quote};
use syn::{parse_macro_input, parse_quote, DataEnum, DataStruct, DeriveInput, Fields};

#[proc_macro_derive(FfiEncode)]
pub fn ffi_encode_derive(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);

    let repr_c = parse_quote!(#[repr(C)]);
    let repr_transparent = parse_quote!(#[repr(transparent)]);

    if input.attrs.contains(&repr_c) || input.attrs.contains(&repr_transparent) {
        return ffi_no_convert(input);
    }

    ffi_convert(input)
}

fn ffi_convert(input: DeriveInput) -> TokenStream {
    let name = &input.ident;
    let ffi_wrapper_name = format_ident!("_Ffi{}", name);

    let ffi_wrapper = match input.data {
        syn::Data::Struct(DataStruct { fields, .. }) => {
            let fields: Vec<_> = fields.into_iter().collect();
            let field_names: Vec<_> = fields.iter().map(|field| field.ident).collect();
               //     field.ty = format_ident!("Ffi{}", field.ty);
               //     field
               // })
               // .collect();

            quote! {
                struct #ffi_wrapper_name {
                    #( #fields, )*
                }

                impl From<#name> for #ffi_wrapper_name {
                    fn from(source: #name) -> Self {
                        Self {
                            #( #field_names: source.#field_names.ffi_encode(), )*
                        }
                    }
                }

                impl From<#ffi_wrapper_name> for #name {
                    fn from(source: #ffi_wrapper_name) -> Self {
                        Self {
                            #( #field_names: source.#field_names.ffi_decode(), )*
                        }
                    }
                }
            }
        }
        syn::Data::Enum(DataEnum { variants, .. }) => {
            let variants = variants.iter().collect::<Vec<_>>();

            quote! {
                enum #ffi_wrapper_name {
                    #( #variants, )*
                }

                impl From<#name> for #ffi_wrapper_name {
                    fn from(source: #name) -> Self {
                        match source {
                            #( #variant_names: source.#variant_names.ffi_encode(), )*
                        }
                        Self {
                        }
                    }
                }
                impl From<#ffi_wrapper_name> for #name {
                    fn from(source: #ffi_wrapper_name) -> Self {
                        Self {
                            #( #variant_names: source.#variant_names.ffi_decode(), )*
                        }
                    }
                }
            }
        }
        _ => panic!("KITA"),
    };

    let k = quote! {
        #ffi_wrapper

        impl FfiEncode for #name {
            type FfiType = #ffi_wrapper_name;

            fn ffi_encode(self) -> Self::FfiType {
                Self::FfiType {
                }
            }

            unsafe fn ffi_decode(source: Self::FfiType) -> Self {
                source
            }
        }
    }
    .into();
    println!("{}", k);
    k
}

fn ffi_no_convert(input: DeriveInput) -> TokenStream {
    let name = &input.ident;

    quote! {
        impl crate::ffi_encode::FfiEncode for #name {
            type FfiType = Self;

            fn ffi_encode(self) -> Self::FfiType {
                self
            }

            unsafe fn ffi_decode(source: Self::FfiType) -> Self {
                source
            }
        }
    }
    .into()
}
