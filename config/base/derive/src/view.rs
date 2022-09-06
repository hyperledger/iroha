use gen::*;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{Meta, NestedMeta};

use super::utils::{
    extract_field_idents, extract_field_types, remove_attr, remove_attr_struct, AttrParser,
    StructField, StructWithFields, View, ViewFieldType, ViewIgnore,
};

pub fn impl_view(ast: StructWithFields) -> TokenStream {
    let original = original_struct(ast.clone());
    let view = view_struct(ast);
    let impl_from = impl_from(&original, &view);
    let impl_has_view = impl_has_view(&original);
    let assertions = assertions(&view);
    let out = quote! {
        #original
        #impl_has_view
        #view
        #impl_from
        #assertions
    };
    out.into()
}

mod gen {
    use super::*;

    pub fn original_struct(mut ast: StructWithFields) -> StructWithFields {
        remove_attr_struct(&mut ast, "view");
        ast
    }

    #[allow(clippy::str_to_string, clippy::expect_used)]
    pub fn view_struct(mut ast: StructWithFields) -> StructWithFields {
        // Remove fields with #[view(ignore)]
        ast.fields.retain(is_view_field_ignored);
        // Change field type to `Type` if it has attribute #[view(into = Type)]
        ast.fields.iter_mut().for_each(view_field_change_type);
        // Replace doc-string for view
        remove_attr(&mut ast.attrs, "doc");
        let view_doc = format!("View for {}", ast.ident);
        ast.attrs.push(syn::parse_quote!(
            #[doc = #view_doc]
        ));
        ast.attrs
            .iter_mut()
            .filter(|attr| attr.path.is_ident("derive"))
            .for_each(|attr| {
                let meta = attr
                    .parse_meta()
                    .expect("derive macro must be in one of the meta forms");
                if let Meta::List(list) = meta {
                    let items: Vec<syn::NestedMeta> = list
                        .nested
                        .into_iter()
                        .filter(|nested| {
                            if let NestedMeta::Meta(Meta::Path(path)) = nested {
                                // remove derives that are needed on the `Configuration`
                                // or `ConfigurationProxy`, but not needed on `ConfigruationView`
                                if path.is_ident("LoadFromEnv")
                                    || path.is_ident("Builder")
                                    || path.is_ident("Proxy")
                                {
                                    return false;
                                }
                            }
                            true
                        })
                        .collect();
                    *attr = syn::parse_quote!(
                        #[derive(#(#items),*)]
                    )
                }
            });
        // TODO: Find a way to make this more ergonomic. As `View` struct
        // are formed inside a proc macro, we have to remove unrelated attributes from `Configuration` here.
        remove_attr_struct(&mut ast, "view");
        remove_attr_struct(&mut ast, "config");
        remove_attr_struct(&mut ast, "builder");
        ast.ident = format_ident!("{}View", ast.ident);
        ast
    }

    pub fn impl_from(
        original: &StructWithFields,
        view: &StructWithFields,
    ) -> proc_macro2::TokenStream {
        let StructWithFields {
            ident: original_ident,
            ..
        } = original;
        let StructWithFields {
            generics,
            ident: view_ident,
            fields,
            ..
        } = view;
        let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
        let field_idents = extract_field_idents(fields);

        quote! {
            impl #impl_generics core::convert::From<#original_ident> for #view_ident #ty_generics #where_clause {
                fn from(config: #original_ident) -> Self {
                    let #original_ident {
                        #(
                            #field_idents,
                        )*
                        ..
                    } =  config;
                    Self {
                        #(
                            #field_idents: core::convert::From::<_>::from(#field_idents),
                        )*
                    }
                }
            }
        }
    }

    pub fn impl_has_view(original: &StructWithFields) -> proc_macro2::TokenStream {
        let StructWithFields {
            generics,
            ident: view_ident,
            ..
        } = original;
        let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

        quote! {
            impl #impl_generics iroha_config_base::view::HasView for #view_ident #ty_generics #where_clause {}
        }
    }

    pub fn assertions(view: &StructWithFields) -> proc_macro2::TokenStream {
        let StructWithFields { fields, .. } = view;
        let field_types = extract_field_types(fields);
        let messages: Vec<String> = extract_field_idents(fields)
            .iter()
            .map(|ident| {
                format!("Field `{ident}` has it's own view, consider adding attribute #[view(into = ViewType)]")
            })
            .collect();
        quote! {
            /// Assert that every field of 'View' doesn't implement `HasView` trait
            const _: () = {
                use iroha_config_base::view::NoView;
                #(
                    const _: () = assert!(!iroha_config_base::view::IsHasView::<#field_types>::IS_HAS_VIEW, #messages);
                )*
            };
        }
    }
}

/// Check if [`Field`] has `#[view(ignore)]`
fn is_view_field_ignored(field: &StructField) -> bool {
    field
        .attrs
        .iter()
        .map(View::<ViewIgnore>::parse)
        .find_map(Result::ok)
        .is_none()
}

/// Change [`Field`] type to `Type` if `#[view(type = Type)]` is present
fn view_field_change_type(field: &mut StructField) {
    if let Some(ty) = field
        .attrs
        .iter()
        .map(View::<ViewFieldType>::parse)
        .find_map(Result::ok)
        .map(ViewFieldType::into)
    {
        field.ty = ty;
    }
}
