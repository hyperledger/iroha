use proc_macro2::TokenStream;
use proc_macro_error::{abort, OptionExt, ResultExt};
use quote::{format_ident, quote};
use syn::visit_mut::{visit_derive_input_mut, VisitMut};

pub fn impl_builder(mut builder: syn::DeriveInput) -> TokenStream {
    let parent_ident = builder.ident.clone();

    let mut builder_resolver = BuilderResolver::new();
    builder_resolver.visit_derive_input_mut(&mut builder);

    let builder_ident = &builder.ident;
    let field_names: Vec<_> = builder_resolver
        .config_fields
        .iter()
        .map(|(field_name, _, _)| field_name)
        .collect();

    let getter_methods = builder_resolver
        .config_fields
        .iter()
        .map(|(field_name, field_ty, _)| gen_getter_method(field_name, field_ty));

    let builder_setter_methods = builder_resolver
        .config_fields
        .iter()
        .map(|(field_name, field_ty, _)| gen_builder_setter_method(field_name, field_ty));

    let default_values = builder_resolver
        .config_fields
        .iter()
        .filter_map(|(field_name, field_ty, default_expr)| {
            if let Some(default_expr) = default_expr {
                return Some((field_name, field_ty, default_expr));
            }

            None
        })
        .map(|(field_name, field_ty, default_expr)| {
            let const_value_ident = gen_default_value_ident(field_name);

            quote! {
                pub fn #const_value_ident() -> #field_ty {
                    #default_expr
                }
            }
        });

    let impl_builder_default = {
        let default_field_values =
            builder_resolver
                .config_fields
                .iter()
                .map(|(field_name, _, default_expr)| {
                    let const_value_ident = gen_default_value_ident(field_name);
                    default_expr.as_ref().map_or_else(
                        || quote! { #field_name: None },
                        |_| quote! { #field_name: Some(#parent_ident::#const_value_ident()) },
                    )
                });

        quote! {
            impl Default for #builder_ident {
                fn default() -> Self {
                    Self { #( #default_field_values ),* }
                }
            }
        }
    };

    let impl_parent_default = if !builder_resolver.has_required_fields() {
        let const_value_ident = field_names.iter().cloned().map(gen_default_value_ident);

        quote! {
            // TODO: Blocked by https://github.com/rust-lang/rust/issues/8995
            //impl #parent_ident {
                  /// Configuration Builder
            //    type Builder = #builder_ident;
            //}

            impl Default for #parent_ident {
                fn default() -> Self {
                    Self { #( #field_names: Self::#const_value_ident() ),* }
                }
            }
        }
    } else {
        quote!()
    };

    quote! {
        #impl_parent_default
        impl #parent_ident {
            #(#default_values)*
            #(#getter_methods)*
        }

        /// [`Configuration`] builder
        #[derive(
            Debug, Clone,
            serde::Deserialize, serde::Serialize,
            iroha_config_base::Documented,
        )]
        #[serde(default)]
        #builder

        #impl_builder_default
        impl #builder_ident {
            pub const fn new() -> Self {
                Self { #( #field_names: None ),* }
            }

            #( #builder_setter_methods )*

            /// Override [`Self`] with values from another [`Self`]
            pub fn override_with(&mut self, other: Self) -> &mut Self { #(
                if let Some(#field_names) = other.#field_names {
                    self.#field_names = Some(#field_names);
                }; )*

                self
            }

            /// Build [`Configuration`]
            ///
            /// # Errors
            ///
            /// - if missing required fields
            pub fn build(self) -> Result<#parent_ident, ::iroha_config_base::derive::Error> {
                let mut config = Self::default();
                config.override_with(self);

                Ok(#parent_ident { #(
                    #field_names: config.#field_names.ok_or(
                        ::iroha_config_base::derive::Error::MissingField(stringify!(#field_names))
                    )? ),*
                })
            }
        }

        impl From<#parent_ident> for #builder_ident {
            fn from(source: #parent_ident) -> Self {
                Self { #( #field_names: Some(source.#field_names) ),* }
            }
        }

        impl TryFrom<#builder_ident> for #parent_ident {
            type Error = iroha_config_base::derive::Error;

            fn try_from(source: #builder_ident) -> Result<Self, Self::Error> {
                source.build()
            }
        }
    }
}

struct BuilderResolver {
    /// field name + field type + default value expression
    config_fields: Vec<(syn::Ident, syn::Type, Option<syn::Expr>)>,
}
impl BuilderResolver {
    fn new() -> Self {
        Self {
            config_fields: Vec::new(),
        }
    }
    fn has_required_fields(&self) -> bool {
        self.config_fields
            .iter()
            .any(|(_, _, default_expr)| default_expr.is_none())
    }
}
impl VisitMut for BuilderResolver {
    fn visit_field_mut(&mut self, node: &mut syn::Field) {
        let field_ty = &node.ty;

        let field_name = node
            .ident
            .as_ref()
            .expect_or_abort("Tuple structs are not supported");

        self.config_fields.push((
            field_name.clone(),
            field_ty.clone(),
            parse_default_expr(&node.attrs),
        ));

        // TODO
        //node.attrs = node
        //    .attrs
        //    .drain(..)
        //    .filter(|attr| {
        //        if let Some(last_seg) = attr.path.segments.last() {
        //            if last_seg.ident == "serde" {
        //                return true;
        //            }
        //        }

        //        false
        //    })
        //    .map(|mut attr| {
        //        if let Some(last_seg) = attr.path.segments.last() {
        //            if last_seg.ident == "serde" {
        //                if let Ok(parse_res) = syn::Attribute::parse_meta(&attr) {
        //                    if let syn::Meta::NameValue(serde_val) = parse_res {
        //                        if let Some(path) = serde_val.path.segments.last() {
        //                            if path.ident == "deserialize_with" {
        //                                attr.tokens = quote!("builder_deserialize_with");
        //                            }
        //                        }
        //                    }
        //                }
        //            }
        //        }

        //        attr
        //    })
        //    .collect();

        node.ty = syn::parse_quote!(Option<#field_ty>);
    }

    fn visit_derive_input_mut(&mut self, node: &mut syn::DeriveInput) {
        node.ident = format_ident!("{}Builder", node.ident);

        node.attrs = Vec::new();
        if !matches!(node.data, syn::Data::Struct(_)) {
            abort!(node, "Configuration can only be a struct");
        };

        visit_derive_input_mut(self, node);
    }
}

fn parse_default_expr(attrs: &[syn::Attribute]) -> Option<syn::Expr> {
    let mut default_exprs = attrs
        .iter()
        .filter(|attr| attr.path.is_ident("config"))
        .filter_map(|attr| {
            if let Ok(syn::Meta::NameValue(name_value)) = attr.parse_args() {
                if name_value.path.is_ident("default") {
                    if let syn::Lit::Str(lit_str) = name_value.lit {
                        return Some(lit_str.parse().expect_or_abort("Expected expression"));
                    } else {
                        abort!(name_value.lit, "Exprected string");
                    }
                }
            }

            None
        });

    let default_expr: Option<syn::Expr> = default_exprs.next();
    if let Some(extra_default_value) = default_exprs.next() {
        abort!(extra_default_value, "Duplicated attribute");
    }

    default_expr
}

fn gen_default_value_ident(field_name: &syn::Ident) -> syn::Ident {
    format_ident!("DEFAULT_{}", field_name.to_string().to_uppercase())
}

fn gen_setter_method_ident(field_name: &syn::Ident) -> syn::Ident {
    format_ident!("set_{}", field_name)
}

fn gen_getter_method(field_name: &syn::Ident, field_ty: &syn::Type) -> TokenStream {
    quote! {
        /// Set the value of this field in the configuration
        pub const fn #field_name(&self) -> &#field_ty {
            &self.#field_name
        }
    }
}

fn gen_builder_setter_method(field_name: &syn::Ident, field_ty: &syn::Type) -> TokenStream {
    let setter_method_name = gen_setter_method_ident(field_name);

    quote! {
        /// Set the value of this field in the configuration
        pub const fn #setter_method_name(&mut self, val: #field_ty) -> &mut Self {
            self.#field_name = Some(val);
            self
        }
    }
}
