//! Crate with various derive macros

#![allow(clippy::restriction)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse, parse_macro_input, parse_quote, punctuated::Punctuated, Ident, ItemTrait, Type, TypePath,
};

/// Attribute for skipping from attribute
const SKIP_FROM_ATTR: &str = "skip_from";
const SKIP_TRY_FROM_ATTR: &str = "skip_try_from";

/// [`FromVariant`] is used for implementing `From<Variant> for Enum` and `TryFrom<Enum> for Variant`.
///
/// ```rust
/// use iroha_derive::FromVariant;
///
/// #[derive(FromVariant)]
/// enum Obj {
///     Uint(u32),
///     Int(i32),
///     String(String),
///     // You can also skip implementing `From`
///     Vec(#[skip_from] Vec<Obj>),
/// }
///
/// // For example for avoid cases like this:
/// impl<T: Into<Obj>> From<Vec<T>> for Obj {
///     fn from(vec: Vec<T>) -> Self {
///         # stringify!(
///         ...
///         # );
///         # todo!()
///     }
/// }
/// ```
#[proc_macro_derive(FromVariant, attributes(skip_from, skip_try_from))]
pub fn from_variant_derive(input: TokenStream) -> TokenStream {
    let ast = parse(input).expect("Failed to parse input Token Stream.");
    impl_from_variant(&ast)
}

fn attrs_have_ident(attrs: &[syn::Attribute], ident: &str) -> bool {
    attrs.iter().any(|attr| attr.path.is_ident(ident))
}

const CONTAINERS: &[&str] = &["Box", "RefCell", "Cell", "Rc", "Arc", "Mutex", "RwLock"];

fn get_type_argument<'a, 'b>(s: &'a str, ty: &'b TypePath) -> Option<&'b syn::GenericArgument> {
    let segments = &ty.path.segments;
    if segments.len() != 1 || segments[0].ident != s {
        return None;
    }

    if let syn::PathArguments::AngleBracketed(ref bracketed_arguments) = segments[0].arguments {
        assert_eq!(bracketed_arguments.args.len(), 1);
        Some(&bracketed_arguments.args[0])
    } else {
        unreachable!("No other arguments for types in enum variants possible")
    }
}

fn from_container_variant_internal(
    into_ty: &Ident,
    into_variant: &Ident,
    from_ty: &syn::GenericArgument,
    container_ty: &TypePath,
) -> proc_macro2::TokenStream {
    quote! {
        impl From<#from_ty> for #into_ty {
            fn from(origin: #from_ty) -> Self {
                #into_ty :: #into_variant (#container_ty :: new(origin))
            }
        }
    }
}

fn from_variant_internal(
    into_ty: &Ident,
    into_variant: &Ident,
    from_ty: &Type,
) -> proc_macro2::TokenStream {
    quote! {
        impl From<#from_ty> for #into_ty {
            fn from(origin: #from_ty) -> Self {
                #into_ty :: #into_variant (origin)
            }
        }
    }
}

fn from_variant(into_ty: &Ident, into_variant: &Ident, from_ty: &Type) -> proc_macro2::TokenStream {
    let from_orig = from_variant_internal(into_ty, into_variant, from_ty);

    if let Type::Path(path) = from_ty {
        let mut code = from_orig;

        for container in CONTAINERS {
            if let Some(inner) = get_type_argument(container, path) {
                let segments = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| {
                        let mut segment = segment.clone();
                        segment.arguments = syn::PathArguments::default();
                        segment
                    })
                    .collect::<Punctuated<_, syn::token::Colon2>>();
                let path = syn::Path {
                    segments,
                    leading_colon: None,
                };
                let path = &TypePath { path, qself: None };

                let from_inner =
                    from_container_variant_internal(into_ty, into_variant, inner, path);
                code = quote! {
                    #code
                    #from_inner
                };
            }
        }

        return code;
    }

    from_orig
}

fn try_into_variant(
    enum_ty: &Ident,
    variant: &Ident,
    variant_ty: &Type,
) -> proc_macro2::TokenStream {
    quote! {
        impl TryFrom<#enum_ty> for #variant_ty {
            type Error = iroha_macro::error::ErrorTryFromEnum<#enum_ty, Self>;

            fn try_from(origin: #enum_ty) -> core::result::Result<Self, iroha_macro::error::ErrorTryFromEnum<#enum_ty, Self>> {
                if let #enum_ty :: #variant(variant) = origin {
                    Ok(variant)
                } else {
                    Err(iroha_macro::error::ErrorTryFromEnum::default())
                }
            }
        }
    }
}

fn impl_from_variant(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let froms = if let syn::Data::Enum(data_enum) = &ast.data {
        &data_enum.variants
    } else {
        panic!("Only enums are supported")
    }
    .iter()
    .filter_map(|variant| {
        if let syn::Fields::Unnamed(ref unnamed) = variant.fields {
            if unnamed.unnamed.len() == 1 {
                let variant_type = &unnamed
                    .unnamed
                    .first()
                    .expect("Won't fail as we have more than one argument for variant")
                    .ty;

                let try_into = if attrs_have_ident(&unnamed.unnamed[0].attrs, SKIP_TRY_FROM_ATTR) {
                    quote!()
                } else {
                    try_into_variant(name, &variant.ident, variant_type)
                };
                let from = if attrs_have_ident(&unnamed.unnamed[0].attrs, SKIP_FROM_ATTR) {
                    quote!()
                } else {
                    from_variant(name, &variant.ident, variant_type)
                };

                return Some(quote!(
                    #try_into
                    #from
                ));
            }
        }
        None
    });

    let gen = quote! {
        #(#froms)*
    };
    gen.into()
}

struct TypedAnyVariants(Vec<Type>);
impl parse::Parse for TypedAnyVariants {
    fn parse(input: parse::ParseStream) -> syn::Result<Self> {
        Ok(Self(
            Punctuated::<_, syn::token::Comma>::parse_terminated(input)?
                .into_iter()
                .collect(),
        ))
    }
}

fn get_trait_object_private_module_name(trait_name: &Ident) -> Ident {
    Ident::new(
        &format!("_typed_any_{}", trait_name.to_string().to_lowercase()),
        proc_macro2::Span::call_site(),
    )
}

// TODO: Maybe allow lifetime parameters?
fn check_trait_is_valid(trait_definition: &ItemTrait) {
    if !trait_definition.generics.params.is_empty() {
        panic!("Parametrized traits are not supported");
    }
}

/// Adds methods for downcasting trait object to types implementing this trait.
///
/// # Example:
///
/// ```
/// struct Foo;
/// struct Bar<T>(T);
///
/// #[typed_any(
///   Foo,
///   Bar<i32>,
/// )]
/// trait Trait1 {}
///
/// #[typed_any(
///   Foo,
///   impl<T> Trait2 for Bar<T> {},
/// )]
/// trait Trait2 {}
///
/// impl Trait1 for Foo {}
/// impl Trait1 for Bar<i32> {}
///
/// impl Trait2 for Foo {}
/// impl<T: 'static> Trait2 for Bar<T> {}
///
/// fn fun() {
///     let mut foo1: Box<dyn Trait1> = Box::new(Foo);
///
///     let bar1: &dyn Trait1 = &Bar(24i32);
///     let bar2: &dyn Trait2 = &Bar(24i32);
///
///     // This produces an error because i32 doesn't implement `Trait1`
///     // foo.downcast_ref::<i32>();
///
///     let foo_ref = foo1.downcast_ref::<Foo>();
///     let foo_mut = foo1.downcast_mut::<Foo>();
///     let foo = foo1.downcast::<Foo>();
/// }
/// ```
#[proc_macro_attribute]
pub fn typed_any(args: TokenStream, input: TokenStream) -> TokenStream {
    let mut trait_definition: ItemTrait = parse_macro_input!(input);

    let TypedAnyVariants(variants) = parse_macro_input!(args);

    check_trait_is_valid(&trait_definition);
    let trait_name = &trait_definition.ident;
    let type_ids = 0..variants.len() as u64;

    let trait_object_private_module_name = get_trait_object_private_module_name(trait_name);
    trait_definition.supertraits.push(
        parse_quote!(iroha_macro::typed_any::TypedAny<#trait_object_private_module_name::#trait_name>),
    );

    quote! {
        #trait_definition

        mod #trait_object_private_module_name {
            mod private {
                /// Prevents implementing the marker trait `#trait_object_private_module_name::#trait_name`
                pub trait Sealed {}
            }

            // NOTE: Usually it would make sense to use enum, not a trait, as a marker type.
            // However, parametrizing with dyn trait represent the actual intent which was
            // to parametrize `TypedAny` with a trait object type of the trait on which it
            // was implemented. This wasn't possible due to cycle in the supertrait predicate
            pub trait #trait_name {}

            impl iroha_macro::typed_any::TraitObject for dyn #trait_name {}
        }

        impl iroha_macro::typed_any::TraitObject for dyn #trait_name {}

        impl dyn #trait_name {
            /// Returns reference to the inner value
            #[inline]
            pub fn downcast_ref<T: #trait_name + 'static>(&self) -> Option<&T> {
                self.as_any().downcast_ref::<T>()
            }

            /// Returns mutable reference to the inner value
            #[inline]
            pub fn downcast_mut<T: #trait_name + 'static>(&mut self) -> Option<&mut T> {
                self.as_any_mut().downcast_mut::<T>()
            }

            /// Downcast the box to a concrete type.
            #[inline]
            // TODO: Fix this method
            pub fn downcast<T>(self: Box<Self>) -> Result<Box<T>, Box<dyn core::any::Any + 'static>>
            where
                T: #trait_name + 'static
            {
                self.into_any().downcast::<T>()
            }
        }

        #(
        unsafe impl iroha_macro::typed_any::TypedAnyVariant<#trait_object_private_module_name::#trait_name> for #variants {
            const ID: iroha_macro::typed_any::TypeId = iroha_macro::typed_any::TypeId(#type_ids);
        }
        )*
    }
    .into()
}

/// Implements `parity_scale_codec::Encode` on a trait object of this trait
///
/// # Panics
///
/// If trait object has more than 256 variants
///
/// # Example:
///
/// ```
/// use parity_scale_codec::{Decode, Encode};
///
/// #[derive(Decode, Encode)]
/// struct Foo;
///
/// #[typed_any_decode]
/// #[typed_any_encode]
/// #[typed_any(Foo)]
/// trait Trait {}
///
/// impl Trait for Foo {}
///
/// fn fun() {
///     let foo: &dyn Trait = &Foo;
///
///     let bytes = foo.encode();
///     let foo: Box<dyn Trait> = Decode::decode(&mut &bytes[..]).unwrap();
/// ```
#[proc_macro_attribute]
pub fn typed_any_encode(_args: TokenStream, input: TokenStream) -> TokenStream {
    let any_downcast_error_message = "Unable to downcast - trait object not of the required type. This\
                                      is a bug. If you implemented this functionality without using the\
                                      `iroha_macro::typed_any` macro, revise your implementation";

    let trait_definition: ItemTrait = parse_macro_input!(input);
    let variants = get_codec_variants(&trait_definition.attrs);
    let trait_name = &trait_definition.ident;

    let trait_object_private_module_name = get_trait_object_private_module_name(trait_name);

    if variants.len() > u8::MAX as usize {
        panic!("Parity scale codec doesn't dupport more than 256 variants");
    }

    quote! {
        #trait_definition

        impl parity_scale_codec::Encode for dyn #trait_name {
            fn size_hint(&self) -> usize {
                1 + match self.type_id() { #(
                    <#variants as iroha_macro::typed_any::TypedAnyVariant<#trait_object_private_module_name::#trait_name>>::ID => {
                        <#variants as parity_scale_codec::Encode>::size_hint(
                            self.downcast_ref::<#variants>().expect(#any_downcast_error_message)
                        )
                    }, )*
                    _ => panic!("{}", #any_downcast_error_message),
                }
            }

            fn encode_to<W: parity_scale_codec::Output + ?Sized>(&self, dest: &mut W) {
                match self.type_id() { #(
                    <#variants as iroha_macro::typed_any::TypedAnyVariant<#trait_object_private_module_name::#trait_name>>::ID => {
                        dest.push_byte(<#variants as iroha_macro::typed_any::TypedAnyVariant<#trait_object_private_module_name::#trait_name>>::ID.0 as u8);
                        <#variants as Encode>::encode_to(
                            self.downcast_ref::<#variants>().expect(#any_downcast_error_message),
                            dest
                        );
                    } )*
                    _ => panic!("{}", #any_downcast_error_message)
                };
            }
        }
    }.into()
}

/// Implements `parity_scale_codec::Decode` on a trait object of this trait
///
/// # Panics
///
/// If trait object id cannot be matched against the implementors of the trait
///
/// # Example:
///
/// ```
/// use parity_scale_codec::{Decode, Encode};
///
/// #[derive(Decode, Encode)]
/// struct Foo;
///
/// #[typed_any_decode]
/// #[typed_any_encode]
/// #[typed_any(Foo)]
/// trait Trait {}
///
/// impl Trait for Foo {}
///
/// fn fun() {
///     let foo: &dyn Trait = &Foo;
///
///     let bytes = foo.encode();
///     let foo: Box<dyn Trait> = Decode::decode(&mut &bytes[..]).unwrap();
/// ```
#[proc_macro_attribute]
pub fn typed_any_decode(_args: TokenStream, input: TokenStream) -> TokenStream {
    let unsupported_any_variant_message: &str = "Trait object variant not supported.";

    let trait_definition: ItemTrait = parse_macro_input!(input);
    let variants = get_codec_variants(&trait_definition.attrs);
    let trait_name = &trait_definition.ident;

    let trait_object_private_module_name = get_trait_object_private_module_name(trait_name);

    quote! {
        #trait_definition

        impl parity_scale_codec::Decode for Box<dyn #trait_name> {
            fn decode<I: parity_scale_codec::Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
                let type_id = input.read_byte().map_err(|e| e.chain("Could not read trait object variant id"))? as u64;

                match iroha_macro::typed_any::TypeId(type_id) { #(
                    <#variants as iroha_macro::typed_any::TypedAnyVariant<#trait_object_private_module_name::#trait_name>>::ID => Ok(
                        Box::new(<#variants as parity_scale_codec::Decode>::decode(input)?)
                    ), )*
                    _ => Err(
                        parity_scale_codec::Error::from(
                            #unsupported_any_variant_message
                        ).chain(format!("Variant id: {}", type_id))
                    ),
                }
            }
        }
    }.into()
}

fn get_codec_variants(trait_definition: &[syn::Attribute]) -> Vec<Type> {
    trait_definition
        .iter()
        .find_map(|attr| {
            if let Some(attr_name) = attr.path.segments.last() {
                if attr_name.ident == "typed_any" {
                    // This cannot fail bcause `typed_any` is a prerequisite
                    let TypedAnyVariants(variants) = attr.parse_args().unwrap();
                    return Some(variants);
                }
            }

            None
        })
        .expect("Couldn't fnd `typed_any` attribute. Did you add the attribute under this one?")
}
