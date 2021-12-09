use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::{abort, proc_macro_error};
use quote::{quote, ToTokens};
use syn::{
    parse::Parse, parse_macro_input, punctuated::Punctuated, token::Comma, FnArg, ItemFn, LitStr,
    Path, Type,
};

fn type_has_metrics_field(ty: &Type) -> bool {
    match ty {
        // This may seem fragile, but it isn't. We use the same
        // convention everywhere in the code base, and if you follow
        // `CONTRIBUTING.md` you'll likely have `use
        // iroha_data_model::WorldStateView` somewhere.
        Type::Path(pth) => {
            let Path {
                leading_colon: _,
                segments,
            } = pth.path.clone();
            let type_name = &segments[0].ident;
            type_name.to_string() == "WorldStateView"
        }
        _ => false,
    }
}

/// The identifier of the first argument that has a type which has
/// metrics.
///
/// # Errors
/// If no argument has type which has a metrics field.
fn arg_metrics(input: &Punctuated<FnArg, Comma>) -> Result<syn::Ident, &Punctuated<FnArg, Comma>> {
    input
        .iter()
        .find(|arg| match arg {
            FnArg::Typed(typ) => match &*typ.ty {
                syn::Type::Reference(typ) => type_has_metrics_field(&typ.elem),
                _ => false,
            },
            _ => false,
        })
        .map_or(None, |arg| match arg {
            FnArg::Typed(typ) => match *typ.pat.clone() {
                syn::Pat::Ident(ident) => Some(ident.ident),
                _ => None,
            },
            _ => None,
        })
        .ok_or(input)
}

struct MetricSpecs(Vec<MetricSpec>); // `HashSet` — idiomatic; slow

impl Parse for MetricSpecs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let vars = Punctuated::<MetricSpec, Comma>::parse_terminated(input)?;
        Ok(Self(vars.into_iter().collect()))
    }
}

struct MetricSpec {
    timing: bool,
    metric_name: LitStr,
}

impl Parse for MetricSpec {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let timing = <syn::Token![+]>::parse(input).is_ok();
        let metric_name_lit = syn::Lit::parse(input.clone())?;
        let metric_name = match metric_name_lit {
            syn::Lit::Str(lit_str) => lit_str,
            _ => {
                return Err(syn::Error::new(
                    proc_macro2::Span::call_site(),
                    "Must be a string literal. Format `[+]\"name_of_metric\"`.",
                ))
            }
        };
        Ok(Self {
            metric_name,
            timing,
        })
    }
}

impl ToTokens for MetricSpec {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.metric_name.to_tokens(tokens)
    }
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn metrics(attr: TokenStream, item: TokenStream) -> TokenStream {
    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    }: ItemFn = parse_macro_input!(item as ItemFn);

    // This is a good sanity check. Possibly redundant.
    if sig.ident.to_string() != "execute" {
        abort!(sig.ident, "Function should be an `impl execute`");
    }
    match sig.output.clone() {
        syn::ReturnType::Default => abort!(
            sig.output,
            "`Fn` must return `Result`. Returns nothing instead. "
        ),
        syn::ReturnType::Type(_, typ) => match *typ {
            Type::Path(pth) => {
                let Path {
                    leading_colon: _,
                    segments,
                } = pth.path;
                let type_name = &segments[0].ident;
                if type_name.to_string() != "Result" {
                    abort!(
                        type_name,
                        format!("Should return `Result`. Found {}", type_name)
                    );
                }
            }
            _ => abort!(
                typ,
                "Should return `Result`. Non-path result type specification found"
            ),
        },
    }
    if sig.inputs.is_empty() {
        abort!(
            sig,
            "Function must have at least one argument of type `WorldStateView`."
        );
    }
    let specs = parse_macro_input!(attr as MetricSpecs);
    let metric_arg_ident = arg_metrics(&sig.inputs)
        .unwrap_or_else(|args| abort!(args, "At least one argument must contain a metrics field"));
    // Again this may seem fragile, but if we move the metrics from
    // the `WorldStateView`, we'd need to refactor many things anyway.
    let inc_metric = |spec: &MetricSpec, kind: &str| {
        quote!(
            #metric_arg_ident
                .metrics
                .isi
                .with_label_values( &[#spec, #kind ]).inc();
        )
    };
    // I agree that casting this to `f64` is not the best
    // idea. However, 1) Prometheus doesn't record more precise data
    // anyway, 2) if the time to handle requests is a sufficiently
    // large `u128` that it **cannot** be a represented as `f64` then
    // we have bigger problems than imprecise metrics. 3) This is way
    // shorter.
    let track_time = |spec: &MetricSpec| {
        quote!(
            #metric_arg_ident
                .metrics
                .isi_times
                .with_label_values( &[#spec])
                .observe((end_time.as_millis() - start_time.as_millis()) as f64);
        )
    };
    let totals: TokenStream2 = specs
        .0
        .iter()
        .map(|spec| inc_metric(spec, "total"))
        .collect();
    let successes: TokenStream2 = specs
        .0
        .iter()
        .map(|spec| inc_metric(spec, "success"))
        .collect();
    let times: TokenStream2 = specs
        .0
        .iter()
        .filter(|spec| spec.timing)
        .map(track_time)
        .collect();

    quote!(
        #(#attrs)* #vis #sig {
            let _closure = || #block;

            let start_time = #metric_arg_ident.metrics.current_time();
            #totals
            let res = _closure();
            let end_time = #metric_arg_ident.metrics.current_time();
            #times
            if let Ok(_) = res {
                #successes
            };
            res
        }
    )
    .into()
}
