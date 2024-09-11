//! Attribute-like macro for instrumenting `isi` for `prometheus`
//! metrics. See [`macro@metrics`] for more details.

use iroha_macro_utils::Emitter;
use manyhow::{emit, manyhow, Result};
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse::Parse, punctuated::Punctuated, token::Comma, FnArg, LitStr, Path, Type};

// TODO: export these as soon as proc-macro crates are able to export
// anything other than proc-macros.
#[cfg(feature = "metric-instrumentation")]
const TOTAL_STR: &str = "total";
#[cfg(feature = "metric-instrumentation")]
const SUCCESS_STR: &str = "success";

fn type_has_metrics_field(ty: &Type) -> bool {
    match ty {
        // This may seem fragile, but it isn't. We use the same convention
        // everywhere in the code base, and if you follow `CONTRIBUTING.md`
        // you'll likely have `use iroha_core::{StateTransaction, StateSnapshot}`
        // somewhere. If you don't, you're violating the `CONTRIBUTING.md` in
        // more than one way.
        Type::Path(pth) => {
            let Path { segments, .. } = pth.path.clone();
            let type_name = &segments
                .last()
                .expect("Should have at least one segment")
                .ident;
            *type_name == "StateTransaction"
        }
        Type::ImplTrait(impl_trait) => impl_trait.bounds.iter().any(|bounds| match bounds {
            syn::TypeParamBound::Trait(trt) => {
                let Path { segments, .. } = trt.path.clone();
                let type_name = &segments
                    .last()
                    .expect("Should have at least one segment")
                    .ident;
                *type_name == "StateReadOnly"
            }
            _ => false,
        }),
        _ => false,
    }
}

/// The identifier of the first argument that has a type which has
/// metrics.
///
/// # Errors
/// If no argument is of type `StateTransaction` of `StateSnapshot`.
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
        .and_then(|arg| match arg {
            FnArg::Typed(typ) => match *typ.pat.clone() {
                syn::Pat::Ident(ident) => Some(ident.ident),
                _ => None,
            },
            _ => None,
        })
        .ok_or(input)
}

struct MetricSpecs(#[allow(dead_code)] Vec<MetricSpec>); // `HashSet` — idiomatic; slow

impl Parse for MetricSpecs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let vars = Punctuated::<MetricSpec, Comma>::parse_terminated(input)?;
        Ok(Self(vars.into_iter().collect()))
    }
}

struct MetricSpec {
    #[cfg(feature = "metric-instrumentation")]
    timing: bool,
    metric_name: LitStr,
}

impl Parse for MetricSpec {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let _timing = <syn::Token![+]>::parse(input).is_ok();
        let metric_name_lit = syn::Lit::parse(input)?;

        let metric_name = match metric_name_lit {
            syn::Lit::Str(lit_str) => {
                if lit_str.value().contains(' ') {
                    return Err(syn::Error::new(
                        proc_macro2::Span::call_site(),
                        "Spaces are not allowed. Use underscores '_'",
                    ));
                };
                lit_str
            }
            _ => {
                return Err(syn::Error::new(
                    proc_macro2::Span::call_site(),
                    "Must be a string literal. Format `[+]\"name_of_metric\"`.",
                ))
            }
        };
        Ok(Self {
            metric_name,
            #[cfg(feature = "metric-instrumentation")]
            timing: _timing,
        })
    }
}

impl ToTokens for MetricSpec {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.metric_name.to_tokens(tokens);
    }
}

/// Macro for instrumenting an `isi`'s `impl execute` to track a given
/// metric.  To specify a metric, put it as an attribute parameter
/// inside quotes.

/// This will increment the `prometheus::IntVec` metric
/// corresponding to the literal provided in quotes, with the second
/// argument being `TOTAL_STR == "total"`. If the execution of the
/// `Fn`'s body doesn't result in an [`Err`] variant, another metric
/// with the same first argument and `SUCCESS_STR = "success"` is also
/// incremented. Thus one can infer the number of rejected
/// transactions based on this parameter. If necessary, this macro
/// should be edited to record different [`Err`] variants as different
/// rejections, so we could (in theory), record the number of
/// transactions that got rejected because of
/// e.g. `SignatureCondition` failure.
///
/// If you also want to track the execution time of the `isi`, you
/// should prefix the quoted metric with the `+` symbol.
///
/// # Examples
///
/// ```rust
/// use iroha_core::state::{StateTransaction, World};
/// use iroha_telemetry_derive::metrics;
///
/// #[metrics(+"test_query", "another_test_query_without_timing")]
/// fn execute(state: &StateTransaction) -> Result<(), ()> {
///     Ok(())
/// }
/// ```
#[manyhow]
#[proc_macro_attribute]
pub fn metrics(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    let Some(func): Option<syn::ItemFn> = emitter.handle(syn::parse2(item)) else {
        return emitter.finish_token_stream();
    };

    // This is a good sanity check. Possibly redundant.
    if func.sig.ident != "execute" {
        emit!(
            emitter,
            func.sig.ident,
            "Function should be an `impl execute`"
        );
    }

    if func.sig.inputs.is_empty() {
        emit!(
            emitter,
            func.sig,
            "Function must have at least one argument of type `StateTransaction` or `StateReadOnly`."
        );
        return emitter.finish_token_stream();
    }

    let Some(metric_specs): Option<MetricSpecs> = emitter.handle(syn::parse2(attr)) else {
        return emitter.finish_token_stream();
    };

    let result = impl_metrics(&mut emitter, &metric_specs, &func);

    emitter.finish_token_stream_with(result)
}

fn impl_metrics(emitter: &mut Emitter, _specs: &MetricSpecs, func: &syn::ItemFn) -> TokenStream {
    let syn::ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = func;

    match sig.output.clone() {
        syn::ReturnType::Default => emit!(
            emitter,
            sig.output,
            "`Fn` must return `Result`. Returns nothing instead. "
        ),
        #[allow(clippy::string_to_string)]
        syn::ReturnType::Type(_, typ) => match *typ {
            Type::Path(pth) => {
                let Path { segments, .. } = pth.path;
                let type_name = &segments.last().expect("non-empty path").ident;
                if *type_name != "Result" {
                    emit!(
                        emitter,
                        type_name,
                        "Should return `Result`. Found {}",
                        type_name
                    );
                }
            }
            _ => emit!(
                emitter,
                typ,
                "Should return `Result`. Non-path result type specification found"
            ),
        },
    }

    // Again this may seem fragile, but if we move the metrics from
    // the `WorldStateView`, we'd need to refactor many things anyway
    let _metric_arg_ident = match arg_metrics(&sig.inputs) {
        Ok(ident) => ident,
        Err(args) => {
            emit!(
                emitter,
                args,
                "At least one argument must be a `StateTransaction` or `StateReadOnly`."
            );
            return quote!();
        }
    };

    #[cfg(feature = "metric-instrumentation")]
    let res = {
        let (totals, successes, times) = write_metrics(_metric_arg_ident, _specs);
        quote!(
            #(#attrs)* #vis #sig {
                let _closure = || #block;
                let started_at = std::time::Instant::now();

                #totals
                let res = _closure();

                #times
                if let Ok(_) = res {
                    #successes
                };
                res
        });
    };

    #[cfg(not(feature = "metric-instrumentation"))]
    let res = quote!(
        #(#attrs)* #vis #sig {
            #block
        }
    );
    res
}

#[cfg(feature = "metric-instrumentation")]
fn write_metrics(
    metric_arg_ident: proc_macro2::Ident,
    specs: MetricSpecs,
) -> (TokenStream, TokenStream, TokenStream) {
    let inc_metric = |spec: &MetricSpec, kind: &str| {
        quote!(
            #metric_arg_ident
                .metrics
                .isi
                .with_label_values( &[#spec, #kind ]).inc();
        )
    };
    let track_time = |spec: &MetricSpec| {
        quote!(
            #metric_arg_ident
                .metrics
                .isi_times
                .with_label_values( &[#spec])
                .observe(started_at.elapsed().as_millis() as f64);
        )
    };
    let totals: TokenStream = specs
        .0
        .iter()
        .map(|spec| inc_metric(spec, "total"))
        .collect();
    let successes: TokenStream = specs
        .0
        .iter()
        .map(|spec| inc_metric(spec, "success"))
        .collect();
    let times: TokenStream = specs
        .0
        .iter()
        .filter(|spec| spec.timing)
        .map(track_time)
        .collect();
    (totals, successes, times)
}
