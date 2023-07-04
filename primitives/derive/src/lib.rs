mod socket;

#[proc_macro]
pub fn socket(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    socket::socket_impl(input.into()).into()
}
