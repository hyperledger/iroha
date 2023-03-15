//! Validation and tokens related to peer operations.

use super::*;

tokens!(
    pattern = {
        #[derive(Token, ValidateGrantRevoke)]
        #[validate(pass_conditions::OnlyGenesis)]
        pub struct _ {}
    },
    peer::tokens: [
        CanUnregisterAnyPeer,
    ]
);

impl DefaultValidate for Register<Peer> {
    fn default_validate<Q>(
        &self,
        _authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        pass!()
    }
}

// TODO: Need to allow peer to unregister it-self somehow
impl DefaultValidate for Unregister<Peer> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        pass_if!(tokens::CanUnregisterAnyPeer {}.is_owned_by(authority));
        deny!("Can't unregister peer")
    }
}
