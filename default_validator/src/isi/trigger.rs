//! Validation and tokens related to trigger operations

use iroha_validator::pass_conditions::PassCondition;

use super::*;

struct Owner<'trigger> {
    trigger_id: &'trigger <Trigger<FilterBox, Executable> as Identifiable>::Id,
}

impl PassCondition for Owner<'_> {
    fn validate(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
        pass_if!(is_trigger_owner(self.trigger_id.clone(), authority));
        deny!("Can't give permission to access trigger owned by another account")
    }
}

macro_rules! impl_froms {
    ($($name:path),+ $(,)?) => {$(
        impl<'token> From<&'token $name> for Owner<'token> {
            fn from(value: &'token $name) -> Self {
                Self {
                    trigger_id: &value.trigger_id,
                }
            }
        }
    )+};
}

tokens!(
    pattern = {
        #[derive(Token, Clone, ValidateGrantRevoke)]
        #[validate(Owner)]
        pub struct _ {
            pub trigger_id: <Trigger<FilterBox, Executable> as Identifiable>::Id,
        }
    },
    trigger::tokens: [
        CanExecuteUserTrigger,
        CanUnregisterUserTrigger,
        CanMintUserTrigger,
    ]
);

impl_froms!(
    tokens::CanExecuteUserTrigger,
    tokens::CanUnregisterUserTrigger,
    tokens::CanMintUserTrigger,
);

impl DefaultValidate for Unregister<Trigger<FilterBox, Executable>> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let trigger_id = self.object_id().clone();

        pass_if!(is_trigger_owner(trigger_id.clone(), authority));
        pass_if!(tokens::CanUnregisterUserTrigger { trigger_id }.is_owned_by(authority));

        deny!("Can't unregister trigger owned by another account")
    }
}

impl DefaultValidate for Register<Trigger<FilterBox, Executable>> {
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

impl DefaultValidate for Mint<Trigger<FilterBox, Executable>, u32> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        let trigger_id = self.destination_id().clone();

        pass_if!(is_trigger_owner(trigger_id.clone(), authority));
        pass_if!(tokens::CanMintUserTrigger { trigger_id }.is_owned_by(authority));

        deny!("Can't mint execution count for trigger owned by another account")
    }
}

pub fn validate_execution(
    trigger_id: <Trigger<FilterBox, Executable> as Identifiable>::Id,
    authority: &<Account as Identifiable>::Id,
) -> Verdict {
    pass_if!(tokens::CanExecuteUserTrigger {
        trigger_id: trigger_id.clone()
    }
    .is_owned_by(authority));

    pass_if!(is_trigger_owner(trigger_id, authority));

    deny!("Can't execute trigger owned by another account")
}

fn is_trigger_owner(
    trigger_id: <Trigger<FilterBox, Executable> as Identifiable>::Id,
    authority: &<Account as Identifiable>::Id,
) -> bool {
    let query_value = QueryBox::from(FindTriggerById::new(trigger_id)).execute();
    let Value::Identifiable(IdentifiableBox::Trigger(TriggerBox::Optimized(trigger))) = query_value else {
        dbg_panic("`FindTriggerById` should always return `Trigger`");
    };

    trigger.action().technical_account() == authority
}
