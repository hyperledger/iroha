// FIXME: `get_key_from_white_rabbit` is an oddly specific name that we never see in Iroha code
// #region get_key_from
let key: PublicKey = get_key_from_white_rabbit();
// #endregion get_key_from

// #region create_account
let create_account =
    RegisterBox::new(IdentifiableBox::from(NewAccount::with_signatory(id, key)));
// #endregion create_account
