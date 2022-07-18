use super::*;

#[test]
fn add_register_domains_permission_denies_registering_domain() {
    let alice_id = AccountId::from_str("alice@test0").expect("Valid");

    let instruction = Instruction::Register(RegisterBox::new(Domain::new(
        "new_domain".parse().expect("Valid"),
    )));

    let wsv = WorldStateView::new(World::new());

    assert!(register::ProhibitRegisterDomains
        .check(&alice_id, &instruction, &wsv)
        .is_deny());
}

#[test]
fn add_register_domains_permission_allows_registering_account() {
    let alice_id = AccountId::from_str("alice@test0").expect("Valid");

    let instruction = Instruction::Register(RegisterBox::new(Account::new(
        "bob@test".parse().expect("Valid"),
        [],
    )));

    let wsv = WorldStateView::new(World::new());

    assert!(register::ProhibitRegisterDomains
        .check(&alice_id, &instruction, &wsv)
        .is_allow());
}

#[test]
fn add_register_domains_permission_allows_registering_domain_with_right_token() {
    let alice_id = AccountId::from_str("alice@test0").expect("Valid");

    let mut alice = Account::new(alice_id.clone(), []).build();
    alice.add_permission(register::CanRegisterDomains::new().into());

    let bob_id = AccountId::from_str("bob@test0").expect("Valid");
    let bob = Account::new(bob_id.clone(), []).build();

    let domain_id = DomainId::from_str("test0").expect("Valid");
    let mut domain = Domain::new(domain_id).build();
    domain.add_account(alice.clone());
    domain.add_account(bob);

    let wsv = WorldStateView::new(World::with([domain], Vec::new()));

    let validator = register::GrantedAllowedRegisterDomains.into_validator();

    let op = Instruction::Register(RegisterBox::new(Domain::new(
        "newdomain".parse().expect("Valid"),
    )));

    assert!(validator.check(&alice_id, &op, &wsv).is_allow());
    assert!(validator.check(&bob_id, &op, &wsv).is_deny());
}

#[test]
fn add_register_domains_permission_denies_registering_domain_with_wrong_token() {
    let alice_id = AccountId::from_str("alice@test0").expect("Valid");

    let mut alice = Account::new(alice_id.clone(), []).build();
    alice.add_permission(PermissionToken::new(
        Name::from_str("incorrecttoken").expect("Valid"),
    ));

    let domain_id = DomainId::from_str("test0").expect("Valid");
    let mut domain = Domain::new(domain_id).build();
    domain.add_account(alice.clone());

    let wsv = WorldStateView::new(World::with([domain], Vec::new()));

    let validator = register::GrantedAllowedRegisterDomains.into_validator();

    let op = Instruction::Register(RegisterBox::new(Domain::new(
        "newdomain".parse().expect("Valid"),
    )));

    assert!(validator.check(&alice_id, &op, &wsv).is_deny());
}
