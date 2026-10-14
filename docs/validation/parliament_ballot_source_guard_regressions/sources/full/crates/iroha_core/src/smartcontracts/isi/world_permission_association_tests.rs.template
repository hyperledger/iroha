// Unregister-cleanup association matrix carried over from the retired Rust executor SDK suite.
// Core owns these predicates: a scoped permission is removed with exactly the account, domain
// or definition it names, and never with an unrelated one.
mod permission_association_tests {
    use iroha_crypto::{Hash, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        asset::{AssetDefinitionId, AssetId},
        nexus::FeeSponsorProgramId,
        permission::Permission,
    };
    use iroha_executor_data_model::permission::{
        account::{
            AccountAliasPermissionScope, CanDelegateAccountAliasResolution, CanManageAccountAlias,
            CanResolveAccountAlias,
        },
        asset::CanMintAssetWithDefinition,
        asset_definition::{AssetDefinitionAliasPermissionScope, CanManageAssetDefinitionAlias},
        nexus::{
            CanEnrollFeeSponsorProgram, CanManageFeeSponsorProgram,
            CanPublishSpaceDirectoryManifestForAccountDomain,
        },
        settlement::CanExecuteSettlement,
    };
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
    use std::collections::BTreeSet;

    fn account() -> AccountId {
        AccountId::new(
            KeyPair::try_random()
                .expect("test fixture random key generation should succeed")
                .public_key()
                .clone(),
        )
    }

    fn domain(name: &str, dataspace: &str) -> DomainId {
        DomainId::try_new(name, dataspace).expect("fixture domain")
    }

    fn definition(domain: DomainId, name: &str) -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(domain, name.parse().expect("asset name"))
    }

    fn domain_associated(
        permission: &Permission,
        domain: &DomainId,
        definitions: &[AssetDefinitionId],
    ) -> bool {
        let definitions = definitions.iter().cloned().collect::<BTreeSet<_>>();
        super::super::is_permission_domain_associated(permission, domain, &definitions, None)
    }

    fn account_associated(permission: &Permission, account: &AccountId) -> bool {
        crate::smartcontracts::isi::domain::isi::is_permission_account_associated(
            permission, account,
        )
    }

    #[test]
    fn fee_sponsor_and_settlement_permissions_follow_their_exact_accounts() {
        let sponsor = account();
        let debited = account();
        let settlement_owner = account();
        let unrelated = account();
        let settlement_domain = domain("settlement", "universal");
        let other_domain = domain("other", "universal");
        let cash = definition(settlement_domain.clone(), "cash");
        let program_id = FeeSponsorProgramId::new(
            sponsor.clone(),
            "retail".parse().expect("fee sponsor program name"),
        );
        for permission in [
            Permission::from(CanManageFeeSponsorProgram {
                sponsor: sponsor.clone(),
            }),
            Permission::from(CanEnrollFeeSponsorProgram { program_id }),
        ] {
            assert!(account_associated(&permission, &sponsor));
            assert!(!account_associated(&permission, &unrelated));
            assert!(!domain_associated(&permission, &settlement_domain, &[]));
            assert!(!domain_associated(
                &permission,
                &settlement_domain,
                core::slice::from_ref(&cash)
            ));
        }
        let consent = Permission::from(CanExecuteSettlement {
            debited_asset: AssetId::new(cash.clone(), debited.clone()),
            settlement_id: iroha_data_model::isi::SettlementId::new(
                settlement_owner.clone(),
                "cleanup_consent".parse().expect("settlement reference"),
            ),
            intent_hash: Hash::new(b"cleanup-bound settlement consent"),
        });
        assert!(account_associated(&consent, &debited));
        assert!(account_associated(&consent, &settlement_owner));
        assert!(!account_associated(&consent, &unrelated));
        assert!(domain_associated(
            &consent,
            &settlement_domain,
            core::slice::from_ref(&cash)
        ));
        assert!(!domain_associated(&consent, &other_domain, &[]));
    }

    #[test]
    fn domain_association_uses_exact_publisher_alias_and_ownership_scopes() {
        let issuer = domain("issuer", "universal");
        let hbl = domain("hbl", "sbp");
        let ubl = domain("ubl", "sbp");
        let foreign_definition = definition(domain("other", "universal"), "token");
        // Definition-scoped permissions follow the authoritative ownership set, not the
        // domain literal inside the definition id.
        let mint = Permission::from(CanMintAssetWithDefinition {
            asset_definition: foreign_definition.clone(),
        });
        assert!(domain_associated(
            &mint,
            &issuer,
            core::slice::from_ref(&foreign_definition)
        ));
        assert!(!domain_associated(&mint, &issuer, &[]));
        let publisher = Permission::from(CanPublishSpaceDirectoryManifestForAccountDomain {
            dataspace: DataSpaceId::new(10),
            domain: hbl.clone(),
        });
        assert!(domain_associated(&publisher, &hbl, &[]));
        assert!(!domain_associated(&publisher, &ubl, &[]));
        let alias_scope = AccountAliasPermissionScope::Domain(hbl.clone());
        for permission in [
            Permission::from(CanResolveAccountAlias {
                scope: alias_scope.clone(),
            }),
            Permission::from(CanDelegateAccountAliasResolution {
                scope: alias_scope.clone(),
            }),
            Permission::from(CanManageAccountAlias { scope: alias_scope }),
            Permission::from(CanManageAssetDefinitionAlias {
                scope: AssetDefinitionAliasPermissionScope::Domain(hbl.clone()),
            }),
        ] {
            assert!(domain_associated(&permission, &hbl, &[]));
            assert!(!domain_associated(&permission, &ubl, &[]));
        }
    }
}
