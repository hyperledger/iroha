//! Source-bound compiler identities for this event capability's existing owners.

use crate::events::captured_event_boundary_identity_tests::check;

// These noncapturing cases keep the literal capture order in static storage.
const CASES: &[fn()] = &[
    || {
        check::<super::ProofEventFilter>(
            "iroha_data_model::events::data::filters::model::ProofEventFilter",
            "d20e11f11a5902a07ec19c4c1b32d9f7",
            "d20e11f11a5902a07ec19c4c1b32d9f7",
        )
    },
    || {
        check::<super::VerifyingKeyEventFilter>(
            "iroha_data_model::events::data::filters::model::VerifyingKeyEventFilter",
            "4cf65beb94872fd614ee22aa5952062c",
            "4cf65beb94872fd614ee22aa5952062c",
        )
    },
    || {
        check::<super::RuntimeUpgradeEventFilter>(
            "iroha_data_model::events::data::filters::model::RuntimeUpgradeEventFilter",
            "778d326cf575ce3c49782ff1de1c7d3b",
            "778d326cf575ce3c49782ff1de1c7d3b",
        )
    },
    || {
        check::<super::SocialEventFilter>(
            "iroha_data_model::events::data::filters::model::SocialEventFilter",
            "2488bf2dca31f45618499079968f35eb",
            "2488bf2dca31f45618499079968f35eb",
        )
    },
    || {
        check::<super::SoradnsDirectoryEventFilter>(
            "iroha_data_model::events::data::filters::model::SoradnsDirectoryEventFilter",
            "75ba2f6909966d355c4253e2c3f43bb2",
            "75ba2f6909966d355c4253e2c3f43bb2",
        )
    },
    || {
        check::<super::SorafsGatewayEventFilter>(
            "iroha_data_model::events::data::filters::model::SorafsGatewayEventFilter",
            "2d25a62b3cf96219f64080ddfad76b2a",
            "2d25a62b3cf96219f64080ddfad76b2a",
        )
    },
    || {
        check::<super::MusubiEventFilter>(
            "iroha_data_model::events::data::filters::model::MusubiEventFilter",
            "ef65b0a596c85ff6a3ce586e290fb81c",
            "ef65b0a596c85ff6a3ce586e290fb81c",
        )
    },
    || {
        check::<super::SpaceDirectoryEventFilter>(
            "iroha_data_model::events::data::filters::model::SpaceDirectoryEventFilter",
            "8a976a8485bb5d862dac8f7f02604f62",
            "8a976a8485bb5d862dac8f7f02604f62",
        )
    },
    || {
        check::<super::EscrowEventFilter>(
            "iroha_data_model::events::data::filters::model::EscrowEventFilter",
            "a1d49ab4519fcd22b584cb1dfb156cbe",
            "a1d49ab4519fcd22b584cb1dfb156cbe",
        )
    },
    || {
        check::<super::GovernanceEventFilter>(
            "iroha_data_model::events::data::filters::model::GovernanceEventFilter",
            "e4fe09f2e6d963e1a1986c3b366be3ea",
            "e4fe09f2e6d963e1a1986c3b366be3ea",
        )
    },
    || {
        check::<super::PeerEventFilter>(
            "iroha_data_model::events::data::filters::model::PeerEventFilter",
            "8da48f9005624c3c07f6b096ab9f832c",
            "8da48f9005624c3c07f6b096ab9f832c",
        )
    },
    || {
        check::<super::DomainEventFilter>(
            "iroha_data_model::events::data::filters::model::DomainEventFilter",
            "46ccf80d486df2cf59520c761b07f5f1",
            "46ccf80d486df2cf59520c761b07f5f1",
        )
    },
    || {
        check::<super::AccountEventFilter>(
            "iroha_data_model::events::data::filters::model::AccountEventFilter",
            "6a3f0042cb73ea626a6966a0767d5a0f",
            "6a3f0042cb73ea626a6966a0767d5a0f",
        )
    },
    || {
        check::<super::AssetEventFilter>(
            "iroha_data_model::events::data::filters::model::AssetEventFilter",
            "1fc1e4a8ad46338fef0200a3e1f08ef4",
            "1fc1e4a8ad46338fef0200a3e1f08ef4",
        )
    },
    || {
        check::<super::AssetDefinitionEventFilter>(
            "iroha_data_model::events::data::filters::model::AssetDefinitionEventFilter",
            "5dbb4c9e30b1591e87a4c3f62a02c4bc",
            "5dbb4c9e30b1591e87a4c3f62a02c4bc",
        )
    },
    || {
        check::<super::NftEventFilter>(
            "iroha_data_model::events::data::filters::model::NftEventFilter",
            "c69eb3ef03522e9bba703c73064b4952",
            "c69eb3ef03522e9bba703c73064b4952",
        )
    },
    || {
        check::<super::RwaEventFilter>(
            "iroha_data_model::events::data::filters::model::RwaEventFilter",
            "8afc29f10cba132b4e9b6166ea2d7f63",
            "8afc29f10cba132b4e9b6166ea2d7f63",
        )
    },
    || {
        check::<super::TriggerEventFilter>(
            "iroha_data_model::events::data::filters::model::TriggerEventFilter",
            "4b2ebcb4a231f4f71dff1080a2518a90",
            "4b2ebcb4a231f4f71dff1080a2518a90",
        )
    },
    || {
        check::<super::RoleEventFilter>(
            "iroha_data_model::events::data::filters::model::RoleEventFilter",
            "5f19c97ea69d8b9b14b310d996fcd071",
            "5f19c97ea69d8b9b14b310d996fcd071",
        )
    },
    || {
        check::<super::ConfigurationEventFilter>(
            "iroha_data_model::events::data::filters::model::ConfigurationEventFilter",
            "6d1f0a711eef59bb41dede64496445fe",
            "6d1f0a711eef59bb41dede64496445fe",
        )
    },
    || {
        check::<super::ExecutorEventFilter>(
            "iroha_data_model::events::data::filters::model::ExecutorEventFilter",
            "eda9b1af494c869d4a614285f47c2121",
            "eda9b1af494c869d4a614285f47c2121",
        )
    },
    || {
        check::<super::OracleEventFilter>(
            "iroha_data_model::events::data::filters::OracleEventFilter",
            "ca5f70dfde00a2419a3cdbd73b002299",
            "ca5f70dfde00a2419a3cdbd73b002299",
        )
    },
    || {
        check::<super::bridge_filters_model::BridgeEventFilter>(
            "iroha_data_model::events::data::filters::bridge_filters_model::model::BridgeEventFilter",
            "2355579e076dcbae635d0362d37eaa50",
            "2355579e076dcbae635d0362d37eaa50",
        )
    },
    || {
        check::<super::SccpEventFilter>(
            "iroha_data_model::events::data::filters::model::SccpEventFilter",
            "ed7059a117dc0017823fa86b8ba74622",
            "ed7059a117dc0017823fa86b8ba74622",
        )
    },
];

#[test]
fn captured_event_codec_schema_identities() {
    for check in CASES {
        check();
    }
}
