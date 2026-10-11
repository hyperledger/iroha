//! Integration tests for the JSON query envelope DSL.

mod json_envelope {
    use iroha_data_model::query::{
        QueryRequest,
        json::QueryEnvelopeJson,
        parameters::{FetchSize, SortOrder},
    };
    const AUTHORITY: &str = "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE";
    #[test]
    fn iterable_envelope_parses_params() {
        let json = r#"{
            "iterable": {
                "type": "FindDomains",
                "params": {
                    "limit": 5,
                    "offset": 1,
                    "fetch_size": 10,
                    "sort_by_metadata_key": "ui.order",
                    "order": "Desc"
                },
                "predicate": {
                    "equals": [
                        {"field": "authority", "value": "__AUTHORITY__"}
                    ]
                }
            }
        }"#
        .replace("__AUTHORITY__", AUTHORITY);
        let envelope: QueryEnvelopeJson = norito::json::from_str(&json).expect("parse envelope");
        let request = envelope.into_request().expect("build query request");
        let QueryRequest::Start(query_with_params) = &request else {
            panic!("expected iterable envelope");
        };
        let params = query_with_params.params();
        let pagination = params.pagination();
        assert_eq!(pagination.offset_value(), 1);
        assert_eq!(
            pagination.limit_value().map(std::num::NonZeroU64::get),
            Some(5)
        );
        let fetch: &FetchSize = params.fetch_size();
        assert_eq!(fetch.value().map(std::num::NonZeroU64::get), Some(10));
        let sorting = params.sorting();
        assert_eq!(
            sorting
                .sort_by_metadata_key()
                .map(std::string::ToString::to_string)
                .as_deref(),
            Some("ui.order")
        );
        assert!(matches!(sorting.order(), Some(SortOrder::Desc)));
    }
    #[test]
    fn iterable_order_without_key_errors() {
        let json = r#"{"iterable": {"type": "FindDomains", "params": {"order": "Asc"}}}"#;
        let envelope: QueryEnvelopeJson = norito::json::from_str(json).expect("parse envelope");
        let err = match envelope.into_request() {
            Ok(_) => panic!("order without sort key must error"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("sort order"));
    }
    #[test]
    fn unknown_iterable_field_is_rejected() {
        let json = r#"{
            "iterable": {
                "type": "FindDomains",
                "params": {"limit": 1},
                "bogus": true
            }
        }"#;
        let err = norito::json::from_str::<QueryEnvelopeJson>(json).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown field `bogus` inside `iterable`"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn unknown_params_field_is_rejected() {
        let json = r#"{
            "iterable": {
                "type": "FindDomains",
                "params": {"limit": 1, "extra": 5}
            }
        }"#;
        let err = norito::json::from_str::<QueryEnvelopeJson>(json).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown field `extra` inside `params`"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn singular_contract_manifest_roundtrip() {
        let artifact_id = iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::new(u64::MAX),
            iroha_crypto::Hash::new(b"canonical manifest query"),
        );
        let json = norito::json::to_json(&norito::json!({
            "singular": {
                "type": "FindContractManifestByArtifactId",
                "payload": {"artifact_id": (artifact_id)}
            }
        }))
        .expect("typed artifact envelope");
        let envelope: QueryEnvelopeJson = norito::json::from_str(&json).expect("parse envelope");
        let request = envelope.into_request().expect("build query request");
        let QueryRequest::Singular(query_box) = &request else {
            panic!("expected singular envelope");
        };
        let iroha_data_model::query::SingularQueryBox::FindContractManifestByArtifactId(query) =
            query_box
        else {
            panic!("expected exact artifact manifest query");
        };
        assert_eq!(
            query,
            &iroha_data_model::query::smart_contract::FindContractManifestByArtifactId::new(
                artifact_id
            )
        );
    }
}
