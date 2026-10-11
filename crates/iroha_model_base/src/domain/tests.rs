//! Domain constructors and canonical JSON-key allocation contracts.

use super::*;

#[test]
fn domain_id_try_new_canonicalizes_both_segments() {
    let domain_id = DomainId::try_new("Treasury", "CentralBank").expect("domain id");
    assert_eq!(domain_id.to_string(), "treasury.centralbank");
}

#[test]
fn domain_id_json_key_constructor_rejects_ambiguous_component_boundaries() {
    // These component pairs would otherwise both display as `a.b.c`.
    for (name, dataspace) in [("a.b", "c"), ("a", "b.c"), ("a。b", "c"), ("a", "b．c")] {
        assert!(DomainId::try_new(name, dataspace).is_err());
    }
    let id = DomainId::try_new("例え", "テスト").expect("one label per component");
    assert_eq!(
        DomainId::parse_fully_qualified(&id.to_string()).expect("unique component boundary"),
        id
    );
}
#[test]
fn domain_id_parse_fully_qualified_requires_both_segments() {
    let domain_id = DomainId::parse_fully_qualified("treasury.centralbank").expect("domain id");
    assert_eq!(domain_id.to_string(), "treasury.centralbank");
    assert!(DomainId::parse_fully_qualified("treasury").is_err());
}

#[test]
fn domain_json_key_accounts_punycode_normalization_before_idna() {
    use norito::json::JsonObjectKeyOwned;

    let key = "xn--r8jz45g.centralbank";
    let component_bytes = key.len() - 1;
    // Seven Punycode bytes can normalize to at most 126 scalars. ICU's
    // 17-element inline buffer therefore grows through capacities 32, 64,
    // and 128: (32 + 64 + 128) * four bytes.
    let a_label_scratch = (32 + 64 + 128) * core::mem::size_of::<u32>();
    let exact = component_bytes * 2 + a_label_scratch;
    let limits = |bytes| {
        norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
    };

    let (decoded, usage) = norito::core::with_decode_limits_measured(limits(exact), || {
        <DomainId as JsonObjectKeyOwned>::from_json_key_text(key)
    });
    assert_eq!(decoded.expect("canonical A-label key").to_string(), key);
    assert_eq!(usage.total_allocated_bytes(), exact);

    let (rejected, usage) = norito::core::with_decode_limits_measured(limits(exact - 1), || {
        <DomainId as JsonObjectKeyOwned>::from_json_key_text(key)
    });
    assert!(matches!(
        rejected,
        Err(norito::json::Error::DecodeResource(
            norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
        ))
    ));
    assert_eq!(usage.total_allocated_bytes(), 0);
}

fn allocation_limit(bytes: usize) -> norito::core::DecodeLimits {
    norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

#[test]
fn domain_key_accounts_canonicalization_before_owner_allocations() {
    let key = "treasury.centralbank";
    let component_bytes = key.len() - 1;
    let expected_allocation = component_bytes * 2;
    let (decoded, usage) =
        norito::core::with_decode_limits_measured(allocation_limit(expected_allocation), || {
            <crate::domain::DomainId as JsonObjectKeyOwned>::from_json_key_text(key)
        });
    assert_eq!(
        decoded
            .expect("domain key at exact allocation bound")
            .to_string(),
        key
    );
    assert_eq!(usage.total_allocated_bytes(), expected_allocation);

    let (rejected, usage) = norito::core::with_decode_limits_measured(
        allocation_limit(expected_allocation - 1),
        || <crate::domain::DomainId as JsonObjectKeyOwned>::from_json_key_text(key),
    );
    assert!(matches!(
        rejected,
        Err(json::Error::DecodeResource(
            norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
        ))
    ));
    assert_eq!(usage.total_allocated_bytes(), 0);

    let (noncanonical, usage) =
        norito::core::with_decode_limits_measured(allocation_limit(usize::MAX), || {
            <crate::domain::DomainId as JsonObjectKeyOwned>::from_json_key_text("例え.centralbank")
        });
    assert!(noncanonical.is_err());
    assert_eq!(usage.total_allocated_bytes(), 0);

    let uppercase = "Treasury.centralbank";
    let (noncanonical, usage) =
        norito::core::with_decode_limits_measured(allocation_limit(usize::MAX), || {
            <crate::domain::DomainId as JsonObjectKeyOwned>::from_json_key_text(uppercase)
        });
    assert!(noncanonical.is_err());
    assert_eq!(usage.total_allocated_bytes(), 0);
}

#[test]
fn domain_checked_json_stream_has_only_exact_destination_allocation() {
    let id = DomainId::try_new("Treasury", "CentralBank").unwrap();
    let expected = norito::json::to_json(&id.to_string()).unwrap();
    let limits = |bytes| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, 32);
    let (encoded, usage) =
        norito::core::with_decode_limits_measured(limits(expected.len()), || {
            norito::json::to_json_bounded_boxed(&id, expected.len())
        });
    assert_eq!(&*encoded.unwrap(), expected.as_bytes());
    assert_eq!(usage.total_allocated_bytes(), expected.len());
    assert!(
        norito::with_decode_limits_scope(limits(expected.len() - 1), || {
            norito::json::to_json_bounded_boxed(&id, expected.len())
        })
        .is_err()
    );
    assert!(norito::json::to_json_bounded_boxed(&id, expected.len() - 1).is_err());
}
