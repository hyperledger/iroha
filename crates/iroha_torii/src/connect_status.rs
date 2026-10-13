//! Strict query decoding for management-token-authorized Connect session status.
/// Decode the one required `sid` query parameter for Connect session status.
///
/// Unknown, duplicate, empty, and malformed parameters are rejected so the protocol-authenticated
/// session route cannot fall through to aggregate node status or admit an ambiguous signed target.
pub fn parse_session_status_sid(raw_query: Option<&str>) -> Result<String, &'static str> {
    let raw = raw_query.ok_or("connect: sid query is required")?;
    if raw.is_empty() {
        return Err("connect: sid query is required");
    }
    if raw.contains('&') {
        return Err("connect: status query must contain exactly one parameter");
    }
    let (key, value) = raw
        .split_once('=')
        .ok_or("connect: malformed status query")?;
    if key != "sid" {
        return Err("connect: unknown status query parameter");
    }
    if value.is_empty() {
        return Err("connect: sid query is required");
    }
    if value
        .bytes()
        .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
    {
        return Err("connect: sid query must be canonical unpadded base64url");
    }
    Ok(value.to_owned())
}
#[cfg(test)]
mod tests {
    use super::parse_session_status_sid;
    #[test]
    fn accepts_one_exact_sid_parameter() {
        assert_eq!(
            parse_session_status_sid(Some("sid=abc-_123")),
            Ok("abc-_123".to_owned())
        );
    }
    #[test]
    fn rejects_missing_unknown_duplicate_and_malformed_parameters() {
        for query in [
            None,
            Some(""),
            Some("other=sid"),
            Some("sid=one&sid=two"),
            Some("sid=one&other=two"),
            Some("sid"),
            Some("sid="),
            Some("sid=%ZZ"),
            Some("sid=abc%2D_123"),
            Some("sid=abc+123"),
        ] {
            assert!(
                parse_session_status_sid(query).is_err(),
                "query must be rejected: {query:?}"
            );
        }
    }
}
