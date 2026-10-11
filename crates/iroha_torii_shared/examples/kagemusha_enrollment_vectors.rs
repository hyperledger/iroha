//! Emit canonical enrollment transport DATA fixtures; these bytes grant no enrollment authority.
//!
//! Regenerate with `cargo run -p iroha_torii_shared --example kagemusha_enrollment_vectors`.

use iroha_torii_shared::kagemusha_enrollment::{
    ENROLLMENT_DISPATCH_MAX_BYTES_V1, ENROLLMENT_EVIDENCE_REQUEST_MAX_BYTES_V1,
    ENROLLMENT_RESULT_MAX_BYTES_V1, ENROLLMENT_SERVICE_REQUEST_MAX_BYTES_V1,
    ENROLLMENT_SERVICE_RESPONSE_MAX_BYTES_V1, ENROLLMENT_SERVICE_ROUTE_V1,
    EnrollmentServiceActionV1 as Action, EnrollmentServiceRequestV1 as Request,
    EnrollmentServiceResponseV1 as Response,
};
use norito::{NoritoSchema, json};
use sha2::{Digest, Sha256};

fn vectors() -> Result<json::Value, Box<dyn std::error::Error>> {
    let record = |name: &str, wire: &[u8], include_wire: bool| {
        let mut value = norito::json!({
            "name": name,
            "wire_length": (wire.len()),
            "sha256": (hex::encode(Sha256::digest(wire))),
            "flags": (wire[39]),
            "header_hex": (hex::encode(&wire[..40])),
        });
        if include_wire {
            value
                .as_object_mut()
                .unwrap()
                .insert("wire_hex".into(), json::Value::String(hex::encode(wire)));
        }
        value
    };
    let mut requests = Vec::new();
    let mut bounds = Vec::new();
    for (name, action) in [
        ("pre_key", Action::PreKey),
        ("evidence", Action::Evidence),
        ("issue", Action::Issue),
        ("deliver", Action::Deliver),
    ] {
        let value = Request {
            version: 1,
            action,
            dispatch_original: vec![1, 2, 3],
            evidence_original: if action == Action::Evidence {
                vec![4, 5, 6]
            } else {
                vec![]
            },
        };
        let wire = value.canonical_wire()?;
        assert_eq!(Request::decode_canonical(&wire)?, value);
        requests.push(record(name, &wire, true));
        let full = Request {
            dispatch_original: vec![1; ENROLLMENT_DISPATCH_MAX_BYTES_V1],
            evidence_original: if action == Action::Evidence {
                vec![2; ENROLLMENT_EVIDENCE_REQUEST_MAX_BYTES_V1]
            } else {
                vec![]
            },
            ..value
        };
        let wire = full.canonical_wire()?;
        assert_eq!(Request::decode_canonical(&wire)?, full);
        bounds.push(record(&format!("request_{name}"), &wire, false));
    }
    let mut responses = Vec::new();
    for (name, value) in [
        ("permit", Response::Permit(vec![7, 8])),
        ("evidence_ready", Response::EvidenceReady),
        ("pending", Response::Pending),
        ("credential_ready", Response::CredentialReady),
        ("credential", Response::Credential(vec![9, 10])),
    ] {
        let wire = value.canonical_wire()?;
        assert_eq!(Response::decode_canonical(&wire)?, value);
        responses.push(record(name, &wire, true));
    }
    for (name, value) in [
        ("response_permit", Response::Permit(vec![1; 2048])),
        (
            "response_credential",
            Response::Credential(vec![2; ENROLLMENT_RESULT_MAX_BYTES_V1]),
        ),
    ] {
        let wire = value.canonical_wire()?;
        assert_eq!(Response::decode_canonical(&wire)?, value);
        bounds.push(record(name, &wire, false));
    }
    Ok(norito::json!({
        "version": 1,
        "scope": "Envelope codec DATA only. Synthetic originals are not permits, evidence or credentials and authorize no operation.",
        "generator": "crates/iroha_torii_shared/examples/kagemusha_enrollment_vectors.rs",
        "route": ENROLLMENT_SERVICE_ROUTE_V1,
        "request_schema_name": (Request::frame_name()),
        "request_schema_hash": (hex::encode(norito::schema::identity::frame_hash::<Request>())),
        "request_payload_alignment": (norito::core::archived_payload_align::<Request>()),
        "response_schema_name": (Response::frame_name()),
        "response_schema_hash": (hex::encode(norito::schema::identity::frame_hash::<Response>())),
        "response_payload_alignment": (norito::core::archived_payload_align::<Response>()),
        "dispatch_hex": "010203",
        "evidence_hex": "040506",
        "permit_hex": "0708",
        "credential_hex": "090a",
        "request_frame_max_bytes": ENROLLMENT_SERVICE_REQUEST_MAX_BYTES_V1,
        "response_frame_max_bytes": ENROLLMENT_SERVICE_RESPONSE_MAX_BYTES_V1,
        "bound_inputs": "Dispatch/Permit use byte 01; Evidence/Credential use byte 02, repeated to their inclusive original limits. Evidence is present only for its action.",
        "requests": requests,
        "responses": responses,
        "inclusive_bounds": bounds,
    }))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", json::to_json_pretty(&vectors()?)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_typed_encodings_match_all_shared_vectors_and_inclusive_bounds() {
        let expected: json::Value = json::from_str(include_str!(
            "../../../fixtures/kagemusha/enrollment_service_v1_vectors.json"
        ))
        .unwrap();
        assert_eq!(vectors().unwrap(), expected);
    }
}
