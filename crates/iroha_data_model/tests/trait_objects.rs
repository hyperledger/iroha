//! Tests for trait object instructions
use iroha_data_model::{instruction_registry_with_ids, isi::set_instruction_registry, prelude::*};
struct RegistryGuard;
impl Drop for RegistryGuard {
    fn drop(&mut self) {
        set_instruction_registry(iroha_data_model::instruction_registry::default());
    }
}

const INSTRUCTION_BOX_NORITO_CHILD: &str = "IROHA_DATA_MODEL_INSTRUCTION_BOX_NORITO_CHILD";

#[test]
fn instruction_box_roundtrip() {
    let log = Log::new(Level::INFO, "roundtrip".to_string());
    let (payload, flags) = norito::codec::encode_with_header_flags(&log);
    let framed = norito::core::frame_bare_with_header_flags::<Log>(&payload, flags)
        .expect("frame instruction payload");
    let registry = instruction_registry_with_ids![Log];
    let decoded = registry
        .decode(Log::WIRE_ID, &framed)
        .expect("registry")
        .expect("decode");
    let decoded_log = decoded.as_any().downcast_ref::<Log>().unwrap();
    assert_eq!(decoded_log, &log);
    assert_eq!(Instruction::dyn_encode(&*decoded), payload);
}
#[test]
fn instruction_box_norito_roundtrip() {
    if std::env::var_os(INSTRUCTION_BOX_NORITO_CHILD).is_none() {
        // Keep the deliberately narrowed process-global registry outside the
        // grouped parent, where unrelated codecs may be running concurrently.
        let test = "trait_objects::instruction_box_norito_roundtrip";
        let output = std::process::Command::new(
            std::env::current_exe().expect("resolve grouped integration-test executable"),
        )
        .args(["--exact", test])
        .env(INSTRUCTION_BOX_NORITO_CHILD, "1")
        .output()
        .expect("run isolated instruction-box registry test");
        assert!(
            output.status.success(),
            "isolated registry test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout
                .lines()
                .any(|line| line == format!("test {test} ... ok")),
            "isolated exact test did not pass: {stdout}",
        );
        assert!(
            stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "isolated test selection changed: {stdout}",
        );
        return;
    }

    let _guard = RegistryGuard;
    set_instruction_registry(instruction_registry_with_ids![Log]);
    let log = Log::new(Level::INFO, "norito".to_string());
    let boxed = InstructionBox::from(log.clone());
    let bytes = norito::core::to_bytes(&boxed).expect("serialize");
    let archived = norito::core::from_bytes::<InstructionBox>(&bytes).expect("from_bytes");
    let decoded = norito::core::DeserializePayload::try_deserialize(archived).expect("deserialize");
    let decoded_log = decoded.as_any().downcast_ref::<Log>().unwrap();
    assert_eq!(decoded_log, &log);
}
