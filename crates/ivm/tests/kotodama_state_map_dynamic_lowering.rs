//! Verify dynamic durable lowering for `StateMap<int, int>`.
use ivm::{CoreHost, IVM};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
#[test]
fn dynamic_map_set_uses_durable_state() {
    let src = r#"
        seiyaku C { permission WriteState;
            state StateMap<int, int> M;
            kotoage fn main() authorize(WriteState) {
                let k = 2;
                let v = 5;
                M[k] = v;
            }
        }
    "#;
    let code = KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&code).expect("load");
    common::select_kotodama_entrypoint(&mut vm, &code, "main");
    vm.run().expect("run");
    // Inspect the host-owned state directly. A second CNTR-less helper image
    // must not inherit the loaded contract's state schema.
    let key = ivm_abi::numeric_tlv::encode_int(&iroha_primitives::bigint::BigInt::from_i128(2))
        .expect("encode canonical int key");
    let path = format!("M/{}", hex::encode(key));
    let stored = {
        let host = vm.host_mut_any().expect("CoreHost available");
        let host = host.downcast_mut::<CoreHost>().expect("CoreHost type");
        host.state_bytes(&path).expect("state value written")
    };
    assert_eq!(common::decode_int_state_value(&stored), 5);
}
