//! Verify Kotodama lowering of `StateMap<int, int>` into durable host state.
use iroha_crypto::PublicKey;
use ivm::{
    CoreHost, IVM,
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
};
use kotodama_lang::{compiler::Compiler as KotodamaCompiler, ir, parser, semantic};
mod common;
fn encoded_state_path(name: &str, key: i64) -> String {
    let key = common::encode_int_state_value(key);
    format!("{name}/{}", hex::encode(key))
}
fn account(_domain: &str, public_key: &str) -> AccountId {
    let public_key: PublicKey = public_key.parse().expect("public key");
    AccountId::new(public_key)
}
#[test]
fn kotodama_state_map_set_writes_corehost_state() {
    let src = r#"
        seiyaku C { permission WriteState;
            state StateMap<int, int> M;
            kotoage fn main() authorize(WriteState) {
                M[1] = 7;
                let _x = M.get(1);
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
    vm.run().expect("run kotodama");
    // Inspect the host-owned state directly. Loading a CNTR-less helper program
    // for a contract-bound state syscall would correctly fail admission.
    let stored = {
        let host = vm.host_mut_any().expect("CoreHost available");
        let host = host.downcast_mut::<CoreHost>().expect("CoreHost type");
        host.state_bytes(&encoded_state_path("M", 1))
            .expect("state value written")
    };
    assert_eq!(common::decode_int_state_value(&stored), 7);
}
#[test]
fn kotodama_nested_struct_map_roundtrip() {
    let src = r#"
        seiyaku C { permission WriteState;
            struct Inner { int value }
            struct Outer { Inner inner }
            state StateMap<int, Outer> state_outer;
            kotoage fn main() authorize(WriteState) -> int {
                state_outer[7] = Outer { inner: Inner { value: 33 } };
                return state_outer.get(7).unwrap_or(Outer { inner: Inner { value: 0 } }).inner.value;
            }
        }
    "#;
    let code = KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile nested map state");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&code).expect("load nested map program");
    common::select_kotodama_entrypoint(&mut vm, &code, "main");
    vm.run().expect("execute nested map program");
    assert_eq!(common::decode_i64_return_word(&vm, 0), 33);
}
#[test]
fn kotodama_foreach_map_lowering_uses_compact_loop() {
    let src = r#"
        seiyaku LoopDemo {
            state StateMap<int, int> M;
            view fn main() authorize(anyone) {
                for (k, v) in M.take(16) {
                    let _tmp = k + v;
                }
            }
        }
    "#;
    let program = parser::parse(src).expect("parse loop demo");
    let typed = semantic::analyze(&program).expect("semantic analysis");
    let ir_prog = ir::lower(&typed).expect("lower");
    let main_fn = ir_prog
        .functions
        .iter()
        .find(|f| f.name == "main")
        .expect("lowered main");
    let mut state_gets = 0usize;
    let mut map_load_pairs = 0usize;
    for bb in &main_fn.blocks {
        for instr in &bb.instrs {
            match instr {
                ir::Instr::StateGet { .. } => state_gets += 1,
                ir::Instr::MapLoadPair { .. } => map_load_pairs += 1,
                _ => {}
            }
        }
    }
    assert_eq!(
        map_load_pairs, 0,
        "state map lowering should avoid MapLoadPair unrolling"
    );
    assert!(
        state_gets >= 1,
        "state map iteration should fetch from durable state"
    );
}
#[test]
fn kotodama_foreach_reads_durable_state_map_entries() {
    let src = r#"
        seiyaku LoopDemo { permission WriteState;
            state StateMap<int, int> M;
            state StateMap<int, int> Mirror;
            kotoage fn main() authorize(WriteState) {
                for (k, v) in M.take(4) {
                    Mirror[k] = v;
                }
            }
        }
    "#;
    let code = KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile durable loop");
    let mut wsv = MockWorldStateView::new();
    wsv.sc_set(
        &encoded_state_path("M", 0),
        common::encode_int_state_value(5),
    )
    .expect("write state index 0");
    wsv.sc_set(
        &encoded_state_path("M", 1),
        common::encode_int_state_value(9),
    )
    .expect("write state index 1");
    let alice = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let host = WsvHost::new_with_subject(wsv, alice.clone());
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&code).expect("load loop program");
    common::select_kotodama_entrypoint(&mut vm, &code, "main");
    vm.run().expect("execute loop program");
    // Read back the mirrored entries from the host-owned world state.
    let wsv = {
        let host = vm.host_mut_any().expect("WsvHost available");
        let host = host.downcast_mut::<WsvHost>().expect("WsvHost type");
        host.wsv.clone()
    };
    for (path, expected) in [
        (encoded_state_path("Mirror", 0), 5_i64),
        (encoded_state_path("Mirror", 1), 9_i64),
    ] {
        let stored = wsv.sc_get(&path).expect("mirrored state value");
        assert_eq!(common::decode_int_state_value(&stored), expected);
    }
}
