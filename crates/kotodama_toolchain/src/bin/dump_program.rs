//! Compile, disassemble, and execute a small Kotodama V1 program.
use iroha_primitives::numeric_abi::IntValueV1;
use ivm::{IVM, PointerType, ProgramMetadata};
fn returned_int(vm: &IVM, register: usize) -> i64 {
    let tlv = vm
        .validate_tlv(vm.register(register))
        .unwrap_or_else(|error| panic!("validate returned int in r{register}: {error:?}"));
    assert_eq!(tlv.type_id, PointerType::Int);
    IntValueV1::decode_frame(tlv.payload)
        .expect("decode canonical returned int")
        .into_int()
        .try_to_i64()
        .expect("dump program result fits i64")
}
fn main() {
    let src = r#"
        seiyaku DumpProgram {
            struct A { int x }
            struct B { A a }
            struct C { B b }
            struct D { C c }
            view fn main() authorize(anyone) -> int {
                let a = A { x: 5 };
                let b = B { a };
                let c = C { b };
                let d = D { c };
                return d.c.b.a.x;
            }
        }
    "#;
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source(src)
        .expect("compile");
    let parsed = ProgramMetadata::parse(&code).unwrap();
    let mut memory = ivm::Memory::new();
    memory
        .load_code(&code[parsed.header_len..])
        .expect("validated program fits code region");
    let mut pc = (parsed.code_offset - parsed.header_len) as u64;
    while pc < memory.code_len() {
        let word = ivm::decode(&memory, pc).unwrap();
        println!("pc=0x{pc:04x} word=0x{word:08x}");
        pc += 4;
    }
    let entrypoint = parsed
        .contract_interface
        .as_ref()
        .expect("dump program contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "main")
        .expect("main entrypoint descriptor");
    let entrypoint_pc =
        u64::try_from(parsed.prefix_len()).expect("program prefix fits u64") + entrypoint.entry_pc;
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&code).unwrap();
    vm.set_program_counter(entrypoint_pc)
        .expect("select main entrypoint");
    vm.run().unwrap();
    for reg in 2..10 {
        println!("x{reg}={}", vm.register(reg));
    }
    println!("x10={}", returned_int(&vm, 10));
}
