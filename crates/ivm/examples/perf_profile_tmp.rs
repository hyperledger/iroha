//! Temporary long-running warm loop for sampling interpreter hot paths.
use ivm::{IVM, Memory, ProgramMetadata, encoding::wide, instruction};

fn main() {
    ivm::set_banner_enabled(false);
    let case = std::env::args().nth(1).unwrap_or_else(|| "add".into());
    let word = match case.as_str() {
        "load" => wide::encode_load(instruction::wide::memory::LOAD64, 5, 4, 0),
        "store" => wide::encode_store(instruction::wide::memory::STORE64, 4, 1, 0),
        _ => wide::encode_rr(instruction::wide::arithmetic::ADD, 3, 1, 2),
    };
    let mut image = ProgramMetadata::default().encode();
    for _ in 0..200_000 {
        image.extend_from_slice(&word.to_le_bytes());
    }
    image.extend_from_slice(&wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(1_000_000_000);
    vm.load_program(&image).expect("load");
    let template = vm.try_runtime_template().expect("template");
    for _ in 0..400 {
        vm.set_register(1, 0x55);
        vm.set_register(2, 7);
        vm.set_register(4, Memory::HEAP_START);
        vm.run().expect("run");
        vm.reset_from_runtime_template(&template).expect("reset");
    }
}
