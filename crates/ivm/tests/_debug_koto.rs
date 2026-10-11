//! Debug-oriented opcode inspection for selected Kotodama snippets.
use ivm::{encoding, instruction::wide};
use kotodama_lang::compiler::{Compiler, CompilerMode, CompilerOptions};
#[test]
fn debug_create_nfts_and_set_detail_words() {
    let src = "seiyaku DebugHostCalls { permission Admin;  kotoage fn main() authorize(Admin) { ledger::nft::create_for_all_users(); ledger::account::set_metadata(account: context::authority(), key: Name::parse(\"cursor\"), value: Json::parse(\"{\\\"cursor\\\":1,\\\"query\\\":\\\"sc_dummy\\\"}\")); } }";
    let compiler = Compiler::new_with_options(CompilerOptions {
        mode: CompilerMode::Test,
        ..CompilerOptions::default()
    });
    let code = compiler.compile_source(src).expect("compile");
    let off = ivm::ProgramMetadata::parse(&code).unwrap().code_offset;
    let mut words = Vec::new();
    let mut i = off;
    while i + 4 <= code.len() {
        words.push(u32::from_le_bytes(code[i..i + 4].try_into().unwrap()));
        i += 4;
    }
    // Print the set of SCALL words we’re looking for
    let scall = wide::system::SCALL;
    let want = [
        encoding::wide::encode_sys(
            scall,
            ivm::syscalls::SYSCALL_CREATE_NFTS_FOR_ALL_USERS as u8,
        ),
        encoding::wide::encode_sys(scall, ivm::syscalls::SYSCALL_SET_ACCOUNT_DETAIL as u8),
    ];
    eprintln!("words count={} contains: ", words.len());
    for (idx, w) in want.iter().enumerate() {
        eprintln!(
            "want[{idx}] = 0x{w:08x} present={}",
            words.iter().any(|x| x == w)
        );
    }
    // Print all SCALL-like words seen
    let mut scall_seen: Vec<u32> = words
        .iter()
        .copied()
        .filter(|w| (w & 0xFF00_0000) == ((scall as u32) << 24))
        .collect();
    scall_seen.sort_unstable();
    scall_seen.dedup();
    eprintln!(
        "SCALL words present: {:?}",
        scall_seen
            .iter()
            .map(|w| format!("0x{w:08x}"))
            .collect::<Vec<_>>()
    );
}
