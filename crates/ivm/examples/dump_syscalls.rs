//! Quick helper to compile an inline Kotodama source string and dump SCALLs.
use ivm::{Memory, ProgramMetadata, decode as ivm_decode};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
fn dump(src: &str) {
    let code = KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile");
    let parsed = ProgramMetadata::parse(&code).expect("parse meta");
    let bytes = &code[parsed.code_offset..];
    let mut mem = Memory::new();
    mem.load_code(bytes)
        .expect("example program fits code region");
    println!("code_len={}, off={}", code.len(), parsed.code_offset);
    let mut count = 0;
    let mut pc = 0u64;
    while pc + 4 <= mem.code_len() {
        let w = ivm_decode(&mem, pc).unwrap();
        let opcode = (w >> 24) as u8;
        let (_, imm) = ivm::encoding::wide::decode_sys(w);
        if opcode == ivm::instruction::wide::system::SCALL {
            println!("SCALL @+{pc} imm=0x{imm:02x}");
        }
        if count < 32 {
            println!("+{pc:03}: op=0x{opcode:02x} imm=0x{imm:02x} raw=0x{w:08x}");
            count += 1;
        }
        pc += 4;
    }
}
fn main() {
    // Case 1: create_nfts_for_all_users + set_account_detail
    let src1 = "seiyaku Sample1 { permission Admin;  kotoage fn run() authorize(Admin) { ledger::nft::create_for_all_users(); ledger::account::set_metadata(account: context::authority(), key: Name::parse(\"cursor\"), value: Json::parse(\"{\\\"cursor\\\":1,\\\"query\\\":\\\"sc_dummy\\\"}\")); } }";
    println!("-- case 1 --");
    dump(src1);
    // Case 2: typed NFT syscalls
    let src2 = "seiyaku Sample2 { permission Admin;  kotoage fn run() authorize(Admin) { ledger::nft::mint(NftId::parse(\"n0$wonderland\"), AccountId::parse(\"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV\")); ledger::nft::transfer(source: AccountId::parse(\"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV\"), nft: NftId::parse(\"n0$wonderland\"), destination: AccountId::parse(\"sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76\")); } }";
    println!("-- case 2 --");
    dump(src2);
}
