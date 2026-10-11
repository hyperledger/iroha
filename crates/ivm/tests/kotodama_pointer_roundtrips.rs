//! Kotodama pointer roundtrip tests.
use ivm::{CoreHost, IVM};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
fn run_prog(body: &str) {
    let src = format!(
        "seiyaku PointerRoundtrip {{ permission FixtureAccess;  kotoage fn main() authorize(FixtureAccess) {{\n{body}\n}} }}"
    );
    let compiler = KotodamaCompiler::new();
    let prog = compiler.compile_source(&src).expect("compile");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&prog).expect("load");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run()
        .expect("program should run with CoreHost TLV validation");
}
#[test]
fn roundtrip_nft_mint_asset() {
    let src = r#"
          ledger::nft::mint(
            nft: NftId::parse("n0$wonderland.universal"),
            owner: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
          );
    "#;
    run_prog(src);
}
#[test]
fn roundtrip_nft_set_metadata() {
    let src = r#"
          ledger::nft::set_metadata(nft: NftId::parse("n1$wonderland.universal"), key: Name::parse("dpn_metadata"), value: Json::parse("{\"meta\":1}"));
    "#;
    run_prog(src);
}
#[test]
fn roundtrip_transfer_asset() {
    let src = r#"
          ledger::asset::transfer(source: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), destination: AccountId::parse("sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76"), asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"), amount: 1, dataspace: DataSpaceId::parse("0"));
    "#;
    run_prog(src);
}
#[test]
fn roundtrip_nft_burn_asset() {
    let src = r#"
          ledger::nft::burn(nft: NftId::parse("n2$wonderland.universal"));
    "#;
    run_prog(src);
}
#[test]
fn roundtrip_nft_mint_asset_accepts_runtime_owner() {
    let src = r#"
          let owner = AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV");
          ledger::nft::mint(
            nft: NftId::parse("n0$wonderland.universal"),
            owner: owner
          );
    "#;
    run_prog(src);
}
#[test]
fn roundtrip_nft_transfer_asset_accepts_runtime_from() {
    let src = r#"
          let from = AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV");
          let to = AccountId::parse("sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76");
          let nft = NftId::parse("n2$wonderland.universal");
          ledger::nft::transfer(source: from, nft: nft, destination: to);
    "#;
    run_prog(src);
}
