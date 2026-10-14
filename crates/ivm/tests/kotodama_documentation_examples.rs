use crate::common;
use iroha_crypto::PublicKey;
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use ivm::{
    IVM, VMError,
    host::IVMHost,
    mock_wsv::{
        AccountId, AssetDefinitionId, Mintable, MockWorldStateView, NftId, PermissionToken, WsvHost,
    },
    syscalls,
};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
use kotodama_lang::compiler::CompilerOptions;
use std::{
    any::Any,
    path::{Path, PathBuf},
    str::FromStr,
};
fn repository_root() -> PathBuf {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(Path::parent)
        .expect("crates/ivm must live two levels below the repository root")
        .to_path_buf()
}
fn documentation_examples() -> Vec<(&'static str, PathBuf)> {
    let root = repository_root();
    vec![
        (
            "hajimari-entrypoint",
            root.join("crates/ivm/docs/examples/01_hajimari.ko"),
        ),
        (
            "call-transfer-asset",
            root.join("crates/ivm/docs/examples/08_call_transfer_asset.ko"),
        ),
        (
            "nft-flow",
            root.join("crates/ivm/docs/examples/12_nft_flow.ko"),
        ),
        (
            "register-and-mint",
            root.join("crates/ivm/docs/examples/13_register_and_mint.ko"),
        ),
        (
            "threshold-escrow",
            root.join("crates/kotodama_lang/src/samples/threshold_escrow.ko"),
        ),
        ("transfer-asset", root.join("examples/transfer/transfer.ko")),
    ]
}
fn kotodama_compiler() -> KotodamaCompiler {
    KotodamaCompiler::new_with_options(CompilerOptions::default())
}
#[test]
fn kotodama_documentation_examples_compile() {
    let compiler = kotodama_compiler();
    for (_, path) in documentation_examples() {
        let artifact = compiler
            .compile_file(&path)
            .unwrap_or_else(|err| panic!("failed to compile {}: {err}", path.display()));
        assert!(
            !artifact.is_empty(),
            "compiler produced empty bytecode for {}",
            path.display()
        );
    }
}
#[test]
fn kotodama_documentation_examples_run() {
    let compiler = kotodama_compiler();
    for (name, path) in documentation_examples() {
        eprintln!("running documentation example {name}");
        match name {
            "hajimari-entrypoint" => run_hajimari_snippet(&compiler, &path),
            "call-transfer-asset" => run_call_transfer_asset_snippet(&compiler, &path),
            "register-and-mint" => run_register_and_mint_snippet(&compiler, &path),
            "transfer-asset" => run_transfer_asset_snippet(&compiler, &path),
            "nft-flow" => run_nft_flow_snippet(&compiler, &path),
            "threshold-escrow" => run_threshold_escrow_snippet(&compiler, &path),
            other => panic!("unexpected snippet {other}"),
        }
    }
}
fn compile_snippet(compiler: &KotodamaCompiler, path: &Path) -> Vec<u8> {
    compiler
        .compile_file(path)
        .unwrap_or_else(|err| panic!("failed to compile {}: {err}", path.display()))
}
fn run_program_with_host<F>(label: &str, entrypoint: &str, bytecode: &[u8], host: WsvHost, check: F)
where
    F: FnOnce(&mut WsvHost),
{
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(bytecode)
        .unwrap_or_else(|err| panic!("load documentation example {label}: {err:?}"));
    common::select_kotodama_entrypoint(&mut vm, bytecode, entrypoint);
    if let Err(err) = vm.run() {
        panic!("run documentation example {label}: {err:?}");
    }
    let host_any = vm
        .host_mut_any()
        .expect("host must remain attached to the VM");
    let host_ref = host_any
        .downcast_mut::<WsvHost>()
        .expect("documentation examples use WsvHost");
    check(host_ref);
}
fn account(domain: &str, public_key: &str) -> AccountId {
    let _domain =
        iroha_model_base::domain::DomainId::try_new(domain, "universal").expect("domain id");
    let public_key: PublicKey = public_key.parse().expect("public key");
    AccountId::new(public_key)
}
const ACCOUNT_A_LITERAL: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
const ACCOUNT_B_LITERAL: &str = "sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76";
const DOCUMENTATION_CALLER_PUBLIC_KEY: &str =
    "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774";
const TEST_ASSET_DEFINITION_LITERAL: &str = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
fn parse_account_literal(raw: &str) -> AccountId {
    AccountId::parse_encoded(raw).expect("valid encoded account literal")
}
fn parse_asset_definition_literal(raw: &str) -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(raw).expect("valid asset definition literal")
}
#[derive(Default)]
struct LoggingCoreHost {
    inner: ivm::CoreHost,
}
impl LoggingCoreHost {
    fn new() -> Self {
        Self {
            inner: ivm::CoreHost::new(),
        }
    }
}
impl IVMHost for LoggingCoreHost {
    fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError> {
        match number {
            syscalls::SYSCALL_DEBUG_PRINT | syscalls::SYSCALL_DEBUG_LOG => Ok(0),
            _ => self.inner.prepare_syscall(number, vm),
        }
    }
    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
        match number {
            syscalls::SYSCALL_DEBUG_PRINT | syscalls::SYSCALL_DEBUG_LOG => Ok(0),
            _ => self.inner.syscall(number, vm),
        }
    }
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
fn setup_base_world(caller: &AccountId) -> MockWorldStateView {
    let domain: DomainId = iroha_model_base::domain::DomainId::try_new("default", "universal")
        .expect("default domain id");
    let mut wsv = MockWorldStateView::new();
    wsv.add_account_unchecked(caller.clone());
    wsv.grant_permission(caller, PermissionToken::RegisterDomain);
    wsv.grant_permission(caller, PermissionToken::RegisterAccount);
    assert!(
        wsv.register_domain(caller, domain.clone()),
        "register domain"
    );
    assert!(
        wsv.link_subject_to_domain(caller.clone(), domain),
        "link caller domain"
    );
    wsv
}
fn run_hajimari_snippet(compiler: &KotodamaCompiler, path: &Path) {
    let program = compile_snippet(compiler, path);
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(LoggingCoreHost::new());
    vm.load_program(&program)
        .expect("load hajimari snippet into IVM");
    common::select_kotodama_entrypoint(&mut vm, &program, "hajimari");
    vm.run().expect("run hajimari snippet");
}
fn run_threshold_escrow_snippet(compiler: &KotodamaCompiler, path: &Path) {
    let program = compile_snippet(compiler, path);
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(LoggingCoreHost::new());
    vm.load_program(&program)
        .expect("load threshold escrow snippet into IVM");
    common::select_kotodama_entrypoint(&mut vm, &program, "hajimari");
    vm.run().expect("run threshold escrow snippet");
}
fn run_register_and_mint_snippet(compiler: &KotodamaCompiler, path: &Path) {
    let program = compile_snippet(compiler, path);
    let caller = account("default", DOCUMENTATION_CALLER_PUBLIC_KEY);
    let mut wsv = setup_base_world(&caller);
    let asset_id = parse_asset_definition_literal(TEST_ASSET_DEFINITION_LITERAL);
    let recipient = parse_account_literal(ACCOUNT_A_LITERAL);
    wsv.grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
    wsv.grant_permission(&caller, PermissionToken::MintAsset(asset_id.clone()));
    assert!(
        wsv.register_account(&caller, recipient.clone()),
        "register recipient"
    );
    let host = WsvHost::new_with_subject(wsv, caller.clone());
    let asset_id_clone = asset_id.clone();
    run_program_with_host(
        "register-and-mint",
        "register_and_mint",
        &program,
        host,
        move |host| {
            let balance = host.wsv.balance(recipient.clone(), asset_id_clone.clone());
            assert!(
                balance >= Quantity::from(250_u64),
                "register-and-mint should mint at least 250 units (observed {balance})"
            );
        },
    );
}
fn run_transfer_asset_snippet(compiler: &KotodamaCompiler, path: &Path) {
    let program = compile_snippet(compiler, path);
    let caller = parse_account_literal(ACCOUNT_A_LITERAL);
    let mut wsv = setup_base_world(&caller);
    let recipient = parse_account_literal(ACCOUNT_B_LITERAL);
    let asset_id = parse_asset_definition_literal(TEST_ASSET_DEFINITION_LITERAL);
    wsv.grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
    wsv.grant_permission(&caller, PermissionToken::MintAsset(asset_id.clone()));
    assert!(
        wsv.register_account(&caller, recipient.clone()),
        "register recipient"
    );
    assert!(
        wsv.register_asset_definition(&caller, asset_id.clone(), Mintable::Infinitely),
        "seed asset definition"
    );
    assert!(
        wsv.mint(
            &caller,
            caller.clone(),
            asset_id.clone(),
            Quantity::from(20_u64)
        ),
        "seed caller balance"
    );
    let host = WsvHost::new_with_subject(wsv, caller.clone());
    let asset_id_clone = asset_id.clone();
    run_program_with_host(
        "transfer-asset",
        "do_transfer",
        &program,
        host,
        move |host| {
            let caller_balance = host.wsv.balance(caller.clone(), asset_id_clone.clone());
            let recipient_balance = host.wsv.balance(recipient.clone(), asset_id_clone.clone());
            assert!(
                recipient_balance >= Quantity::from(10_u64),
                "recipient balance should increase (observed {recipient_balance})"
            );
            let total = caller_balance
                .checked_add(&recipient_balance)
                .expect("sum caller + recipient");
            assert_eq!(
                total,
                Quantity::from(20_u64),
                "transfer preserves total balance"
            );
        },
    );
}
fn run_call_transfer_asset_snippet(compiler: &KotodamaCompiler, path: &Path) {
    let program = compile_snippet(compiler, path);
    let caller = account("default", DOCUMENTATION_CALLER_PUBLIC_KEY);
    let mut wsv = setup_base_world(&caller);
    let alice = parse_account_literal(ACCOUNT_A_LITERAL);
    let bob = parse_account_literal(ACCOUNT_B_LITERAL);
    let asset_id = parse_asset_definition_literal(TEST_ASSET_DEFINITION_LITERAL);
    wsv.grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
    wsv.grant_permission(&caller, PermissionToken::MintAsset(asset_id.clone()));
    wsv.grant_permission(&caller, PermissionToken::TransferAsset(asset_id.clone()));
    assert!(
        wsv.register_account(&caller, alice.clone()),
        "register alice"
    );
    assert!(wsv.register_account(&caller, bob.clone()), "register bob");
    assert!(
        wsv.register_asset_definition(&caller, asset_id.clone(), Mintable::Infinitely),
        "register asset definition"
    );
    assert!(
        wsv.mint(
            &caller,
            alice.clone(),
            asset_id.clone(),
            Quantity::from(15_u64)
        ),
        "seed alice balance"
    );
    let asset_id_clone = asset_id.clone();
    run_program_with_host(
        "call-transfer-asset",
        "pay",
        &program,
        WsvHost::new_with_subject(wsv, caller.clone()),
        move |host| {
            let alice_balance = host.wsv.balance(alice.clone(), asset_id_clone.clone());
            let bob_balance = host.wsv.balance(bob.clone(), asset_id_clone.clone());
            assert!(
                bob_balance >= Quantity::from(10_u64),
                "contract transfer should credit bob (observed {bob_balance})"
            );
            let total = alice_balance
                .checked_add(&bob_balance)
                .expect("sum alice + bob");
            assert_eq!(
                total,
                Quantity::from(15_u64),
                "transfer preserves total supply"
            );
        },
    );
}
fn run_nft_flow_snippet(compiler: &KotodamaCompiler, path: &Path) {
    let program = compile_snippet(compiler, path);
    let caller = parse_account_literal(ACCOUNT_A_LITERAL);
    let mut wsv = setup_base_world(&caller);
    let recipient = parse_account_literal(ACCOUNT_B_LITERAL);
    assert!(
        wsv.register_account(&caller, recipient.clone()),
        "register recipient"
    );
    let nft_id = NftId::from_str("n0$wonderland.universal").expect("nft id");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(WsvHost::new_with_subject(wsv, caller.clone()));
    vm.load_program(&program)
        .expect("load documentation example nft-flow");
    common::select_kotodama_entrypoint(&mut vm, &program, "nft_issue_and_transfer");
    if let Err(err) = vm.run() {
        let host_any = vm
            .host_mut_any()
            .expect("host must remain attached to the VM");
        let host_ref = host_any
            .downcast_mut::<WsvHost>()
            .expect("developer snippets use WsvHost");
        let owner_after = host_ref.wsv.nft_owner(&nft_id);
        panic!(
            "nft-flow failed with {err:?}; owner_after={owner_after:?} issuer_callers={}",
            host_ref.caller
        );
    }
    let host_any = vm
        .host_mut_any()
        .expect("host must remain attached to the VM");
    let host_ref = host_any
        .downcast_mut::<WsvHost>()
        .expect("developer snippets use WsvHost");
    assert!(
        host_ref.wsv.nft_owner(&nft_id).is_none(),
        "nft should be burned by the flow"
    );
}
