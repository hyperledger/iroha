//! Fresh-state installed deployment for bytecode and package inputs.

use super::*;

#[derive(Clone, Copy)]
enum Input {
    Bytecode,
    Package,
}

/// Exercise each remaining input with an independent, previously absent managed store.
pub(in crate::mochi) fn run(kagami: &Path) -> Result<(), Box<dyn Error>> {
    run_input(kagami, Input::Bytecode)?;
    run_input(kagami, Input::Package)
}

fn run_input(kagami: &Path, input: Input) -> Result<(), Box<dyn Error>> {
    let mut harness = Harness::new(kagami)?;
    let (path, expected) = match input {
        Input::Bytecode => {
            fs::write(
                harness.workspace.join("hello.to"),
                prepare_distinct_bytecode()?,
            )?;
            ("hello.to", "60")
        }
        Input::Package => {
            let package = harness.workspace.join("package");
            fs::create_dir(&package)?;
            fs::write(package.join("Musubi.toml"), PACKAGE_MANIFEST)?;
            fs::write(package.join("contract.ko"), PACKAGE_SOURCE)?;
            ("package", "90")
        }
    };
    match fs::symlink_metadata(&harness.state) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("cold deployment requires an absent managed store".into()),
    }
    let result = (|| {
        let first = harness.command(&["contract", "deploy", path])?;
        require_deployment(&first)?;
        let initial = harness.command(&["localnet", "status"])?;
        require_phase(&initial, "ready", 4)?;
        harness.execute_on_every_peer(&first, expected)?;
        let repeated = harness.command(&["contract", "deploy", path])?;
        require_same_deployment(&first, &repeated)?;
        let retained = harness.command(&["localnet", "status"])?;
        require_same_context(&initial, &retained)?;
        require_phase(&retained, "ready", 4)
    })();
    let stopped = harness
        .command(&LOCAL_CLEANUP)
        .and_then(|value| require_zero_owned_resources(&value));
    match (result, stopped) {
        (Ok(()), Ok(())) => Ok(()),
        (result, stopped) => {
            let root = harness.root.keep();
            Err(format!("cold {path} deployment failed; retained diagnostics at {}: flow={result:?}; cleanup={stopped:?}", root.display()).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both inputs must start their own default network in the first deployment invocation.
    #[test]
    #[ignore = "requires IROHA_DEVEX_BUNDLE_BIN pointing to matching native runtime binaries"]
    fn installed_bytecode_and_package_start_without_configuration() {
        let directory = std::env::var_os("IROHA_DEVEX_BUNDLE_BIN")
            .map(PathBuf::from)
            .expect("set IROHA_DEVEX_BUNDLE_BIN to the canonical installed runtime directory");
        let kagami = directory.join(if cfg!(windows) {
            "kagami.exe"
        } else {
            "kagami"
        });
        run(&kagami).expect("each input must start four peers and retain its exact deployment");
    }
}
