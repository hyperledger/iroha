# Mochi native developer bundle

The bundle contains matching native executables for the desktop, developer CLI
and four-validator runtime:

On macOS the package contains one application with all three programs:

```text
Mochi.app/Contents/Info.plist
Mochi.app/Contents/MacOS/mochi
Mochi.app/Contents/MacOS/kagami
Mochi.app/Contents/MacOS/iroha3d
Mochi.app/Contents/Resources/Mochi.icns # Finder icon
Mochi.app/Contents/Resources/network-profiles.nrt # required release-owned Taira preset
docs/README.md
LICENSE
manifest.json
```

Linux and Windows put the three programs and release-owned `network-profiles.nrt` in
`bin/`; executable names end in `.exe` on Windows. macOS has no outer `bin/`
copies or launch scripts. Keep the application intact: its CLI and validator
are part of the same installed runtime. You may move or rename the application
before creating a managed environment. Retained environments pin their original
runtime location; relocation does not rewrite that custody.

The application metadata supplies a native desktop identity and the Mochi icon
shown in Finder. Bundle assembly alone does not establish code signing,
notarization or authenticated release provenance.

## Start from a project

On macOS, copy `Mochi.app` to your preferred installation directory and use its
CLI directly (or add that exact `Contents/MacOS` directory to your shell PATH):

```sh
/Applications/Mochi.app/Contents/MacOS/kagami localnet up
/Applications/Mochi.app/Contents/MacOS/kagami contract deploy hello.ko
/Applications/Mochi.app/Contents/MacOS/kagami localnet down
```

On Linux and Windows use the corresponding `bin/kagami` or `bin/kagami.exe`
inside the extracted bundle.

No supplied TOML, source checkout, build tools or container runtime is needed.
Deployment accepts `.ko`, `.to` and existing Musubi packages. With no selected
context, deployment starts the default localnet in the same invocation.

Open the desktop for the same project with:

```sh
/Applications/Mochi.app/Contents/MacOS/mochi --workspace /path/to/project
```

You can also open `Mochi.app` in Finder, then choose the project directory in the
workspace field and select **Open** before starting a network. Launch alone
creates no network or signing identity. On Linux/Windows launch `bin/mochi`
(`mochi.exe` on Windows). Omit `--workspace` when launching from a shell to use
the current directory. Both frontends call the same
services and select the same retained context. The desktop does not own a
separate network generator or supervisor.

## Retained state

Generated configuration, keys, journals and ledger files stay in private OS
application storage outside the project. Each workspace has its own selection.
Repeated `localnet up` and `down`/`up` retain the same network and account.
Repeated unchanged deployment recovers its original evidence and verifies
current code and alias state.
The result says which localnet or private dataspace applied the deployment.
Any parent receipt is shown separately as historical evidence; parent observation
failure preserves the original successful deployment and recovery journal.

Use `kagami context list`, `context show`, `context use <name>`,
`localnet status` and `localnet logs` to inspect the environment.
`localnet reset local` explicitly retires a stopped generation; a subsequent
`localnet up` creates a fresh ledger. Reset does not transfer old funds or
contract state.

Advanced operator bundle generation is `kagami localnet generate`; managed
startup needs none of its input files or generated scripts.

## Artifact verification and qualification

`manifest.json` records every packaged file and its size and SHA-256 digest.
Release provenance must authenticate the manifest before those digests establish
trust in a downloaded bundle.

Release tooling automatically includes the exact committed
`defaults/developer/network-profiles.nrt` from the authenticated release source. It requires
an independently approved Taira release key, rollback floor and HTTPS checkpoint location;
missing or changed original material refuses packaging. The bundle manifest includes its
exact digest. Installed developers supply no artifact. Neither a downloaded checkpoint nor
an installer argument may choose the official release authority. Debug/development bundles
may intentionally supply an explicit fixture profile or omit remote authority.

Preset installation does not prove current remote service or attachment. Production Taira
checkpoint publication and official remote attachment still require their separate checks.

The repository's `cargo xtask` alias enables the required `dev-tools` feature.

The release acceptance gates include clean-install runs on macOS/Linux ARM64
and x86-64 and Windows x86-64. Source compilation and component tests do not
establish those native runtime results. Private dataspace attachment and startup
latency remain separate acceptance gates in the repository's developer-experience
specification.

The repository's `devex_native.yml` workflow is a manual native qualification
entry point. Dispatch it at the candidate commit with existing runner labels for
all five required OS/architecture targets; each runner must provide at least
13 GiB RAM and 50 GiB free build storage. It builds the locked `release` profile,
runs native custody and managed-runtime tests, and exercises the installed bundle.
Its runtime-directory inputs resolve to `Mochi.app/Contents/MacOS` on both macOS
architectures and `bin` on Linux/Windows.
It also runs the ignored eight-validator attachment fixture. That test controller
requires Python 3.10 or newer with SSL support and OpenSSL; its temporary CA is
supplied only to the fixture's child processes, without changing system trust.
These tools are qualification prerequisites; installed developer commands use
the native executables in the bundle.
`local-release` is rejected for packaging. Workflow source and component checks
do not imply that those native jobs have passed; official-network attachment and
the repeated startup-latency campaign remain separate qualification work.
