# Kotodama for Visual Studio Code

Kotodama is the smart-contract language of the Iroha Virtual Machine: `.ko`
sources compile to IVM bytecode (`.to`). This extension starts `musubi lsp` for
Musubi projects and `koto lsp` for standalone sources, and ships the canonical
TextMate grammar.

Editor features come from the compiler itself:

- diagnostics, including standalone `*.test.ko` modules checked in test mode
  against their `koto_test { target: ... }` seiyaku;
- completion that follows the cursor position (source-unit keywords at the top
  level, declarations inside a seiyaku or module, statements and values inside
  function bodies, members after `.`, paths after `::`);
- hover and signature help rendered in Kotodama syntax, with the documentation
  of every builtin;
- definition, references, highlights and rename, including compile-time checked
  `kotoage: "name"` test selector references; test calls pass schema-checked typed
  argument records;
- document outline, workspace symbols, folding and semantic highlighting;
- a **Run test** code lens on every `#[test]` function;
- formatting with `koto fmt` rules and quick fixes.

The branded keywords have two equal spellings: `seiyaku`/`誓約`,
`kotoage`/`言挙げ`, `hajimari`/`始まり` and `kaizen`/`改善`. Both spellings are the
same keyword, may be mixed freely, highlight identically and are both offered
by completion; hover echoes the spelling you wrote.

## Install

The extension and the `koto` and `musubi` executables must come from the same Iroha checkout
or release. The language server reports its version in the `serverInfo` of
its LSP `initialize` response.

1. Build both tools from the Iroha workspace:

   ```sh
   cargo build --release -p kotodama_toolchain --bin koto -p musubi --bin musubi
   ```

   Put `target/release` on `PATH`, or set the absolute executable paths in
   `kotodama.kotoPath` and `kotodama.musubiPath`.

2. Package and install the extension from this directory (Node.js 22 or newer):

   ```sh
   npm ci --ignore-scripts
   npm test
   npm run package          # runs `vsce package --out kotodama.vsix`
   code --install-extension kotodama.vsix
   ```

   `npm test` checks the client configuration and tokenizes the grammar
   samples with the same TextMate engine VS Code uses. After an intentional
   grammar change, review and refresh the snapshot with
   `KOTODAMA_UPDATE_SNAPSHOT=1 npm test`. The extension is not published to a
   marketplace; install the packaged `.vsix`.

## Configure

| Setting | Default | Meaning |
| --- | --- | --- |
| `kotodama.kotoPath` | `koto` | Standalone compiler executable. |
| `kotodama.musubiPath` | `musubi` | Project tool executable. |
| `kotodama.manifestPath` | empty | Explicit `Musubi.toml`, relative to the workspace folder; `${workspaceFolder}` expands. Otherwise discover the nearest ancestor manifest. |
| `kotodama.contract` | empty | Select a unique target name or `namespace/package::target` for navigation in shared sources. |
| `kotodama.chainDiscriminant` | `753` | Account-address chain discriminant for standalone sources. |
| `kotodama.zk` | `false` | Enable the explicit ZK compilation capability. |

The client starts one server per workspace folder. A folder with a Musubi
manifest uses `musubi lsp --manifest-path <Musubi.toml> [--contract <target>]
[--zk]`. Musubi resolves the same manifest and lockfile as its build and test
commands. Diagnostics include all selected targets; navigation in a source with
several distinct package identities requires an explicit contract selection.
Local workspace manifest buffers participate in resolution and export rename.
Cached dependency manifests remain read-only.

A folder without a manifest uses `koto lsp --source-root <folder> [--zk]`.
Each open seiyaku follows its own `include` and `import` directives; other open
files do not establish imports. Standalone test modules attach to the seiyaku
named by `koto_test { target: ... }`, including entrypoint selector rename.
For several independent projects inside one large directory, add their folders
to the editor workspace or set an explicit manifest for the folder.

**Kotodama: Restart Language Server** restarts every client after replacing an
executable. Configuration and workspace-folder changes restart clients
automatically. The extension requires a trusted workspace and passes arguments
without a shell. **Run test** invokes the matching tool with an exact test
filter; project tests retain their manifest, package, and contract selection.
Both tools retain the resolved chain discriminant and ZK compilation capability.
Project tests also retain explicit network/client-config selection and run with
`--locked --offline`, preserving the dependency graph used by the editor.

## Other editors

Any Language Server Protocol client can run either server over stdio. Use
`musubi lsp --manifest-path <Musubi.toml>` for a project, adding `--contract`
when navigating an ambiguous shared source. Use `koto lsp --source-root <dir>`
for standalone sources. Both accept `--zk`, use UTF-16 positions and full-document
synchronization. Forward editable `Musubi.toml` buffers to the project server
without replacing the editor's TOML formatting and completion providers.

The TextMate grammar in `syntaxes/` is generated by
`scripts/regenerate_kotodama_syntax.py` from
`crates/kotodama_lang/grammar/v1.lex`; edit the generator, not the generated
regions. It is also the grammar proposed to GitHub Linguist.

[Kotodama smart contracts](https://docs.iroha.tech/blockchain/smart-contracts)
