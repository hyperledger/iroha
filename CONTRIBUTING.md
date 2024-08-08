# Contributing Guide

Thank you for taking the time to contribute to Iroha 2!

Please read this guide to learn how you can contribute and which guidelines we expect you to follow. This includes the guidelines about code and documentation as well as our conventions regarding git workflow.

Reading these guidelines will save you time later.

## How Can I Contribute?

There are a lot of ways you could contribute to our project:

- Report [bugs](#reporting-bugs) and [vulnerabilities](#reporting-vulnerabilities)
- [Suggest improvements](#suggesting-improvements) and implement them
- [Ask questions](#asking-questions) and engage with the community

New to our project? [Make your first contribution](#your-first-code-contribution)!

### TL;DR

- Find [ZenHub](https://app.zenhub.com/workspaces/iroha-v2-60ddb820813b9100181fc060/board?repos=181739240).
- Fork [Iroha](https://github.com/hyperledger/iroha/tree/main).
- Fix your issue of choice.
- Ensure you follow our [style guides](#style-guides) for code and documentation.
- Write [tests](https://doc.rust-lang.org/cargo/commands/cargo-test.html). Ensure they all pass (`cargo test --workspace`).
- Perform pre-commit routine like formatting & artifacts regeneration (see [`pre-commit.sample`](./hooks/pre-commit.sample))
- With the `upstream` set to track [Hyperledger Iroha repository](https://github.com/hyperledger/iroha), `git pull -r upstream main`, `git commit -s`, `git push <your-fork>`, and [create a pull request](https://github.com/hyperledger/iroha/compare) to the `main` branch. Ensure it follows the [pull request guidelines](#pull-request-etiquette).

### Reporting Bugs

A *bug* is an error, design flaw, failure or fault in Iroha that causes it to produce an incorrect, unexpected, or unintended result or behaviour.

We track Iroha bugs via [Github Issues](https://github.com/hyperledger/iroha/issues?q=is%3Aopen+is%3Aissue+label%3ABug) labeled with the `Bug` tag.

When you create a new issue, there is a template for you to fill in. Here's the checklist of what you should do when you are reporting bugs:
- [ ] Add the `Bug` tag
- [ ] Explain the issue
- [ ] Provide a minimum working example
- [ ] Attach a screenshot

<details> <summary>Minimum working example</summary>

For each bug, you should provide a [minimum working example](https://en.wikipedia.org/wiki/Minimal_working_example). For example:

```
# Minting negative Assets with value spec `Numeric`.

I was able to mint negative values, which shouldn't be possible in Iroha. This is bad because <X>.

# Given

I managed to mint negative values by running
<paste the code here>

# I expected

not to be able to mint negative values

# But, I got

<code showing negative value>

<paste a screenshot>
```

</details>

---
**Note:** Issues such as outdated documentation, insufficient documentation, or feature requests should use the `Documentation` or `Enhancement` labels. They are not bugs.

---

### Reporting Vulnerabilities

While we are proactive in preventing security problems, it is possible that you might come across a security vulnerability before we do.

- Before the First Major Release (2.0) all vulnerabilities are considered bugs, so feel free to submit them as bugs [following the instructions above](#reporting-bugs).
- After the First Major Release, use our [bug bounty program](https://hackerone.com/hyperledger) to submit vulnerabilities and get your reward.

:exclamation: To minimize the damage caused by an unpatched security vulnerability, you should disclose the vulnerability directly to Hyperledger as soon as possible and **avoid disclosing the same vulnerability publicly** for a reasonable period of time.

If you have any questions regarding our handling of security vulnerabilities, please feel free to contact any of the currently active maintainers in Rocket.Chat private messages.

### Suggesting Improvements

Create [an issue](https://github.com/hyperledger/iroha/issues/new) on GitHub with the appropriate tags (`Optimization`, `Enhancement`) and describe the improvement you are suggesting. You may leave this idea for us or someone else to develop, or you may implement it yourself.

If you intend to implement the suggestion yourself, do the following:

1. Assign the issue you created to yourself **before** you start working on it.
2. Work on the feature you suggested and follow our [guidelines for code and documentation](#style-guides).
3. When you are ready to open a pull request, make sure you follow the [pull request guidelines](#pull-request-etiquette) and mark it as implementing the previously created issue:

   ```
   feat: Description of the feature

   Explanation of the feature

   Closes #1234
   ```

4. If your change requires an API change, use the `api-changes` tag.

   **Note:** features that require API changes may take longer to implement and approve as they require Iroha library makers to update their code.

### Asking Questions

A question is any discussion that is neither a bug nor a feature or optimization request.

<details> <summary> How do I ask a question? </summary>

Please post your questions to [one of our instant messaging platforms](#contacts) so that the staff and members of the community could help you in a timely manner.

You, as part of the aforementioned community, should consider helping others too. If you decide to help, please do so in a [respectful manner](CODE_OF_CONDUCT.md).

</details>

## Your First Code Contribution

1. Find a beginner-friendly issue among issues with the [good-first-issue](https://github.com/hyperledger/iroha/labels/good%20first%20issue) label.
2. Make sure that no one else is working on the issues you have chosen by checking that it is not assigned to anybody.
3. Assign the issue to yourself so that others can see that someone is working on it.
4. Read our [Rust Style Guide](#rust-style-guide) before you start writing code.
5. When you are ready to commit your changes, read the [pull request guidelines](#pull-request-etiquette).

## Pull Request Etiquette

Please [fork](https://docs.github.com/en/get-started/quickstart/fork-a-repo) the [repository](https://github.com/hyperledger/iroha/tree/main) and [create a feature branch](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-and-deleting-branches-within-your-repository) for your contributions. When working with **PRs from forks**, check [this manual](https://help.github.com/articles/checking-out-pull-requests-locally).

#### Working on code contribution:
- Follow the [Rust Style Guide](#rust-style-guide) and the [Documentation Style Guide](#documentation-style-guide).
- Ensure that the code you've written is covered by tests. If you fixed a bug, please turn the minimum working example that reproduces the bug into a test.

#### Committing your work:
- Follow the [Git Style Guide](#git-workflow).
- Squash your commits [either before](https://www.git-tower.com/learn/git/faq/git-squash/) or [during the merge](https://rietta.com/blog/github-merge-types/).
- If during the preparation of your pull request your branch got out of date, rebase it locally with `git pull --rebase upstream main`. Alternatively, you may use the drop-down menu for the `Update branch` button and choose the `Update with rebase` option.

  In the interest of making this process easier for everyone, try not to have more than a handful of commits for a pull request, and avoid re-using feature branches.

#### Creating a pull request:
- Use an appropriate pull request description by filling in the [description template](.github/PULL_REQUEST_TEMPLATE.md). Avoid deviating from this template if possible.
- Add an appropriately formatted [pull request title](#pull-request-titles).
- If you feel like your code isn't ready to merge, but you want the maintainers to look through it, create a draft pull request.

#### Merging your work:
- A pull request must pass all automated checks before being merged. At a minimum, the code must be formatted, passing all tests, as well as having no outstanding `clippy` lints.
- A pull request cannot be merged without two approving reviews from the active maintainers.
- Each pull request will automatically notify the code owners. An up to date list of current maintainers can be found in [MAINTAINERS.md](MAINTAINERS.md).

#### Review etiquette:
- Do not resolve a conversation on your own. Let the reviewer make a decision.
- Acknowledge review comments and engage with the reviewer (agree, disagree, clarify, explain, etc.). Do not ignore comments.
- For simple code change suggestions, if you apply them directly, you can resolve the conversation.
- Avoid overwriting your previous commits when pushing new changes. It obfuscates what changed since the last review and forces the reviewer to start from scratch. Commits are squashed before merging automatically.

### Pull Request Titles

We parse the titles of all the merged pull requests to generate changelogs. We also check that the title follows the convention via the *`check-PR-title`* check.

To pass the *`check-PR-title`* check, the pull request title must adhere to the following guidelines:

<details> <summary> Expand to read the detailed title guidelines</summary>

1. Follow the [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/#commit-message-with-multi-paragraph-body-and-multiple-footers) format.

2. If the pull request has a single commit, the PR title should be the same as the commit message.

</details>

### Git Workflow

- [Fork](https://docs.github.com/en/get-started/quickstart/fork-a-repo) the [repository](https://github.com/hyperledger/iroha/tree/main) and [create a feature branch](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-and-deleting-branches-within-your-repository) for your contributions.
- [Configure the remote](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/configuring-a-remote-for-a-fork) to sync your fork with the [Hyperledger Iroha repository](https://github.com/hyperledger/iroha/tree/main).
- Use the [Git Rebase Workflow](https://git-rebase.io/). Avoid using `git pull`. Use `git pull --rebase` instead.
- Use the provided [git hooks](./hooks/) to ease the development process.

Follow these commit guidelines:

- **Sign-off every commit**. If you don't, [DCO](https://github.com/apps/dco) will not let you merge.

  Use `git commit -s` to automatically add `Signed-off-by: $NAME <$EMAIL>` as the final line of your commit message. Your name and email should be the same as specified in your GitHub account.

  We also encourage you to sign your commits with GPG key using `git commit -sS` ([learn more](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)).

  You may use [the `commit-msg` hook](./hooks/) to automatically sign-off your commits.

- Commit messages must follow [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/#commit-message-with-multi-paragraph-body-and-multiple-footers) and the same naming schema as for [pull request titles](#pull-request-titles). This means:
  - **Use present tense** ("Add feature", not "Added feature")
  - **Use imperative mood** ("Deploy to docker..." not "Deploys to docker...")
- Write a meaningful commit message.
- Try keeping a commit message short.
- If you need to have a longer commit message:
  - Limit the first line of your commit message to 50 characters or less.
  - The first line of your commit message should contain the summary of the work you've done. If you need more than one line, leave a blank line between each paragraph and describe your changes in the middle. The last line must be the sign-off.
- If you modify the Schema (check by generating the schema with `kagami schema` and diff), you should make all changes to the schema in a separate commit with the message `[schema]`.
- Try to stick to one commit per meaningful change.
  - If you fixed several issues in one PR, give them separate commits.
  - As mentioned previously, changes to the `schema` and the API should be done in appropriate commits separate from the rest of your work.
  - Add tests for functionality in the same commit as that functionality.

## Tests and Benchmarks

- To run the source-code based tests, execute [`cargo test`](https://doc.rust-lang.org/cargo/commands/cargo-test.html) in the Iroha root. Note that this is a long process.
- To run benchmarks, execute [`cargo bench`](https://doc.rust-lang.org/cargo/commands/cargo-bench.html) from the Iroha root. To help debug benchmark outputs, set the `debug_assertions` environment variable like so: `RUSTFLAGS="--cfg debug_assertions" cargo bench`.
- If you are working on a particular component, be mindful that when you run `cargo test` in a [workspace](https://doc.rust-lang.org/cargo/reference/workspaces.html), it will only run the tests for that workspace, which usually doesn't include any [integration tests](https://www.testingxperts.com/blog/what-is-integration-testing).
- If you want to test your changes on a minimal network, the provided [`docker-compose.yml`](defaults/docker-compose.yml) creates a network of 4 Iroha peers in docker containers that can be used to test consensus and asset propagation-related logic. We recommend interacting with that network using either [`iroha-python`](https://github.com/hyperledger/iroha-python), or the included Iroha client CLI.
- Do not remove failing tests. Even tests that are ignored will be run in our pipeline eventually.
- If possible, please benchmark your code both before and after making your changes, as a significant performance regression can break existing users' installations.

### Debugging tests

<details> <summary> Expand to learn how to change the log level or write logs to a JSON.</summary>

If one of your tests is failing, you may want to decrease the maximum logging level. By default, Iroha only logs `INFO` level messages, but retains the ability to produce both `DEBUG` and `TRACE` level logs. This setting can be changed either using the `LOG_LEVEL` environment variable for code-based tests, or using the `/configuration` endpoint on one of the peers in a deployed network.

While logs printed in the `stdout` are sufficient, you may find it more convenient to produce `json`-formatted logs into a separate file and parse them using either [node-bunyan](https://www.npmjs.com/package/bunyan) or [rust-bunyan](https://crates.io/crates/bunyan).

Set the `LOG_FILE_PATH` environment variable to an appropriate location to store the logs and parse them using the above packages.

</details>

### Debugging using tokio console

<details> <summary> Expand to learn how to compile Iroha with tokio console support.</summary>

Sometimes it might be helpful for debugging to analyze tokio tasks using [tokio-console](https://github.com/tokio-rs/console).

In this case you should compile Iroha with support of tokio console like that:

```bash
RUSTFLAGS="--cfg tokio_unstable" cargo build --features tokio-console
```

Port for tokio console can by configured through `LOG_TOKIO_CONSOLE_ADDR` configuration parameter (or environment variable).
Using tokio console require log level to be `TRACE`, can be enabled through configuration parameter or environment variable `LOG_LEVEL`.

Example of running Iroha with tokio console support using `scripts/test_env.sh`:

```bash
# 1. Compile Iroha
RUSTFLAGS="--cfg tokio_unstable" cargo build --features tokio-console
# 2. Run Iroha with TRACE log level
LOG_LEVEL=TRACE ./scripts/test_env.sh setup
# 3. Access Iroha. Peers will be available on ports 5555, 5556, ...
tokio-console http://127.0.0.1:5555
```

</details>

### Profiling

<details> <summary> Expand to learn how to profile Iroha. </summary>

To optimize performance it's useful to profile Iroha.

To do that you should compile Iroha with `profiling` profile and with `profiling` feature:

```bash
RUSTFLAGS="-C force-frame-pointers=on" cargo +nightly -Z build-std build --target your-desired-target --profile profiling --features profiling
```

Then start Iroha and attach profiler of your choice to the Iroha pid.

Alternatively it's possible to build Iroha inside docker with profiler support and profile Iroha this way.

```bash
docker build -f Dockerfile.glibc --build-arg="PROFILE=profiling" --build-arg='RUSTFLAGS=-C force-frame-pointers=on' --build-arg='FEATURES=profiling' --build-arg='CARGOFLAGS=-Z build-std' -t iroha:profiling .
```

E.g. using perf (available only on linux):

```bash
# to capture profile
sudo perf record -g -p <PID>
# to analyze profile
sudo perf report
```

To be able to observe profile of the executor during Iroha profiling, executor should be compiled without stripping symbols.
It can be done by running:

```bash
# compile executor without optimizations
cargo run --bin iroha_wasm_builder -- build ./path/to/executor --out-file executor.wasm
```

With profiling feature enabled Iroha exposes endpoint to scrap pprof profiles:

```bash
# profile Iroha for 30 seconds and get protobuf profile
curl host:port/debug/pprof/profile?seconds=30 -o profile.pb
# analyze profile in browser (required installed go)
go tool pprof -web profile.pb
```

</details>

## Style Guides

Please follow these guidelines when you make code contributions to our project:

### Git Style Guide

:book: [Read git guidelines](#git-workflow)

### Rust Style Guide

<details> <summary> :book: Read code guidelines</summary>

- Use `cargo +nightly fmt --all` to format code (we use [`group_imports`](https://github.com/rust-lang/rustfmt/issues/5083) and [`imports_granularity`](https://github.com/rust-lang/rustfmt/issues/4991)).

Code guidelines:

- Unless otherwise specified, refer to [Rust best practices](https://github.com/mre/idiomatic-rust).
- Use the `mod.rs` style. [Self-named modules](https://rust-lang.github.io/rust-clippy/master/) will not pass static analysis, except as [`trybuild`](https://crates.io/crates/trybuild) tests.
- Use a domain-first modules structure.

  Example: don't do `constants::logger`. Instead, invert the hierarchy, putting the object for which it is used first: `iroha_logger::constants`.
- Use [`expect`](https://learning-rust.github.io/docs/e4.unwrap_and_expect.html) with an explicit error message or proof of infallibility instead of `unwrap`.
- Never ignore an error. If you can't `panic` and can't recover, it at least needs to be recorded in the log.
- Prefer to return a `Result` instead of `panic!`.

  Exception: when implementing something that uses `issue_send` instead of `send` ([more about actors](docs/source/guides/actor.md)). Actors and parallelism don't mix; you could deadlock the entire peer, so it's better to `panic!` if something goes wrong. This is a necessary concession for asynchronous programming.
- Group related functionality spatially, preferably inside appropriate modules.

  For example, instead of having a block with `struct` definitions and then `impl`s for each individual struct, it is better to have the `impl`s related to that `struct` next to it.
- Declare before implementation: `use` statements and constants at the top, unit tests at the bottom.
- Try to avoid `use` statements if the imported name is used only once. This makes moving your code into a different file easier.
- Do not silence `clippy` lints indiscriminately. If you do, explain your reasoning with a comment (or `expect` message).
- Prefer  `#[outer_attribute]` to `#![inner_attribute]` if either is available.
- If your function doesn't mutate any of its inputs (and it shouldn't mutate anything else), mark it as `#[must_use]`.
- Avoid `Box<dyn Error>` if possible (we prefer strong typing).
- If your function is a getter/setter, mark it `#[inline]`.
- If your function is a constructor (i.e., it's creating a new value from the input parameters and calls `default()`), mark it `#[inline]`.
- Avoid tying your code to concrete data structures; `rustc` is smart enough to turn a `Vec<InstructionExpr>` into `impl IntoIterator<Item = InstructionExpr>` and vice versa when it needs to.

Naming guidelines:
- Use only full words in *public* structure, variable, method, trait, constant, and module names. However, abbreviations are allowed if:
  - The name is local (e.g. closure arguments).
  - The name is abbreviated by Rust convention (e.g. `len`, `typ`).
  - The name is an accepted abbreviation (e.g. `tx`, `wsv` etc) TODO link glossary.
  - The full name would have been shadowed by a local variable (e.g. `msg <- message`).
  - The full name would have made the code cumbersome with more than 5-6 words in it (e.g. `WorldStateViewReceiverTrait -> WSVRecvTrait`).
- If you change naming conventions, make sure that the new name that you've chosen is _much_ clearer than what we had before.

Comment guidelines:
- When writing non-doc comments, instead of describing *what* your function does, try to explain *why* it does something in a particular way. This will save you and the reviewer time.
- You may leave `TODO` markers in code as long as you reference an issue that you created for it. Not creating an issue means it doesn't get merged.

We use pinned dependencies. Follow these guidelines for versioning:

- If your work depends on a particular crate, see if it wasn't already installed using [`cargo tree`](https://doc.rust-lang.org/cargo/commands/cargo-tree.html) (use `bat` or `grep`), and try to use that version, instead of the latest version.
- Use the full version "X.Y.Z" in `Cargo.toml`.
- Provide version bumps in a separate PR.

</details>

### Documentation Style Guide

<details> <summary> :book: Read documentation guidelines</summary>


- Use the [`Rust Docs`](https://doc.rust-lang.org/cargo/commands/cargo-doc.html) format.
- Prefer the single-line comment syntax. Use `///` above inline modules and `//!` for file-based modules.
- If you can link to a structure/module/function's docs, do it.
- If you can provide an example of usage, do it. This [is also a test](https://doc.rust-lang.org/rustdoc/documentation-tests.html).
- If a function can error or panic, avoid modal verbs. Example: `Fails if disk IO fails` instead of `Can possibly fail, if disk IO happens to fail`.
- If a function can error or panic for more than one reason, use a bulleted list of failure conditions, with the appropriate `Error` variants (if any).
- Functions *do* things. Use imperative mood.
- Structures *are* things. Get to the point. For example `Log level for reloading from the environment` is better than `This struct encapsulates the idea of logging levels, and is used for reloading from the environment`.
- Structures have fields, which also *are* things.
- Modules *contain* things, and we know that. Get to the point. Example: use `Logger-related traits.` instead of `Module which contains logger-related logic`.


</details>

## Contact

Our community members are active at:

| Service       | Link                                                         |
| ------------- | ------------------------------------------------------------ |
| RocketChat    | https://chat.hyperledger.org/channel/iroha                   |
| StackOverflow | https://stackoverflow.com/questions/tagged/hyperledger-iroha |
| Mailing List  | hyperledger-iroha@lists.hyperledger.org                      |
| Gitter        | https://gitter.im/hyperledger-iroha/Lobby                    |
| Telegram      | https://t.me/hl_iroha                                        |
| YouTube       | https://www.youtube.com/channel/UCYlK9OrZo9hvNYFuf0vrwww     |

---
