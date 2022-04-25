# Contributing Guide

First off, thanks for taking the time to contribute!

The following is a short set of guidelines for contributing to Iroha.

## How Can I Contribute?

### TL;DR

* Find [ZenHub](https://app.zenhub.com/workspaces/iroha-v2-60ddb820813b9100181fc060/board?repos=181739240).
* Fork [Iroha](https://github.com/hyperledger/iroha/tree/iroha2-dev).
* Fix your issue of choice.
* Write [tests](https://doc.rust-lang.org/cargo/commands/cargo-test.html). Ensure they all pass (`cargo test`).
* Fix [`clippy`](https://lib.rs/crates/cargo-lints) warnings: `cargo lints clippy --workspace --benches --tests --examples --all-features`
* Format code `cargo +nightly fmt --all` and generate docs `cargo run --bin kagami -- docs >"docs/source/references/config.md" && git add "docs/source/references/config.md"`
* `git pull -r hyperledger iroha2-dev`, `git commit -s`, `git push <your-fork>`, and [create a pull request](https://github.com/hyperledger/iroha/compare) to the `iroha2-dev` branch on GitHub.

### Reporting Bugs

A *Bug* is an error, design flaw, failure or fault in Iroha that causes it to produce an incorrect or unexpected result, or to behave in unintended ways.

For each bug, there is something called a [minimum working example](https://en.wikipedia.org/wiki/Minimal_working_example), which you should try to write down in the GitHub issue.

Example:
```
# Minting negative Assets with value type `Fixed`.

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

Bugs are tracked as Github issues with tags `iroha2` and `bug`.

The bug reporting checklist is
- [ ] Add the `iroha2` tag (for Iroha 2-related problems)
- [ ] Explain the problem
- [ ] Provide a minimum working example
- [ ] Attach a screenshot

Other issues such as outdated documentation, insufficient documentation, or feature requests should use the `Documentation` and `Enhancement**. They are not bugs.

### Reporting Vulnerabilities

While we are proactive in preventing security problems, it is possible that you might come across a security vulnerability before we do.

As is standard practice, in order to minimize the damage caused by an un-patched security vulnerability, you should disclose the vulnerability to us — hyperledger, as soon as possible, and **avoid disclosing the same vulnerability publicly** for a reasonable period of time.

**note**: Before the First Major Release (2.0) all vulnerabilities are considered bugs, so feel free to submit them as described [above](#reporting-bugs). After the First Major Release please use our [bug bounty program](https://hackerone.com/hyperledger) in order to submit vulnerabilities and get your reward.

If you have any questions regarding our handling of security vulnerabilities, please feel free to contact any of the currently active maintainers in Rocket.Chat private messages.

### Suggesting Improvements

Create an issue on GitHub with the tags `Optimization`, `Enhancement` and mark the pull requests implementing those features as `[feature] #<issue number>: Description`, where the issue number can be for example `#1630` (no angle brackets, yes `#` symbol, mandatory colon `:`).

Features that require an API change must be marked appropriately with the tag `api-changes`. Such features may take longer to implement/approve as they require Iroha library makers to update their code.

### Asking Questions

A question is any discussion that is neither a bug nor a feature/optimization request.

Please post your question to [one of our instant messaging platforms](#places-where-community-is-active) so that staff and members of the community could help you in a timely manner.

You, as part of the aforementioned community, should consider helping others too. If you decide to help, please do so in a [respectful manner](CODE_OF_CONDUCT.md).

### Your First Code Contribution

Read our [Rust Style Guide](#rust-style-guide) and start with a beginner-friendly issue with the label [good-first-issue](https://github.com/hyperledger/iroha/labels/good%20first%20issue). In the interest of optimal collaboration, we advise you to **check** that *the issue isn't already being worked on by someone else*, and if you do decide to take up an issue, please **assign it to yourself**, so that others can see that it's being worked on.

### Pull Request etiquette

-  Please [fork](https://docs.github.com/en/get-started/quickstart/fork-a-repo) the [repository](https://github.com/hyperledger/iroha/tree/iroha2-dev) and [create a feature branch](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-and-deleting-branches-within-your-repository) for your contributions.
-  Squash your commits [either before](https://www.git-tower.com/learn/git/faq/git-squash/) or [during the merge](https://rietta.com/blog/github-merge-types/).
-  Use an appropriate pull request description, by filling in the [description template](.github/PULL_REQUEST_TEMPLATE.md). Avoid deviating from this template if possible.
-  Add an appropriately formatted [pull request title](#pull-request-titles).
-  Ensure that the code you've written is covered by tests. If you fixed a bug, please turn the minimum working example that reproduces the bug into a test.
-  A pull request must pass all automated checks before being merged. At a minimum, the code must be formatted, passing all tests, as well as having no outstanding `clippy` lints.
-  If you feel like your code isn't ready to merge, but you want the maintainers to look through it, e.g. to help, create a draft pull request.
-  A pull request cannot be merged without two approving reviews from the active maintainers.
-  Each pull request will automatically notify the code owners. An up to date list of current maintainers can be found in [MAINTAINERS.md](MAINTAINERS.md).
-  If during the preparation of your pull request your branch got out of date **DO NOT USE THE GitHub merge branch button**. You should instead rebase your commits on top of the recently merged changes. In the interest of making this process easier for everyone, try not to have more than a handful of commits, and avoid re-using feature branches.
-  Follow the [Rust Style Guide](#rust-style-guide)
-  Follow the [Git Style Guide](#git-style-guide)
-  Follow the [Documentation Style Guide](#documentation-style-guide)
-  When working with **PRs from forks** check [this manual](https://help.github.com/articles/checking-out-pull-requests-locally)

### Pull request titles
Internally, to generate changelogs we parse the titles of all the merged pull requests. Thus in order to pass the *`check-PR-title`* check, you should do the following:

Put the type of pull request into square brackets as the first part of the title. This can be `feature`, `fix`, `ci`, `documentation`, and `refactor`. Example:
```
[feature] #1623: implement a `RawGenesisBlockBuilder`
```

For `feature` and `fix` adding the issue to the title is mandatory. For all other types it is optional but highly encouraged. If your pull request solves multiple issues simultaneously, you can chain them with commas. The colon before the description is mandatory. Examples:

```
[fix] #1234, #2345, #4567: fix lots of problems
[refactor]: tidy `p2p` crate
```

The description should use imperative mood and present tense.


### Tests and Benchmarks

-  To run the source-code based tests execute [`cargo test`](https://doc.rust-lang.org/cargo/commands/cargo-test.html) in the Iroha root. Be mindful that this is a long process.
-  To run benchmarks execute [`cargo bench`](https://doc.rust-lang.org/cargo/commands/cargo-bench.html) from the Iroha root. To help debug  benchmark outputs, you can set the `debug_assertions` environment variable like so `RUSTFLAGS="--cfg debug_assertions" cargo bench`.
-  If you are working on a particular component, be mindful that `cargo test` when ran in a [workspace](https://doc.rust-lang.org/cargo/reference/workspaces.html) will only run the tests for that workspace, which usually doesn't include any [integration tests](https://www.testingxperts.com/blog/what-is-integration-testing).
-  If you want to test your changes on a minimal network, the provided [`docker-compose.yml`](docker-compose.yml) creates a network of 4 Iroha peers in docker containers, that can be used to test consensus and asset propagation-related logic. We recommend interacting with that network using either [`iroha-python`](https://github.com/hyperledger/iroha-python), or the included `iroha_client_cli`.
-  Do not remove failing tests. Even tests that are ignored will be run in our pipeline eventually.
-  If possible, please benchmark your code both before and after making your changes, as a significant performance regression can break existing users' installations.

#### Debugging tests

If one of your tests is failing, you may want to decrease the maximum logging level. By default Iroha only logs `INFO` level messages, but retains the ability to produce both `DEBUG` and `TRACE` level logs. This setting can be changed either using the `MAX_LOG_LEVEL` environment variable for code-based tests, or using the `/configuration` endpoint on one of the peers in a deployed network.

While logs printed in the command's `stdout` are sufficient, you may find it more convenient to produce `json`-formatted logs into a separate file and parse them using either
- [node-bunyan](https://www.npmjs.com/package/bunyan)
- [rust-bunyan](https://crates.io/crates/bunyan)

Set the `LOG_FILE_PATH` environment variable to an appropriate location to store the logs and parse them using the above packages.

## Style Guides

### Git Style Guide

-  We require you to **Sign-off every commit**. If you don't [DCO](https://github.com/apps/dco) will not let you merge. Please add: `Signed-off-by: $NAME <$EMAIL>` as the final line of your commit message. You can do it automatically using `git commit -s`
-  It's also useful to format your commit messages appropriately. Try to keep them short.
-  Use the PR categories as a template for your commit messages: e.g. `[fix] #1969: Fix regression in Kotlin SDK tests`.
-  **Prefer present tense** ("Add feature", not "Added feature").
-  **Prefer imperative mood** ("Deploy to docker..." not "Deploys to docker...").
-  Write a meaningful commit message. Imagine that you're looking at someone's code, titled "Fixed error".
-  Limit the first line of your commit message to 50 characters or less.
-  The first line of your commit message should contain the summary of the work you've done. If you need more than one line, leave a blank line between each paragraph and describe your changes in the middle. The last line must be the sign-off.
-  Use the [Git Rebase Workflow](https://git-rebase.io/). Avoid using `git pull` use `git pull --rebase` instead.
-  If you modify the Schema (check by generating the schema with `kagami schema` and diff), you should make all changes to the schema in a separate commit with the message `[schema]`.
-  Generally, try to stick to one commit per meaningful change.
  -  If you fixed several issues in one PR, give them separate commits.
  -  As mentioned previously changes to the `schema` and the API should be done in appropriate commits separate from the rest of your work.
  -  Don't bother with separate commits for fixing review comments. Amend the last one, unless the review comment asks to change the `schema`-affecting work. In that case, you want to rebase interactively.
  -  Tests for functionality in the same commit as the functionality.



### Rust Style Guide

- Use `cargo +nightly fmt --all` (We use [`group_imports`](https://github.com/rust-lang/rustfmt/issues/5083) and [`imports_granularity`](https://github.com/rust-lang/rustfmt/issues/4991))
- Unless otherwise specified refer to [rust's best practices](https://github.com/mre/idiomatic-rust).
- Use the `mod.rs` style. [Self-named modules](https://rust-lang.github.io/rust-clippy/master/) will not pass static analysis, except as [`trybuild`](https://crates.io/crates/trybuild) tests.
- Use a domain-first modules structure. (Example: don't do `constants::logger`, instead invert the hierarchy, putting the object for which it is used first: `iroha_logger::constants`).
- Use [`expect`](https://learning-rust.github.io/docs/e4.unwrap_and_expect.html) with an explicit error message or proof of infallibility instead of `unwrap`.
- Use only full words in *public* structure, variable, method, trait, constant and module names.
- However, abbreviations are allowed if:
  - The name is local (e.g. closure arguments).
  - The name is abbreviated by rust convention (e.g. `len`, `typ`).
  - The name is an accepted abbreviation (e.g. `tx`, `wsv` etc) TODO link glossary.
  - The full name would have been shadowed by a local variable (e.g. `msg <- message`).
  - The full name would have made the code cumbersome (no more than 5-6 words in name) (e.g. `WorldStateViewReceiverTrait -> WSVRecvTrait`).
  - If in doubt: clearer is better than shorter.
- Never ignore an error. If you can't panic and can't recover, it at least needs to be recorded in the log.
- Prefer to return a `Result` instead of `panic!`.
  - Except when implementing something that uses `issue_send` instead of `send` ([more about actors](docs/source/guides/actor.md)). Actors and parallelism don't mix; you could deadlock the entire peer, so it's better to `panic!` if something goes wrong. This is a necessary concession for asynchronous programming.
- Group related functionality spatially, preferably inside appropriate modules. For example, instead of having a block with `struct` definitions and then `impl`s for each individual struct, it is better to have the `impl`s related to that `struct` next to it.
- Otherwise:  declaration before implementation;`use` statements and constants at the top, unit tests at the bottom.
- When writing non-doc comments, instead of describing *what* your function does, try to explain *why* it does something in a particular way. This will save you and the reviewer time.
- Try to avoid `use` statements if the imported name is used only once. This makes moving your code into a different file easier.
- Do not silence clippy lints indiscriminately. If you do, explain your reasoning with a comment (or `expect` message).
- We use pinned dependencies. If your work depends on a particular crate, see if it wasn't already installed using [`cargo tree`](https://doc.rust-lang.org/cargo/commands/cargo-tree.html) (hint use `bat` or `grep`), and try to use that version, instead of the latest version.
- We use pinned dependencies. Use the full version "X.Y.Z" in `Cargo.toml`.
- Version bumps in separate PR.
- Prefer  `#[outer_attribute]` to `#![inner_attribute]` if either is available.

### Documentation Style Guide

-  Use [`Rust Docs`](https://doc.rust-lang.org/cargo/commands/cargo-doc.html) format.
-  If you can link to a structure/module/function's docs, do it.
-  If you can provide an example of usage — do it. This [is also a test](https://doc.rust-lang.org/rustdoc/documentation-tests.html).
-  If your function can error or panic, avoid modal verbs. Example: `Fails if disk IO fails` instead of `Can possibly fail, if disk IO happens to fail`.
-  If your function can error or panic for more than one reason, use a bulleted list of failure conditions, with the appropriate `Error` variants (if any).
-  Functions *do* things. Use imperative mood.
-  Structures *are* things. Get to the point. For example `Log level for reloading from the environment` is better than`This struct encapsulates the idea of logging levels, and is used for reloading from the environment`.
-  Structures have fields, which also *are* things.
-  Modules *contain* things, and we know that. Get to the point! Example: use `Logger-related traits.` instead of `Module which contains logger-related logic`.
-  Prefer the single-line comment syntax. Use `///` above inline modules and `//!` for file-based modules.


### General rules of thumb
- If your function doesn't mutate any of its inputs (and it shouldn't mutate anything else), mark it as `#[must_use]`.
- We prefer strong typing. Avoid `Box<dyn Error>` if possible.
- If your function is a getter/setter it should be marked `#[inline]`.
- If your function is a constructor (i.e. it's creating a new value from the input parameters and calls `default()`) it should be `#[inline]`.
- Leaving `TODO` markers in code is fine, as long as you reference an issue that you created for it. Not creating an issue, means it doesn't get merged.
- If you change naming conventions, make sure that the new name that you've chosen is _much_ clearer than what we had before.
- Avoid tying your code to concrete data structures; `rustc` is smart enough to turn a `Vec<Instruction>` into `impl IntoIterator<Item = Instruction>` and vice versa when it needs to.

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

Thank you for reading the document!
