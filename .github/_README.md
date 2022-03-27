GitHub Actions CI for Iroha
===========================


> ### For the **smooth experience** please `pre-commit install` after `git clone`.

---------------------

USAGE
-----
GitHub Actions Workflow [`Iroha1`](build-iroha1.src.yml) solves task of automated build and deployment Iroha1.
There are events when it is running:
- on **pull request** to Iroha1 main and development branches
- on **push** to main or development branches including event when PR is **merged**
- on **workflow dispatch** to run WF manually on special branch with defined buildspec through web interface or via CLI tool
- **scheduled** every night
- _(under construction PR #XX) on **comment to PR** which contains buildspec._

Default `buildspec` is _`/build all`_

### Buildspec
Build matrix is a way to select among number of configurations to be built.
Build matrix is generated from buildspec string and handled by script [`chatops-gen-matrix.sh`](./chatops-gen-matrix.sh)

## List of files
- `build-iroha1.src.yml`
  Main file here. GitHub workflow YAML description with ANCHORS, code is not duplicated.
  IMPORTANT: regeneration required after after edit, which is automated with pre-commit.
- `workflows/build-iroha1.yml`
  Result worflow taken by GitHub and generated with make-workflows script. Long file of repeated code. DO NOT EDIT MANUALLY.
- `make-workflows.sh`
  A tool to generate workflows/*.yml from *.src.yml - evaluates anchors. [Read the docs](_README.make-workflows.md).
- `chatops-gen-matrix.sh`
  Generates build matrixes form convenient user input. See `--help`
  ```
  USAGE:
    chatops-gen-matrix.sh --help
    chatops-gen-matrix.sh /build ubuntu clang
    chatops-gen-matrix.sh '/build ubuntu clang; /build macos release ursa'
    echo /build [build_spec...] | chatops-gen-matrix.sh
  EXAMPLE build_spec:
    /build ubuntu release gcc10
    /build macos llvm release; /build macos clang ursa release
    /build all
    /build ubuntu all              ## build all possible configurations on Ubuntu
    /build ubuntu burrow all       ## build release and debug on Ubuntu with Burrow
  AVAILABLE build_spec keywords:
    ubuntu|linux
    macos
    windows
    normal
    burrow
    ursa
    release|Release
    debug|Debug
    gcc|gcc-9|gcc9
    gcc-10|gcc10
    clang|clang-10|clang10
    llvm
    msvc
    skip-testing|skip_testing
    all|everything|beforemerge|before_merge|before-merge|readytomerge|ready-to-merge|ready_to_merge
   ```
- `pre-commit-hook.sh`
  See docs of make-workflows. Use instead of pre-commit as `ln -s ../../.github/pre-commit-hook.sh .git/hooks/pre-commit`, reserv alternative.
- `TESTS_ALLOWED_TO_FAIL`
  One day tests of Iroha became failing. To fix CI and postpone fixing tests, this file was invented. It allows CI to pass even when listed tests are failing. DO NOT USE UNLESS YOU DEFINITELY KNOW WHAT'S GOING. KEEP IT EMPTY.
