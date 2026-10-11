# Kotodama Linguist PR Checklist

Use this checklist when opening the upstream `github-linguist/linguist` pull
request.

## 1. Prove public usage

Run these in an authenticated GitHub browser session:
- `extension:ko seiyaku NOT is:fork`
- `extension:ko 誓約 NOT is:fork`
- `extension:ko kotoage NOT is:fork`
- `extension:ko 言挙げ NOT is:fork`

Every deployable Kotodama file declares its source unit with `seiyaku` or the
equal Japanese spelling `誓約` (reusable files use `module`), and entrypoints use
`kotoage` or `言挙げ`; count both spellings of each keyword.

Acceptance caveat:
- Linguist's current public guidance says new extensions are only accepted when
  they show enough public usage on GitHub. For a normal extension such as
  `.ko`, the stated threshold is at least `2000` indexed files in the last
  year, excluding forks, with reasonable spread across distinct repositories.

## 2. Publish the grammar source

Turn `tools/kotodama_linguist/grammar-repo/` into its own repository, for
example `https://github.com/<org>/language-kotodama`.

## 3. Add Kotodama to Linguist

From a local Linguist checkout:

```sh
git clone https://github.com/github-linguist/linguist.git
cd linguist

script/add-grammar https://github.com/<org>/language-kotodama
mkdir -p samples/Kotodama
cp /path/to/iroha/tools/kotodama_linguist/samples/*.ko samples/Kotodama/
```

Then:
- add the contents of `linguist/kotodama-language-entry.yml` into
  `lib/linguist/languages.yml`
- run `script/update-ids`
- inspect the generated grammar metadata and any files added under `vendor/`

## 4. Run upstream validation

```sh
bundle exec rake test
```

If the grammar repo changed and the compiler reports issues, fix them before
opening the PR.

## 5. Fill the PR template completely

The Linguist maintainers explicitly state they will not review PRs with an
empty or partially filled template.

Attach:
- links or screenshots for the authenticated GitHub code-search counts
- the distribution check across unique `owner/repo` pairs
- the sample-file license explanation
- the grammar source repository URL

## 6. Expect rollout lag

Even after merge:
- GitHub.com only picks up the change after a later Linguist release and deploy
- GitHub search language detection may lag further behind Linguist by weeks or
  months
