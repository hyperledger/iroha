## Summary

Add `Kotodama` as a first-class language in Linguist, mapping `.ko` files to
the TextMate scope `source.kotodama`.

## Why

Kotodama is the smart-contract language of the Iroha Virtual Machine; its
sources compile to IVM bytecode. Its declaration keywords have romanized and
Japanese spellings (`seiyaku`/`誓約`, `kotoage`/`言挙げ`, `hajimari`/`始まり`,
`kaizen`/`改善`) that the grammar highlights identically.
Public repositories already store contract sources as `.ko` files, but GitHub
currently treats them as plain text or requires repository-local overrides to
force an unrelated language.

## Grammar source

- Grammar repository: `https://github.com/<org>/language-kotodama`
- Scope name: `source.kotodama`

## Usage evidence

- Authenticated GitHub code-search queries (each deployable file declares its
  unit with `seiyaku` or the equal Japanese spelling `誓約`):
  - `extension:ko seiyaku NOT is:fork`
  - `extension:ko 誓約 NOT is:fork`
- Result counts:
  - `<fill in>`
- Additional supporting queries:
  - `extension:ko kotoage NOT is:fork`
  - `extension:ko 言挙げ NOT is:fork`
- Distribution check across unique repositories:
  - `<fill in>`

## Samples and license

- The `.ko` samples in this PR are contributed under Apache-2.0 from the
  Hyperledger Iroha repository, or are newly authored representative Kotodama
  samples contributed under the same license.

## Testing

```sh
script/add-grammar https://github.com/<org>/language-kotodama
script/update-ids
bundle exec rake test
```

## Notes

- `.ko` does not appear to be claimed by another language in `languages.yml`,
  so this PR does not add a heuristic classifier.
- After merge, GitHub.com and GitHub search may still need a later Linguist
  release before the change becomes visible publicly.
