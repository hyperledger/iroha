GitHub Actions
==============

GitHub Workflow description in YAML does not support anchors.
There are several workarounds => anyway they come to building-editing workflow yaml from source.
So I suggest yet another one `make-workflows.sh` based on YAML tool `yq`.

### USAGE
0. Move your workflows to `.github/*.src.yml`
1. Put `make-workflows.sh` to directory `.github/`
2. (optional) Copy or link `pre-commit.sh` to `.git/hooks/pre-commit`
   Like `ln -s ../../.github/pre-commit.sh .git/hooks/pre-commit`

### Using pre-commit
```yaml
repos:
- repo: local
  hooks:
  - id: make-workflows
    name: Make GitHub workflows from *.src.yml
    entry: bash -c '.github/make-workflows.sh && git add .github/workflows'
    language: system
    types: [yaml]
    pass_filenames: false
```

### Links
1. https://stackoverflow.com/questions/67368724/share-same-steps-for-different-github-actions-jobs
2. https://github.community/t/support-for-yaml-anchors/16128/60
3. https://github.com/mithro/actions-includes
4. https://github.com/allejo/gha-workflows
