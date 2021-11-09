# Iroha hooks

For easy development you can copy(or link) those hooks after you clone repo. This way you won't forget to generate docs if anything is changed.
```sh
$ cp hooks/pre-commit.sample .git/hooks/pre-commit
$ cp hooks/commit-msg.sample .git/hooks/commit-msg
```

# LEGAL DISCLAIMER
commit-msg hook will automatically sign-off your commits, to learn more about why we require the `signed-off-by:` line, please consult [this question](https://stackoverflow.com/questions/1962094/what-is-the-sign-off-feature-in-git-for). By signing off your commits, you certify that you have the right to contribute the code within the signed-off commits, i.e. that you are not violating copyright law, DMCA, or any software patent.
