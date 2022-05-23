# Iroha hooks

To ease the development process, you can copy or link these hooks after you clone the repository.

```sh
$ cp hooks/pre-commit.sample .git/hooks/pre-commit
$ cp hooks/commit-msg.sample .git/hooks/commit-msg
```

This way you won't forget to generate the docs if anything is changed.

## Sign-off
The `commit-msg` hook will automatically sign-off your commits.

By signing off your commits, you certify that you have the right to contribute the code within the signed-off commits, i.e. that you are not violating copyright law, DMCA, or any software patent. Check [Developer Certificate of Origin](https://developercertificate.org/) for details.

To learn more about why we require the `signed-off-by:` line, please consult [this question on Stack Overflow](https://stackoverflow.com/questions/1962094/what-is-the-sign-off-feature-in-git-for).