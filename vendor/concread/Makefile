.DEFAULT: help
.PHONY: help
help:
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

test: ## run the maintained storage engine and reduced-fanout tests
test:
	cargo test -p concread
	cargo test -p concread --features skinny

clippy: ## lint every supported storage feature
clippy:
	cargo clippy -p concread --all-targets --all-features -- -D warnings

check: ## check all the things
check: test clippy codespell
	cargo fmt --check
	cargo outdated -R
	cargo audit


.PHONY: coverage/run
coverage/run: ## Run coverage tests
coverage/run:
	rm -rf "$(PWD)/target/profile/coverage-*.profraw"
	LLVM_PROFILE_FILE="$(PWD)/target/profile/coverage-%p-%m.profraw" RUSTFLAGS="-C instrument-coverage" cargo test -p concread
	LLVM_PROFILE_FILE="$(PWD)/target/profile/coverage-%p-%m.profraw" RUSTFLAGS="-C instrument-coverage" cargo test -p concread --features skinny

.PHONY: coverage/grcov
coverage/grcov: ## Run grcov
coverage/grcov:
	rm -rf ./target/coverage/html
	grcov . --binary-path ./target/debug/deps/ \
		-s . \
		-t html \
		--branch \
		--llvm \
		--ignore-not-existing \
		--ignore '../*' \
		--ignore "/*" \
		--ignore "target/*" \
		-o target/coverage/html

.PHONY: coverage
coverage: ## Run all the coverage tests
coverage: coverage/run coverage/grcov
	echo "Coverage report is in ./target/coverage/html/index.html"

.PHONY: codespell
codespell: ## spell-check things.
codespell:
	codespell -c \
	--ignore-words .codespell_ignore \
	--skip='./target'
