# Overview

This directory contains the `pytest` framework with test suites for the Iroha 2 Client CLI.

For quick access to a topic that interests you, select one of the following:

- [Framework Structure](#framework-structure)
- [Iroha 2 Test Model](#iroha-2-test-model)
- [Using Test Suites](#using-test-suites)
	- [Poetry Configuration](#poetry-configration)
	- [Tests Configuration](#tests-configuration)
- [Running Tests](#running-tests)
- [Viewing Test Reports](#viewing-test-reports)

## Framework Structure

The framework is organized into the following directories:

- `common`: Contains common constants and helpers used throughout the framework.
- `models`: Contains the data model classes for accounts, assets, and domains.
- `src`: Contains the source code for the Iroha 2 Client CLI tests, including the `client_cli.py` and related utilities.
- `test`: Contains the test suite for the framework, organized into subdirectories for different test categories (`accounts`, `assets`, `atomicity`, `domains`, and `roles`).

The framework also includes the following configuration files in its root directory:

- `poetry.lock` and `pyproject.toml` — configuration files for [Poetry](https://python-poetry.org/), the dependency management and virtual environment tool used in this test framework.
- `pytest.ini` — configuration file for the `pytest` framework.

All tests are written with [Allure Report](https://allurereport.org/) in mind, and therefore require certain configuration prior to being executed.\
For details, see [Running Tests](#running-tests) and [Viewing Test Reports](#viewing-test-reports).

## Iroha 2 Test Model

The Iroha 2 Test Model consists of several test categories that cover different aspects of the Iroha 2 blockchain platform.\
The test model has the following structure:

- **Configurations**: Test configurations for the Iroha 2 platform.

---

- **Accounts**: Test cases for account-related operations, such as account registration, key management, and metadata manipulation.
- **Assets**: Test cases for asset-related operations, including asset creation, minting, burning, transferring, and managing asset definitions and metadata.
- **Atomicity**: Test cases for transaction atomicity, including multiple instructions within a single transaction, paired instructions, and invalid instructions.
- **Domains**: Test cases for domain-related operations, such as registering and unregistering domains.
- **Roles**: Test cases for roles management.

---
ALT:
- **Accounts**: Test cases for account-related operations:
	- `test_accounts_query_filters.py` — various accounts-related filter queries.
	- `test_register_accounts.py` — account registration.
	- `test_set_key_value_pair.py` — key management.
- **Assets**: Test cases for asset-related operations:
	- `test_assets_query_filters.py` — various assets-related filter queries.
	- `test_burn_assets.py` — burning assets.
	- `test_mint_assets.py` — minting assets.
	- `test_register_asset_definitions.py` — registering various types of asset definitions.
	- `test_transfer_assets.py` — transferring assets.
- **Atomicity**: Test cases for transaction atomicity:
	- `test_multiple_instructions_within_transaction.py` — multiple instructions within a single transaction.
	- `test_pair_instructions_within_transaction.py` — paired instructions within a single transaction.
	- `test_wrong_instructions_within_transaction.py` — invalid instructions within a single transaction.
- **Domains**: Test cases for domain-related operations:
	- `test_domains_query_filters.py` — various domain-related filter queries.
	- `test_register_domains.py` — registering various types of domains.
	- `test_transfer_domains.py` — transferring a domain.
- **Roles** Test cases for roles management:
	- `test_register_roles.py` — registering a role, attaching permissions to a role, granting a role to an account.

## Using Test Suites

1. Set up a test environment using the [`test_env.py`](../../scripts/test_env.py) file:

	 ```shell
	 # Must be executed from the repo root:
	 ./scripts/test_env.py setup
	 ```

   By default, this builds `iroha`, `iroha_client_cli`, and `kagami`, and runs four peers with their API exposed through the `8080`-`8083` ports.\
	 This behavior can be reconfigured. You can run `./scripts/test_env.py --help` to see the list of available commands and options.

2. Install and configure [Poetry](https://python-poetry.org/). For details, see [Poetry Configuration](#poetry-configuration) below.
3. Configure the tests. For details, see [Tests Configuration](#tests-configuration) below.
4. Run the tests:

	 ```shell
	 poetry run pytest
	 ```

5. Clean up the test environment:

	 ```shell
	 # Must be executed from the repo root:
	 ./scripts/test_env.py cleanup
	 ```

### Poetry Configuration

This test framework uses [Poetry](https://python-poetry.org/) for dependency management and virtual environment setup. To get started with Poetry, follow these steps:

1. Install Poetry by following the [official installation guide](https://python-poetry.org/docs/#installation).
2. Navigate to the `client_cli/pytests` directory in your terminal.
3. Install the dependencies and set up a virtual environment using Poetry:

   ```bash
   poetry install
   ```

4. Activate the virtual environment:

	 ```bash
	 poetry shell
	 ```

Now you are in the virtual environment with all the required dependencies installed. All the subsequent commands (e.g., `pytest`, `allure`) must be executed within this virtual environment.

Once you're done working with the virtual environment, deactivate it:

```bash
exit
```

### Tests Configuration

Tests are configured via environment variables. These variables can be optionally defined in a `.env` file that must be created in this directory.

The variables:

- `CLIENT_CLI_DIR` — Specifies a path to a directory containing the `iroha_client_cli` binary and its `config.json` configuration file.\
Set to `/client_cli`, by default.
- `TORII_API_PORT_MIN`/`TORII_API_PORT_MAX` — This pair specifies the range of local ports through which the Iroha 2 peers are deployed. A randomly selected port from the specified range is used for each test.\
Set to `8080` and `8083` respectively, by default.

**Example**:

```shell
CLIENT_CLI_DIR=/path/to/iroha_client_cli/with/config.json/dir/
TORII_API_PORT_MIN=8080
TORII_API_PORT_MAX=8083
```

## Running Tests

To run tests and generate an [Allure](https://allurereport.org/) report in to the `allure-results` folder, execute the following command:

```bash
pytest -k "not xfail" --alluredir allure-results
```

The `-k` option specifies tests which contain names that match the given string expression (case-insensitive), which can include Python operators that use filenames, class names and function names as variables.\
The `"not xfail"` value specifies that only tests that are _not_ signed with the [`xfail`](https://docs.pytest.org/en/6.2.x/skipping.html#xfail-mark-test-functions-as-expected-to-fail) marking will be conducted.\
This is due to the fact that tests with the `xfail` marking are currently Work-in-Progress and expected to fail.

The `--alluredir` option specifies the directory where the report is stored.

## Viewing Test Reports

To launch a web server that serves the generated [Allure](https://allurereport.org/) report, execute the following command:

```bash
allure serve allure-results
```

The `allure-results` argument specifies the directory where the report is stored. After running this command, you will be able to view the report in your web browser by navigating to `http://localhost:port`, where `port` is the port number displayed in the terminal output.
