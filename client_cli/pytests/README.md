# Overview

This directory contains the pytest framework with test suites for Iroha 2's Client CLI.

## Iroha 2 Test Model
The Iroha 2 Test Model consists of several test categories that cover different aspects of the Iroha 2 blockchain platform. The structure of the test model is as follows:

- **Configurations:** Test configurations for the Iroha 2 platform.

- **Accounts:** Test cases for account-related operations, such as account registration, key management, and metadata manipulation.

- **Assets:** Test cases for asset-related operations, including asset creation, minting, burning, transferring, and managing asset definitions and metadata.

- **Domains:** Test cases for domain-related operations, such as registering and unregistering domains.

- **Roles:** Test cases for roles management.

- **Atomicity:** Test cases for transaction atomicity, including multiple instructions within a single transaction, paired instructions, and invalid instructions.

## Usage

1. Set up test environment using [`test_env.py`](../../scripts/test_env.py):
	```shell
	# running from the repo root
	./scripts/test_env.py setup
	```
   By default, this builds `iroha`, `iroha_client_cli`, and `kagami`, and runs 4 peers with their API exposed on ports 8080..8083. This behaviour could be configured, see `./scripts/test_env.py --help` for details.
2. Configure `Poetry` according to the [Poetry Configuration section](#poetry-configuration) below.
3. Configure tests with environment variables or `.env` file in this directory according to the [Tests Configuration section](#tests-configuration) below.
4. Run tests:
	```shell
	poetry run pytest
	```
5. Clean up the test environment:
	```shell
	# running from the repo root
	./scripts/test_env.py cleanup
	```

## Tests Configuration

Tests are configured via environment variables, optionally defined in an `.env` file in this directory.

The variables:

- `CLIENT_CLI_DIR` (defaults to `/client_cli`): path to the directory containing `iroha_client_cli` binary and its configuration as `config.json`.
- `TORII_API_PORT_MIN`/`TORII_API_PORT_MAX` (defaults to `8080`/`8083`): set the range of local ports on which Iroha peers are deployed. Tests will randomly pick one of them for each test.

Example:

```shell
CLIENT_CLI_DIR=/path/to/iroha_client_cli/with/config.json/dir/
TORII_API_PORT_MIN=8080
TORII_API_PORT_MAX=8083
```

## Poetry Configuration

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
    Now, you should be in the virtual environment with all the required dependencies installed. All the subsequent commands (e.g., pytest, allure) should be executed within this virtual environment.
 5. When you're done working in the virtual environment, deactivate it by running:
    ```bash
    exit
    ```

## Run tests

To run tests and generate a report in the allure-results folder, execute the following command:

```bash
pytest -k "not xfail" --alluredir allure-results
```

The `--alluredir` option specifies the directory where the report should be stored.

## View the report

To launch a web server that serves the Allure report generated, run:

```bash
allure serve allure-results
```

The `allure-results` argument specifies the directory where the report is stored. After running this command, you should be able to view the report in your web browser by navigating to `http://localhost:port`, where port is the port number displayed in the console output.

## Structure
The framework is organized into the following directories:

`common`: Contains common constants and helpers used throughout the framework.

`models`: Contains the data model classes for accounts, assets, and domains.

`src`: Contains the source code for the Iroha 2 Client CLI tests, including the client CLI and related utilities.

`test`: Contains the test suite for the framework, organized into subdirectories for different test categories (accounts, assets, atomicity, domains, and permissions).

The framework also includes configuration files:

`poetry.lock` and `pyproject.toml`: Configuration files for Poetry, the dependency management and virtual environment tool used in this framework.
`pytest.ini`: Configuration file for pytest, the testing framework used in this framework.
