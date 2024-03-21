# Overview

This directory contains the `pytest` framework with test suites for the Iroha 2 Client CLI.

For quick access to a topic that interests you, select one of the following:

- [Overview](#overview)
	- [Framework Structure](#framework-structure)
	- [Iroha 2 Test Model](#iroha-2-test-model)
	- [Using Test Suites](#using-test-suites)
		- [Custom Test Environment with Docker Compose](#custom-test-environment-with-docker-compose)
		- [Poetry Configuration](#poetry-configuration)
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

All tests are written with [Allure Report](https://allurereport.org/) in mind, and therefore require certain configuration prior to being executed.\
For details, see [Running Tests](#running-tests) and [Viewing Test Reports](#viewing-test-reports).

## Iroha 2 Test Model

The Iroha 2 Test Model consists of several test categories that cover different aspects of the Iroha 2 blockchain platform.\
The test model has the following structure:

- **Accounts**: Test cases for account-related operations.
- **Assets**: Test cases for asset-related operations.
- **Atomicity**: Test cases for transaction atomicity.
- **Domains**: Test cases for domain-related operations.
- **Roles**: Test cases for roles management.

<!-- TODO: Add once implemented: - **Configurations**: Test configurations for the Iroha 2 platform. -->

## Using Test Suites

> [!NOTE]
> The following instructions assume that you're using the `test_env.py` script that is being provided for the default test environment.
> However, it is possible to run the tests in a custom environment, e.g., with Docker Compose.
> For instructions on how to do so, see [Custom Test Environment with Docker Compose](#custom-test-environment-with-docker-compose).

1. Set up a test environment using the [`test_env.py`](../../scripts/test_env.py) script:

	 ```shell
	 # Must be executed from the repo root:
	 ./scripts/test_env.py setup
     # Note: make sure you have installed packages from `./scripts/requirements.txt`
	 ```

   By default, this builds `iroha`, `iroha_client_cli`, and `kagami` binaries, and runs four peers with their API exposed through the `8080`-`8083` ports.\
	 This behavior can be reconfigured. You can run `./scripts/test_env.py --help` to see the list of available commands and options.

2. Install and configure [Poetry](https://python-poetry.org/).\
	 For details, see [Poetry Configuration](#poetry-configuration) below.
3. Configure the tests by creating the following `.env` file in _this_ (`<repo root>/client_cli/pytests/`) directory:

	 ```shell
     CLIENT_CLI_BINARY=/path/to/iroha_client_cli
     CLIENT_CLI_CONFIG=/path/to/config.toml
	 TORII_API_PORT_MIN=8080
	 TORII_API_PORT_MAX=8083
	 ```

	 For details, see [Tests Configuration](#tests-configuration) below.
4. Run the tests:

	 ```shell
	 poetry run pytest
	 ```

5. Once you are done, clean up the test environment:

	 ```shell
	 # Must be executed from the repo root:
	 ./scripts/test_env.py cleanup
	 ```

### Custom Test Environment with Docker Compose

By default, we provide the [`test_env.py`](../../scripts/test_env.py) script to set up a test environment. This environment is composed of a running network of Iroha peers and an `iroha_client_cli` configuration to interact with it.

However, if for any reason this approach is inconvenient, it is possible to set up a custom network of Iroha peers using the provided Docker Compose configurations.

To do so, perform the following steps:

1. Have a local or remote server that has a custom Docker Compose development environment already setup:

	 ```bash
	 docker-compose -f docker-compose.dev.yml up
	 ```

2. Build the `iroha_client_cli` binary:

	 ```bash
	 cargo build --bin iroha_client_cli
	 ```

3. Create a new directory, then copy the `iroha_client_cli` binary and its `client.toml` configuration file into it:

	 ```shell
	 # Create a new directory:
	 mkdir test
	 # Copy the files:
	 cp configs/swarm/client.toml test
	 cp target/debug/iroha_client_cli test
	 ```

4. Proceed with _Step 2_ of the [Using Test Suites](#using-test-suites) instructions.

> [!NOTE]
> Don't forget to specify the path to the directory created for the `iroha_client_cli` binary and its `client.toml` configuration file (see Step 3) in the `CLIENT_CLI_DIR` variable of the `.env` file.
> For details, see [Tests Configuration](#tests-configuration) below.

### Poetry Configuration

This test framework uses [Poetry](https://python-poetry.org/) for dependency management and virtual environment setup.

To get started with Poetry, follow these steps:

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

Tests are configured via environment variables. These variables can be optionally defined in a `.env` file that must be created in _this_ (`<repo root>/client_cli/pytests/`) directory.

The variables:

- `CLIENT_CLI_DIR` — Specifies a path to a directory containing the `iroha_client_cli` binary and its `config.json` configuration file.\
	Set to `/client_cli`, by default.
- `TORII_API_PORT_MIN`/`TORII_API_PORT_MAX` — This pair specifies the range of local ports through which the Iroha 2 peers are deployed. A randomly selected port from the specified range is used for each test.\
	Set to `8080` and `8083` respectively, by default.

**Example**:

```shell
CLIENT_CLI_BINARY=/path/to/iroha_client_cli
CLIENT_CLI_CONFIG=/path/to/client.toml
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
