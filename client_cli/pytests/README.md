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

## How to use
At first, you need to installed and running [Iroha 2](https://hyperledger.github.io/iroha-2-docs/guide/install.html), and also need to have built [Client CLI](https://hyperledger.github.io/iroha-2-docs/guide/build.html)

## Configuration

To configure the application, you can use a `.env` file in the `client_cli/pytest` directory. The `.env` file should contain the following variables:

```
CLIENT_CLI_DIR=/path/to/iroha_client_cli/with/config.json/dir/
TORII_API_PORT_MIN=8080
TORII_API_PORT_MAX=8083
```
Replace `/path/to/iroha_client_cli/dir` with the actual paths to the respective files on your system.

If the `.env` file is not present or these variables are not defined in it

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