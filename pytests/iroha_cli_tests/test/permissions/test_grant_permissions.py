import allure  # type: ignore
import pytest

from ...common.consts import Stderr
from ...src.iroha_cli import iroha_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_unregisters_asset():
    allure.dynamic.story("Account grant permission")


@allure.label("sdk_test_id", "grant_permission")
@allure.label("permission", "no_permission_required")
def test_grant_permission(GIVEN_registered_account, GIVEN_currently_authorized_account):
    with allure.step(
        f'WHEN "{GIVEN_currently_authorized_account}" grants '
        f'the account "{GIVEN_registered_account}" with permission CanSetParameters'
    ):
        iroha_cli.grant_permission(
            destination=GIVEN_registered_account, permission="CanSetParameters"
        )

    with allure.step(
        f'THEN the account "{GIVEN_registered_account}" should have the granted permission'
    ):
        assert iroha_cli.should(have.transaction_hash())


@allure.label("sdk_test_id", "grant_not_permitted_permission")
@allure.label("permission", "no_permission_required")
def test_grant_not_permitted_permission(
    GIVEN_registered_account, GIVEN_currently_authorized_account
):
    with allure.step(
        f'WHEN "{GIVEN_currently_authorized_account}" grants '
        f'the account "{GIVEN_registered_account}" with not permitted CanRegisterDomain permission'
    ):
        iroha_cli.grant_permission(
            destination=GIVEN_registered_account, permission="CanRegisterDomain"
        )

    with allure.step(
        "THEN get an error Operation is not permitted:"
        "This operation is only allowed inside the genesis block"
    ):
        assert iroha_cli.should(have.error(Stderr.NOT_PERMITTED.value))


@allure.label("sdk_test_id", "grant_invalid_permission")
@allure.label("permission", "no_permission_required")
def test_grant_invalid_permission(
    GIVEN_registered_account, GIVEN_currently_authorized_account
):
    with allure.step(
        f'WHEN "{GIVEN_currently_authorized_account}" attempts to grant '
        f'an invalid permission NonExistentPermission to "{GIVEN_registered_account}"'
    ):
        iroha_cli.grant_permission(
            destination=GIVEN_registered_account, permission="NonExistentPermission"
        )

    with allure.step("THEN get an error stating that the permission is invalid"):
        assert iroha_cli.should(have.error(Stderr.UNKNOWN_PERMISSION.value))


@allure.label("sdk_test_id", "grant_permission_to_nonexistent_account")
@allure.label("permission", "no_permission_required")
def test_grant_permission_to_nonexistent_account(GIVEN_currently_authorized_account):

    with allure.step(
        f'WHEN "{GIVEN_currently_authorized_account}" attempts to grant '
        f"permission to non existent account"
    ):
        iroha_cli.grant_permission(
            destination="ed01200A303A7FBEDE8FC3D48F46681FF52D533F8B29E564412FA015A68D720C492777@wonderland",
            permission="CanSetParameters",
        )

    with allure.step(
        "THEN get an error stating that the destination account does not exist"
    ):
        assert iroha_cli.should(have.error(Stderr.FAILED_TO_FIND_ACCOUNT.value))
