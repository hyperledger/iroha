import allure  # type: ignore
import pytest

from ...common.consts import Stderr
from ...src.iroha_cli import iroha_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_unregisters_asset():
    allure.dynamic.story("Account revoke permission")


@allure.label("sdk_test_id", "revoke_permission")
@allure.label("permission", "no_permission_required")
@pytest.mark.xfail(reason="wait for #3036")
def test_revoke_permission(
    GIVEN_registered_account_granted_with_CanSetParameters,
    GIVEN_currently_authorized_account,
):
    with allure.step(
        f'WHEN "{GIVEN_currently_authorized_account}" revokes CanSetParameters'
        f'from the "{GIVEN_registered_account_granted_with_CanSetParameters}"'
    ):
        iroha_cli.revoke_permission(
            destination=GIVEN_registered_account_granted_with_CanSetParameters,
            permission="CanSetParameters",
        )

    with allure.step(
        f'THEN the account "{GIVEN_registered_account_granted_with_CanSetParameters}" should be revoked'
    ):
        assert iroha_cli.should(have.transaction_hash())


@allure.label("sdk_test_id", "revoke_permission_not_granted")
@allure.label("permission", "no_permission_required")
@pytest.mark.xfail(reason="wait for #3036")
def test_revoke_not_granted_permission(
    GIVEN_registered_account, GIVEN_currently_authorized_account
):
    with allure.step(
        f'WHEN "{GIVEN_currently_authorized_account}" tries to revoke permission '
        f'CanSetParameters from "{GIVEN_registered_account}" which was not granted'
    ):
        iroha_cli.revoke_permission(
            destination=GIVEN_registered_account, permission="CanSetParameters"
        )

    with allure.step("THEN the system should handle the operation appropriately"):
        assert iroha_cli.should(have.transaction_hash())


@allure.label("sdk_test_id", "revoke_permission_nonexistent_account")
@allure.label("permission", "no_permission_required")
@pytest.mark.xfail(reason="wait for #3036")
def test_revoke_permission_nonexistent_account(GIVEN_currently_authorized_account):
    with allure.step(
        f'WHEN "{GIVEN_currently_authorized_account}" tries to revoke permission '
        f"CanSetParameters from non-existent account nonexistent@domain"
    ):
        iroha_cli.revoke_permission(
            destination="nonexistent@domain", permission="CanSetParameters"
        )

    with allure.step(
        "THEN the system should return an error indicating the account does not exist"
    ):
        assert iroha_cli.should(have.error(Stderr.ACCOUNT_NOT_FOUND.value))


@allure.label("sdk_test_id", "revoke_permission_without_rights")
@allure.label("permission", "no_permission_required")
@pytest.mark.xfail(reason="wait for #3036")
def test_revoke_permission_without_rights(
    GIVEN_registered_account_granted_with_CanSetParameters,
    GIVEN_account_without_revoke_rights,
):
    with allure.step(
        f'WHEN "{GIVEN_account_without_revoke_rights}" tries to revoke permission '
        f'CanSetParameters from "{GIVEN_registered_account_granted_with_CanSetParameters}"'
    ):
        iroha_cli.revoke_permission(
            destination=GIVEN_registered_account_granted_with_CanSetParameters,
            permission="CanSetParameters",
        )

    with allure.step(
        "THEN the system should return an error indicating insufficient permissions"
    ):
        assert iroha_cli.should(have.error(Stderr.NOT_PERMITTED.value))


@allure.label("sdk_test_id", "revoke_permission_from_self")
@allure.label("permission", "no_permission_required")
@pytest.mark.xfail(reason="wait for #3036")
def test_revoke_permission_from_self(
    GIVEN_currently_authorized_account_granted_with_CanSetParameters,
):
    with allure.step(
        f'WHEN "{GIVEN_currently_authorized_account_granted_with_CanSetParameters}" tries to revoke '
        f"permission CanSetParameters from itself"
    ):
        iroha_cli.revoke_permission(
            destination=GIVEN_currently_authorized_account_granted_with_CanSetParameters,
            permission="CanSetParameters",
        )

    with allure.step(
        "THEN the operation should be processed according to the system logic"
    ):
        assert iroha_cli.should(have.transaction_hash())


@allure.label("sdk_test_id", "revoke_permission_invalid_data_format")
@allure.label("permission", "no_permission_required")
@pytest.mark.xfail(reason="wait for #3036")
def test_revoke_permission_invalid_data_format(GIVEN_registered_account):
    with allure.step(
        f'WHEN attempting to revoke permission with invalid data format from "{GIVEN_registered_account}"'
    ):
        iroha_cli.revoke_permission(
            destination=GIVEN_registered_account, permission=12345
        )

    with allure.step(
        "THEN the system should return an error due to invalid data format"
    ):
        assert iroha_cli.should(have.error(Stderr.INVALID_INPUT.value))
