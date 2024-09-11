import allure  # type: ignore
import pytest

from ...src.iroha_cli import iroha_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_transfers_domain():
    allure.dynamic.story("Account transfers a domain")
    allure.dynamic.label("permission", "no_permission_required")


@allure.label("sdk_test_id", "transfer_domain_successfully")
def test_transfer_domain(
    GIVEN_currently_authorized_account,
    GIVEN_registered_account,
    GIVEN_registered_domain,
):
    with allure.step(
        f"WHEN {GIVEN_currently_authorized_account} transfers domains "
        f"to {GIVEN_registered_account}"
    ):
        iroha_cli.execute(
            f"domain transfer "
            f"--from={GIVEN_currently_authorized_account} "
            f"--to={GIVEN_registered_account} "
            f"--id={GIVEN_registered_domain.name}"
        )
    with allure.step(
        f"THEN {GIVEN_registered_account} should own {GIVEN_registered_domain}"
    ):
        iroha.should(
            have.domain(GIVEN_registered_domain.name, owned_by=GIVEN_registered_account)
        )
