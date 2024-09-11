import allure  # type: ignore
import pytest

from ...src.iroha_cli import iroha_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_client_burn_asset():
    allure.dynamic.story("Account burn an asset")


@allure.label("sdk_test_id", "burn_asset_for_account_in_same_domain")
@allure.label("permission", "no_permission_required")
def test_burn_asset_for_account_in_same_domain(
    GIVEN_currently_authorized_account,
    GIVEN_currently_account_quantity_with_two_quantity_of_asset,
):
    with allure.step(
        f"WHEN {GIVEN_currently_authorized_account.signatory} burns 1"
        f"of {GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}"
    ):
        iroha_cli.burn(
            asset=GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition,
            account=GIVEN_currently_authorized_account,
            quantity="1",
        )
    with allure.step(
        f"THEN {GIVEN_currently_authorized_account.signatory} "
        f"has 1 of {GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}"
    ):
        iroha.should(
            have.asset_has_quantity(
                f"{GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}##"
                f"{GIVEN_currently_authorized_account}",
                "1",
            )
        )
