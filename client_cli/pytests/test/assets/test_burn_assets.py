import allure  # type: ignore
import pytest

from src.client_cli import client_cli, have, iroha


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
        client_cli.burn(
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


@allure.label("sdk_test_id", "burn_other_user_asset")
@allure.label("permission", "can_burn_assets_with_definition")
@pytest.mark.xfail(reason="TO DO")
def test_burn_other_user_asset(
    GIVEN_registered_asset_definition_with_numeric_value_type,
    GIVEN_registered_account,
    GIVEN_numeric_value,
):
    assert 0


@allure.label("sdk_test_id", "burn_asset_if_condition")
@pytest.mark.xfail(reason="TO DO")
def test_burn_asset_if_condition(GIVEN_currently_authorized_account):
    assert 0


@allure.label("sdk_test_id", "not_burn_asset_if_condition_not_met")
@pytest.mark.xfail(reason="TO DO")
def test_not_burn_asset_if_condition_not_met(GIVEN_currently_authorized_account):
    assert 0


@allure.label("sdk_test_id", "burn_fixed_asset")
@pytest.mark.xfail(reason="TO DO")
def test_burn_fixed_asset(GIVEN_registered_account):
    assert 0
