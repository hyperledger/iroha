import allure  # type: ignore
import pytest

from ...src.iroha_cli import iroha_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_mint_asset():
    allure.dynamic.story("Account mints an asset")


@allure.label("sdk_test_id", "mint_asset_for_account_in_same_domain")
def test_mint_asset_for_account_in_same_domain(
    GIVEN_registered_asset_definition_with_numeric_type,
    GIVEN_registered_account,
    GIVEN_numeric_value,
):
    with allure.step(
        f'WHEN iroha_cli mint "{GIVEN_numeric_value}" of '
        f'"{GIVEN_registered_asset_definition_with_numeric_type}" '
        f'for the "{GIVEN_registered_account}"'
    ):
        iroha_cli.mint().asset(
            account=GIVEN_registered_account,
            asset_definition=GIVEN_registered_asset_definition_with_numeric_type,
            value_of_type=GIVEN_numeric_value,
        )
    with allure.step(
        f'THEN "{GIVEN_registered_account}" '
        f'should have the "{GIVEN_numeric_value}" of '
        f'"{GIVEN_registered_asset_definition_with_numeric_type}"'
    ):
        iroha.should(
            have.asset(
                f"{GIVEN_registered_asset_definition_with_numeric_type.name}##"
                f"{GIVEN_registered_account}"
            )
        )
        iroha.should(
            have.asset_has_quantity(
                f"{GIVEN_registered_asset_definition_with_numeric_type.name}##"
                f"{GIVEN_registered_account}",
                GIVEN_numeric_value,
            )
        )


@allure.label("sdk_test_id", "mint_asset_quantity_after_minting")
def test_mint_asset_quantity_after_minting(GIVEN_minted_asset_quantity):
    with allure.step(
        f'WHEN iroha_cli mint additional asset "{GIVEN_minted_asset_quantity.definition}" '
        f'for the "{GIVEN_minted_asset_quantity.account}" '
        f'with "{GIVEN_minted_asset_quantity.value}" quantity'
    ):
        iroha_cli.mint().asset(
            account=GIVEN_minted_asset_quantity.account,
            asset_definition=GIVEN_minted_asset_quantity.definition,
            value_of_type="1",
        )
        expected_quantity = int(GIVEN_minted_asset_quantity.value) + 1
    with allure.step(
        f'THEN "{GIVEN_minted_asset_quantity.account}" account '
        f'should have the "{GIVEN_minted_asset_quantity.definition}" asset '
        f'with updated quantity "{expected_quantity}"'
    ):
        iroha.should(
            have.asset_has_quantity(
                f"{GIVEN_minted_asset_quantity.definition.name}##{GIVEN_minted_asset_quantity.account}",
                str(expected_quantity),
            )
        )
