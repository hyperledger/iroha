import allure
import pytest

from src.client_cli import client_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_mint_asset():
    allure.dynamic.story('Account mints an asset')

@allure.label('sdk_test_id', 'mint_asset_for_account_in_same_domain')
def test_mint_asset_for_account_in_same_domain(
        GIVEN_existence_asset_definition_with_quantity_value_type,
        GIVEN_new_one_existence_account,
        GIVEN_quantity_value):
    with allure.step(
            f'WHEN client_cli mint the asset "{GIVEN_existence_asset_definition_with_quantity_value_type.name}" '
            f'for the "{GIVEN_new_one_existence_account.name}" '
            f'in the "{GIVEN_existence_asset_definition_with_quantity_value_type.domain}" domain'
    ):
        client_cli.mint().asset(
                account=GIVEN_new_one_existence_account,
                asset_definition=GIVEN_existence_asset_definition_with_quantity_value_type,
                value_of_value_type=GIVEN_quantity_value
        )
    with allure.step(
            f'THEN "{GIVEN_new_one_existence_account}" account '
            f'should have the "{GIVEN_existence_asset_definition_with_quantity_value_type}" asset definition'):
        iroha.should(have.asset(f'{GIVEN_existence_asset_definition_with_quantity_value_type.name}##{GIVEN_new_one_existence_account}'))


@allure.label("sdk_test_id", "mint_fixed_asset")
@pytest.mark.xfail(reason="TO DO")
def test_mint_fixed_asset(
        GIVEN_new_one_existence_account):
    assert 0
