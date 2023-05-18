import pytest
import allure

from test import (
    GIVEN_new_one_existence_account,
    GIVEN_existence_asset_definition_with_quantity_value_type,
    GIVEN_existence_asset_definition_with_store_value_type,
    GIVEN_new_one_existence_domain,
    GIVEN_fake_asset_name,
    GIVEN_fake_name,
    GIVEN_public_key,
    GIVEN_quantity_value,
    GIVEN_quantity_value_type,
    GIVEN_currently_authorized_account,
    GIVEN_currently_account_quantity_with_two_quantity_of_asset,
    before_each)

@pytest.fixture(scope="function", autouse=True)
def asset_test_setup():
    allure.dynamic.feature('Assets')
    allure.dynamic.label('permission', 'no_permission_required')
