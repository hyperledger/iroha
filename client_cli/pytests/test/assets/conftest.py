from test import (
    GIVEN_129_length_name,
    GIVEN_big_quantity_value_type,
    GIVEN_currently_account_quantity_with_two_quantity_of_asset,
    GIVEN_currently_authorized_account,
    GIVEN_fake_asset_name,
    GIVEN_fake_name,
    GIVEN_minted_asset_quantity,
    GIVEN_not_existing_name,
    GIVEN_public_key,
    GIVEN_quantity_asset_for_account,
    GIVEN_quantity_value,
    GIVEN_quantity_value_type,
    GIVEN_registered_account,
    GIVEN_registered_asset_definition_with_big_quantity_value_type,
    GIVEN_registered_asset_definition_with_quantity_value_type,
    GIVEN_registered_asset_definition_with_store_value_type,
    GIVEN_registered_domain,
    GIVEN_store_value_type,
    before_all,
    before_each,
)

import allure  # type: ignore
import pytest


@pytest.fixture(scope="function", autouse=True)
def asset_test_setup():
    allure.dynamic.feature("Assets")
    allure.dynamic.label("permission", "no_permission_required")
