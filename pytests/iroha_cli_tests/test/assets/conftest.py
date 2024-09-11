from .. import (
    GIVEN_129_length_name,
    GIVEN_currently_account_quantity_with_two_quantity_of_asset,
    GIVEN_currently_authorized_account,
    GIVEN_fake_asset_name,
    GIVEN_fake_name,
    GIVEN_minted_asset_quantity,
    GIVEN_not_existing_name,
    GIVEN_public_key,
    GIVEN_numeric_asset_for_account,
    GIVEN_numeric_value,
    GIVEN_numeric_type,
    GIVEN_registered_account,
    GIVEN_registered_asset_definition_with_numeric_type,
    GIVEN_registered_asset_definition_with_store_type,
    GIVEN_registered_domain,
    GIVEN_store_type,
    before_all,
    before_each,
)

import allure  # type: ignore
import pytest


@pytest.fixture(scope="function", autouse=True)
def asset_test_setup():
    allure.dynamic.feature("Assets")
    allure.dynamic.label("permission", "no_permission_required")
