from test import (
    GIVEN_129_length_name,
    GIVEN_fake_name,
    GIVEN_key_with_invalid_character_in_key,
    GIVEN_not_existing_name,
    GIVEN_public_key,
    GIVEN_random_character,
    GIVEN_registered_account,
    GIVEN_registered_domain,
    before_all,
    before_each,
)

import allure  # type: ignore
import pytest


@pytest.fixture(scope="function", autouse=True)
def account_test_setup():
    allure.dynamic.feature("Accounts")
    allure.dynamic.label("permission", "no_permission_required")
