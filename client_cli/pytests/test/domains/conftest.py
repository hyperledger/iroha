from test import (
    GIVEN_128_lenght_name,
    GIVEN_129_lenght_name,
    GIVEN_currently_authorized_account,
    GIVEN_fake_name,
    GIVEN_public_key,
    GIVEN_random_character,
    GIVEN_registered_account,
    GIVEN_registered_domain,
    GIVEN_registered_domain_with_uppercase_letter,
    GIVEN_string_with_reserved_character,
    GIVEN_string_with_whitespaces,
    before_all,
    before_each,
)

import allure  # type: ignore
import pytest


@pytest.fixture(scope="function", autouse=True)
def domain_test_setup():
    allure.dynamic.feature("Domains")
    allure.dynamic.label("permission", "no_permission_required")
