import pytest
import allure

from test import (
    GIVEN_128_lenght_name,
    GIVEN_129_lenght_name,
    GIVEN_new_one_existence_domain,
    GIVEN_fake_name,
    GIVEN_random_character,
    GIVEN_string_with_reserved_character,
    GIVEN_string_with_whitespaces,
    GIVEN_existence_domain_with_uppercase_letter,
    before_each)

@pytest.fixture(scope="function", autouse=True)
def domain_test_setup():
    allure.dynamic.feature('Domains')
    allure.dynamic.label('permission', 'no_permission_required')
