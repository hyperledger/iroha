import pytest
import allure

from test import (
    GIVEN_fake_name,
    before_each)

@pytest.fixture(scope="function", autouse=True)
def permission_test_setup():
    allure.dynamic.feature('Roles')
