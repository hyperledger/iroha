from test import GIVEN_fake_name, before_all, before_each

import allure  # type: ignore
import pytest


@pytest.fixture(scope="function", autouse=True)
def role_test_setup():
    allure.dynamic.feature("Roles")
