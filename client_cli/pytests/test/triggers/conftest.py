from test import GIVEN_currently_authorized_account

import allure
import pytest


@pytest.fixture(scope="function", autouse=True)
def trigger_test_setup():
    allure.dynamic.feature('Triggers')
