from test import before_all, before_each

import allure
import pytest


@pytest.fixture(scope="function", autouse=True)
def atomicity_test_setup():
    allure.dynamic.feature('Atomicity')
    allure.dynamic.label('permission', 'no_permission_required')
