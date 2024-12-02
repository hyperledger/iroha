from .. import (
    GIVEN_currently_authorized_account,
    GIVEN_registered_account,
    before_all,
    before_each,
)

import allure  # type: ignore
import pytest


@pytest.fixture(scope="function", autouse=True)
def domain_test_setup():
    allure.dynamic.feature("Permissions")
