from .. import (
    GIVEN_currently_authorized_account,
)

import allure  # type: ignore
import pytest


@pytest.fixture(scope="function", autouse=True)
def events_test_setup():
    allure.dynamic.feature("Events")
