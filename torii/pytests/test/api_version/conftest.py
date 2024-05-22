from test import GIVEN_api_up_and_running

import allure
import pytest
import requests


from common.settings import BASE_URL


@pytest.fixture(scope="module")
def GIVEN_get_request_to_api_version_enpoint_is_sent():
    with allure.step("GIVEN GET request to /api_version is sent"):
        return requests.get(f"{BASE_URL}/api_version")


@pytest.fixture(scope="module")
def GIVEN_get_request_with_unexpected_param_to_api_version_enpoint_is_sent():
    with allure.step("GIVEN GET request with unexpected param to /api_version is sent"):
        return requests.get(f"{BASE_URL}/api_version", params={"unexpected": "param"})
