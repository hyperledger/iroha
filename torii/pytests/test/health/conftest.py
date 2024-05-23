from test import GIVEN_api_up_and_running

import allure
import pytest
import requests


from common.settings import BASE_URL


@pytest.fixture(scope="module")
def GIVEN_get_request_to_health_endpoint_is_sent():
    with allure.step("GIVEN GET request to /health is sent"):
        return requests.get(f"{BASE_URL}/health")


@pytest.fixture(scope="module")
def GIVEN_get_request_with_unexpected_param_to_health_enpoint_is_sent():
    with allure.step("GIVEN GET request with unexpected param to /health is sent"):
        return requests.get(f"{BASE_URL}/health", params={"unexpected": "param"})
