import allure
import pytest
import requests


from ...common.settings import BASE_URL


@pytest.fixture(scope="module")
def GIVEN_get_request_to_status_endpoint_is_sent():
    with allure.step("GIVEN GET request to /status is sent"):
        return requests.get(f"{BASE_URL}/status")


@pytest.fixture(scope="module")
def GIVEN_get_request_with_unexpected_param_to_status_enpoint_is_sent():
    with allure.step("GIVEN GET request with unexpected param to /status is sent"):
        return requests.get(f"{BASE_URL}/status", params={"unexpected": "param"})
