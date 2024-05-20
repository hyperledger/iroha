import allure
import pytest
import requests


from common.settings import BASE_URL

@pytest.fixture(scope="module")
def GIVEN_get_request_to_configuration_endpoint_is_sent():
    with allure.step("GIVEN GET request to /configuration is sent"):
        return requests.get(f"{BASE_URL}/configuration")

@pytest.fixture(scope="module")
def GIVEN_get_request_with_unexpected_param_to_configuration_enpoint_is_sent():
    with allure.step("GIVEN GET request with unexpected param to /configuration is sent"):
        return requests.get(f"{BASE_URL}/configuration", params={"unexpected": "param"})

@pytest.fixture(scope="module")
def GIVEN_post_request_to_configuration_endpoint_is_sent():
    with allure.step("GIVEN POST request to /configuration is sent"):
        return requests.post(f"{BASE_URL}/configuration")
