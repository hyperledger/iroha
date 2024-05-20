import allure
import pytest
import requests


from common.settings import BASE_URL

@pytest.fixture(scope="module")
def GIVEN_get_request_to_schema_endpoint_is_sent():
    with allure.step("GIVEN GET request to /schema is sent"):
        return requests.get(f"{BASE_URL}/schema")

@pytest.fixture(scope="module")
def GIVEN_get_request_with_unexpected_param_to_schema_enpoint_is_sent():
    with allure.step("GIVEN GET request with unexpected param to /schema is sent"):
        return requests.get(f"{BASE_URL}/schema", params={"unexpected": "param"})