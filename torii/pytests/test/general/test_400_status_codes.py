import allure
import pytest
import requests

from common.settings import BASE_URL


@pytest.fixture(scope="function", autouse=True)
def status_codes_400():
    allure.dynamic.label("endpoint", "general")


@allure.id("1255")
@allure.label("method", "GET")
@allure.label("status_code", "405")
def test_method_not_allowed():
    with allure.step("WHEN I send GET request to /method_not_allowed"):
        response = requests.get(f"{BASE_URL}/method_not_allowed")
    with allure.step("THEN the response status code should be 405"):
        assert (
            response.status_code == 405
        ), "Status code is not 405 for /method_not_allowed"


@allure.id("1288")
@allure.label("method", "GET")
@allure.label("status_code", "414")
def test_request_uri_too_long():
    with allure.step("WHEN I send an oversized GET request to /metrics"):
        response = requests.get(
            f"{BASE_URL}/metrics", params={"long_param": "a" * 65515}
        )
    with allure.step(
        "THEN the response status code should be 414 (Request-URI Too Long)"
    ):
        assert response.status_code == 414, "Status code is not 414"
