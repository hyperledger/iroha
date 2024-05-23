import time

import requests
import pytest
import allure

from common.settings import BASE_URL


@pytest.fixture(scope="function", autouse=True)
def setup_health_check():
    allure.dynamic.label("endpoint", "/health")
    allure.dynamic.label("method", "GET")
    allure.dynamic.label("status_code", "200")


@allure.id("1035")
def test_health_status_presence(GIVEN_get_request_to_health_endpoint_is_sent):
    with allure.step("WHEN I get the response"):
        response = GIVEN_get_request_to_health_endpoint_is_sent
    with allure.step("THEN the response should contain health status"):
        assert response is not None, "Response does not contain any information"


@allure.id("1029")
@pytest.mark.xfail(reason="https://github.com/hyperledger/iroha/issues/4218")
def test_health_content_type(GIVEN_get_request_to_health_endpoint_is_sent):
    with allure.step("WHEN I get the response"):
        response = GIVEN_get_request_to_health_endpoint_is_sent
    with allure.step("THEN the Content-Type should be text/plain; charset=utf-8"):
        assert (
            response.headers["Content-Type"] == "text/plain; charset=utf-8"
        ), "Content-Type is not text/plain; charset=utf-8"


@allure.id("1030")
@pytest.mark.xfail(reason="https://github.com/hyperledger/iroha/issues/4218")
def test_health_format_with_unexpected_param(
    GIVEN_get_request_with_unexpected_param_to_health_enpoint_is_sent,
):
    with allure.step("WHEN I get the response"):
        response = GIVEN_get_request_with_unexpected_param_to_health_enpoint_is_sent
    with allure.step(
        "THEN the version should be present and match the expected format"
    ):
        assert response == "Healthy", "Healthy is missing or in incorrect format"


@allure.id("1028")
@pytest.mark.xfail(reason="https://github.com/hyperledger/iroha/issues/4218")
def test_health_response_format(GIVEN_get_request_to_health_enpoint_is_sent):
    with allure.step("WHEN I get the response"):
        response = GIVEN_get_request_to_health_enpoint_is_sent
    with allure.step(
        "THEN the version should be present and match the expected format"
    ):
        assert response == "Healthy", "Healthy is missing or in incorrect format"


@allure.id("1027")
def test_health_response_time():
    start_time = time.time()
    with allure.step("WHEN I send GET request to /health"):
        requests.get(f"{BASE_URL}/health")
        elapsed_time = time.time() - start_time
    with allure.step("THEN the response time should be less than 100ms"):
        assert (
            elapsed_time < 0.1
        ), f"Response time is {elapsed_time}s, which is longer than 100ms"
