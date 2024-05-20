import re
import time

import requests
import pytest
import allure

from common.settings import BASE_URL

@pytest.fixture(scope="function", autouse=True)
def setup_api_version():
    allure.dynamic.label('endpoint', "/api_version")
    allure.dynamic.label("method", "GET")
    allure.dynamic.label("status_code", "200")

@allure.id("1036")
def test_api_version_responce_presence(
        GIVEN_get_request_to_api_version_enpoint_is_sent):
    with allure.step(
            "WHEN I get the response"):
        response = GIVEN_get_request_to_api_version_enpoint_is_sent
    with allure.step(
            "THEN the response should have a information"):
        assert response is not None, \
            "Response does not contain any information"

@allure.id("1032")
@pytest.mark.xfail(reason="https://github.com/hyperledger/iroha/issues/4218")
def test_api_version_response_format(
        GIVEN_get_request_to_api_version_enpoint_is_sent):
    with allure.step(
            "WHEN I get the response"):
        response = GIVEN_get_request_to_api_version_enpoint_is_sent
    with allure.step(
            "THEN the version should be present and match the expected format"):
        assert re.match(r'^\d+', response), \
            "Version is missing or in incorrect format"

@allure.id("1026")
@pytest.mark.xfail(reason="https://github.com/hyperledger/iroha/issues/4218")
def test_api_version_request_with_unexpected_param(
        GIVEN_get_request_with_unexpected_param_to_api_version_enpoint_is_sent):
    with allure.step(
            "WHEN I get the response"):
        response = GIVEN_get_request_with_unexpected_param_to_api_version_enpoint_is_sent
    with allure.step(
            "THEN the version should be present and match the expected format"):
        version = response.get("version")
        assert version and re.match(r'^\d+', version), \
            "Version is missing or in incorrect format"

@allure.id("1033")
@pytest.mark.xfail(reason="https://github.com/hyperledger/iroha/issues/4218")
def test_api_version_response_content_type(
        GIVEN_get_request_to_api_version_enpoint_is_sent):
    with allure.step(
            "WHEN I get the response"):
        response = GIVEN_get_request_to_api_version_enpoint_is_sent
    with allure.step(
            "THEN the Content-Type should be text/plain; charset=utf-8"):
        assert response.headers["Content-Type"] == "text/plain; charset=utf-8", \
            "Content-Type is not text/plain; charset=utf-8"

@allure.id("1037")
@pytest.mark.xfail(reason="https://github.com/hyperledger/iroha/issues/4218")
def test_api_version_response_format(
        GIVEN_get_request_to_api_version_enpoint_is_sent):
    with allure.step(
            "WHEN I get the response"):
        response = GIVEN_get_request_to_api_version_enpoint_is_sent
    with allure.step(
            "THEN the response should be plain text"):
        assert 0, \
            "Response is not a valid plain text"

@allure.id("1031")
def test_api_version_response_time():
    start_time = time.time()
    with allure.step(
            "WHEN I send GET request to /api_version"):
        requests.get(f"{BASE_URL}/api_version")
        elapsed_time = time.time() - start_time
    with allure.step(
            "THEN the response time should be less than 100ms"):
        assert elapsed_time < 0.1, \
            f"Response time is {elapsed_time}s, which is longer than 100ms"

@allure.id("1024")
@pytest.mark.xfail(reason="https://github.com/hyperledger/iroha/issues/4218")
def test_api_version_response_content_length(
        GIVEN_get_request_to_api_version_enpoint_is_sent):
    with allure.step(
            "WHEN I get the response"):
        response = GIVEN_get_request_to_api_version_enpoint_is_sent
    with allure.step(
            "THEN the content length should be 1 byte"):
        assert len(response.content) == 1, \
            "Response content is 1 byte"
