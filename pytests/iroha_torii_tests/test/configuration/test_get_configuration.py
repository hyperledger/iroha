import json
import time
from pathlib import Path

import requests
import pytest
import allure
from jsonschema import validate
from jsonschema.exceptions import ValidationError

from common.settings import BASE_URL

valid_log_levels = ["trace", "debug", "info", "warn", "error"]


@pytest.fixture(scope="function", autouse=True)
def setup_configuration():
    allure.dynamic.label("endpoint", "/configuration")
    allure.dynamic.label("method", "GET")
    allure.dynamic.label("status_code", "200")


@allure.id("1329")
def test_configuration_response_json_format(
    GIVEN_get_request_to_configuration_endpoint_is_sent,
):
    with allure.step("WHEN I send GET request to /configuration"):
        response = GIVEN_get_request_to_configuration_endpoint_is_sent
    with allure.step("THEN the response should be in JSON format"):
        assert response.json(), "Response is not a valid JSON object"


@allure.id("1388")
def test_configuration_request_with_unexpected_param(
    GIVEN_get_request_with_unexpected_param_to_configuration_enpoint_is_sent,
):
    with allure.step("WHEN I send GET request to /configuration"):
        response = (
            GIVEN_get_request_with_unexpected_param_to_configuration_enpoint_is_sent
        )
    with allure.step("THEN the response should be in JSON format"):
        assert response.json(), "Response is not a valid JSON object"


@allure.id("1330")
def test_configuration_response_content_type(
    GIVEN_get_request_to_configuration_endpoint_is_sent,
):
    with allure.step("WHEN I send GET request to /configuration"):
        response = GIVEN_get_request_to_configuration_endpoint_is_sent
    with allure.step("THEN the Content-Type should be application/json"):
        assert (
            response.headers["Content-Type"] == "application/json"
        ), "Content-Type is not application/json"


@allure.id("1328")
def test_configuration_response_json_schema(
    GIVEN_get_request_to_configuration_endpoint_is_sent,
):
    schema_file_path = (
        Path(__file__).parents[2]
        / "common"
        / "schemas"
        / "get_configuration_response_schema.json"
    )
    with open(schema_file_path) as schema_file:
        schema = json.load(schema_file)

    with allure.step("WHEN I send a GET request to /configuration"):
        response = GIVEN_get_request_to_configuration_endpoint_is_sent.json()

    with allure.step("THEN the response JSON should match the expected schema"):
        try:
            validate(instance=response, schema=schema)
        except ValidationError as ve:
            assert False, f"Response JSON does not match the expected schema: {ve}"


@allure.id("1354")
def test_configuration_response_time():
    start_time = time.time()
    with allure.step("WHEN I send GET request to /configuration"):
        requests.get(f"{BASE_URL}/configuration")
        elapsed_time = time.time() - start_time
    with allure.step("THEN the response time should be less than 100ms"):
        assert (
            elapsed_time < 0.1
        ), f"Response time is {elapsed_time}s, which is longer than 100ms"


@allure.id("1327")
def test_configuration_response_logger_level(
    GIVEN_get_request_to_configuration_endpoint_is_sent,
):

    with allure.step("WHEN I send a GET request to /configuration"):
        response = GIVEN_get_request_to_configuration_endpoint_is_sent.json()

    with allure.step("THEN the 'logger.level' should be one of the valid log levels"):
        assert (
            response["logger"]["level"] in valid_log_levels
        ), f"Logger level '{response['logger']['level']}' is not a valid log level"


@allure.id("1387")
def test_configuration_response_content_length(
    GIVEN_get_request_to_configuration_endpoint_is_sent,
):
    with allure.step("WHEN I get the response"):
        response = GIVEN_get_request_to_configuration_endpoint_is_sent

    with allure.step(
        "THEN the content length should be within the expected range 27-28 bytes"
    ):
        content_length = len(response.content)
        assert (
            27 <= content_length <= 28
        ), f"Response content length is {content_length} bytes"
