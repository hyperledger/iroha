import json
import time
from pathlib import Path

import requests
import pytest
import allure
from jsonschema import validate
from jsonschema.exceptions import ValidationError

from ...common.settings import BASE_URL


@pytest.fixture(scope="function", autouse=True)
def setup_status():
    allure.dynamic.label("endpoint", "/status")
    allure.dynamic.label("method", "GET")
    allure.dynamic.label("status_code", "200")


@allure.id("1454")
def test_status_response_json_format(GIVEN_get_request_to_status_endpoint_is_sent):
    with allure.step("WHEN I send GET request to /status"):
        response = GIVEN_get_request_to_status_endpoint_is_sent
    with allure.step("THEN the response should be in JSON format"):
        assert response.json(), "Response is not a valid JSON object"


@allure.id("1453")
def test_status_request_with_unexpected_header(
    GIVEN_get_request_with_unexpected_param_to_status_enpoint_is_sent,
):
    with allure.step("WHEN I send GET request to /status with unexpected header"):
        response = GIVEN_get_request_with_unexpected_param_to_status_enpoint_is_sent
    with allure.step("THEN the response should be in JSON format"):
        assert response.json(), "Response is not a valid JSON object"


@allure.id("1456")
def test_status_response_content_type(GIVEN_get_request_to_status_endpoint_is_sent):
    with allure.step("WHEN I send GET request to /status"):
        response = GIVEN_get_request_to_status_endpoint_is_sent
    with allure.step("THEN the Content-Type should be application/json"):
        assert (
            response.headers["Content-Type"] == "application/json"
        ), "Content-Type is not application/json"


@allure.id("1457")
def test_status_response_json_schema(GIVEN_get_request_to_status_endpoint_is_sent):
    schema_file_path = (
        Path(__file__).parents[2] / "common" / "schemas" / "get_status_response.json"
    )
    with open(schema_file_path) as schema_file:
        schema = json.load(schema_file)
    with allure.step("WHEN I send a GET request to /status"):
        response = GIVEN_get_request_to_status_endpoint_is_sent.json()
    with allure.step("THEN the response JSON should match the expected schema"):
        try:
            validate(instance=response, schema=schema)
        except ValidationError as ve:
            assert False, f"Response JSON does not match the expected schema: {ve}"


@allure.id("1455")
def test_status_response_time(GIVEN_api_up_and_running):
    start_time = time.time()
    with allure.step("WHEN I send GET request to /status"):
        requests.get(f"{BASE_URL}/status")
        elapsed_time = time.time() - start_time
    with allure.step("THEN the response time should be less than 100ms"):
        assert (
            elapsed_time < 0.1
        ), f"Response time is {elapsed_time}s, which is longer than 100ms"
