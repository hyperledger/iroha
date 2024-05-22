import json
import requests
import pytest
import allure
from jsonschema import validate
from jsonschema.exceptions import ValidationError

from common.settings import BASE_URL

valid_log_levels = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"]


@pytest.fixture(scope="function", autouse=True)
def setup_configuration():
    allure.dynamic.label("endpoint", "/configuration")
    allure.dynamic.label("method", "POST")


@allure.id("1552")
@allure.label("status_code", "400")
def test_post_configuration_invalid_data():
    with allure.step("WHEN I send POST request with invalid data to /configuration"):
        response = requests.post(
            f"{BASE_URL}/configuration",
            data=json.dumps({"logger": {"level": "invalid"}}),
        )

    with allure.step("THEN the response status code should be a client error"):
        assert (
            400 == response.status_code
        ), "Response status code is not a client or server error for invalid data"


@allure.label("status_code", "202")
@pytest.mark.parametrize("log_level", valid_log_levels)
def test_post_configuration_valid_logger_level(log_level):
    with allure.step(
        f"WHEN I send POST request to /configuration with logger level {log_level}"
    ):
        requests.post(
            f"{BASE_URL}/configuration",
            data=json.dumps({"logger": {"level": log_level}}),
        )

    with allure.step(f"THEN the log level should be {log_level}"):
        get_response = requests.get(f"{BASE_URL}/configuration")
        assert (
            get_response.json()["logger"]["level"] == log_level
        ), f"Logger level '{get_response.json()['logger']['level']}' is not {log_level}"
