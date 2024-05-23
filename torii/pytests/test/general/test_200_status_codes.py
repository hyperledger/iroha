import allure
import pytest
import requests
import json

from common.settings import BASE_URL


@pytest.fixture(scope="function", autouse=True)
def status_codes_200():
    allure.dynamic.label("status_code", "200")


valid_log_levels = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"]


@allure.id("1553")
@allure.label("endpoint", "/configuration")
@allure.label("method", "POST")
@pytest.mark.parametrize("log_level", valid_log_levels)
def test_post_configuration_logger_level(log_level):
    with allure.step(
        f"WHEN I send POST request to /configuration with logger level {log_level}"
    ):
        response = requests.post(
            f"{BASE_URL}/configuration",
            data=json.dumps({"logger": {"level": log_level}}),
        )

    with allure.step("THEN the response should be accepted"):
        assert (
            response.status_code == 202
        ), f"Expected status code 202, but got {response.status_code}"


@allure.id("1097")
@allure.label("endpoint", "/api_version")
@allure.label("method", "GET")
def test_api_version_status_code_200():
    with allure.step("WHEN I send GET request to /api_version"):
        response = requests.get(f"{BASE_URL}/api_version")
    with allure.step("THEN the response status code should be 200"):
        assert response.status_code == 200, "Status code is not 200 for /api_version"


@allure.id("1099")
@allure.label("endpoint", "/configuration")
@allure.label("method", "GET")
def test_configuration_status_code_200():
    with allure.step("WHEN I send GET request to /configuration"):
        response = requests.get(f"{BASE_URL}/configuration")
    with allure.step("THEN the response status code should be 200"):
        assert response.status_code == 200, "Status code is not 200 for /configuration"


@allure.id("1090")
@allure.label("endpoint", "/health")
@allure.label("method", "GET")
def test_health_status_code_200():
    with allure.step("WHEN I send GET request to /health"):
        response = requests.get(f"{BASE_URL}/health")
    with allure.step("THEN the response status code should be 200"):
        assert response.status_code == 200, "Status code is not 200 for /health"


@allure.id("1094")
@allure.label("endpoint", "/schema")
@allure.label("method", "GET")
def test_schema_status_code_200():
    with allure.step("WHEN I send GET request to /schema"):
        response = requests.get(f"{BASE_URL}/schema")
    with allure.step("THEN the response status code should be 200"):
        assert response.status_code == 200, "Status code is not 200 for /schema"


@allure.id("1096")
@allure.label("endpoint", "/status")
@allure.label("method", "GET")
def test_status_status_code_200():
    with allure.step("WHEN I send GET request to /status"):
        response = requests.get(f"{BASE_URL}/status")
    with allure.step("THEN the response status code should be 200"):
        assert response.status_code == 200, "Status code is not 200 for /status"


@allure.id("1098")
@allure.label("endpoint", "/metrics")
@allure.label("method", "GET")
def test_metrics_status_code_200():
    with allure.step("WHEN I send GET request to /metrics"):
        response = requests.get(f"{BASE_URL}/metrics")
    with allure.step("THEN the response status code should be 200"):
        assert response.status_code == 200, "Status code is not 200 for /metrics"


@allure.id("1092")
@allure.label("endpoint", "/api_version")
@allure.label("method", "GET")
def test_api_version_status_code_200_with_unexpected_param():
    with allure.step(
        "WHEN I send GET request to /api_version with an unexpected parameter"
    ):
        response = requests.get(
            f"{BASE_URL}/api_version", params={"unexpected": "param"}
        )
    with allure.step("THEN the response status code should be 200"):
        assert (
            response.status_code == 200
        ), "Status code is not 200 for /api_version with unexpected parameter"


@allure.id("1099")
@allure.label("endpoint", "/configuration")
@allure.label("method", "GET")
def test_configuration_status_code_200_with_unexpected_param():
    with allure.step(
        "WHEN I send GET request to /configuration with an unexpected parameter"
    ):
        response = requests.get(
            f"{BASE_URL}/configuration", params={"unexpected": "param"}
        )
    with allure.step("THEN the response status code should be 200"):
        assert (
            response.status_code == 200
        ), "Status code is not 200 for /configuration with unexpected parameter"


@allure.id("1093")
@allure.label("endpoint", "/health")
@allure.label("method", "GET")
def test_health_status_code_200_with_unexpected_param():
    with allure.step("WHEN I send GET request to /health with an unexpected parameter"):
        response = requests.get(f"{BASE_URL}/health", params={"unexpected": "param"})
    with allure.step("THEN the response status code should be 200"):
        assert (
            response.status_code == 200
        ), "Status code is not 200 for /health with unexpected parameter"


@allure.id("1095")
@allure.label("endpoint", "/schema")
@allure.label("method", "GET")
def test_schema_status_code_200_with_unexpected_param():
    with allure.step("WHEN I send GET request to /schema with an unexpected parameter"):
        response = requests.get(f"{BASE_URL}/schema", params={"unexpected": "param"})
    with allure.step("THEN the response status code should be 200"):
        assert (
            response.status_code == 200
        ), "Status code is not 200 for /schema with unexpected parameter"


@allure.id("1100")
@allure.label("endpoint", "/status")
@allure.label("method", "GET")
def test_status_status_code_200_with_unexpected_param():
    with allure.step("WHEN I send GET request to /status with an unexpected parameter"):
        response = requests.get(f"{BASE_URL}/status", params={"unexpected": "param"})
    with allure.step("THEN the response status code should be 200"):
        assert (
            response.status_code == 200
        ), "Status code is not 200 for /status with unexpected parameter"


@allure.id("1101")
@allure.label("endpoint", "/metrics")
@allure.label("method", "GET")
def test_metrics_status_code_200_with_unexpected_param():
    with allure.step(
        "WHEN I send GET request to /metrics with an unexpected parameter"
    ):
        response = requests.get(f"{BASE_URL}/metrics", params={"unexpected": "param"})
    with allure.step("THEN the response status code should be 200"):
        assert (
            response.status_code == 200
        ), "Status code is not 200 for /metrics with unexpected parameter"
