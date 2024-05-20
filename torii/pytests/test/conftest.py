import allure
import pytest


@pytest.fixture(scope="session", autouse=True)
def GIVEN_api_up_and_running():
    with allure.step("Given the API is up and running"):
        pass