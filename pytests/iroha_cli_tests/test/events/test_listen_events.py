import allure  # type: ignore
import pytest

from ...src.iroha_cli import iroha_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_transfers_domain():
    allure.dynamic.story("Account streams events")


@allure.label("sdk_test_id", "stream_data_events_timeouts")
def test_stream_data_events_timeouts(GIVEN_currently_authorized_account):
    with allure.step(
        f"WHEN {GIVEN_currently_authorized_account} streams block-pipeline events with timeout "
    ):
        iroha_cli.execute(
            f"events data --timeout 1s"
        )

        iroha_cli.should(
            have.error("Timeout period has expired.\n")
        )
