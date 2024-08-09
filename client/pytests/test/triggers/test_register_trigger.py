import allure  # type: ignore
import pytest

from src.client_cli import client_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_registers_trigger():
    allure.dynamic.story("Account register a register_trigger")
    allure.dynamic.label("permission", "no_permission_required")


@allure.label("sdk_test_id", "register_trigger")
@pytest.mark.xfail(reason="wait for #4151")
def test_register_trigger(GIVEN_currently_authorized_account):
    with allure.step(
        f'WHEN client_cli registers a register_trigger for "{GIVEN_currently_authorized_account}"'
    ):
        client_cli.register_trigger(GIVEN_currently_authorized_account)
    with allure.step(
        "THEN Iroha should have the asset with nft_number_1_for_genesis##\
        ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4@genesis"
        # TODO use the same source as GENESIS_PUBLIC_KEY of peer
    ):
        iroha.should(
            have.asset(
                "nft_number_1_for_genesis##\
                ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4@genesis"
                # TODO use the same source as GENESIS_PUBLIC_KEY of peer
            )
        )
