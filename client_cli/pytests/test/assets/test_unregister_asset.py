import allure  # type: ignore
import pytest

from src.client_cli import client_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_unregisters_asset():
    allure.dynamic.story("Account unregisters an asset")
    allure.dynamic.label("permission", "no_permission_required")


@allure.label("sdk_test_id", "unregister_asset")
@pytest.mark.parametrize(
    "GIVEN_numeric_asset_for_account",
    [
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland"
    ],
    indirect=True,
)
@pytest.mark.xfail(reason="wait for #4039")
def test_unregister_asset(
    GIVEN_numeric_asset_for_account,
):
    with allure.step(
        f'WHEN client_cli unregisters the asset "{GIVEN_numeric_asset_for_account.definition.name}"'
    ):
        client_cli.unregister_asset(
            asset_id=f"{GIVEN_numeric_asset_for_account.definition.name}#"
            f"{GIVEN_numeric_asset_for_account.account}@"
            f"{GIVEN_numeric_asset_for_account.definition.domain}"
        )
    with allure.step(
        f'THEN Iroha should not have the asset "{GIVEN_numeric_asset_for_account.definition.name}"'
    ):
        iroha.should(
            have.asset(
                f"{GIVEN_numeric_asset_for_account.definition.name}##"
                f"{GIVEN_numeric_asset_for_account.account}@"
                f"{GIVEN_numeric_asset_for_account.definition.domain}"
            )
        )
