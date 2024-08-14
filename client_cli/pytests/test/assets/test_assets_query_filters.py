import json

import allure  # type: ignore

from src.client_cli import client_cli, iroha


# using existing account with asset to have at least one in response
def test_filter_by_domain(GIVEN_currently_account_quantity_with_two_quantity_of_asset):
    def condition():
        domain = (
            GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.domain
        )
        with allure.step(f"WHEN client_cli query assets" f'in the "{domain}" domain'):
            assets = iroha.list_filter(
                {"Atom": {"Id": {"DefinitionId": {"DomainId": {"Equals": domain}}}}}
            ).assets()
        with allure.step("THEN Iroha should return only assets with this domain"):
            allure.attach(
                json.dumps(assets),
                name="assets",
                attachment_type=allure.attachment_type.JSON,
            )
            return assets and all(
                f"#{domain}#" in asset or ("##" in asset and f"@{domain}" in asset)
                for asset in assets
            )

    client_cli.wait_for(condition)


def test_filter_by_asset_name(
    GIVEN_currently_account_quantity_with_two_quantity_of_asset,
):
    def condition():
        name = (
            GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name
        )
        with allure.step(f'WHEN client_cli query assets with name "{name}"'):
            assets = iroha.list_filter(
                {"Atom": {"Id": {"DefinitionId": {"Name": {"Equals": name}}}}}
            ).assets()
        with allure.step("THEN Iroha should return only assets with this name"):
            allure.attach(
                json.dumps(assets),
                name="assets",
                attachment_type=allure.attachment_type.JSON,
            )
            return assets and all(asset.startswith(name) for asset in assets)

    client_cli.wait_for(condition)


def test_filter_by_asset_id(
    GIVEN_currently_authorized_account,
    GIVEN_currently_account_quantity_with_two_quantity_of_asset,
):
    def condition():
        asset_id = (
            GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name
            + "##"
            + GIVEN_currently_authorized_account.signatory
            + "@"
            + GIVEN_currently_authorized_account.domain
        )
        with allure.step(f'WHEN client_cli query assets with asset id "{asset_id}"'):
            assets = iroha.list_filter({"Atom": {"Id": {"Equals": asset_id}}}).assets()
        with allure.step("THEN Iroha should return only assets with this id"):
            allure.attach(
                json.dumps(assets),
                name="assets",
                attachment_type=allure.attachment_type.JSON,
            )
            return assets and all(asset == asset_id for asset in assets)

    client_cli.wait_for(condition)
