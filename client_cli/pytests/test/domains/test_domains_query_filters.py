import json

import allure  # type: ignore

from src.client_cli import client_cli, iroha


def test_filter_by_domain(GIVEN_registered_domain):
    def condition():
        domain_name = GIVEN_registered_domain.name
        with allure.step(
            f'WHEN client_cli query domains filtered by name "{domain_name}"'
        ):
            domains = iroha.list_filter(
                {"Atom": {"Id": {"Equals": domain_name}}}
            ).domains()
        with allure.step(
            f'THEN Iroha should return only return domains with "{domain_name}" name'
        ):
            allure.attach(
                json.dumps(domains),
                name="domains",
                attachment_type=allure.attachment_type.JSON,
            )
            return domains and all(domain == domain_name for domain in domains)

    client_cli.wait_for(condition)
