use std::collections::BTreeSet;

use eyre::Result;
use iroha_client::{client, data_model::prelude::*};
use serde_json::json;
use test_network::*;

#[test]
fn playing_with_custom_parameter() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_135).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    assert!(
        client
            .request(client::executor::data_model())?
            .parameters()
            .is_empty(),
        "existing parameters should be empty"
    );

    // Registering some domain while there is no prefix requirement
    client
        .submit_blocking(Register::domain(Domain::new("axolotl".parse().unwrap())))
        .expect("should be fine");

    let _err = client
        .submit_blocking(SetParameter::new(Parameter::new(
            "Whatever".parse().unwrap(),
            json!({ "foo": "bar" }),
        )))
        .expect_err("should not allow setting unknown parameters");

    super::upgrade::upgrade_executor(
        &client,
        "tests/integration/smartcontracts/executor_with_custom_parameter",
    )?;

    assert_eq!(
        *client.request(client::executor::data_model())?.parameters(),
        ["EnforceDomainPrefix"]
            .into_iter()
            .map(|x| ParameterId::new(x.parse().unwrap()))
            .collect::<BTreeSet<_>>(),
        "data model should have this set of parameters after upgrade"
    );

    let parameter = Parameter::new(
        "EnforceDomainPrefix".parse().unwrap(),
        json!({ "prefix": "disney_" }),
    );

    client
        .submit_blocking(SetParameter::new(parameter.clone()))
        .expect("should work, since this parameter is now registered");

    let _err = client
        .submit_blocking(SetParameter::new(Parameter::new(
            "WrongNonExistingParameter".parse().unwrap(),
            json!({ "prefix": "whatever" }),
        )))
        .expect_err("should still not work");

    assert_eq!(
        client
            .request(client::parameter::all())?
            .map(Result::unwrap)
            .collect::<BTreeSet<_>>(),
        [parameter.clone()].into_iter().collect(),
        "we should find set parameter in the parameters list"
    );

    let _err = client
        .submit_blocking(Register::domain(Domain::new("land".parse().unwrap())))
        .expect_err("should fail since `land` is not prefixed with `disney_`");

    client
        .submit_blocking(Register::domain(Domain::new(
            "disney_land".parse().unwrap(),
        )))
        .expect("should be fine, since we used prefix according to the parameter");

    Ok(())
}
