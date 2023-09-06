// TODO Consider whether such a test can be performed without an actual peer
// and how reasonable it is.
//
// We'll need to have a mock server imitating a peer and sending back the responses,
// serialized with a SCALE codec.

fn main() {
    register_without_metadata_test()
        .expect("Registration example is expected to work correctly");
    register_with_metadata_test()
        .expect("Registration example with metadata is expected to work correctly");
    println!("Success!");
}

fn register_without_metadata_test() -> Result<(), Error> {
    // #region submit
    iroha_client.submit(create_looking_glass)?;
    // #endregion submit

    // Finish the test successfully
    Ok(())
}

fn register_with_metadata_test() -> Result<(), Error> {
    // #region submit_with_metadata
    iroha_client
        .submit_with_metadata(create_looking_glass, UnlimitedMetadata::default())?;
    // #endregion submit_with_metadata

    // Finish the test successfully
    Ok(())
}