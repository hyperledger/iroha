// #region filter_requirements
use iroha_data_model::prelude::*;
// #endregion filter_requirements

fn main() {
    event_listen_test()
        .expect("Event filter example is expected to work correctly");
}

fn event_listen_test() -> Result<(), Error> {
    // #region build_a_filter
    let filter = FilterBox::Pipeline(PipelineEventFilter::identity());
    // #endregion build_a_filter

    // #region listen
    for event in iroha_client.listen_for_events(filter)? {
        match event {
            Ok(event) => println!("Success: {:#?}", event),
            Err(err) => println!("Sadness:( {:#?}",  err),
        }
    };
    // #endregion listen

    // Finish the test successfully
    Ok(())
}