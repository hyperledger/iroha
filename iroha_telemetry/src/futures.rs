//! Module with telemetry future telemetry processing

use std::collections::HashMap;
use std::convert::TryFrom;
use std::marker::Unpin;
use std::time::Duration;

use async_std::future;
use async_std::stream::{Stream, StreamExt};
use iroha_futures::FuturePollTelemetry;
use iroha_logger::telemetry::Telemetry;
use serde::{Deserialize, Serialize};

pub mod post_process {
    //! Module with telemetry post processing

    #![allow(clippy::clippy::unwrap_used, clippy::fallible_impl_from)]
    use super::*;

    /// Post processed info of function
    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct PostProcessedInfo {
        /// Function name
        pub name: String,
        /// Standard deviation
        pub stddev: f64,
        /// Variance
        pub variance: f64,
        /// Median
        pub median: f64,
        /// Mean
        pub mean: f64,
        /// Minimum
        pub min: f64,
        /// Maximum
        pub max: f64,
    }

    impl From<(String, HashMap<u64, Vec<Duration>>)> for PostProcessedInfo {
        fn from((name, entries): (String, HashMap<u64, Vec<Duration>>)) -> Self {
            let iter = entries
                .values()
                .flat_map(IntoIterator::into_iter)
                .map(Duration::as_secs_f64);
            let minmax = iter.clone().collect::<stats::MinMax<f64>>();

            let mean = stats::mean(iter.clone());
            let median = stats::median(iter.clone()).unwrap();
            let variance = stats::variance(iter.clone());
            let stddev = stats::stddev(iter.clone());
            let min = *minmax.min().unwrap();
            let max = *minmax.max().unwrap();

            Self {
                min,
                max,
                name,
                mean,
                median,
                variance,
                stddev,
            }
        }
    }

    /// Collects info from stream of future poll telemetry
    pub async fn collect_info(
        mut receiver: impl Stream<Item = FuturePollTelemetry> + Unpin + Send,
    ) -> Vec<PostProcessedInfo> {
        let mut out = HashMap::<String, HashMap<u64, Vec<_>>>::new();
        let timeout = Duration::from_millis(100);
        while let Ok(Some(FuturePollTelemetry { id, name, duration })) =
            future::timeout(timeout, receiver.next()).await
        {
            out.entry(name)
                .or_default()
                .entry(id)
                .or_default()
                .push(duration);
        }
        out.into_iter().map(Into::into).collect()
    }
}

/// Gets stream of future poll telemetry out of general telemetry stream
pub fn get_stream(
    receiver: impl Stream<Item = Telemetry> + Unpin,
) -> impl Stream<Item = FuturePollTelemetry> + Unpin {
    receiver
        .map(FuturePollTelemetry::try_from)
        .filter_map(Result::ok)
        .map(
            |FuturePollTelemetry {
                 id,
                 mut name,
                 duration,
             }| {
                name.retain(|c| !c.is_whitespace());
                FuturePollTelemetry { id, name, duration }
            },
        )
}
