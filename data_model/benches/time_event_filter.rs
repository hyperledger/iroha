#![allow(missing_docs, clippy::restriction)]

use criterion::{criterion_group, criterion_main, Criterion};

#[cfg_attr(not(feature = "transparent_api"), allow(unused_variables))]
fn schedule_from_zero_with_little_period(criterion: &mut Criterion) {
    #[cfg(feature = "transparent_api")]
    {
        use std::time::Duration;

        use iroha_data_model::prelude::*;

        //                       *         *
        // --|-*-*-*- ... -*-*-*-[-*-...-*-)-*-*-*-
        //   p     52 years     i1   1sec  i2

        const TIMESTAMP: u64 = 1_647_443_386;

        let since = Duration::from_secs(TIMESTAMP);
        let length = Duration::from_secs(1);
        let interval = TimeInterval { since, length };
        let event = TimeEvent {
            prev_interval: None,
            interval,
        };
        let schedule =
            TimeSchedule::starting_at(Duration::ZERO).with_period(Duration::from_millis(1));
        let filter = TimeEventFilter::new(ExecutionTime::Schedule(schedule));

        criterion.bench_function("count_matches_from_zero", |b| {
            b.iter(|| filter.count_matches(&event));
        });
    }
}

criterion_group!(benches, schedule_from_zero_with_little_period);
criterion_main!(benches);
