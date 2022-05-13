//! Benchmark by iterating a tps measurement and analyzing it into a statistical report
//! using [criterion](https://github.com/bheisler/criterion.rs)
//! for performance check during development
#![allow(missing_docs)]

use criterion::{
    black_box, criterion_group, criterion_main,
    measurement::{Measurement, ValueFormatter},
    BenchmarkId, Criterion, Throughput,
};

use crate::lib::Config;

mod lib;

#[allow(clippy::multiple_inherent_impl)]
impl Config {
    #[allow(clippy::expect_used)]
    fn bench(self, c: &mut Criterion<Tps>) {
        let mut group = c.benchmark_group("tps");

        group.sample_size(self.sample_size as usize);

        group.bench_function(BenchmarkId::from_parameter(&self), move |b| {
            b.iter_custom(|_| self.measure().expect("Failed to measure"));
        });

        group.finish();
    }
}

#[allow(clippy::expect_used)]
fn bench_tps_with_config(c: &mut Criterion<Tps>) {
    let config = Config::from_path("benches/tps/config.json").expect("Failed to configure");
    iroha_logger::info!(?config);
    black_box(config).bench(c);
}

fn alternate_measurement() -> Criterion<Tps> {
    Criterion::default().with_measurement(Tps)
}

criterion_group! {
    name = benches;
    config = alternate_measurement();
    targets = bench_tps_with_config
}
criterion_main!(benches);

struct Tps;

impl Measurement for Tps {
    type Intermediate = ();
    type Value = lib::Tps;

    fn start(&self) -> Self::Intermediate {
        unreachable!()
    }
    fn end(&self, _i: Self::Intermediate) -> Self::Value {
        unreachable!()
    }
    #[allow(clippy::float_arithmetic)]
    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        *v1 + *v2
    }
    fn zero(&self) -> Self::Value {
        f64::MIN_POSITIVE
    }
    fn to_f64(&self, value: &Self::Value) -> f64 {
        *value
    }
    fn formatter(&self) -> &dyn ValueFormatter {
        &TpsFormatter
    }
}

struct TpsFormatter;

impl ValueFormatter for TpsFormatter {
    fn scale_values(&self, _typical_value: f64, _values: &mut [f64]) -> &'static str {
        "tps"
    }
    fn scale_throughputs(
        &self,
        _typical_value: f64,
        _throughput: &Throughput,
        _values: &mut [f64],
    ) -> &'static str {
        unreachable!()
    }
    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        "tps"
    }
}
