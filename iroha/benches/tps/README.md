# Benchmarks: Transactions per Second (TPS)

Benchmark your code during development and get a statistical report with tps measurements. [Criterion.rs](https://github.com/bheisler/criterion.rs) is used for benchmarking.

## Usage

1. Establish a baseline:

    Checkout the target branch (`main`):
    ```
    git checkout main
    ```
    Then run:
    ```
    cargo bench --bench tps-dev
    ```

2. Compare against the baseline:

    Checkout the commit you want to benchmark:
    ```
    git checkout <your-optimization-commit>
    ```
    Then run:
    ```
    cargo bench --bench tps-dev
    ```
    
    :exclamation: Since Criterion.rs measures time instead of throughput by default, `"improved"` and `"regressed"` messages are reversed.

3. Check the report at `../../../target/criterion/report/index.html`.

## Troubleshooting

If a benchmark fails, reduce the load by increasing the interval between transactions (`interval_us_per_tx`) in the [configuration file](config.json).

You can also run a single trial of the measurement:

```
cd client
cargo run --release --example tps-oneshot
```
