# tps

## Usage

1. Establish a baseline:

    ```
    git checkout iroha2-dev
    ```
    ```
    cargo bench --bench tps-dev
    ```

2. Compare against the baseline:

    ```
    git checkout <your-optimization-commit>
    ```
    ```
    cargo bench --bench tps-dev
    ```
    * CAUTION: "improved" and "regressed" message are reversed due to the nature of Criterion.rs, which is supposed to measure time instead of throughput by default

3. See [the report](../../../target/criterion/report/index.html)

* In case the benchmark fails, please try to take [`interval_us_per_tx`](config.json) longer.

* Also single trial of the measurement would help:

    ```
    cd client
    ```
    ```
    cargo run --example tps-oneshot
    ```
