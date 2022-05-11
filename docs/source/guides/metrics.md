# Metrics

To conveniently and thoroughly monitor the performance of the network, we recommend using [`prometheus`](https://prometheus.io/). Prometheus is a program that can monitor your Iroha peer over a separate socket and provide different kinds of performance metrics.

This data can help you find performance bottlenecks and optimise your Iroha configuration.

## How to use metrics

To use metrics, you need to configure the `/metrics` endpoint in the [Iroha configuration](../references/config.md). By default, the endpoint is exposed at `127.0.0.1:8180/metrics`. If the port is not available, Iroha will still start and work normally, but metrics won't be accessible.

After that, use the IP address to access the data from the running Iroha instance. For example:

```bash
curl http://127.0.0.1:8080/metrics
```

This will give you a result like this:

```bash
# HELP blocks_height Total number of blocks in chain
# TYPE blocks_height gauge
blocks_height 135543
# HELP peers_number Total number peers to send transactions and request proposals
# TYPE peers_number gauge
peers_number 7
# HELP number_of_domains Total number of domains in WSV
# TYPE number_of_domains gauge
number_of_domains 14
# HELP total_number_of_transactions Total number of transactions in blockchain
# TYPE total_number_of_transactions gauge
total_number_of_transactions 216499
# HELP number_of_signatures_in_last_block Number of signatures in last block
# TYPE number_of_signatures_in_last_block gauge
number_of_signatures_in_last_block 5
```

## `/metrics` endpoint

Refer to the [API specification](../references/api_spec.md#metrics).