# How to Monitor Iroha Peer

When you need to monitor state and work of Iroha peer, use this guide.

## Prerequisites

* [Iroha CLI](https://github.com/hyperledger/iroha/blob/iroha2-dev/iroha_client_cli/README.md)

## Steps

### 1. Run CLI Command to check Peer's Health

```bash
./iroha_client_cli maintenance health
```

### 2. Check Output

If output is `Health is Healthy` then peer is in a good state.

### 3. Run CLI Command to scrape Peer's Metrics

```bash
./iroha_client_cli maintenance metrics
```

### 4. Check Output

Output will contain information about peer's metrics:

```bash
Metrics { cpu: Cpu { load: Load { frequency: "Ok(CpuFrequency { current: 1204494750 s^-1, min: Some(800000000 s^-1), max: Some(3700000000 s^-1) })", stats: "Ok(CpuStats { ctx_switches: 420120348, interrupts: 88638100 })", time: "Ok(CpuTime { user: 17592.36 s^1, system: 6387.2 s^1, idle: 66334.01 s^1 })" } }, disk: Disk { block_storage_size: 0, block_storage_path: "./blocks" }, memory: Memory { memory: "Ok(Memory { total: 7972520000, available: 1874804000, free: 599556000 })", swap: "Ok(Swap { total: 16777212000, used: 5232588000, free: 11544624000 })" } }
```

## Conclusion

CLI Client or custom solution using `iroha-client` library can easily check Iroha peers helth and metrics.
