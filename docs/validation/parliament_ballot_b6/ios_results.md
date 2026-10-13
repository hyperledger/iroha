# Attached iPhone observations

All 272 proofs completed on the physical iPhone 17 Pro Max (`iPhone18,2`, iOS 26.7): 31 candidate and three comparator proofs per case in each feature mode. Every honest proof accepted and every designated late-invalid proof rejected. All 136 feature-mode proof-digest/retry pairs matched; all 272 same-mode comparisons to the Mac records matched. This is ARM64 macOS/iOS evidence, not x86/ARM qualification.

The phone remained USB-connected and charging. It is not the required iPhone SE third generation. These runs are supplementary engineering observations, not battery-operation, sustained thermal, SDK cancellation or baseline qualification. No production integration was enabled.

## Identity and method

[Receipt](ios-receipt.json), [summary](ios-summary.json), [core source manifest](mac-source.sha256), and [native host template](ios_host_template/README.md) retain identities, conditions and reproduction instructions. The 223 core source files matched after all four runs. The template includes its separate lock graph and explicit substitutions for local source/signing paths; runtime signing/device identifiers are not saved here.

Rust used the repository 1.93.1 toolchain and aarch64-apple-ios target. The temporary bridge used optimization level 3, thin LTO and one codegen unit; its profile and dependency resolution differ from the desktop example. Xcode 27.0 (27A266a) built a release native UIKit application. Each run used one dedicated worker with an 8 MiB virtual stack reservation, plus the main UI/observation thread. Cross-platform timing differences cannot be attributed to hardware alone.

Cases ran in order: registration, vote3, vote500, vote1000. Mode/row order was accelerated candidate, accelerated comparator, portable candidate, portable comparator. No controlled cooling interval, cache reset, energy measurement or CPU isolation was imposed. The run headers and [runner method](../../../crates/iroha_parliament_ballot_proof/examples/QUALIFICATION.md) specify maximum registration fields, public test tapes, fresh input verification and allocator scope. Cold means fresh test-record decoding and digest/transcript work in a warm process, not cold process/cache conditions.

## Timings and heap

Times are **median / nearest-rank p95 / maximum milliseconds**. Candidate n=31 per case; comparator n=3 is exploratory, with p95 equal to maximum. Heap values are maximum requested live Rust bytes, including retained inputs and harness buffers, not whole-process memory bounds.

| Mode | Row | Case | n | Prove ms | Cold valid ms | Warm valid ms | Cold late-invalid ms | Prove heap B | Cold heap B | Maximum retry counter |
| --- | --- | --- | ---: | --- | --- | --- | --- | ---: | ---: | ---: |
| accel | candidate | registration | 31 | 162.442/171.924/176.176 | 80.371/85.751/88.530 | 80.332/85.323/91.725 | 80.587/86.467/90.739 | 3125371 | 2517799 | 931 |
| accel | candidate | vote3 | 31 | 259.459/272.915/273.377 | 126.999/131.714/133.062 | 127.870/131.520/133.681 | 128.096/133.077/134.994 | 4328339 | 3711295 | 997 |
| accel | candidate | vote500 | 31 | 283.084/297.514/306.135 | 135.335/142.946/143.390 | 135.186/142.704/144.506 | 135.089/144.609/151.390 | 4455571 | 3902143 | 1576 |
| accel | candidate | vote1000 | 31 | 315.937/328.490/354.411 | 150.092/159.977/161.520 | 148.710/156.332/156.635 | 151.728/160.906/166.352 | 4583571 | 4094143 | 1549 |
| accel | comparator | registration | 3 | 307.876/314.786/314.786 | 229.435/230.456/230.456 | 222.518/237.377/237.377 | 224.080/226.741/226.741 | 8339406 | 6146990 | 518 |
| accel | comparator | vote3 | 3 | 434.798/438.627/438.627 | 308.540/315.744/315.744 | 314.257/316.264/316.264 | 307.671/316.818/316.818 | 9518086 | 6185702 | 269 |
| accel | comparator | vote500 | 3 | 459.371/465.692/465.692 | 325.579/326.269/326.269 | 333.673/334.159/334.159 | 314.759/324.018/324.018 | 9645318 | 6376550 | 638 |
| accel | comparator | vote1000 | 3 | 482.507/487.658/487.658 | 324.405/330.365/330.365 | 330.086/335.542/335.542 | 328.246/331.763/331.763 | 9773318 | 6568550 | 760 |
| portable | candidate | registration | 31 | 305.038/317.616/323.802 | 218.274/231.675/231.930 | 219.889/233.130/239.958 | 221.899/234.396/240.503 | 3125385 | 2517813 | 931 |
| portable | candidate | vote3 | 31 | 474.019/483.427/487.879 | 334.489/342.275/342.332 | 334.401/345.758/346.900 | 336.126/345.964/346.786 | 4328353 | 3711309 | 997 |
| portable | candidate | vote500 | 31 | 490.925/499.529/502.088 | 343.640/356.310/356.592 | 346.185/357.420/361.665 | 344.630/357.981/363.513 | 4455585 | 3902157 | 1576 |
| portable | candidate | vote1000 | 31 | 519.712/553.631/565.759 | 358.049/389.082/391.331 | 359.818/380.725/384.670 | 358.938/380.050/381.364 | 4583585 | 4094157 | 1549 |
| portable | comparator | registration | 3 | 1662.496/1724.289/1724.289 | 1587.178/1641.032/1641.032 | 1602.093/1643.373/1643.373 | 1593.149/1664.259/1664.259 | 8339420 | 6147004 | 518 |
| portable | comparator | vote3 | 3 | 2379.481/2524.554/2524.554 | 2312.818/2382.299/2382.299 | 2340.723/2364.600/2364.600 | 2371.687/2381.796/2381.796 | 9518100 | 6185716 | 269 |
| portable | comparator | vote500 | 3 | 2558.200/2634.195/2634.195 | 2411.853/2476.364/2476.364 | 2411.382/2463.333/2463.333 | 2418.042/2472.884/2472.884 | 9645332 | 6376564 | 638 |
| portable | comparator | vote1000 | 3 | 2658.171/2754.586/2754.586 | 2493.454/2508.299/2508.299 | 2418.351/2498.750/2498.750 | 2504.318/2527.647/2527.647 | 9773332 | 6568564 | 760 |

Sample counters are actual unsuccessful challenge candidates, not a certificate of the grinding tail. The counter range and exhaustion behavior remain defined by the frozen protocol. Raw records retain each proof digest, counter, phase and allocation observation.

## Process, thermal and battery observations

The UIKit main thread sampled task_info, thermal state, battery and low-power mode every 250 ms, with initial and final observations. All task_info calls succeeded and low-power mode remained off. Thermal state values are 0 nominal, 1 fair and 2 serious. Battery state 2 means charging. Sampled maxima may miss short peaks and cannot establish a deterministic memory ceiling. Resident bytes and physical footprint are different OS quantities; neither should be added to the Rust counter.

| Mode / row | Duration s | Observations | Thermal states | Maximum physical footprint B | Maximum resident B |
| --- | ---: | ---: | --- | ---: | ---: |
| accel / candidate31 | 78 | 316 | 0 | 22250344 | 101138432 |
| accel / comparator3 | 17 | 70 | 0 | 29377432 | 104644608 |
| portable / candidate31 | 174 | 698 | 0, 1 | 22037400 | 101154816 |
| portable / comparator3 | 115 | 462 | 1, 2 | 27771800 | 104775680 |

The portable comparator run reached serious thermal state; this is retained, not filtered out. Its three samples per case do not characterize a population tail or thermal steady state. Both candidate runs and the accelerated comparator completed before that state was observed.

## Raw evidence

- accel candidate31: [measurements](ios-accel-candidate31.jsonl), [device observations](ios-accel-candidate31-device.plist), [completion](ios-accel-candidate31-complete.txt).
- accel comparator3: [measurements](ios-accel-comparator3.jsonl), [device observations](ios-accel-comparator3-device.plist), [completion](ios-accel-comparator3-complete.txt).
- portable candidate31: [measurements](ios-portable-candidate31.jsonl), [device observations](ios-portable-candidate31-device.plist), [completion](ios-portable-candidate31-complete.txt).
- portable comparator3: [measurements](ios-portable-comparator3.jsonl), [device observations](ios-portable-comparator3-device.plist), [completion](ios-portable-comparator3-complete.txt).

The completion marker, final run_complete record, expected source/feature labels, exact sample counts, honest and late-invalid outcomes, bounded counters and digest/retry parity were checked before archiving. The host's two wrapper tests plus eight runner helper tests passed in both configurations on the development Mac; those host tests alone are not device qualification. [Artifact checksums](IOS_RESULTS_SHA256SUMS) cover this report and the device evidence.

A later unrelated root lockfile change occurred after the measured runs. The [exact measured lock](measured-root-Cargo.lock.template) and [recovery provenance](post-measurement-lock-change.json) retain the original graph; the live checkout was not reverted. The source manifest describes the measurement snapshot, not the later checkout.
