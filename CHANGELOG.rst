Changelog
=========


(current)
---------

Features
~~~~~~~~
- 1970: Add optional schema endpoint. [Aleksandr]
- 1620: Introduce time based triggers (#1961) [Daniil]
- 1918: Implement basic authentication for `client` (#1942) [Daniil]
- 1726: Implement a release PR workflow. (#1932) [Aleksandr Petrosyan]
- 1815: Make query responses more type-structured (#1867) [s8sato]
- 1928: implement changelog generation using `gitchangelog` (#1930)
  [Aleksandr Petrosyan]
- 1902: Bare metal 4-peer setup script. (#1923) [Aleksandr Petrosyan]

  Added a version of setup_test_env.sh that does not require docker-compose and uses the debug build of Iroha.
- 1619: Introduce event-based triggers (#1874) [Aleksandr Petrosyan]
- 1195: Close a websocket connection cleanly (#1899) [Daniil]
- 1606: Add ipfs link to domain logo in Domain structure (#1886)
  [Daniil]
- 1767: restrict linear memory usage for wasm smartcontracts (#1879)
  [Marin Veršić]

  restrict linear memory usage for wasm smartcontracts.
- 1766: Wasm permission validation (#1861) [Marin Veršić]

  * custom decode for SignaturesOf.
- 1754: Add Kura inspector CLI (#1817) [s8sato]

  * Define the interface.
- 1790: Improve performance by using stack-based vectors. (#1826)
  [Aleksandr Petrosyan]
- 1425: Wasm helper crate. [Marin Veršić]

  * add helper crate for writing wasm smartcontracts.
- 1425: add limits to wasm execution (#1828) [Marin Veršić]
- 1805: Optional terminal colors for panic errors (#1818) [Egor Ivkov]
- 1749: `no_std` in `data_model` (#1779) [Marin Veršić]
- 1179: Add revoke-permission-or-role instruction (#1748) [Aleksandr
  Petrosyan]
- 1782: make iroha_crypto no_std compatible. [Marin Veršić]
- 1425: add wasm runtime (#1759) [Marin Veršić]

  * add wasm runtime.
- 1172: Implement instruction events (#1764) [s8sato]

  * Split `iroha_data_model::events` to files.
- 1734: Validate `Name` to exclude whitespaces (#1743) [s8sato]

  * Unify metadata key to `Name`
- 1144: Add metadata nesting (#1738) [Aleksandr Petrosyan]

  * Added nested metadata.
- 1210 Block streaming - server side (#1724) [Marin Veršić]

  * move transaction related functionality to data_model/transaction module.
- 1331: Implement more `Prometheus` metrics (#1720) [Aleksandr
  Petrosyan]

  * Initial implementation of some metrics.
- 1689: Fix feature dependencies. (#1688) [Aleksandr Petrosyan]

  * [feature] #1261: Add cargo bloat.
- 1675: use type instead of wrapper struct for versioned items (#1665)
  [Marin Veršić]

  * use type instead of wrapper struct for inner versioned items.
- 1643: Wait for peers to commit genesis in tests (#1655) [Egor Ivkov]
- 1678: `try_allocate` (#1679) [GaroRobe]

  * Added allocation error handling using try_reserve.
- 1216: Add Prometheus endpoint.  (#1656) [Aleksandr Petrosyan]

  * [feature] #1216 - initial implementation of metrics endpoint.
- 1238: Run-time log-level updates (#1603) [Aleksandr Petrosyan]

  * [feat] Created basic `connection` entrypoint-based reloading.
- 1652: PR Title Formatting. [Egor Ivkov]
- Add the number of connected peers to `Status` (#1576) [s8sato]

  * Revert "Delete things related to the number of connected peers"

  This reverts commit b228b41dab3c035ce9973b6aa3b35d443c082544.

  Signed-off-by: s8sato <49983831+s8sato@users.noreply.github.com>

  * Clarify `Peer` has true public key only after handshake

  Signed-off-by: s8sato <49983831+s8sato@users.noreply.github.com>

  * `DisconnectPeer` without tests

  Signed-off-by: s8sato <49983831+s8sato@users.noreply.github.com>

  * Implement unregister peer execution

  Signed-off-by: s8sato <49983831+s8sato@users.noreply.github.com>

  * Add (un)register peer subcommand to `client_cli`

  Signed-off-by: s8sato <49983831+s8sato@users.noreply.github.com>

  * Refuse reconnections from an unregistered peer by its address

  After your peer unregisters and disconnects another peer,
  your network will hear reconnection requests from the peer.
  All you can know at first is the address whose port number is arbitrary.
  So remember the unregistered peer by the part other than the port number
  and refuse reconnection from there.
- Add `/status` endpoint to a specific port (#1646) [s8sato]

  * Add `/status` endpoint to a specific port.

Fixes
~~~~~
- 2013: Hotfix CLI args. [Aleksandr]
- 1955: Fix possibility to pass `:` inside `web_login` (#1956) [Daniil]
- 1943: Add query errors to the schema (#1950) [s8sato]
- 1939: Proper features for `iroha_config_derive`. (#1940) [Aleksandr
  Petrosyan]
- 1908: fix zero value handling for telemetry analysis script (#1906)
  [Ahmed Elkashef]
- 0000: Make implicitly ignored doc-test explicitly ignored. Fix typo.
  (#1878) [Aleksandr Petrosyan]
- 1865: use latest smallstr to be able to build no_std wasm
  smartcontracts. [Marin Veršić]
- 1848: Prevent public keys from being burned to nothing (#1860)
  [s8sato]
- 1811: added tests and checks to dedup trusted peer keys. (#1844)
  [Aleksandr Petrosyan]
- 1821: add IntoSchema for MerkleTree and VersionedValidBlock, fix
  HashOf and SignatureOf schemas. [Marin Veršić]
- 1819: Remove traceback from error report in validation. (#1820)
  [Aleksandr Petrosyan]
- 1774: log exact reason for validation failures. (#1810) [Aleksandr
  Petrosyan]
- 1714: Compare PeerId only by key (#1800) [Egor Ivkov]
- 1788: Reduce memory footprint of `Value`. (#1807) [Aleksandr
  Petrosyan]
- 1804: fix schema generation for HashOf, SignatureOf, add test to
  ensure no schemas are missing. [Marin Veršić]
- 1802: Logging readability improvements (#1803) (#1806) [Egor Ivkov]

  - events log moved to trace level
  - ctx removed from log capture
  - terminal colors are made optional (for better log output to files)
- 1783: Fixed torii benchmark. (#1784) [Aleksandr Petrosyan]
- 1772: Fix after #1764 (#1773) [s8sato]
- 1755: Minor fixes for #1743, #1725 (#1760) [s8sato]

  * Fix JSONs according to #1743 `Domain` struct change.
- 1751: Consensus fixes (#1757) [Egor Ivkov]

  * [fix] #1715: Consensus fixes to handle high load (#1746)

  * View change handling fixes

  - View change proofs made independent of particular transaction hashes
  - Reduced message passing
  - Collect view change votes instead of sending messages right away (improves network resilience)
  - Fully use Actor framework in Sumeragi (schedule messages to self instead of task spawns)

  Signed-off-by: Egor Ivkov <e.o.ivkov@gmail.com>

  * Improves fault injection for tests with Sumeragi

  - Brings testing code closer to production code
  - Removes overcomplicated wrappers
  - Allows Sumeragi use actor Context in test code.
- 1734: Update genesis to fit the new Domain validation. (#1756)
  [Aleksandr Petrosyan]
- 1742: Concrete errors returned in `core` instructions. (#1744)
  [Aleksandr Petrosyan]
- 1404: Verify fixed. (#1745) [Aleksandr Petrosyan]
- 1636: Remove `trusted_peers.json` and `structopt` (#1739) [Aleksandr
  Petrosyan]

  * [fix] #1636: Remove `trusted_peers.json`.
- 1706: Update `max_faults` with Topology update (#1710) [s8sato]

  * Update `max_faults` with Topology update.
- 1698: Fixed public keys, documentation and error messages. (#1700)
  [Aleksandr Petrosyan]
- Minting issues (1593 and 1405) (#1629) [Aleksandr Petrosyan]

  * [fix] issue 1405.

Refactor
~~~~~~~~
- : Core, `sumeragi`, instance functions, `torii` (#1965) [Aleksandr
  Petrosyan]
- 1903: move event emission to `modify_*` methods (#1931) [Daniil]
- : Split `data_model` lib.rs file (#1905) [Daniil]
- : add wsv reference to quueue. [Marin Veršić]
- 1210: Split event stream (#1729) [Marin Veršić]

  * move transaction related functionality to data_model/transaction module.
- 1725: Remove global state in Torii (#1721) [Marin Veršić]

  * implement add_state macro_rules and remove `ToriiState`
- : Fix linter error (#1681) [GaroRobe]
- 1661: `Cargo.toml` cleanup (#1670) [Marin Veršić]

  * sort out cargo dependencies.
- 1650: tidy up `data_model` (#1645) [Marin Veršić]

  * move World to wsv, fix roles feature, derive IntoSchema for CommittedBlock.
- Organisation of `json` files and readme.  (#1617) [Aleksandr
  Petrosyan]

  * [README.md] Updated Readme to conform to template.
- 1529: structured logging (#1598) [Marin Veršić]

  * refactor log messages.
- `iroha_p2p` (#1573) [Aleksandr Petrosyan]

  * Added p2p privatisation.

Documentation
~~~~~~~~~~~~~
- : Update outdated README files. [Aleksandr]
- : Added missing docs to `api_spec.md`. (#1941) [Aleksandr Petrosyan]
- : add wasm README (#1919) [Marin Veršić]

  * add wasm README.
- : Updates codeowners file (#1843) [Egor Ivkov]
- . (#1705) [Aleksandr Petrosyan]

  * [documentation] #1685: Update [Contributing.md].

CI/CD changes
~~~~~~~~~~~~~
- : Fix push workflow. [Aleksandr]
- : Add telemetry to default features. [Aleksandr]
- : add proper tag to push workflow on main. [Aleksandr]
- : fix failing tests. (#1938) [Aleksandr Petrosyan]
- 1657: Update image to rust 1.57 (#1666) [Aleksandr Petrosyan]

  * [fix] #1630: Move back to self-hosted runners.
- CI improvements (#1566) [Aleksandr Petrosyan]

  * Switched coverage to use `lld`.
- CI Dependency FIx (#1547) [Aleksandr Petrosyan]

  * Master rebase.
- CI segmentation improvements (#1542) [Aleksandr Petrosyan]

  * Master rebase.
- Uses a fixed Rust version in CI. [Egor Ivkov]
- Fixes Docker publish and iroha2-dev push CI. [Egor Ivkov]

  Also moves coverage and bench into PR.
- Removes unnecessary full Iroha build in CI docker test. [Egor Ivkov]

  The Iroha build became useless as it is now done in docker image itself. So the CI only builds the client cli which is used in tests.
- Adds supports for iroha2 branch in CI pipeline. [Egor Ivkov]

  - long tests only ran on PR into iroha2
  - publish docker images only from iroha2.
- Additional CI caches. [Nikita Puzankov]

Version bumps
~~~~~~~~~~~~~
- Update Mold 1.0 (#1736) [Aleksandr Petrosyan]
- Bump dependencies (#1677) [Marin Veršić]
- Update api_spec.md: fix request/response bodies (#1663) [0x009922]
- CODEOWNER update and minor fixes (#1579) [Marin Veršić]

  - add @mversic as codeowner
  - link to git hooks instead of copying
  - use --workspace vs --all for cargo subcommands.
- Update rust version to 1.56.0. [i1i1]
- Update contributing guide. [i1i1]
- Updated README.md and `iroha/config.json` to match new API and URL
  format. [Aleksandr]
- Update docker publish target to hyperledger/iroha2 #1453 (#1475)
  [s8sato]

  Fix some workflows #
- Updates workflow so that it matches main. [Egor Ivkov]
- Update CODEOWNERS.md with new team members. [Egor Ivkov]
- Update api spec and fix health endpoint. [i1i1]
- Rust update to 1.54. [i1i1]
- Docs(iroha_crypto): update `Signature` docs and align args of `verify`
  [0x009922]
- Ursa version bump from 0.3.5 to 0.3.6. [Egor Ivkov]
- Update workflows to new runners. [i1i1]
- Update dockerfile for caching and faster ci builds. [i1i1]
- Update libssl version. [i1i1]
- Update dockerfiles and async-std. [i1i1]
- Fix updated clippy. [i1i1]
- Update CODEOWNERS. [Nikita Puzankov]
- Updates asset structure. [Egor Ivkov]

  - Support for key-value instructions in asset
  - Asset types as an enum
  - Overflow vulnerability in asset ISI fix.
- Updates contributing guide. [Egor Ivkov]
- Update out of date lib. [武宮誠]
- Update whitepaper and fix linting issues. [武宮誠]
- Update the cucumber_rust lib. [武宮誠]
- README updates for key generation. [Egor Ivkov]
- Update Github Actions workflows. [Nikita Puzankov]
- Update Github Actions workflows. [Nikita Puzankov]
- Update requirements.txt. [Sara]
- Update common.yaml. [Nikita Puzankov]
- Docs updates from Sara. [Nikita Puzankov]
- Update instruction logic. [武宮誠]
- Update whitepaper. [武宮誠]
- Updates network functions description. [Egor Ivkov]
- Update whitepaper based on comments. [武宮誠]
- Separation of WSV update and migration to Scale. [Nikita Puzankov]
- Update gitignore. [武宮誠]
- Update slightly description of kura in WP. [武宮誠]
- Update description about kura in whitepaper. [武宮誠]

Schema
~~~~~~
- Make schema, version and macro no_std compatible (#1781) [Marin
  Veršić]
- Fix signatures in schema. [i1i1]
- Altered  representation of `FixedPoint` in schema. [rkharisov]
- Added `RawGenesisBlock` to schema introspection. [rkharisov]
- Changed object-models to create schema IR-115. [rkharisov]

Tests
~~~~~
- Standardize ui tests format, move derive ui tests to derive crates
  (#1708) [Marin Veršić]
- Fix mock tests - futures unordered bug (#1642) [Egor Ivkov]
- Removed the DSL crate & moved tests to `data_model` (#1545) [Aleksandr
  Petrosyan]
- Ensure that unstable network tests pass for valid code. [Egor Ivkov]
- Added tests to iroha_p2p. [Revertron]
- Captures logs in tests unless test fails. [Egor Ivkov]
- Add polling for tests and fix rarely breaking tests. [i1i1]
- Tests parallel setup. [i1i1]
- Remove root from iroha init and iroha_client tests. [i1i1]
- Fix tests clippy warnings and adds checks to ci. [i1i1]
- Fixes tx validation errors during benchmark tests. [Egor Ivkov]

  Also fixes a bug with tarpauline segfault.
- IR-860: Iroha Queries and tests. [Nikita Puzankov]
- Iroha custom ISI guide and Cucumber tests. [Nikita Puzankov]
- Add tests for no-std client. [Vladislav Markushin]
- Bridge registration changes & tests. [Vladislav Markushin]
- Consensus tests with network mock. [Egor Ivkov]
- Usage of temp dir for tests execution. [Nikita Puzankov]
- Benches tests positive cases. [Nikita Puzankov]
- Initial Merkle Tree functionality with tests. [Nikita Puzankov]
- Fixed tests and World State View initialization. [Nikita Puzankov]

Other
~~~~~
- Fix return value for QueryBox execution in wasm (#1954) [Marin Veršić]
- Share workdir as a volume with dev docker instances (#1910) [Marin
  Veršić]
- Remove Diff associated type in Execute (#1895) [Marin Veršić]
- Produce events while executing wasm smartcontract (#1894) [Marin
  Veršić]
- Add arjentix into codeowners file (#1880) [Daniil]
- Use custom encoding instead of multival return (#1873) [Marin Veršić]
- Remove serde_json as iroha_crypto dependency (#1722) [Marin Veršić]
- Allow only known fields in version attribute (#1723) [Marin Veršić]
- Clarify different ports for endpoints (#1697) [s8sato]
- Remove Io derive (#1691) [Marin Veršić]
- Initial documentation of key_pairs. (#1684) [Aleksandr Petrosyan]
- Move back to self-hosted runners. (#1682) [Aleksandr Petrosyan]
- Fix new clippy lints in the code (#1669) [Marin Veršić]
- Remove i1i1 from maintainers (#1667) [Ivan]
- Add actor doc and minor fixes (#1647) [Ivan]
- Poll instead of pushing latest blocks (#1613) [Marin Veršić]

  * poll instead of pushing latest blocks.
- Transaction status events tested for each of 7 peers (#1631) [Egor
  Ivkov]
- Removed myself from CODEOWNERS (#1634) [GaroRobe]

  * Removed myself from CODEOWNERS

  * Removed myself from CODEOWNERS.
- `FuturesUnordered` instead of `join_all` (#1627) [Marin Veršić]

  * use FuturesUnordered instead of join_all.
- Switch to GitHub Runners (#1625) [Egor Ivkov]
- Use VersionedQueryResult vs QueryResult for /query endpoint (#1611)
  [Marin Veršić]

  * return versioned query response for /query endpoint.
- Reconnect telemetry (#1574) [Alexey]
- Fix dependabot config (#1584) [Marin Veršić]
- Add commit-msg git hook to include signoff (#1586) [Marin Veršić]

  * add commit-msg git hook to ensure signoff is included in commit msg.
- Fix the push pipeline. (#1575) [Aleksandr Petrosyan]
- Upgrade dependabot (#1580) [Marin Veršić]
- Detect future timestamp on queue push (#1570) [s8sato]

  * Add utility function to get the current system time.
- GaroRobe/issue1197 (#1569) [GaroRobe]

  * Added DiskIO mock for error injection in Kura tests.
- Add Unregister peer instruction (#1555) [Aleksandr Petrosyan]

  * Master rebase.
- Add optional nonce to distinguish transactions. Close #1493 (#1563)
  [s8sato]
- Removed unnecessary `sudo`. (#1562) [Aleksandr Petrosyan]
- Metadata for domains (#1541) [Alexey]
- Fix the random bounces in `create-docker` workflow. (#1556) [Aleksandr
  Petrosyan]

  * Should fix the random bounces in `create-docker` workflow.
- Added `buildx` as suggested by the failing pipeline. (#1553)
  [Aleksandr Petrosyan]
- Fix query error response with specific status code and hints. Close
  #1454 (#1527) [s8sato]

  * Fix query error response with specific status code and hints. Close #1454.
- Sending telemetry (#1524) [Alexey]
- GaroRobe/issue1533 (#1537) [GaroRobe]

  * Fixed VersionedTransaction::from modifying creation timestamp.
  * Changed trx to tx, according to naming convention
  * Moved keypair and account into shared Lazy<>
- Fixup configure endpoint. [i1i1]
- Added boolean-based asset mintability check. (#1530) [Aleksandr
  Petrosyan]

  * Added boolean-based asset mintability check.
- Addition of typed crypto primitives and migration to typesafe
  cryptography. [i1i1]
- Logging improvements (#1518) [Aleksandr Petrosyan]

  * Removed code duplication via monomorphic dispatch.
- GaroRobe/issue1458 (#1523) [GaroRobe]

  * For each Actor added mailbox size
  as a config parmeter.
- GaroRobe/issue1451 (#1520) [GaroRobe]

  Removed MAX_FAULTY_PEERS parameter.
  Now max_faulty_peers() is a SumeragiConfiguration method.
  Calculated as (f-1)/3, where f is trusted peers count.
- Add handler for getting specific block hash. [i1i1]
- Added new query FindTransactionByHash. (#1517) [GaroRobe]
- Change crates name and path. Close #1185 (#1504) [s8sato]

  * Rename the library: `iroha` to `iroha_core`
- Added myself to CODEOWNERS. [Aleksandr]
- Fix logs and general improvements. [i1i1]
- GaroRobe/issue1150 (#1491) [GaroRobe]

  * Implemented feature for data files to store configurable number of blocks.
  * Proper async stream-style deserialization.
  * Added BlockStoreError for better error markup and 3 error-specific tests:
  1. Inconsequent write error
  2. Inconsequent read error
  3. Corrupted datafile error
  * Changed frame size type to u64.
  Temporarily limited buffer size for frame with 500Kb constant.
- Queue stress test. [Egor Ivkov]

  - Queue stress test
  - Some other minor tests added for queue cases
  - Queue test fixes
  - Fixes in the queue behavior due to improper rebase.
- Log level fix. [i1i1]
- Add header specification to client library. [i1i1]
- Queue panic failure fix. [Egor Ivkov]
- Gossip separated from round. [Egor Ivkov]

  Fixes bug when sometimes leader wouldn't propagate MST transactions.
- Fixup queue. [i1i1]
- Fixup dockerfile release build. [i1i1]
- Https client fixup. [i1i1]
- Speedup ci. [i1i1]
- 1. Removed all ursa dependences, except for iroha_crypto (#1470)
  [GaroRobe]
- Fix overflow when subtracting durations (#1194) (#1464) [s8sato]
- PR to add myself to CODEOWNERS.md (#1469) [Artem Ponomarev, GaroRobe]

  Fixes #1468.
- Make fields public in client. [i1i1]
- Push Iroha2 to Dockerhub as nightly. [i1i1]
- Fix http status codes. [i1i1]
- Replace iroha_error with thiserror, eyre and color-eyre. [Alexey
  Kalita]
- Substitute queue with crossbeam one. [i1i1]
- Remove some useless lint allowences. [i1i1]
- Introduces metadata for asset definitions. [Egor Ivkov]
- Removal of arguments from test_network crate. [i1i1]
- Remove unnecessary dependencies. [i1i1]
- Fix iroha_client_cli::events (#1395) [satu-n]
- Remove old network implementation. Closes #1382. [Revertron]
- Added precision for assets. Closes #1169. [Revertron]
- Improvements in peer start up. [Egor Ivkov]

  - Allows loading genesis public key only from env
  - config, genesis and trusted_peers path can now be specified in cli params.
- Integration of Iroha P2P. Closes #1134. [Revertron]
- Change query endpoint to POST instead of GET. [Egor Ivkov]
- Execute on_start in actor synchronously. [Egor Ivkov]
- Migrate to warp. [i1i1]
- Rework commit with broker bug fixes. [i1i1]
- Revert "Introduces multiple broker fixes" [i1i1]

  This reverts commit 9c148c33826067585b5868d297dcdd17c0efe246.
- Introduces multiple broker fixes. [Egor Ivkov]

  1. Unsubscribe from broker on actor stop
  2. Support multiple subscriptions from the same actor type (previously a TODO)
  3. Fixes a bug where broker always put self as an actor id.
- Broker bug - test showcase. [Egor Ivkov]
- Add derives for data model. [i1i1]
- Remove rwlock from torii. [i1i1]
- OOB Query Permission Checks. [Egor Ivkov]
- Implementation of peer counts, closes #1272. [Revertron]
- Recursive check for query permissions inside of instructions. [Egor
  Ivkov]
- Schedule stop actors. [Egor Ivkov]
- Implementation of peer counts, closes #1165. [Revertron]
- Check query permissions by account in torii endpoint. [Egor Ivkov]
- Removed exposing CPU and memory usage in system metrics. [rkharisov]
- Replace JSON with SCALE for WS messages. [Egor Ivkov]
- Store proof of view changes. [Egor Ivkov]

  - Store proofs
  - Use these proofs in BlockCreated to be up to date
  - Refactor view change handling logic.
- Added logging if transaction does not passed sugnature check condition
  IR-1168. [rkharisov]
- Fixed small issues, added connection listen code. [Revertron]
- Introduce network topology builder. [Egor Ivkov]
- Implement P2P network for Iroha. [Revertron]
- Adds block size metric. [Egor Ivkov]
- PermissionValidator trait renamed to IsAllowed. [Egor Ivkov]

  and corresponding other name changes.
- API spec web socket corrections. [Egor Ivkov]
- Removes unnecessary dependencies from docker image. [Egor Ivkov]
- Fmt uses Crate import_granularity. [Egor Ivkov]
- Introduces Generic Permission Validator. [Egor Ivkov]

  This will enable us to check permissions for query, with the use of already written combinators.
- Migrate to actor framework. [i1i1]
- Change broker design and add some functionality to actors. [i1i1]
- Configures codecov status checks. [Egor Ivkov]

  - The project status check will fail if the relative decrease in coverage is more than 5%
  - Check for percentage of new code coverage disabled.
- Uses source based coverage with grcov. [Egor Ivkov]
- Fixed multiple build-args format and redeclared ARG for intermediate
  build containers. [rkharisov]
- Introduces SubscriptionAccepted message. [Egor Ivkov]

  The message means that all event connection is initialized and will be supplying events starting from the next one.
- Remove zero-value assets from accounts after operating upon.
  [Revertron]
- Fixed docker build arguments format. [rkharisov]
- Fixed error message if child block not found. [Revertron]
- Added vendored OpenSSL to build, fixes pkg-config dependency.
  [Revertron]
- Fixes repository name for dockerhub and coverage diff. [Egor Ivkov]
- Added clear error text and filename if TrustedPeers could not be
  loaded. [Revertron]
- Changed text entities to links in docs. [Revertron]
- Fixes wrong username secret in Docker publish. [Egor Ivkov]
- Add self to codeowners. [Revertron]
- Fix small typo in whitepaper. [Revertron]
- Allows mod.rs usage for better file structure. [Egor Ivkov]
- Move main.rs into separate crate and make permissions for public
  blockchain. [i1i1]
- Add querying inside client cli. [i1i1]
- Migrate from clap to structopts for cli. [i1i1]
- Limit telemetry to unstable network test. [i1i1]
- Move traits to smartcontracts module. [i1i1]
- Sed -i "s/world_state_view/wsv/g" [i1i1]
- Move smart contracts into separate module. [i1i1]
- Iroha network content length bugfix. [i1i1]
- Adds task local storage for actor id. [Egor Ivkov]

  Useful for deadlock detection.

  Also adds deadlock detection test to CI.
- Add Introspect macro. [i1i1, i1i1, rkharisov]
- Removes Aler from codeowners. [Egor Ivkov]
- Disambiguates workflow names. [Egor Ivkov]

  also formatting corrections.
- Change of query api. [i1i1]
- Migration from async-std to tokio. [Egor Ivkov]
- Add analyze of telemetry to ci. [i1i1]
- Add futures telemetry for iroha. [i1i1]
- Add iroha futures to every async function. [i1i1]
- Add iroha futures for observability of number of polls. [i1i1]
- Manual deploy and configuration added to README. [Egor Ivkov]
- Reporter fixup. [i1i1]
- Add derive Message macro. [i1i1]
- Add simple actor framework. [i1i1]
- Add dependabot configuration. [i1i1]
- Add nice panic and error reporters. [i1i1]
- Rust version migration to 1.52.1 and corresponding fixes. [Egor Ivkov]
- Spawn blocking CPU intensive tasks in separate threads. [Egor Ivkov]
- Use unique_port and cargo-lints from crates.io. [Egor Ivkov]
- Fixes for lockfree WSV. [Egor Ivkov]

  - removes unnecessary Dashmaps and locks in API
  - fixes bug with excessive number of blocks created (rejected transactions were not recorded)
  - Displays full error cause for errors.
- Add telemetry subscriber. [i1i1]
- Queries for roles and permissions. [Egor Ivkov]
- Move blocks from kura to wsv. [i1i1]
- Change to lock-free data structures inside wsv. [i1i1]
- Network timeout fix. [i1i1]
- Fixup health endpoint. [i1i1]
- Introduces Roles. [Egor Ivkov]
- Add push docker images from dev branch. [i1i1]
- Add more agressive linting and remove panics from code. [i1i1]
- Rework of Execute trait for instructions. [i1i1]
- Remove old code from iroha_config. [i1i1]
- IR-1060 Adds Grant checks for all the existing permissions. [Egor
  Ivkov]
- Fix ulimit and timeout for iroha_network. [i1i1]
- Ci timeout test fix. [i1i1]
- Remove all assets when their definition was removed. [Egor Ivkov]
- Fix wsv panic at adding asset. [i1i1]
- Remove Arc and Rwlock for channels. [i1i1]
- Iroha network fixup. [i1i1]
- Permission Validators use references in checks. [Egor Ivkov]
- Grant Instruction. [Egor Ivkov]
- Added configuration for string length limits and validation of id's
  for NewAccount, Domain and AssetDefinition IR-1036. [rkharisov]
- Substitute log with tracing lib. [i1i1]
- Add ci check for docs and deny dbg macro. [i1i1]
- Introduces grantable permissions. [Egor Ivkov]
- Add iroha_config crate. [i1i1]
- Add @alerdenisov as a code owner to approve all incoming merge
  requests. [Aler Denisov]
- Fix of transaction size check during consensus. [i1i1]
- Revert upgrading of async-std. [i1i1]
- Replace some consts with power of 2 IR-1035. [rkharisov]
- Add query to retrieve transaction history IR-1024. [rkharisov]
- Add validation of permissions for store and restructure of permission
  validators. [i1i1]
- Add NewAccount for account registration. [i1i1]
- Add types for asset definition. [i1i1]
- Introduces configurable metadata limits. [Egor Ivkov]
- Introduces transaction metadata. [Egor Ivkov]
- Add expressions inside queries. [i1i1]
- Add lints.toml and fix warnings. [i1i1]
- Separate trusted_peers from config.json. [Sonoko Mizuki]
- Fix typo in URL to Iroha 2 community in Telegram. [rkharisov]
- Fix clippy warnings. [i1i1]
- Introduces key-value metadata support for Account. [Egor Ivkov]
- Add versioning of blocks. [i1i1]
- Fixup ci linting repetitions. [i1i1]
- Add mul,div,mod,raise_to expressions. [i1i1]
- Add into_v* for versioning. [i1i1]
- Substitute Error::msg with error macro. [i1i1]
- Rewrite iroha_http_server and rework torii errors. [i1i1]
- Upgrades SCALE version to 2. [Egor Ivkov]
- Whitepaper versioning description. [Egor Ivkov]
- Infallable pagination. [Egor Ivkov]

  Fixes the cases when pagination may unnecessary through errors, not returns empty collections instead.
- Add derive(Error) for enums. [i1i1]
- Fix nightly version. [i1i1]
- Add iroha_error crate. [i1i1]
- Versioned messages. [Egor Ivkov]
- Introduces container versioning primitives. [Egor Ivkov]
- Fix benchmarks. [i1i1]
- Add pagination. [i1i1]
- Add varint encoding decoding. [i1i1]
- Change query timestamp to u128. [i1i1]
- Add RejectionReason enum for pipeline events. [i1i1]
- Removes outdated lines from genesis files. [Egor Ivkov]

  The destination was removed from register ISI in previous commits.
- Simplifies register and unregister ISIs. [Egor Ivkov]
- Fixes commit timeout not being sent in 4 peer network. [Egor Ivkov]
- Topology shuffle at change view. [Egor Ivkov]
- Add other containers for FromVariant derive macro. [i1i1]
- Add MST support for client cli. [i1i1]
- Add FromVariant macro and cleanup codebase. [i1i1]
- Add i1i1 to code owners. [i1i1]
- Gossip transactions. [Egor Ivkov]
- Add length for instructions and expressions. [i1i1]

  Remove double boxing for some instruction variants.
- Add docs to block time and commit time parameters. [i1i1]
- Replaced Verify and Accept traits with TryFrom. [i1i1]
- Wait only for the minimum number of peers. [Egor Ivkov]

  Before submitting genesis tx. For this purpose set A is formed out of the first minimum peers that are online.

  Also some restructuring for genesis code.
- Add github action to test api with iroha2-java (#795) [Alexey]
- Add genesis for docker-compose-single.yml. [Alexey-N-Chernyshov]
- Default signature check condition for account. [Egor Ivkov]
- Adds test for account with multiple signatories. [Egor Ivkov]
- Client API support for MST. [Egor Ivkov]
- Build in docker. [Alexey-N-Chernyshov]
- Adds genesis to docker compose. [Sonoko Mizuki]
- Introduces Conditional MST. [Egor Ivkov]
- Add wait_for_active_peers impl. [Sonoko Mizuki]
- Adds test for isahc client in iroha_http_server. [Egor Ivkov]
- Client API spec. [Egor Ivkov]
- Query execution in Expressions. [Egor Ivkov]
- Integrates expressions and ISIs. [Egor Ivkov]
- Expressions for ISI. [Egor Ivkov]
- Account config benchmarks fix. [Egor Ivkov]
- Account config for client. [Egor Ivkov]

  Account is no longer hardcoded in client lib.
  Also minor submit_blocking fixes.
- Pipeline events are sent. [Egor Ivkov]
- Iroha client web socket connection. [Egor Ivkov]
- Events separation for pipeline and data events. [Egor Ivkov]

  Also web socket connection for events on server.
- Integration test for permissions. [Egor Ivkov]
- Burn, Mint permission checks. [Egor Ivkov]

  Also some doc comments added.
- Unregister ISI permission. [Egor Ivkov]
- Fixes benchmarks for world struct PR. [Egor Ivkov]
- Introduces World struct. [Egor Ivkov]

  to improve top level ISI design.
- Implement the genesis block loading component. [Sonoko Mizuki]
- Introduces genesis account. [Egor Ivkov]
- Introduces permissions validator builder. [Egor Ivkov]
- Adds labels to Iroha2 PRs with Github Actions. [Egor Ivkov]
- Introduces Permissions Framework. [Egor Ivkov]
- Queue tx tx number limit and Iroha initialization fixes. [Egor Ivkov]
- Wraps Hash in a struct. [Egor Ivkov]

  Benefits:
  - Better hex Display
  - Better type checking.
- Logging level improvements. [Egor Ivkov]

  - Added info level logs to consensus
  - Marked network communication logs as trace level
  - Removed block vector from WSV as it is a duplication and it showed all the blockchain in logs
  - Set info log level as default.
- Removes mutable WSV references for validation. [Egor Ivkov]
- Heim version increment. [Egor Ivkov]
- Add default trusted peers to the config. [Sonoko Mizuki]
- Client API migration to http. [Egor Ivkov]
- Add transfer isi to CLI. [StepanLavrentev]
- Configuration of Iroha Peer related Instructions. [Nikita]
- Implementation of missing ISI execute methods and test. [Nikita]
- Url query params parsing. [Egor Ivkov]

  Also
  1. Adds HttpResponse::ok()
  2. Adds HttpResponse::upgrade_required(..)
  3. Fixes consume bytes TODO.
- Replacement of old Instruction and Query models with Iroha DSL
  approach. [Nikita Puzankov]
- Adds BLS signatures support. [Egor Ivkov]
- Introduces http server crate. [Egor Ivkov]
- Patched libssl.so.1.0.0 with symlink. [Kyle Ueckermann]
- Verifies account signature for transaction. [Egor Ivkov]
- Refactors transaction stages. [Egor Ivkov]

  It is done to better fit our current tx pipeline.
- Initial domains improvements. [Egor Ivkov]
- Implement DSL prototype. [Nikita Puzankov]
- Torii Benchmarks improvements. [Egor Ivkov]

  1. Disabled logging in benchmarks
  2. Added success ratio assert.
- Test coverage pipeline improvements. [Egor Ivkov]

  1. Replaces tarpaulin with grcov (because of tarpaulin being unstable and periodically failing with segfaults)
  2. Publish test coverage report to codecov.io.
- RTD theme fix. [Sara]
- Delivery artifacts for iroha subprojects. [Egor Ivkov]
- Introduces SignedQueryRequest. [Egor Ivkov]

  Also fixes a bug with signature verification.
- Support transactions rollback\commit. [Nikita Puzankov]
- Print generated keypair as json. [Egor Ivkov]
- Secp256k1 keypair support. [Egor Ivkov]
- Initial support for different crypto alogorithms. [Egor Ivkov]
- DEX Features. [Nikita Puzankov]
- CODEOWNERS for Iroha 2 branches. [Nikita Puzankov]
- Replaces hardcoded config path with cli param. [Egor Ivkov]
- Bench master workflow fix. [Egor Ivkov]
- Docker event connection test. [Egor Ivkov]
- Iroha Monitor Guide and CLI. [Nikita Puzankov]
- Events cli improvements. [Egor Ivkov]
- Events filter. [Egor Ivkov]
- Event connections. [Egor Ivkov]
- Fixes in master workflow. [Nikita Puzankov]
- Rtd for iroha2. [Sara]
- Merkle tree root hash for block transactions. [Egor Ivkov]
- Publication to docker hub. [Nikita Puzankov]
- CLI functionality for Maintenance Connect. [Nikita Puzankov]
- CLI functionality for Maintenance Connect. [Nikita Puzankov]
- Eprintln to log macro. [Egor Ivkov]
- Log improvements. [Egor Ivkov]
- IR-802 Subscription to blocks statuses changes. [Nikita Puzankov]
- Events sending of transactions and blocks. [Nikita Puzankov]
- Moves Sumeragi message handling into message impl. [Egor Ivkov]
- General Connect Mechanism. [Nikita Puzankov]
- Extract Iroha domain entities for no-std client. [Vladislav Markushin]
- Transactions TTL. [Egor Ivkov]
- Max transactions per block configuration. [Egor Ivkov]
- Store invalidated blocks hashes. [Egor Ivkov]
- Synchronize blocks in batches. [Egor Ivkov]
- Configuration of connect functionality. [Nikita Puzankov]
- Connect to Iroha functionality. [Nikita Puzankov]
- Block validation corrections. [Egor Ivkov]
- Block synchronization: diagrams. [Egor Ivkov]
- Connect to Iroha functionality. [Nikita Puzankov]
- Bridge: remove clients. [Maksim Surkov]
- Block synchronization. [Egor Ivkov]
- AddPeer ISI. [Egor Ivkov]
- Commands to Instructions renaming. [Nikita Puzankov]
- Simple metrics endpoint. [Nikita Puzankov]
- Bridge: get registered bridges and external assets. [Vladislav
  Markushin]
- Docker compose test in pipeline. [Egor Ivkov]
- Not enough votes Sumeragi test. [Egor Ivkov]
- Block chaining. [Egor Ivkov]
- Bridge: manual external transfers handling. [Vladislav Markushin]
- Simple Maintenance endpoint. [Nikita Puzankov]
- Migration to serde-json. [Nikita Puzankov]
- Demint ISI. [Vladislav Markushin]
- Adding bridge clients. [Vladislav Markushin]

  Also added:
  - AddSignatory ISI
  - CanAddSignatory permission.
- Sumeragi: peers in set b related TODO fixes. [Egor Ivkov]
- Validates the block before signing in Sumeragi. [Egor Ivkov]
- Bridge external assets. [Vladislav Markushin]
- Replace [u8;64] type alias with PrivateKey struct. [Nikita Puzankov]
- Signature validation in Sumeragi messages. [Egor Ivkov]
- Binary asset-store. [Vladislav Markushin]
- Replacement of PublicKey alias to type. [Nikita Puzankov]
- Crates preparation for publish. [Nikita Puzankov]
- Minimum votes logic inside NetworkTopology. [Egor Ivkov]
- TransactionReceipt validation refactoring. [Egor Ivkov]
- OnWorldStateViewChange trigger change - IrohaQuery instead of
  Instruction. [Nikita Puzankov]
- Separates construction from initialization in NetworkTopology. [Egor
  Ivkov]
- Iroha Special Instructions related to Iroha events. [Nikita Puzankov]
- Block creation timeout handling. [Egor Ivkov]
- Glossary and How-to add Iroha Module docs. [Nikita Puzankov]
- Replacement of hardcoded bridge model with origin Iroha model. [Nikita
  Puzankov]
- Introduces NetworkTopology struct. [Egor Ivkov]
- Add Permission entity with transformation from Instructions. [Nikita
  Puzankov]
- Sumeragi Messages in the message module. [Egor Ivkov]
- Genesis Block functionality for Kura. [Nikita Puzankov]
- Add README files for Iroha crates. [Nikita Puzankov]
- Bridge and RegisterBridge ISI. [Vladislav Markushin]
- Initial work with Iroha changes listeners. [Nikita Puzankov]
- Injection of Permission checks into OOB ISI. [Nikita Puzankov]
- Docker multiple peers fix. [Egor Ivkov]
- Peer to peer docker example. [Nikita Puzankov]
- Transaction Receipt handling. [Egor Ivkov]
- Iroha Permissions. [Nikita Puzankov]
- Module for Dex and crates for Bridges. [Nikita Puzankov]
- Fixes integration test with asset creation with several peers. [Egor
  Ivkov]
- Reimplementation of Asset model into EC-S-. [Nikita Puzankov]
- Commit timeout handling. [Egor Ivkov]
- Block header. [Egor Ivkov]
- ISI related methods for domain entities. [Nikita Puzankov]
- Kura Mode enumeration and Trusted Peers configuration. [Nikita
  Puzankov]
- Documentation linting rule. [Nikita Puzankov]
- Adds CommittedBlock. [Egor Ivkov]
- Decoupling kura from sumeragi. [Egor Ivkov]
- Check that transactions are not empty before block creation. [Nikita
  Puzankov]
- Reimplementation of Iroha Special Instructions. [Nikita Puzankov]
- Benchmarks for transactions and blocks transitions. [Nikita Puzankov]
- Transactions lifecycle and states reworked. [Nikita Puzankov]
- Blocks lifecycle and states. [Nikita Puzankov]
- Fixed validation bug, sumeragi loop cycle synced with
  block_build_time_ms configuration parameter. [Nikita Puzankov]
- Encapsulation of Sumeragi algorithm inside sumeragi module. [Nikita
  Puzankov]
- Mocking module for Iroha Network crate implemented via channels.
  [Nikita Puzankov]
- Migration to async-std API. [Nikita Puzankov]
- Network mock feature. [Egor Ivkov]
- Asynchronous related code clean up. [Nikita Puzankov]
- Perfomance optimizations in transaction processing loop. [Nikita
  Puzankov]
- Generation of key pairs was extracted from Iroha start. [Nikita
  Puzankov]
- Docker packaging of Iroha executable. [Nikita Puzankov]
- Sumeragi basic scenario. [Egor Ivkov]

  The test now correctly uses 4 peers consensus through sumeragi.
- Iroha CLI client. [Nikita Puzankov]
- Drop of iroha after bench group execution. [Nikita Puzankov]
- Integrate sumeragi. [Egor Ivkov]
- Sort_peers implementation changed. [Egor Ivkov]

  peers are sorted by rand shuffle seeded with previous block hash.
- Removal of Message wrapper in peer module. [Nikita Puzankov]
- Encapsulation of network related information inside torii::uri and
  iroha_network. [Nikita Puzankov]
- Add Peer instruction implemented instead of hardcode handling. [Nikita
  Puzankov]
- Peers communication via trusted peers list. [Nikita Puzankov]
- Encapsulation of network requests handling inside Torii. [Nikita
  Puzankov]
- Encapsulation of crypto logic inside crypto module. [Nikita Puzankov]
- Block sign with timestamp and previous block hash as payload. [Nikita
  Puzankov]
- Crypto functions placed on top of the module and work with ursa signer
  encapsulated into Signature. [Nikita Puzankov]
- Sumeragi initial. [Egor Ivkov]
- Validation of transaction instructions on world state view clone
  before commit to store. [Nikita Puzankov]
- Verify signatures on transaction acceptence. [Nikita Puzankov]
- Fixed bug in Request deserialization. [Nikita Puzankov]
- Implementation of Iroha signature. [Nikita Puzankov]
- Blockchain entity was removed to clean up codebase. [Nikita Puzankov]
- Changes in Transactions API - better creation and work with requests.
  [Nikita Puzankov]
- Fixes rh2-59. [Egor Ivkov]

  Fixes the bug that would create blocks with empty vector of transaction.
- Forward pending transactions. [Egor Ivkov]
- Fixed bug with missing byte in u128 scale encoded TCP packet. [Nikita
  Puzankov]
- Attribute macros for methods tracing. [Nikita Puzankov]
- P2p module. [Egor Ivkov]
- Usage of iroha_network in torii and client. [Nikita Puzankov]
- Add new ISI info. [武宮誠]
- Specific type alias for network state. [Egor Ivkov]
- Box<dyn Error> replaced with String. [Egor Ivkov]
- Network listen stateful. [Egor Ivkov]
- Initial validation logic for transactions. [Nikita Puzankov]
- Iroha_network crate. [Egor Ivkov]
- Derive macro for Io, IntoContract and IntoQuery traits. [Nikita
  Puzankov]
- Queries implementation for Iroha-client. [Nikita Puzankov]
- Transformation of Commands into ISI contracts. [Nikita Puzankov]
- Add proposed design for conditional multisig. [武宮誠]
- Migration to Cargo workspaces. [Nikita Puzankov]
- Modules migration. [Nikita Puzankov]
- External configuration via environemnt variables. [Nikita Puzankov]
- Get and Put requests handling for Torii. [Nikita Puzankov]
- Github ci correction. [Egor Ivkov]
- Cargo-make cleansup blocks after test. [Egor Ivkov]
- Clean up directory with blocks. [Egor Ivkov]

  1. Introduces test_helper_fns module with a function to cleanup directory with blocks
  2. Calls this function in all of the tests that use default block directory.
- Validation via merkle tree. [Nikita Puzankov]
- Remove unused derive. [Egor Ivkov]
- Propagates async/await. [Egor Ivkov]

  and fixes unawaited wsv::put.
- Use join from futures crate. [Egor Ivkov]
- Parallel store execution. [Egor Ivkov]

  Write to disk and WSV update are happening in parallel.
- References usage instead of ownership for de/serialization. [Nikita
  Puzankov]
- Code ejection from  files. [Nikita Puzankov]
- Use ursa::blake2. [Egor Ivkov]
- Rule about mod.rs in Contributing guide. [Nikita Puzankov]
- Comment corrected. [Egor Ivkov]
- Hash 32 bytes. [Egor Ivkov]

  Also hash is array of zeros for the first block.
- Blake2 hash. [Egor Ivkov]
- Disk accepts references to block. [Egor Ivkov]

  Conversion from block to vec also accepts reference
  Should improve performance if we don't do so many clones.
- Refactoring of commands module and Initial Merkle Tree. [Nikita
  Puzankov]
- Refactored modules structure. [Nikita Puzankov]
- Formatting corrections. [Egor Ivkov]
- Added doc comments to read_all. [Egor Ivkov]
- Implemented read_all. [Egor Ivkov]

  also reorganized storage tests and turned tests with async functions into async tests.
- Removed unnecessary mutable capture. [Egor Ivkov]
- Review issue, fix clippy. [kamilsa]
- Format. [kamilsa]
- Remove dash. [kamilsa]
- Add format check. [kamilsa]
- Add token. [kamilsa]
- Create rust.yml for github actions. [kamilsa]
- Disk storage prototype. [Egor Ivkov]

  file structure improvements
  reading from file
  async disk read and write
  initial read renamed to read_vec.
- Transfer asset test and functionality. [Nikita Puzankov]
- Add default initializer to structs. [武宮誠]
- Change name of MSTCache struct. [武宮誠]
- Add forgotten borrow. [武宮誠]
- Initial outline of iroha2 code. [武宮誠]
- Initial Kura API. [Nikita Puzankov]
- Add some basic files and also release the first draft of the
  whitepaper outlining the vision for iroha v2. [武宮誠]
- Basic iroha v2 branch. [武宮誠]


1.4.0 (2022-01-31)
------------------
- Feature/syncing node (#1648) [Alexander Lednev]

  * Syncing node.
- Feature/rdb metrics (#1692) [Alexander Lednev]

  * rocksdb metrics.
- Feature/healthcheck (#1735) [Alexander Lednev]

  * civetweb as http server.
- Fix/Iroha v1.4-rc.2 fixes (#1824) [Alexander Lednev]

  [Iroha] version fixup
  [RDB] optimistic db -> transactions db
  [RDB] cache size reduced to 500 Mb
  [RDB] column families.
- Gha docker tag latest (#1609) [kuvaldini]

  * GHA docker.meta: flavor: suffix=....onlatest=true
  * GHA no dockertag for release
  * GHA clean up.
- Fix/Iroha v1.4-rc.1 fixes (#1785) [Alexander Lednev]

  * added 10bit bloom filter.
- Iroha 1 compile errors when compiling with g++11 (#1765) [G. Bazior]

  * Compilation error fix for g++11.
- Docs(build): add zip and pkg-config to list of build deps (#1393)
  [Peter Somogyvari]

  These were also missing from my WSL 2 Ubuntu 20.04 installation
  and had to install them manually before I could build the project
  successfully.
- Replace deprecated param "max_rounds_delay" with
  "proposal_creation_timeout" (#1662) [G. Bazior]

  Update sample config file to have not deprecated DB connection params.
- Docs(readme): fix broken links: build status, build guide, etc.
  (#1318) [Peter Somogyvari]
- Docs: Small Fixes on Config and Docker Metrics (#1654) [Sara]

  * small fixes.
- Feature/syncing node (#1648) [Alexander Lednev]

  * Syncing node.
- Feature/rdb metrics (#1692) [Alexander Lednev]

  * rocksdb metrics.
- Feature/healthcheck (#1735) [Alexander Lednev]

  * civetweb as http server.


