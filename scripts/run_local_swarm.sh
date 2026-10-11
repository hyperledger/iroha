#!/usr/bin/env bash
set -euo pipefail

# Bare-metal 4-node swarm (no Docker). Run from repo root.
# Prerequisites: Bash, Python 3, Cargo or existing target/release binaries.
# Required existing paired GENESIS_PUBLIC_KEY_FILE / GENESIS_PRIVATE_KEY_FILE and
# GENESIS_CREATION_TIME_MS pin the operator-admitted signed network. No fresh
# genesis signer or implicit wall-clock network identity is generated.
# See scripts/README.run-local-swarm.md for node configuration and launch prerequisites.

usage() {
  cat <<'HELP'
Usage: scripts/run_local_swarm.sh [--help]

Start four bare-metal local Iroha peers from the repository root.
Required: existing paired GENESIS_PUBLIC_KEY_FILE / GENESIS_PRIVATE_KEY_FILE
and GENESIS_CREATION_TIME_MS (canonical u64 Unix milliseconds).
Wallet loads use ordinary transaction validation and finalized blocks.
Other inputs: BASE, BASE_API_PORT, BASE_P2P_PORT, SKIP_BUILD, RESET_STORAGE.
RESET_STORAGE defaults to 0; explicitly set it to 1 to delete prior storage.
HELP
}
if [[ $# -ne 0 ]]; then
  if [[ $# -eq 1 && ( "$1" == "--help" || "$1" == "-h" ) ]]; then
    usage
    exit 0
  fi
  usage >&2
  exit 2
fi

# Generated node and client configs contain existing private demo identities.
umask 077
RESET_STORAGE="${RESET_STORAGE-0}"

BASE="${BASE:-/tmp/iroha-bare}"
GENESIS_PUBLIC_KEY_FILE="${GENESIS_PUBLIC_KEY_FILE:-}"
GENESIS_PRIVATE_KEY_FILE="${GENESIS_PRIVATE_KEY_FILE:-}"
GENESIS_CREATION_TIME_MS="${GENESIS_CREATION_TIME_MS:-}"

PKS=(
  "ea01308A230D5DA9DE92163DDE5F662CD859985ADC53040D9BFE1FA4A091CA7E1D8E88914535FC790CACC077DCC2F2D06FE106"
  "ea0130A3EBC016AF760F9B5FD20B45D6FDC0A6EC420DC08BC6D56EAF01F211DC23E4E0FB77C1A2E6984265ACB4450CFF4F2E3D"
  "ea0130904BB61D85D9AD526E4711D8B5A734B2335B71511BB66D0FBF2AE7EEE6C18A57BE44B1B9B1ACECA2C5C66384DC4F62D7"
  "ea0130AAB578FED3452B1629FF416025BF3D646D89C86DAAE0184A49C2A15D1D59A5DC39B38C606309FC38E3D5DF7ED2120B2E"
)
SKS=(
  "8926205F6436289BE34CE48DD72C52597B13B15D1F5EF078548AAE3AAEE1A3EDE6FA36"
  "892620DC0938B53B52D0C33B6FE5757EEB9CD6B535C55DFF0A5642E27A80F39330A753"
  "892620093156CF77B49FC14185247B8FE1539C288D56E63B83BDB06EBD9E0F8A5F4D56"
  "892620AF64535BCE4B6775610F0E660C021A4165E1629ED160369C1174FAAB06301909"
)
POPS=(
  "850859fa719dd75be661bc1a429e4d30a2151429e2f9a4c189347f9b0e1116219454f5d27a8834e40d9ae076aaea6285043586b4fb5c963df6b03b4e5363597a615af0915edef8ed6fa1cd268a31c437bd72c8a7f6666c0b7194df8739c1c3d8"
  "ac3a32b36684a7860eb5864d3f21806766f1faafc02a7b2c5fc6d687b6658e01edcb8aa18f8ee8b56763822a5bf6a3cb0e502cbf9ab04498e37f74b7cfd8f3d3509c1240ea899390d84f6826bd58bf053f8ef9b564df2e366aa3e786f5b1b24d"
  "927f73fd6614147584ad7886bb14761140dee5317bdca188be4e903d92335d8c704e5049de8ad56321a4a76794902a9309f507b4abc8d3639486a9500f7eb34fb89a2b1c311204ef30b1ea7d957ecae154df823f55e8a1d8af6c24ad68bd0b97"
  "b2b098c400391fd43cc643a235e6a408d748b654a024f9997109ca02e918dcdb78a3b2aa089d1fa12ed692217578965f01097d7749b5c0464b8f1f46a1b6853f7f7ef6f1f280a9b184602f7d8566e65b5983621c6e7a6e93de6ae932f522745f"
)
STREAM_PKS=(
  "ed0120A98BAFB0663CE08D75EBD506FEC38A84E576A7C9B0897693ED4B04FD9EF2D18D"
  "ed01209897952D14BDFAEA780087C38FF3EB800CB20B882748FC95A575ADB9CD2CB21D"
  "ed01204EE2FCD53E1730AF142D1E23951198678295047F9314B4006B0CB61850B1DB10"
  "ed0120CACF3A84B8DC8710CE9D6B968EE95EC7EE4C93C85858F026F3B4417F569592CE"
)
STREAM_SKS=(
  "802620A4DFC16789FBF9A588525E4AC7F791AC51B12AEE8919EACC03EB2FC31D32C692"
  "8026203ECA64ADC23DC106C9D703233375EA6AC345AD7299FF3AD45F355DE6CD1B5510"
  "8026207B1C78F733EDAFD6AF9BAC3A0D6C5A494557DD031609A4FDD9796EEF471D928C"
  "8026206C7FF4CA09D395C7B7332C654099406E929C6238942E3CE85155CC1A5E2CF519"
)
# Dedicated Ed25519 SoraNet transport identities derived from the SHA-256 seeds
# `iroha-run-local-swarm-soranet-transport-v1-peer-{0,1,2,3}`.
SORANET_TRANSPORT_PKS=(
  "ed01208FB5364C3275F840CFF3DA7B2585D0EF5DA34E6EA47D742A9F2AF0ACAE90D51E"
  "ed012006DA31B9676E61B33B8160415145CC28943ED419402F7412FBF9D7D1E7EDF56E"
  "ed01208F6F75539C6420238C08C07311C3BF594866B8F867E9FA032C533F9603134DE7"
  "ed01206CBFE275EB73969EB8A7C5842E1CB89AC6D2DEE9C6AB2E71B7A42D6E5938A3A2"
)
SORANET_TRANSPORT_SKS=(
  "802620A64266B9BC7DFA8DB70EAB99A1C9E7470858A87D850CF48F5A1F81950ADBF36C"
  "802620A1D97AD9C6106A50E82BED39CF0A4CD1AEF6DAF5AE3299E09D3D9EBB387522D5"
  "802620FFBF7F577A39A1ADB7E043EE9B7D24C2158F8E4FACEB432A76011B01959C2E01"
  "8026200177E60BE138D5F97520629FCF270EE9B4C9EB69870B1F67A5DC86C8E8E6FC41"
)
BASE_API_PORT="${BASE_API_PORT:-8080}"
BASE_P2P_PORT="${BASE_P2P_PORT:-1337}"
APIS=(
  "$BASE_API_PORT"
  "$((BASE_API_PORT + 1))"
  "$((BASE_API_PORT + 2))"
  "$((BASE_API_PORT + 3))"
)
P2PS=(
  "$BASE_P2P_PORT"
  "$((BASE_P2P_PORT + 1))"
  "$((BASE_P2P_PORT + 2))"
  "$((BASE_P2P_PORT + 3))"
)

pid_matches_local_swarm_peer() {
  local pid="$1"
  local config_path="$2"
  local command_line

  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  command -v ps >/dev/null 2>&1 || return 1
  command_line="$(ps -p "$pid" -o command= 2>/dev/null || true)"
  [[ -n "$command_line" ]] || return 1
  printf '%s' "$command_line" | grep -F -- "--config $config_path" >/dev/null \
    || printf '%s' "$command_line" | grep -F -- "--config=$config_path" >/dev/null
}

pid_is_running() {
  local pid="$1"

  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  command -v ps >/dev/null 2>&1 || return 0
  ps -p "$pid" -o pid= >/dev/null 2>&1
}

write_stop_script() {
  write_private_config "$BASE/stop.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

pid_matches_peer() {
  local pid="$1"
  local config="$2"
  local command_line

  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  command -v ps >/dev/null 2>&1 || return 1
  command_line="$(ps -p "$pid" -o command= 2>/dev/null || true)"
  [[ -n "$command_line" ]] || return 1
  printf '%s' "$command_line" | grep -F -- "--config $config" >/dev/null \
    || printf '%s' "$command_line" | grep -F -- "--config=$config" >/dev/null
}

pid_is_running() {
  local pid="$1"

  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  command -v ps >/dev/null 2>&1 || return 0
  ps -p "$pid" -o pid= >/dev/null 2>&1
}

for pidfile in "$DIR"/peer*.pid; do
  [[ -f "$pidfile" ]] || continue
  pid="$(cat "$pidfile" 2>/dev/null || true)"
  if [[ -z "$pid" ]]; then
    rm -f "$pidfile"
    continue
  fi
  if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
    echo "removing malformed pidfile $pidfile (pid=$pid)" >&2
    rm -f "$pidfile"
    continue
  fi
  if ! pid_is_running "$pid"; then
    rm -f "$pidfile"
    continue
  fi
  peer_name="$(basename "$pidfile" .pid)"
  config="$DIR/${peer_name}.toml"
  if ! pid_matches_peer "$pid" "$config"; then
    echo "leaving $pidfile in place: live pid $pid does not match $config" >&2
    continue
  fi
  kill "$pid" 2>/dev/null || true
  for _ in {1..40}; do
    if pid_is_running "$pid"; then
      sleep 0.25
    else
      break
    fi
  done
  if pid_is_running "$pid"; then
    echo "leaving $pidfile in place: local-swarm peer $peer_name pid $pid is still running" >&2
    continue
  fi
  rm -f "$pidfile"
done
EOF
  chmod 700 "$BASE/stop.sh"
}

preflight_existing_pidfiles() {
  local found_live=0
  local pidfile pid peer_name config_path

  for pidfile in "$BASE"/peer*.pid; do
    [[ -f "$pidfile" ]] || continue
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [[ -z "$pid" ]]; then
      rm -f "$pidfile"
      continue
    fi
    if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
      echo "Removing malformed pidfile $pidfile (pid=$pid)" >&2
      rm -f "$pidfile"
      continue
    fi
    if ! pid_is_running "$pid"; then
      rm -f "$pidfile"
      continue
    fi
    peer_name="$(basename "$pidfile" .pid)"
    config_path="$BASE/${peer_name}.toml"
    if pid_matches_local_swarm_peer "$pid" "$config_path"; then
      echo "Refusing to overwrite live local-swarm peer $peer_name pid $pid; run $BASE/stop.sh first." >&2
    else
      echo "Leaving $pidfile in place: live pid $pid does not match $config_path." >&2
    fi
    found_live=1
  done

  if [[ "$found_live" -ne 0 ]]; then
    exit 1
  fi
}

addr_literal() {
  python3 - <<'PY' "$1"
import sys

tag = "addr"
body = sys.argv[1]
crc = 0xFFFF
for byte in (tag + ":" + body).encode():
    crc ^= byte << 8
    for _ in range(8):
        if crc & 0x8000:
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF
        else:
            crc = (crc << 1) & 0xFFFF
print(f"{tag}:{body}#{crc:04X}")
PY
}

inject_topology() {
  python3 - "$BASE/genesis.json" \
    "${PKS[0]}" "${POPS[0]}" \
    "${PKS[1]}" "${POPS[1]}" \
    "${PKS[2]}" "${POPS[2]}" \
    "${PKS[3]}" "${POPS[3]}" <<'PY'
import json
import sys

path = sys.argv[1]
items = sys.argv[2:]
if len(items) % 2 != 0:
    raise SystemExit("expected peer/pop pairs")
topology = []
for i in range(0, len(items), 2):
    topology.append({"peer": items[i], "pop_hex": items[i + 1]})
with open(path) as fh:
    data = json.load(fh)
txs = data.get("transactions")
if not isinstance(txs, list):
    raise SystemExit("genesis missing transactions array")
txs.append({"instructions": [], "ivm_triggers": [], "topology": topology})
with open(path, "w") as fh:
    json.dump(data, fh, indent=2)
PY
}

validate_genesis_inputs() {
  if ! python3 - "$GENESIS_CREATION_TIME_MS" <<'PY_TIME'
import re
import sys

value = sys.argv[1]
if (re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is None
        or int(value) > 2**64 - 1):
    raise SystemExit("GENESIS_CREATION_TIME_MS must be explicit canonical u64 Unix milliseconds")
PY_TIME
  then
    return 1
  fi
  if [[ -z "$GENESIS_PUBLIC_KEY_FILE" || -z "$GENESIS_PRIVATE_KEY_FILE" ]]; then
    echo "Both existing GENESIS_PUBLIC_KEY_FILE and GENESIS_PRIVATE_KEY_FILE are required for the admitted network." >&2
    return 1
  fi
  [[ -s "$GENESIS_PUBLIC_KEY_FILE" && -s "$GENESIS_PRIVATE_KEY_FILE" ]] || {
    echo "Both genesis signing input files must already exist and be nonempty." >&2
    return 1
  }
}

validate_storage_reset() {
  case "$RESET_STORAGE" in
    0|1) ;;
    *) echo "RESET_STORAGE must be exactly 0 or 1; deletion requires explicit 1." >&2; return 1 ;;
  esac
}

validate_local_swarm_output_targets() {
  python3 - "$BASE" <<'PY_OUTPUTS'
import os
import stat
import sys

try:
    directory = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        protected = os.fstat(directory)
        if (not stat.S_ISDIR(protected.st_mode) or protected.st_uid != os.geteuid()
                or protected.st_mode & 0o077 or protected.st_mode & 0o700 != 0o700):
            raise ValueError("BASE must be an owner-only readable, writable, searchable directory")
        names = ["stop.sh", "client.toml", "genesis.json", "genesis.signed.nrt",
                 "genesis.expected_hash", "gen.sign.log"]
        names += [f"peer{index}.{suffix}" for index in range(4)
                  for suffix in ("toml", "log", "pid", "check-config.log")]
        for name in names:
            try:
                protected = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if (not stat.S_ISREG(protected.st_mode) or protected.st_uid != os.geteuid()
                    or protected.st_nlink != 1 or protected.st_mode & 0o022):
                raise ValueError("existing local-swarm output must be an owner-held single-link regular file without group/other writes")
            if name in ("client.toml", "stop.sh") or name.endswith(".toml"):
                if protected.st_mode & 0o077:
                    raise ValueError("existing local-swarm private config/script must be owner-only")
    finally:
        os.close(directory)
except (OSError, ValueError) as error:
    raise SystemExit(f"local-swarm output custody is unsafe: {error}") from None
PY_OUTPUTS
}

write_private_config() {
  # Open without truncation and refuse aliases/public files before writing bytes.
  # BASE preflight separately protects all log, PID and genesis output targets.
  python3 -c '
import os
import shutil
import stat
import sys

try:
    descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        protected = os.fstat(descriptor)
        if (not stat.S_ISREG(protected.st_mode) or protected.st_uid != os.geteuid()
                or protected.st_nlink != 1 or protected.st_mode & 0o077):
            raise ValueError("private output must be an owner-only single-link regular file")
        os.ftruncate(descriptor, 0)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            shutil.copyfileobj(sys.stdin.buffer, output)
            output.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
except (OSError, ValueError) as error:
    raise SystemExit(f"private local-swarm output refused: {error}") from None
' "$1"
}

validate_transport_identities() {
  local i j
  for i in 0 1 2 3; do
    if [[ "${SORANET_TRANSPORT_PKS[$i]}" == "${PKS[$i]}" ]] \
      || [[ "${SORANET_TRANSPORT_PKS[$i]}" == "${STREAM_PKS[$i]}" ]] \
      || [[ "${SORANET_TRANSPORT_SKS[$i]}" == "${SKS[$i]}" ]] \
      || [[ "${SORANET_TRANSPORT_SKS[$i]}" == "${STREAM_SKS[$i]}" ]]; then
      echo "Peer $i reuses a node or streaming key for SoraNet transport." >&2
      exit 1
    fi
    for ((j = 0; j < i; j++)); do
      if [[ "${SORANET_TRANSPORT_PKS[$i]}" == "${SORANET_TRANSPORT_PKS[$j]}" ]] \
        || [[ "${SORANET_TRANSPORT_SKS[$i]}" == "${SORANET_TRANSPORT_SKS[$j]}" ]]; then
        echo "Peers $j and $i share a SoraNet transport identity." >&2
        exit 1
      fi
    done
  done
}

validate_storage_reset
validate_genesis_inputs
validate_transport_identities
mkdir -p "$BASE"
BASE="$(cd "$BASE" && pwd -P)"
validate_local_swarm_output_targets
write_stop_script
preflight_existing_pidfiles
if [[ "$RESET_STORAGE" == 1 ]]; then
  rm -rf "$BASE/storage"
fi

export NORITO_SKIP_BINDINGS_SYNC=1
if [ "${SKIP_BUILD:-0}" -ne 1 ]; then
  cargo build --release --bin iroha3d --bin iroha --bin kagami
fi
IROHAD=target/release/iroha3d
IROHA=target/release/iroha
KAGAMI=target/release/kagami


if [[ "$(wc -l < "$GENESIS_PUBLIC_KEY_FILE" | tr -d ' ')" -ne 1 ]] \
  || [[ -n "$(tail -c 1 < "$GENESIS_PUBLIC_KEY_FILE")" ]]; then
  echo "Genesis public-key file must contain exactly one newline-terminated record." >&2
  exit 1
fi
GEN_PUB="$(cat "$GENESIS_PUBLIC_KEY_FILE")"
[[ -n "$GEN_PUB" ]] || {
  echo "Genesis public-key file is empty." >&2
  exit 1
}

echo "[1/6] Generate genesis"

$KAGAMI genesis generate --ivm-dir . --genesis-public-key "$GEN_PUB" \
  default | write_private_config "$BASE/genesis.json"

echo "[2/6] Inject topology"
inject_topology

echo "[3/6] Sign genesis"
$KAGAMI genesis sign "$BASE/genesis.json" \
  -o "$BASE/genesis.signed.nrt" \
  --expected-hash-out "$BASE/genesis.expected_hash" \
  --private-key-file "$GENESIS_PRIVATE_KEY_FILE" \
  --expected-public-key "$GEN_PUB" \
  --creation-time-ms "$GENESIS_CREATION_TIME_MS" \
  2>&1 | tee "$BASE/gen.sign.log"
echo "Genesis public key: $GEN_PUB"
if [[ "$(wc -l < "$BASE/genesis.expected_hash" | tr -d ' ')" -ne 1 ]] \
  || [[ -n "$(tail -c 1 < "$BASE/genesis.expected_hash")" ]]; then
  echo "Genesis expected-hash file must contain exactly one newline-terminated record." >&2
  exit 1
fi
GENESIS_NETWORK_ID="$(cat "$BASE/genesis.expected_hash")"
if [[ ! "$GENESIS_NETWORK_ID" =~ ^hash:[0-9A-F]{63}[13579BDF]#[0-9A-F]{4}$ ]]; then
  echo "Genesis network identity is not one canonical checked NetworkId literal." >&2
  exit 1
fi

trusted_peers_literal() {
  printf '["%s@%s","%s@%s","%s@%s","%s@%s"]' \
    "${PKS[0]}" "$(addr_literal "127.0.0.1:${P2PS[0]}")" \
    "${PKS[1]}" "$(addr_literal "127.0.0.1:${P2PS[1]}")" \
    "${PKS[2]}" "$(addr_literal "127.0.0.1:${P2PS[2]}")" \
    "${PKS[3]}" "$(addr_literal "127.0.0.1:${P2PS[3]}")"
}

write_config() {
  local idx=$1
  local store_dir="$BASE/storage/peer${idx}"
  mkdir -p "$store_dir"
  write_private_config "$BASE/peer${idx}.toml" <<EOF
chain = "00000000-0000-0000-0000-000000000000"
public_key = "${PKS[$idx]}"
private_key = "${SKS[$idx]}"
soranet_transport_public_key = "${SORANET_TRANSPORT_PKS[$idx]}"
soranet_transport_private_key = "${SORANET_TRANSPORT_SKS[$idx]}"
trusted_peers = $(trusted_peers_literal)
[[trusted_peers_pop]]
public_key = "${PKS[0]}"
pop_hex = "${POPS[0]}"

[[trusted_peers_pop]]
public_key = "${PKS[1]}"
pop_hex = "${POPS[1]}"

[[trusted_peers_pop]]
public_key = "${PKS[2]}"
pop_hex = "${POPS[2]}"

[[trusted_peers_pop]]
public_key = "${PKS[3]}"
pop_hex = "${POPS[3]}"
[network]
address = "$(addr_literal "0.0.0.0:${P2PS[$idx]}")"
public_address = "$(addr_literal "127.0.0.1:${P2PS[$idx]}")"
[torii]
address = "$(addr_literal "0.0.0.0:${APIS[$idx]}")"
[torii.transport.norito_rpc]
allowed_clients = ["*"]
enabled = true
require_mtls = false
stage = "ga"
[streaming]
identity_public_key = "${STREAM_PKS[$idx]}"
identity_private_key = "${STREAM_SKS[$idx]}"
[genesis]
public_key = "$GEN_PUB"
file = "$BASE/genesis.signed.nrt"
expected_hash_file = "$BASE/genesis.expected_hash"
[kura]
init_mode = "fast"
store_dir = "$store_dir"
[snapshot]
store_dir = "$store_dir/snapshot"
[confidential]
enabled = true
# Consensus mode, validator set, and DA geometry come from the signed genesis.
[logger]
format = "compact"
level = "info"
EOF
}

write_client_config() {
  write_private_config "$BASE/client.toml" <<EOF
chain = "00000000-0000-0000-0000-000000000000"
network_id_file = "$BASE/genesis.expected_hash"
torii_url = "http://127.0.0.1:${APIS[0]}/"

[basic_auth]
web_login = "mad_hatter"
password = "ilovetea"

[account]
# The default genesis and peer configuration use I105 chain discriminant 753.
chain_discriminant = 753
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
private_key = "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"

[connect]
# Root directory for Connect queue diagnostics and evidence export. Defaults to ~/.iroha/connect.
# queue_root = "/home/alice/.iroha/connect"
EOF
}

echo "[4/6] Write configs"
for i in 0 1 2 3; do write_config "$i"; done
write_client_config

# Admit every generated node configuration before starting any peer.
for i in 0 1 2 3; do
  "$IROHAD" --config "$BASE/peer${i}.toml" --check-config > "$BASE/peer${i}.check-config.log" 2>&1
done

echo "[5/6] Start peers"
for i in 0 1 2 3; do
  RUST_LOG=info "$IROHAD" --config "$BASE/peer${i}.toml" > "$BASE/peer${i}.log" 2>&1 &
  echo $! > "$BASE/peer${i}.pid"
  echo "peer$i pid $(cat "$BASE/peer${i}.pid") api ${APIS[$i]} p2p ${P2PS[$i]}"
done

echo "Waiting 5s for peers to settle..."
sleep 5

echo "[6/6] Asset flow (transfer, query)"
ASSET="rose#wonderland"
SENDER="sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
RECIP="34mSYmj74pAZ6nNwwEsmGKGrHErCPMWtqeBwWhHkT9WcsndXbe2FjCNWFYCn5FiW5fdUcsbQD"

CLIENT_CONFIG="$BASE/client.toml"
$IROHA --config "$CLIENT_CONFIG" asset get --id "$ASSET#$SENDER"
$IROHA --config "$CLIENT_CONFIG" asset transfer --id "$ASSET#$SENDER" --to "$RECIP" --quantity 1
$IROHA --config "$CLIENT_CONFIG" asset get --id "$ASSET#$RECIP"

echo "Logs: $BASE/peer*.log  PIDs: $BASE/peer*.pid"
echo "To stop safely: cd $BASE && ./stop.sh"
