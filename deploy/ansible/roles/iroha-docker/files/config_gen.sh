#!/bin/bash
set -e

FORCE_OVERWRITE=0
OUT_DIR='config'

function config_gen {
  if [[ "$FORCE_OVERWRITE" == "1" || "$FORCE_OVERWRITE" == "0" && ! -d "$OUT_DIR" ]]; then
    rm -rf $OUT_DIR
    mkdir -p $OUT_DIR
    echo 'host;port;priv_key_hex;pub_key_hex' > peers.csv
    for p in $(echo "$PEERS" | tr ',' '\n'); do
      KEY_PAIR=($(python3 ed25519.py))
      PRIVATE_KEY=${KEY_PAIR[0]}
      PUBLIC_KEY=${KEY_PAIR[1]}
      PORT=$(echo $p | cut -d':' -f2 -s)
      if [ -z "$PORT" ]; then
        PORT=10001
      else
        p=$(echo "$p" | cut -d':' -f1)
      fi
      echo "$p;$PORT;$PRIVATE_KEY;$PUBLIC_KEY" >> peers.csv
    done
    python3 genesis-add-peers.py add_iroha_peers peers.csv genesis.block
    python3 genesis-add-peers.py make_key_files peers.csv
    mv *.{priv,pub} $OUT_DIR/
    cp genesis.block $OUT_DIR/
    rm -f peers.csv
  else
    echo "configs dir \`$OUT_DIR\` is not empty. Use \`-f\` to overwrite. Exiting..."
    exit 1
  fi
}

function usage {
    echo "usage: $0 -p peers_list [--force-overwrite || --out-dir]"
    echo "Generates keypairs for a number of Iroha peers and prepares genesis.block filled with those peers.
    Make sure 'genesis.block', 'genesis-add-peers.py' and 'ed25519.py' scripts are in the same directory."
    echo ""
    echo "  -p | --peers             : Comma-delimeted list of Iroha peers (optionally, with port numbers)"
    echo "  -f | --force-overwrite   : Forces creation of the new keypairs"
    echo "  -o | --out-dir           : Output directory for generated files. Defaults to './config'"
    echo "  -h | --help              : This message"
}

if ! TEMP=$(getopt -o fp:o:: --long force-overwrite,peers:,out-dir:: -- "$@"); then
  usage
  exit 1
fi
eval set -- "$TEMP"

# extract options and their arguments into variables.
while true ; do
    case "$1" in
      -h|--help) usage ; shift ;;
      -f|--force-overwrite) FORCE_OVERWRITE=1 ; shift ;;
      -p|--peers) PEERS="$2" ; shift 2 ;;
      -o|--out-dir)
        case "$2" in
            "") OUT_DIR='config' ; shift 2 ;;
            *) OUT_DIR="$2" ; shift 2 ;;
        esac ;;
      --) shift ; break ;;
      *) echo "Unknown argument" ; exit 1 ;;
    esac
done

if [[ -z "$PEERS" ]]; then
  echo "Provide -p parameter"
  usage
  exit 1
fi

config_gen
