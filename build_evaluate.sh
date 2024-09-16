#!/bin/bash

# Run `./build_evaluate.sh 12` (12 cores for 3h for all except SDOS1 and SIG, for which we used 1 core for 24h and run it 90 times)

if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
    exit 1
fi

START_CORE=$(( 0 ))
# Mut be at least 1
CORES_PER_EXPERIMENT=$(( $1 ))
START_PORT=$(( 6000 ))
${BUILD:-true}
${DRY:-false}

function check_available  {
  if command -v "$1" >/dev/null 2>&1 ; then
      echo "$1 found"
  else
      echo "$1 not found"
      exit 1
  fi
}

check_available "tmux"

if ! pgrep -x "tlspuffin" >/dev/null
then
    echo "Clearing shared memory"
    ipcs -m | tail -n +5 | awk '{print $2}' | xargs -i sh -c "ipcrm -m {} || true"
fi

# echo "Downloading latest evaluation build"
# rm -rf tlspuffin-*
# to_download=$(gh run list -R tlspuffin/tlspuffin -b "$BRANCH"  -L 1 --json databaseId --jq ".[0].databaseId")
# echo "https://github.com/tlspuffin/tlspuffin/actions/runs/$to_download"
# gh run download -p "tlspuffin-*" -R tlspuffin/tlspuffin "$to_download" || { echo >&2 "Failed to download"; exit 1; }
# chmod +x tlspuffin-*/tlspuffin


session="REFIND_VULN"

# Start
tmux start-server
tmux new-session -d -s "$session"

start_window=$(( 1 ))

core=$START_CORE
window=$start_window
port=$START_PORT

function start_experiment  {
  experiment=$1
  features=$2
  additional_args=$3
  binary="target/release/tlspuffin-${experiment}"

  tmux new-window -t "$session:$window" -n "$experiment"
  end_core=$(( core + CORES_PER_EXPERIMENT - 1 ))

  tmux send-keys " nix-shell " C-m

  if [ "$BUILD" = true ] ; then
    tmux send-keys "cargo build --bin tlspuffin-${experiment} --release --features=${features}"  C-m
  fi

  tmux send-keys " $binary seed " C-m
  tmux send-keys " $binary --cores $core-$end_core --port $port $additional_args experiment -d $experiment -t $experiment" C-m

  (( core += CORES_PER_EXPERIMENT ))
  (( port++ ))
  (( window++ ))
}

start_experiment "SDOS2" '"wolfssl540","asan","wolfssl-disable-postauth","fix-CVE-2022-39173"' "--put-use-clear"
if [ "$DRY" = true ] ; then
  tmux select-window -t "$session:0"
  tmux attach-session -t "$session"
  exit 0
fi
start_experiment "SDOS1" '"openssl111j","asan"'
start_experiment "HEAP"  '"wolfssl540","asan","fix-CVE-2022-39173"'
start_experiment "CDOS"  '"wolfssl530","asan","fix-CVE-2022-39173"'
start_experiment "BUF"   '"wolfssl540","asan","fix-CVE-2022-42905"'
start_experiment "SIG"   '"wolfssl510","fix-CVE-2022-25640","fix-CVE-2022-39173"'
start_experiment "SKIP"  '"wolfssl510","fix-CVE-2022-25638","fix-CVE-2022-39173"'


## Takes longer and has high variance
#start_experiment "SDOS1"
#start_experiment "SIG"

# return to main window
tmux select-window -t "$session:0"
tmux send-keys "htop" C-m

# Finally attach
tmux attach-session -t "$session"
