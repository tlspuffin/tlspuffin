#!/bin/bash

BRANCH=evaluate
START_CORE=$(( 0 ))
# Mut be at least 1
CORES_PER_EXPERIMENT=$(( 8 ))
START_PORT=$(( 6000 ))

function check_available  {
  if command -v "$1" >/dev/null 2>&1 ; then
      echo "$1 found"
  else
      echo "$1 not found"
      exit 1
  fi
}

check_available "gh"
check_available "tmux"

echo "Downloading latest evaluation build"

rm -rf tlspuffin-*
to_download=$(gh run list -R tlspuffin/tlspuffin -b "$BRANCH"  -L 1 --json databaseId --jq ".[0].databaseId")
gh run download -p "tlspuffin-*" -R tlspuffin/tlspuffin "$to_download" || { echo >&2 "Failed to download"; exit 1; }
chmod +x tlspuffin-*/tlspuffin


session="evaluation"

# Start
tmux start-server
tmux new-session -d -s $session

start_window=$(( 1 ))

core=$START_CORE
window=$start_window
port=$START_PORT

function start_experiment  {
  experiment=$1
  binary=$2
  additional_args=$3

  tmux new-window -t $session:$window -n "$experiment"
  end_core=$(( core + CORES_PER_EXPERIMENT - 1 ))
  tmux send-keys "$binary --cores $core-$end_core --port $port $additional_args experiment -d $experiment -t $experiment" C-m

  (( core += CORES_PER_EXPERIMENT ))
  (( port++ ))
  (( window++ ))
}

start_experiment "SDOS1" "./tlspuffin-openssl111j/tlspuffin" ""
start_experiment "SIG" "./tlspuffin-wolfssl510-fix-CVE-2022-25640/tlspuffin" ""
start_experiment "SKIP" "./tlspuffin-wolfssl510-fix-CVE-2022-25638/tlspuffin" ""
start_experiment "SDOS2" "./tlspuffin-wolfssl530/tlspuffin" "--put-use-clear"
start_experiment "CDOS" "./tlspuffin-wolfssl530/tlspuffin" ""
start_experiment "BUF" "./tlspuffin-wolfssl540/tlspuffin" ""

# return to main window
tmux select-window -t $session:0
tmux send-keys "htop" C-m

# Finally attach
tmux attach-session -t $session
