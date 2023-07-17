#!/bin/bash

# if [ "$#" -ne 1 ]; then
#     echo "Illegal number of parameters"
#     exit 1
# fi

BRANCH="eval22-compare"
START_CORE=$(( 0 ))
# Mut be at least 1
CORES_PER_EXPERIMENT=$(( 2 ))
START_PORT=$(( 6000 ))

function check_available  {
  if command -v "$1" >/dev/null 2>&1 ; then
      echo "$1 found"
  else
      echo "$1 not found"
      exit 1
  fi
}

# check_available "gh"
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


session="EVAL-SCRIPT-$BRANCH"

# Start
tmux start-server
tmux new-session -d -s "$session"

start_window=$(( 1 ))

core=$START_CORE
window=$start_window
port=$START_PORT

function start_experiment  {
  # binary=$2
  additional_args=$3


  for MUT in  "no-repeat" "no-skip" "no-replaceR" "no-replaceM" "no-remove" "no-gen" "no-swap"
  do
      features=$2
      experiment="EVAL_ABLATION_$1_$MUT"
      end_core=$(( core + CORES_PER_EXPERIMENT - 1 ))

      tmux new-window -t "$session:$window" -n "$experiment"
      RUN="cargo run --target x86_64-unknown-linux-gnu --bin tlspuffin -p tlspuffin --features $2,$MUT --release -- --cores $core-$end_core --port $port $additional_args experiment -d $experiment -t $experiment"
      echo "$RUN"
      tmux send-keys -t "$session:$window" "${RUN}"  C-m
      
      (( core += CORES_PER_EXPERIMENT ))
      (( core = core % 64 ))
      (( port++ ))
      (( window++ ))
  done
}

start_experiment "SDOS1" "openssl111j" ""
start_experiment "SIG" "wolfssl510,fix-CVE-2022-25640,fix-CVE-2022-39173" ""
start_experiment "SKIP" "wolfssl510,fix-CVE-2022-25638,fix-CVE-2022-39173" ""
start_experiment "SDOS2" "wolfssl540,wolfssl-disable-postauth,fix-CVE-2022-39173" "--put-use-clear"
start_experiment "CDOS" "wolfssl530,fix-CVE-2022-39173" ""
start_experiment "BUF" "wolfssl540,asan,fix-CVE-2022-39173" ""
start_experiment "HEAP" "wolfssl540,asan,fix-CVE-2022-39173" ""

# return to main window
tmux select-window -t "$session:0"
tmux send-keys "htop" C-m

# Finally attach
tmux attach-session -t "$session"
