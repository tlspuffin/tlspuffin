#!/bin/bash


BRANCH=evaluation
START_CORE=$(( 0 ))
# Mut be at least 1
CORES_PER_EXPERIMENT=$(( 1 ))
START_PORT=$(( 6000 ))
TIMEOUT=24h

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

if ! pgrep -x "tlspuffin" >/dev/null
then
    echo "Clearing shared memory"
    ipcs -m | tail -n +5 | awk '{print $2}' | xargs -i sh -c "ipcrm -m {} || true"
fi



echo "Downloading latest evaluation build"

rm -rf tlspuffin-*
to_download=$(gh run list -R tlspuffin/tlspuffin -b "$BRANCH"  -L 1 --json databaseId --jq ".[0].databaseId")
echo "https://github.com/tlspuffin/tlspuffin/actions/runs/$to_download"
gh run download -p "tlspuffin-*" -R tlspuffin/tlspuffin "$to_download" || { echo >&2 "Failed to download"; exit 1; }
chmod +x tlspuffin-*/tlspuffin


session=parallel

# Start
tmux start-server
tmux new-session -d -s "$session"

start_window=$(( 1 ))

core=$START_CORE
window=$start_window
port=$START_PORT

function start_experiment  {
  experiment=$1
  binary=$2
  additional_args=$3

  tmux new-window -t "$session:$window" -n "$experiment"
  end_core=$(( core + CORES_PER_EXPERIMENT - 1 ))
  tmux send-keys " for run in {1..3}; do timeout $TIMEOUT $binary --cores $core-$end_core --port $port $additional_args experiment -d $experiment -t $experiment; done" C-m

  (( core += CORES_PER_EXPERIMENT ))
  (( port++ ))
  (( window++ ))
}

for i in {1..30}; do
  start_experiment "$i-SDOS1" "./tlspuffin-openssl111j/tlspuffin" ""
  start_experiment "$i-SIG" "./tlspuffin-wolfssl510-sig/tlspuffin" ""
done


# return to main window
tmux select-window -t "$session:0"
tmux send-keys "htop" C-m

# Finally attach
tmux attach-session -t "$session"
