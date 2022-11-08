#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Illegal number of parameters"
    exit 1
fi

BRANCH=$1
START_CORE=$(( 0 ))
# Mut be at least 1
CORES_PER_EXPERIMENT=$(( 1 ))
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


session=$BRANCH

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
  tmux send-keys " $binary --cores $core-$end_core --port $port $additional_args experiment -d $experiment -t $experiment" C-m

  (( core += CORES_PER_EXPERIMENT ))
  (( port++ ))
  (( window++ ))
}

#!/bin/bash
for i in {1..5}
do
  start_experiment "$i" "../tlspuffin" ""
done

# return to main window
tmux select-window -t "$session:0"
tmux send-keys "htop" C-m

# Finally attach
tmux attach-session -t "$session"
