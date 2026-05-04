#!/bin/bash
# Rerun explorers with the correctly compiled binary

set -e

BINARY="./target/debug/tlspuffin"
SCRIPT="run_explorers_batch.py"

# Wait for binary to be built
echo "Waiting for binary to be compiled..."
while [ ! -f "$BINARY" ]; do
  sleep 10
  echo -n "."
done
echo ""
echo "Binary found! Running explorers..."

# Verify the binary has the right PUTs
echo "Verifying openssl340 and libressl421 PUTs..."
if ! $BINARY differential-execute --json openssl340 libressl421 /dev/null 2>&1 | grep -q "Available PUTs"; then
    echo "ERROR: Binary does not have required PUTs"
    exit 1
fi

# Run the explorer script
python3 $SCRIPT

echo ""
echo "Done!"
