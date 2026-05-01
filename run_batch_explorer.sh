#!/bin/bash
set -e

# Wait for binary to be built
while ! [ -f ./target/release/tlspuffin ]; do
    echo "Waiting for binary to be built..."
    sleep 30
done

echo "Binary ready! Running explorer..."
python3 /home/nbaffou/dev/tlspuffin/explorer_batch.py
