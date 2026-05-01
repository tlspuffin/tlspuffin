#!/bin/bash
set -e

echo "Waiting for binary to be built..."
while ! [ -f /home/nbaffou/dev/tlspuffin/target/release/tlspuffin ]; do
    sleep 30
done

echo "Binary ready! Testing libressl421..."
/home/nbaffou/dev/tlspuffin/target/release/tlspuffin differential-execute --json openssl340 libressl421 /home/nbaffou/dev/tlspuffin/objective/20260428-224539921-89c793b2c31348ae.trace > /tmp/test_libressl.json 2>&1
if grep -q "Executing" /tmp/test_libressl.json; then
    echo "LibreSSL421 is working! Running explorer..."
    cd /home/nbaffou/dev/tlspuffin
    python3 /home/nbaffou/dev/tlspuffin/explorer_batch.py
else
    echo "LibreSSL421 test failed"
    cat /tmp/test_libressl.json
    exit 1
fi
