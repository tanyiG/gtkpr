#!/usr/bin/env bash
#
# teardown_test_env.sh – Remove the test network namespace and veth pair
# previously created by setup_test_env.sh.
#
# Usage: sudo ./teardown_test_env.sh

set -e

NS_NAME="testns"

echo "[*] Deleting network namespace '$NS_NAME'..."
if ip netns list | grep -q "$NS_NAME"; then
    ip netns del "$NS_NAME"
    echo "[✓] Namespace and associated veth pair removed."
else
    echo "[!] Namespace '$NS_NAME' does not exist. Nothing to clean up."
fi