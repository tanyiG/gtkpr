#!/usr/bin/env bash
#
# setup_test_env.sh – Create network namespace and veth pair for testing the
# XDP gatekeeper without affecting real network interfaces.
#
# Usage: sudo ./setup_test_env.sh
#
# After running, the environment will be:
#   - testns : network namespace with IP 10.0.0.2/24 on veth1
#   - veth0  : peer in the host namespace with IP 10.0.0.1/24 (XDP attached here)
#   - Default route in testns points to 10.0.0.1
#
# You can then run commands inside the test namespace with:
#   sudo ip netns exec testns <command>

set -e

NS_NAME="testns"
VETH_HOST="veth0"
VETH_NS="veth1"
HOST_IP="10.0.0.1/24"
NS_IP="10.0.0.2/24"
HOST_ADDR="10.0.0.1"
NS_ADDR="10.0.0.2"

echo "[*] Creating network namespace '$NS_NAME'..."
ip netns add "$NS_NAME"

echo "[*] Creating veth pair..."
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"

echo "[*] Moving $VETH_NS into $NS_NAME..."
ip link set "$VETH_NS" netns "$NS_NAME"

echo "[*] Bringing interfaces up..."
ip link set "$VETH_HOST" up
ip netns exec "$NS_NAME" ip link set "$VETH_NS" up

echo "[*] Assigning IP addresses..."
ip addr add "$HOST_IP" dev "$VETH_HOST"
ip netns exec "$NS_NAME" ip addr add "$NS_IP" dev "$VETH_NS"

echo "[*] Enabling loopback and setting default route in $NS_NAME..."
ip netns exec "$NS_NAME" ip link set lo up
ip netns exec "$NS_NAME" ip route add default via "$HOST_ADDR"

echo "[✓] Test environment setup complete."
echo ""
echo "    Host-side interface: $VETH_HOST ($HOST_IP)"
echo "    Namespace interface: $VETH_NS ($NS_IP)"
echo "    Namespace name: $NS_NAME"
echo ""
echo "    To test connectivity from the namespace, run:"
echo "      sudo ip netns exec $NS_NAME ping $HOST_ADDR"
echo ""
echo "    To enter a shell inside the namespace:"
echo "      sudo ip netns exec $NS_NAME bash"