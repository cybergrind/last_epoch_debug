#!/bin/bash
# IMMUTABLE PART
# THIS IS INSTRUCTION: DO NOT EDIT IT
# This script creates a new namespace that won't use system VPN
# It should use host local network gateway: 192.168.88.1
# It should use nameserver=192.168.88.1

# Remove any existing namespace with the same name to start fresh
if ip netns list | grep -q novpn; then
    echo "Removing existing 'novpn' namespace..."
    sudo ip netns del novpn
    sudo ip link del veth1 2>/dev/null
fi

# Create the network namespace
sudo ip netns add novpn

DEFAULT_GATEWAY=192.168.88.1
DEFAULT_INTERFACE=enp6s0
# END OF IMMUTABLE PARTH INSTRUCTION
# PUT edits below this line

# Get current user and UID
CURRENT_USER=kpi
CURRENT_UID=1000
CURRENT_HOST_IP=192.168.88.38

# Fix variable naming for consistency
DEFAULT_IFACE=$DEFAULT_INTERFACE
HOST_XDG_RUNTIME_DIR="/run/user/$CURRENT_UID"

# Completely clean up any previous setup
sudo ip rule del fwmark 1 table 200 2>/dev/null || true
sudo ip route flush table 200 2>/dev/null || true
sudo iptables -t mangle -F PREROUTING 2>/dev/null || true
sudo iptables -t nat -F POSTROUTING 2>/dev/null || true
sudo ip link del veth0 2>/dev/null || true

# Create a macvlan interface directly connected to the physical network
# This completely bypasses the host's routing tables and VPN
sudo ip link add link $DEFAULT_IFACE novpn-direct type macvlan mode bridge
sudo ip link set novpn-direct netns novpn

# Create a veth pair for host-namespace communication
# This is needed because macvlan interfaces typically can't communicate with their parent interface
echo "Setting up veth pair for host-namespace connectivity..."
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns novpn
sudo ip addr add 192.168.100.1/24 dev veth0
sudo ip netns exec novpn ip addr add 192.168.100.2/24 dev veth1
sudo ip link set veth0 up
sudo ip netns exec novpn ip link set veth1 up

# Configure the namespace with a direct connection to the physical network
sudo ip netns exec novpn ip link set novpn-direct up
sudo ip netns exec novpn ip link set lo up

# Get a fresh IP address on the same subnet as the gateway
SUBNET=$(echo $DEFAULT_GATEWAY | sed 's/\.[0-9]*$/.0\/24/')
RANDOM_IP=$(echo $DEFAULT_GATEWAY | sed "s/\.[0-9]*$/.$(($RANDOM % 200 + 10))/")

# This completely bypasses the host's routing tables and VPN
echo "Using subnet: $SUBNET and IP: $RANDOM_IP with gateway: $DEFAULT_GATEWAY"
echo "Host IP: $CURRENT_HOST_IP (will connect directly to this)"
echo "Host-namespace link: 192.168.100.1 <-> 192.168.100.2"

# Configure IP directly on the physical network
sudo ip netns exec novpn ip addr add $RANDOM_IP/24 dev novpn-direct
sudo ip netns exec novpn ip route add default via $DEFAULT_GATEWAY dev novpn-direct

# Add special route to reach host via veth interface
# This is crucial since macvlan typically can't communicate with its parent
sudo ip netns exec novpn ip route add $CURRENT_HOST_IP/32 via 192.168.100.1 dev veth1

# Add fixed route on host to reach namespace
sudo ip route add $RANDOM_IP/32 via 192.168.100.2 dev veth0

# Enable IP forwarding for communication between interfaces
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/conf/all/forwarding'

# Add iptables rules to allow communication through veth interface
sudo iptables -F FORWARD
sudo iptables -A FORWARD -i veth0 -o veth1 -j ACCEPT
sudo iptables -A FORWARD -i veth1 -o veth0 -j ACCEPT
sudo iptables -A FORWARD -i $DEFAULT_IFACE -o veth0 -j ACCEPT
sudo iptables -A FORWARD -i veth0 -o $DEFAULT_IFACE -j ACCEPT
sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -j MASQUERADE

# Make sure the host can receive traffic from the namespace
sudo iptables -A INPUT -i veth0 -j ACCEPT

# Temporarily disable firewall to test connectivity (if available)
if command -v firewall-cmd >/dev/null 2>&1; then
    echo "Temporarily disabling firewall to test connectivity..."
    sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="192.168.100.0/24" accept' --timeout=300
fi

# Add CAP_NET_RAW capability to ping for ICMP packets
PING_PATH=$(which ping)
sudo setcap cap_net_raw+ep $PING_PATH

# Fix for mount failures - use bind mount instead of move_mount
fix_mount() {
    src=$1
    dst=$2
    sudo mkdir -p "$dst" 2>/dev/null || true
    # Unmount first if already mounted
    sudo umount "$dst" 2>/dev/null || true
    # Use bind mount with explicit options
    sudo mount --bind "$src" "$dst" || echo "⚠️ Warning: Failed to mount $src to $dst"
}

# Add DNS configuration - using 192.168.88.1 as specified
echo "nameserver 192.168.88.1" | sudo tee /etc/netns/novpn/resolv.conf

# Set up PulseAudio and D-Bus access
# Create required directories in the namespace
XDG_RUNTIME_DIR="$HOST_XDG_RUNTIME_DIR"
sudo mkdir -p /run/netns/novpn
sudo ip netns exec novpn mkdir -p "$XDG_RUNTIME_DIR" 2>/dev/null || true
sudo ip netns exec novpn mkdir -p "$XDG_RUNTIME_DIR/pulse" 2>/dev/null || true
sudo ip netns exec novpn mkdir -p "$XDG_RUNTIME_DIR/bus" 2>/dev/null || true
sudo ip netns exec novpn mkdir -p /tmp/dbus-for-novpn 2>/dev/null || true

# Fix for finding the namespace identifier
NS_PID=$(sudo ip netns pids novpn | head -n1)
if [ -z "$NS_PID" ]; then
    # If no process exists yet, start a sleep process to get a PID
    sudo ip netns exec novpn sleep 1000 &
    SLEEP_PID=$!
    NS_PID=$SLEEP_PID
    # Give it time to start
    sleep 1
fi
NS_PATH="/proc/$NS_PID/root"
echo "Namespace root path: $NS_PATH"

# Mount entire XDG_RUNTIME_DIR for Wayland sockets and other services
echo "Setting up XDG_RUNTIME_DIR access from $XDG_RUNTIME_DIR..."
fix_mount "$XDG_RUNTIME_DIR" "$NS_PATH$XDG_RUNTIME_DIR"

# Set up access for Wayland-specific sockets (different than X11)
if [ -n "$WAYLAND_DISPLAY" ] && [ -e "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]; then
    echo "Setting up Wayland socket access..."
    # Wayland socket is already included in the XDG_RUNTIME_DIR mount
    # Just need to ensure permissions are correct
    sudo ip netns exec novpn chmod 777 "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" 2>/dev/null || true
fi

# Set up X11 socket access (as fallback)
if [ -e "/tmp/.X11-unix" ]; then
    echo "Setting up X11 socket access..."
    fix_mount "/tmp/.X11-unix" "$NS_PATH/tmp/.X11-unix"
    
    # Make sure DISPLAY variable is set in the wrapper script
    DISPLAY_VAR=${DISPLAY:-$SUDO_DISPLAY}
    if [ -z "$DISPLAY_VAR" ]; then
        DISPLAY_VAR=":0"
    fi
    echo "X11 DISPLAY: $DISPLAY_VAR"
fi

# Clean up the sleep process if we created one
if [ -n "$SLEEP_PID" ]; then
    sudo kill $SLEEP_PID 2>/dev/null || true
fi

# Verify connectivity
echo "Testing connectivity from namespace..."
# First test direct internet connectivity
sudo ip netns exec novpn ping -c 1 -W 2 $DEFAULT_GATEWAY > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Connected to local gateway ($DEFAULT_GATEWAY)"
    sudo ip netns exec novpn ping -c 1 -W 2 8.8.8.8 > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "✅ Network namespace 'novpn' created successfully with internet connectivity!"
        
        # Test host connectivity in multiple ways
        echo "Testing host connectivity (multiple methods)..."
        echo "Method 1: Direct ping via macvlan..."
        if sudo ip netns exec novpn ping -c 1 -W 2 $CURRENT_HOST_IP > /dev/null 2>&1; then
            echo "✅ Namespace can reach host at $CURRENT_HOST_IP via direct ping"
        else
            echo "⚠️ Direct ping to host failed, trying alternative route..."
            
            # Try via veth pair
            echo "Method 2: Ping via veth interface..."
            if sudo ip netns exec novpn ping -c 1 -W 2 192.168.100.1 > /dev/null 2>&1; then
                echo "✅ Namespace can reach veth endpoint (192.168.100.1)"
                
                # Try to reach host IP via veth route
                echo "Method 3: Trace route to host IP..."
                sudo ip netns exec novpn traceroute -n $CURRENT_HOST_IP 2>&1 | head -n 5
                
                # Check if port is being blocked by firewall
                echo "Testing connection to compiler server (port 8765)..."
                if command -v nc >/dev/null 2>&1; then
                    if sudo ip netns exec novpn nc -z -w1 $CURRENT_HOST_IP 8765 2>/dev/null; then
                        echo "✅ Can connect to compiler server port 8765"
                    else
                        echo "⚠️ Cannot connect to port 8765 - checking if service is running..."
                        if ss -tlnp | grep -q ":8765"; then
                            echo "  Service is running on host, but port may be blocked"
                            echo "  Service binding details:"
                            ss -tlnp | grep ":8765"
                            
                            # Check if binding is localhost-only
                            if ss -tlnp | grep ":8765" | grep -q "127.0.0.1"; then
                                echo "  ⚠️ Service is bound to localhost (127.0.0.1) only!"
                                echo "  You need to modify the compiler service to bind to $CURRENT_HOST_IP or 0.0.0.0"
                                
                                # Suggest command to update the compiler service
                                echo "  Suggestion: Edit compiler_server.py to change --host from localhost to 0.0.0.0"
                            fi
                        else
                            echo "  ⚠️ Service doesn't appear to be running on port 8765"
                        fi
                    fi
                fi
            else
                echo "⚠️ Cannot reach veth endpoint - network setup issue"
                echo "Debug information:"
                echo "Namespace interfaces:"
                sudo ip netns exec novpn ip addr
                echo "Host interfaces:"
                ip addr | grep -A 2 "veth0"
                echo "Namespace routing table:"
                sudo ip netns exec novpn ip route
                echo "Host routing table:"
                ip route
            fi
        fi
        
        # Temporary direct connection test via socat if all else fails
        echo "Creating temporary proxy for compiler server (port 8765)..."
        sudo pkill -f "socat.*:8765" 2>/dev/null || true
        sudo socat TCP-LISTEN:8765,fork TCP:127.0.0.1:8765 &
        SOCAT_PID=$!
        echo "Proxy running with PID: $SOCAT_PID (will be killed when script exits)"
        
        # Ensure socat is killed on script exit
        trap "sudo kill $SOCAT_PID 2>/dev/null || true" EXIT
        
        echo "Try these commands to test connectivity:"
        echo "  sudo ip netns exec novpn curl http://$CURRENT_HOST_IP:8765/status"
        echo "  run-novpn curl http://$CURRENT_HOST_IP:8765/status"
        
        # Continue with VPN bypass verification
        HOST_IP=$(curl -s ifconfig.me)
        NAMESPACE_IP=$(sudo ip netns exec novpn curl -s ifconfig.me)
        echo "Host public IP: $HOST_IP"
        echo "Namespace public IP: $NAMESPACE_IP"
        if [ "$HOST_IP" != "$NAMESPACE_IP" ]; then
            echo "✅ VPN successfully bypassed! Different public IPs detected."
        else
            echo "⚠️ Same public IPs detected. VPN might still be in use."
        fi
    else
        echo "⚠️ Can reach local gateway but not internet (8.8.8.8)"
        echo "DNS might still work. Try a domain name lookup:"
        sudo ip netns exec novpn nslookup google.com 192.168.88.1
    fi
else
    echo "⚠️ Network namespace created but connectivity test failed."
    echo "Running diagnostics..."
    # Check routes in namespace
    echo -e "\n--- Routes in namespace ---"
    sudo ip netns exec novpn ip route
    # Check DNS in namespace
    echo -e "\n--- DNS configuration ---"
    sudo ip netns exec novpn cat /etc/resolv.conf
    # Try traceroute from namespace to diagnose routing issues
    echo -e "\n--- Traceroute to gateway ---"
    sudo ip netns exec novpn traceroute -n 192.168.88.1 2>&1 | head -n 5
fi