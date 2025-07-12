# UDev Event Forwarder

## Overview
This project forwards udev events from the host system to a network namespace through a Unix socket. This enables containerized or sandboxed environments to receive hardware events from the host.

## Architecture

### Components
1. **Forwarder** (`udev-forwarder`) - Runs on the host, captures netlink events
2. **Receiver** (`udev-receiver`) - Runs in the namespace, rebroadcasts events
3. **Rebroadcast** (`udev-rebroadcast`) - Manages both components automatically

### Communication Flow
```
Host netlink (group 2) → Forwarder → Unix Socket → Receiver → Namespace netlink (group 2)
```

## Key Features

- **Raw netlink sockets** with direct `libc` calls for maximum control
- **Epoll-based monitoring** for efficient, zero-CPU-usage event handling
- **Multicast group 2** for udev event communication
- **Simple message protocol**: 4-byte size header + raw event data
- **Automatic process management** with PID file tracking
- **Namespace support** with configurable target namespace

## Implementation Details

### Netlink Configuration
- Protocol: `NETLINK_KOBJECT_UEVENT` (15)
- Multicast Group: 2 (configured in `NETLINK_MULTICAST_GROUP`)
- Socket Flags: `SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK`
- Buffer Size: 1MB for handling event bursts

### Message Protocol
```
[4 bytes: size as u32 LE] [N bytes: raw netlink event data]
```

### Event Format
Raw udev events contain null-terminated strings:
```
action@devpath\0SUBSYSTEM=...\0DEVNAME=...\0KEY=value\0...
```

## Usage

### Quick Start - Automatic Mode
Run both components with a single command:
```bash
sudo udev-rebroadcast --namespace novpn
```

### Manual Mode
Run components separately:
```bash
# On host (terminal 1)
sudo udev-forwarder

# In namespace (terminal 2)  
sudo ip netns exec novpn udev-receiver
```

### Testing
Use echo mode to verify netlink events:
```bash
# Test reception on host
sudo udev-forwarder --echo

# Test reception in namespace
sudo ip netns exec novpn udev-forwarder --echo
```

## Requirements

- **Root access** for netlink socket operations
- **Network namespace** already created (e.g., `novpn`)
- **Unix socket path**: `/run/udev-forwarder.sock`
- **PID file**: `/run/udev-rebroadcast.pid` (for automatic mode)

## Signal Handling

All components handle graceful shutdown via:
- `SIGTERM` - Termination signal
- `SIGINT` - Interrupt signal (Ctrl+C)

The rebroadcast manager automatically cleans up both child processes on shutdown.