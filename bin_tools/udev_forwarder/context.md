# UDev Event Forwarder

## Overview
This project creates two Rust executables to forward udev events from the host system to a namespace through a Unix socket. This is useful for containerized or sandboxed environments that need to receive hardware events from the host.

## Architecture

### Components
1. **Forwarder** (`udev-forwarder`) - Runs on the host
2. **Receiver** (`udev-receiver`) - Runs in the namespace/container

### Communication Flow
```
Host udev events → Forwarder → Unix Socket → Receiver → Namespace udev
```

## Implementation Details

### Socket Configuration
- **Path**: `/tmp/udev.sock`
- **Type**: Unix domain socket (AF_UNIX)
- **Protocol**: Stream-based for reliable delivery

### Forwarder (Host Side)
The forwarder will:
1. Create and bind to a netlink socket using `NETLINK_KOBJECT_UEVENT`
2. Listen for udev events from the kernel
3. Extract raw event bytes
4. Forward events through the Unix socket to receivers
5. Handle multiple receiver connections
6. Implement proper error handling and reconnection logic

### Receiver (Namespace Side)
The receiver will:
1. Connect to the Unix socket
2. Receive raw udev event bytes
3. Inject events into the namespace's udev system using netlink
4. Handle connection drops and reconnection
5. Validate event format before injection

## Neli Library Details

### Key Types and Constants
- `neli::consts::socket::KobjectUevent` - NETLINK_KOBJECT_UEVENT socket type
- `neli::consts::nl::NlmF` - Netlink message flags
- `neli::socket::NlSocketHandle` - Main socket interface
- `neli::genl::Genlmsghdr` - Generic netlink message header
- `neli::nl::Nlmsghdr` - Netlink message header

### Socket Setup
```rust
use neli::{
    consts::socket::KobjectUevent,
    socket::NlSocketHandle,
    types::GenlBuffer,
};

// Create netlink socket for udev events
let socket = NlSocketHandle::connect(
    KobjectUevent, 
    None, 
    &[]
)?;
```

### Message Format
UDev events are transmitted as netlink messages containing:
- Action (add, remove, change, etc.)
- Device path
- Subsystem
- Environment variables
- Device attributes

## Error Handling

### Forwarder Error Cases
- Netlink socket creation failure
- Unix socket binding failure  
- Event parsing errors
- Client disconnection handling

### Receiver Error Cases
- Unix socket connection failure
- Netlink injection failure
- Malformed event data
- Permission issues

## Security Considerations
- Validate event data before injection
- Implement proper access controls on Unix socket
- Consider event filtering/whitelisting
- Handle privilege escalation requirements

## Usage

### Running the Forwarder (Host)
```bash
sudo ./udev-forwarder --socket-path /tmp/udev.sock
```

### Running the Receiver (Namespace)
```bash
./udev-receiver --socket-path /tmp/udev.sock
```

## Dependencies
- `neli` v0.6.5 with tokio and async features
- `tokio` for async runtime
- `serde` for message serialization (if needed)
- `log` and `env_logger` for logging

## Development Notes
- Events should maintain original kernel format
- Consider batching for performance
- Implement graceful shutdown handling
- Add comprehensive logging for debugging
- Unit tests for event parsing and injection