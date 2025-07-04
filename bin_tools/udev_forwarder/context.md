# UDev Event Forwarder

## Current Status

The `udev-forwarder` is implemented using raw netlink sockets with direct `libc` calls. It successfully captures and displays udev events from the kernel with proper signal handling for graceful shutdown.

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

### Raw Netlink Socket Configuration
- **Family**: `AF_NETLINK`
- **Protocol**: `NETLINK_KOBJECT_UEVENT` (15)
- **Flags**: `SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK`
- **Multicast Group**: 1 (udev events)
- **Buffer Size**: 1MB for handling event bursts

### Socket Setup
```rust
// Create raw netlink socket for udev events
let socket_fd = unsafe {
    libc::socket(
        libc::AF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        15, // NETLINK_KOBJECT_UEVENT
    )
};

// Bind to multicast group 1 for udev events
let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
addr.nl_family = libc::AF_NETLINK as u16;
addr.nl_pid = 0; // Kernel assigns PID
addr.nl_groups = 1; // Subscribe to multicast group 1
```

### Epoll-Based Event Monitoring
The implementation uses Linux epoll for efficient event-driven socket monitoring:

```rust
// Create epoll instance
let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };

// Add socket to epoll interest list for read events
let mut epoll_event = libc::epoll_event {
    events: libc::EPOLLIN as u32,
    u64: socket_fd as u64,
};

// Wait for events with timeout
let ready_count = unsafe {
    libc::epoll_wait(epoll_fd, events.as_mut_ptr(), events.len() as i32, 100)
};
```

**Benefits over polling approach:**
- **Zero CPU usage** when no events are available
- **Immediate notification** when data becomes available  
- **Scalable** to multiple file descriptors if needed
- **Timeout support** for responsive shutdown handling

### Message Format
UDev events are transmitted as netlink messages containing:
- **Netlink Header**: Standard netlink message header
- **Payload**: Raw udev event data with null-terminated strings
- **Structure**: `action@devpath\0SUBSYSTEM=...\0DEVNAME=...\0...`

### Event Processing
The forwarder processes events by:
1. Creating an epoll instance for efficient socket monitoring
2. Adding the netlink socket to epoll interest list
3. Using `epoll_wait()` with timeout to wait for socket readiness
4. Reading available data when socket is ready
5. Extracting payload from netlink message header
6. Parsing null-terminated string fields
7. Displaying structured information including:
   - Action (add, remove, change, etc.)
   - Device path
   - Subsystem
   - Device name
   - Environment variables
   - Binary data (if present)

## Error Handling

### Socket Errors
- Netlink socket creation failure
- Binding failure to multicast group
- Non-blocking receive errors (EAGAIN/EWOULDBLOCK)
- Socket buffer overflow handling

### Event Processing Errors
- Malformed netlink headers
- Invalid UTF-8 in event strings
- Incomplete packet handling

## Signal Handling

The application implements graceful shutdown for:
- **SIGTERM** - Termination signal
- **SIGINT** - Interrupt signal (Ctrl+C)

Shutdown process:
1. Signal received in main async loop
2. Shutdown signal sent to netlink listener
3. Listener closes socket and exits
4. Main loop waits for listener completion with timeout

## Security Considerations

### Privileges Required
- **Root access** required for netlink socket access
- Application checks `geteuid() == 0` on startup

### Safety Measures
- Validates netlink message headers before parsing
- Handles binary data safely with hex display
- Limits event field display length for large payloads

## Usage

### Running the Forwarder
```bash
sudo ./udev-forwarder
```

### Sample Output
```
=== UDev Event ===
Event: add @ /devices/virtual/block/loop0
  SUBSYSTEM: block
  DEVNAME: /dev/loop0
  DEVPATH: /devices/virtual/block/loop0
  ACTION: add
  MAJOR: 7
  MINOR: 0
Summary: add action on /devices/virtual/block/loop0 [block] (/dev/loop0)
==================
```

## Dependencies

- `tokio` - Async runtime and signal handling
- `anyhow` - Error handling and context
- `log` + `env_logger` - Structured logging
- `libc` - Direct system call access

## Development Notes

### Architecture Decisions
- **Raw sockets** instead of high-level libraries for maximum control
- **Non-blocking sockets** with epoll for responsive and efficient event handling
- **Epoll-based monitoring** eliminates busy waiting and reduces CPU usage
- **Separate blocking task** for socket operations to avoid blocking async runtime
- **Detailed event parsing** for comprehensive debugging information

### Performance Considerations
- Large socket buffer (1MB) prevents event loss during bursts
- Efficient string parsing without unnecessary allocations
- **Epoll-based event monitoring** eliminates CPU waste from polling
- **Event-driven architecture** provides immediate response to socket events
- **100ms timeout** in epoll_wait allows responsive shutdown signal handling

### Future Enhancements
- Event filtering by subsystem or device type
- JSON output format option
- Event forwarding to external systems
- Persistent event logging