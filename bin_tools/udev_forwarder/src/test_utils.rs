#![cfg(any(test, feature = "test-utils"))]

/// Test utilities and sample data for udev_forwarder tests

/// Sample udev event data for testing
pub mod sample_events {
    /// USB device add event
    pub const USB_ADD: &[u8] = b"add@/devices/pci0000:00/0000:00:14.0/usb1/1-1\0\
        SUBSYSTEM=usb\0\
        DEVNAME=/dev/bus/usb/001/002\0\
        DEVTYPE=usb_device\0\
        PRODUCT=46d/c52b/1211\0\
        TYPE=0/0/0\0\
        BUSNUM=001\0\
        DEVNUM=002\0";

    /// Block device change event  
    pub const BLOCK_CHANGE: &[u8] = b"change@/devices/virtual/block/loop0\0\
        SUBSYSTEM=block\0\
        DEVNAME=/dev/loop0\0\
        DEVTYPE=disk\0\
        MAJOR=7\0\
        MINOR=0\0\
        DISKSEQ=1\0";

    /// Network interface remove event
    pub const NET_REMOVE: &[u8] = b"remove@/devices/virtual/net/dummy0\0\
        SUBSYSTEM=net\0\
        INTERFACE=dummy0\0";

    /// Minimal event
    pub const MINIMAL: &[u8] = b"bind@/devices/platform/test\0";

    /// Malformed event (no action@path)
    pub const MALFORMED: &[u8] = b"SUBSYSTEM=misc\0DEVNAME=/dev/null\0";
}

/// Generate a test event with custom parameters
pub fn make_test_event(action: &str, devpath: &str, properties: &[(&str, &str)]) -> Vec<u8> {
    let mut event = format!("{}@{}", action, devpath).into_bytes();
    event.push(0);

    for (key, value) in properties {
        event.extend_from_slice(format!("{}={}", key, value).as_bytes());
        event.push(0);
    }

    event
}

/// Generate random bytes for stress testing
pub fn random_bytes(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_test_event() {
        let event = make_test_event(
            "add",
            "/devices/test",
            &[("SUBSYSTEM", "test"), ("DEVNAME", "/dev/test0")],
        );

        let expected = b"add@/devices/test\0SUBSYSTEM=test\0DEVNAME=/dev/test0\0";
        assert_eq!(event, expected);
    }

    #[test]
    fn test_sample_events_valid() {
        // Ensure sample events are properly null-terminated
        for event in [
            sample_events::USB_ADD,
            sample_events::BLOCK_CHANGE,
            sample_events::NET_REMOVE,
            sample_events::MINIMAL,
        ] {
            assert!(event.iter().any(|&b| b == 0));
        }
    }
}
