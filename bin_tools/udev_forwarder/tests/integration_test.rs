use udev_forwarder::event::UdevEvent;
use udev_forwarder::message::{extract_messages, pack_message};
use udev_forwarder::test_utils::{make_test_event, sample_events};

#[test]
fn test_message_flow_integration() {
    // Simulate the complete flow: event → pack → extract → parse
    let original_event = sample_events::USB_ADD;

    // Pack the event
    let packed = pack_message(original_event);

    // Simulate accumulating data
    let buffer = packed.clone();

    // Extract messages
    let (messages, remaining) = extract_messages(&buffer);
    assert_eq!(messages.len(), 1);
    assert_eq!(remaining.len(), 0);

    // Parse the extracted event
    let event = UdevEvent::parse(&messages[0]).unwrap();
    assert_eq!(event.action, Some("add".to_string()));
    assert_eq!(event.subsystem, Some("usb".to_string()));
    assert_eq!(event.devname, Some("/dev/bus/usb/001/002".to_string()));
}

#[test]
fn test_multiple_events_in_buffer() {
    let events = vec![
        sample_events::USB_ADD,
        sample_events::BLOCK_CHANGE,
        sample_events::NET_REMOVE,
    ];

    // Pack all events
    let mut buffer = Vec::new();
    for event in &events {
        buffer.extend_from_slice(&pack_message(event));
    }

    // Extract all messages
    let (messages, remaining) = extract_messages(&buffer);
    assert_eq!(messages.len(), 3);
    assert_eq!(remaining.len(), 0);

    // Verify each event
    let parsed: Vec<_> = messages
        .iter()
        .map(|m| UdevEvent::parse(m).unwrap())
        .collect();

    assert_eq!(parsed[0].action, Some("add".to_string()));
    assert_eq!(parsed[1].action, Some("change".to_string()));
    assert_eq!(parsed[2].action, Some("remove".to_string()));
}

#[test]
fn test_partial_message_handling() {
    // Create a complete message followed by a partial one
    let complete_event = sample_events::MINIMAL;
    let partial_event = sample_events::BLOCK_CHANGE;

    let mut buffer = pack_message(complete_event);
    let packed_partial = pack_message(partial_event);

    // Add only part of the second message
    buffer.extend_from_slice(&packed_partial[..10]);

    let (messages, remaining) = extract_messages(&buffer);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0], complete_event);
    assert_eq!(remaining, &packed_partial[..10]);
}

#[test]
fn test_round_trip_custom_events() {
    let test_cases = vec![
        ("add", "/dev/test1", vec![("SUBSYSTEM", "test")]),
        (
            "remove",
            "/sys/class/input/event0",
            vec![("DEVNAME", "/dev/input/event0")],
        ),
        (
            "change",
            "/devices/virtual/block/dm-0",
            vec![("SUBSYSTEM", "block"), ("MAJOR", "253"), ("MINOR", "0")],
        ),
    ];

    for (action, devpath, props) in test_cases {
        let original = make_test_event(action, devpath, &props);
        let packed = pack_message(&original);
        let (messages, _) = extract_messages(&packed);

        assert_eq!(messages.len(), 1);

        let event = UdevEvent::parse(&messages[0]).unwrap();
        assert_eq!(event.action.as_deref(), Some(action));
        assert_eq!(event.devpath.as_deref(), Some(devpath));

        for (key, value) in props {
            if key == "SUBSYSTEM" {
                assert_eq!(event.subsystem.as_deref(), Some(value));
            } else if key == "DEVNAME" {
                assert_eq!(event.devname.as_deref(), Some(value));
            } else {
                assert_eq!(event.properties.get(key).map(|s| s.as_str()), Some(value));
            }
        }
    }
}
