/// Message protocol for Unix socket communication
/// Format: [4 bytes: size as u32 LE] [N bytes: payload]

/// Pack a payload with size header
pub fn pack_message(payload: &[u8]) -> Vec<u8> {
    let size = payload.len() as u32;
    let mut message = Vec::with_capacity(4 + payload.len());
    message.extend_from_slice(&size.to_le_bytes());
    message.extend_from_slice(payload);
    message
}

/// Unpack a message, returning the payload
pub fn unpack_message(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 4 {
        return None;
    }

    let size_bytes: [u8; 4] = data[0..4].try_into().ok()?;
    let size = u32::from_le_bytes(size_bytes) as usize;

    if data.len() < 4 + size {
        return None;
    }

    Some(&data[4..4 + size])
}

/// Extract complete messages from a buffer
/// Returns (messages, remaining_bytes)
pub fn extract_messages(buffer: &[u8]) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut messages = Vec::new();
    let mut pos = 0;

    while pos + 4 <= buffer.len() {
        let size_bytes: [u8; 4] = buffer[pos..pos + 4].try_into().unwrap();
        let size = u32::from_le_bytes(size_bytes) as usize;

        if pos + 4 + size > buffer.len() {
            // Incomplete message
            break;
        }

        messages.push(buffer[pos + 4..pos + 4 + size].to_vec());
        pos += 4 + size;
    }

    let remaining = buffer[pos..].to_vec();
    (messages, remaining)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_empty() {
        let payload = b"";
        let packed = pack_message(payload);
        assert_eq!(packed.len(), 4);
        assert_eq!(packed, [0, 0, 0, 0]);

        let unpacked = unpack_message(&packed);
        assert_eq!(unpacked, Some(&b""[..]));
    }

    #[test]
    fn test_pack_unpack_simple() {
        let payload = b"hello";
        let packed = pack_message(payload);
        assert_eq!(packed.len(), 9); // 4 + 5
        assert_eq!(&packed[0..4], &[5, 0, 0, 0]); // 5 in little-endian
        assert_eq!(&packed[4..], b"hello");

        let unpacked = unpack_message(&packed);
        assert_eq!(unpacked, Some(&b"hello"[..]));
    }

    #[test]
    fn test_pack_unpack_large() {
        let payload = vec![0xAB; 1000];
        let packed = pack_message(&payload);
        assert_eq!(packed.len(), 1004);

        let size_bytes = &packed[0..4];
        assert_eq!(u32::from_le_bytes(size_bytes.try_into().unwrap()), 1000);

        let unpacked = unpack_message(&packed);
        assert_eq!(unpacked, Some(payload.as_slice()));
    }

    #[test]
    fn test_unpack_incomplete_header() {
        assert_eq!(unpack_message(&[1, 2, 3]), None);
        assert_eq!(unpack_message(&[]), None);
    }

    #[test]
    fn test_unpack_incomplete_payload() {
        let packed = pack_message(b"hello world");
        // Truncate the message
        assert_eq!(unpack_message(&packed[..10]), None);
    }

    #[test]
    fn test_extract_messages_single() {
        let msg = pack_message(b"test");
        let (messages, remaining) = extract_messages(&msg);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], b"test");
        assert_eq!(remaining.len(), 0);
    }

    #[test]
    fn test_extract_messages_multiple() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&pack_message(b"first"));
        buffer.extend_from_slice(&pack_message(b"second"));
        buffer.extend_from_slice(&pack_message(b"third"));

        let (messages, remaining) = extract_messages(&buffer);
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0], b"first");
        assert_eq!(messages[1], b"second");
        assert_eq!(messages[2], b"third");
        assert_eq!(remaining.len(), 0);
    }

    #[test]
    fn test_extract_messages_partial() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&pack_message(b"complete"));

        // Add incomplete message (header + partial payload)
        buffer.extend_from_slice(&[10, 0, 0, 0]); // Size = 10
        buffer.extend_from_slice(b"part"); // Only 4 bytes of 10

        let (messages, remaining) = extract_messages(&buffer);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], b"complete");
        assert_eq!(remaining, [10, 0, 0, 0, b'p', b'a', b'r', b't']);
    }

    #[test]
    fn test_round_trip_various_sizes() {
        for size in [0, 1, 100, 255, 256, 1000, 65535] {
            let payload = vec![0x42; size];
            let packed = pack_message(&payload);
            let unpacked = unpack_message(&packed).unwrap();
            assert_eq!(unpacked, payload.as_slice());
        }
    }
}
