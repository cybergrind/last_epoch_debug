/// UDev event parsing utilities
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct UdevEvent {
    pub action: Option<String>,
    pub devpath: Option<String>,
    pub subsystem: Option<String>,
    pub devname: Option<String>,
    pub properties: HashMap<String, String>,
}

impl UdevEvent {
    /// Parse raw udev event data
    /// Format: action@devpath\0KEY=value\0KEY=value\0...
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let parts: Vec<&str> = data
            .split(|&b| b == 0)
            .filter_map(|part| {
                if part.is_empty() {
                    None
                } else {
                    std::str::from_utf8(part).ok()
                }
            })
            .collect();

        if parts.is_empty() {
            return Err(ParseError::EmptyEvent);
        }

        let mut event = UdevEvent {
            action: None,
            devpath: None,
            subsystem: None,
            devname: None,
            properties: HashMap::new(),
        };

        // Parse first part (action@devpath)
        if let Some(first) = parts.first() {
            if let Some((action, devpath)) = first.split_once('@') {
                event.action = Some(action.to_string());
                event.devpath = Some(devpath.to_string());
            }
        }

        // Parse properties (start from 1 if we found action@devpath, otherwise from 0)
        let start_idx = if event.action.is_some() { 1 } else { 0 };
        for part in parts.iter().skip(start_idx) {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "SUBSYSTEM" => event.subsystem = Some(value.to_string()),
                    "DEVNAME" => event.devname = Some(value.to_string()),
                    _ => {
                        event.properties.insert(key.to_string(), value.to_string());
                    }
                }
            }
        }

        Ok(event)
    }

    /// Get a summary string for logging
    pub fn summary(&self) -> String {
        match (&self.action, &self.devpath, &self.subsystem) {
            (Some(a), Some(d), Some(s)) => {
                format!(
                    "{} action on {} [{}]{}",
                    a,
                    d,
                    s,
                    self.devname
                        .as_ref()
                        .map(|n| format!(" ({})", n))
                        .unwrap_or_default()
                )
            }
            (Some(a), Some(d), None) => format!("{} action on {}", a, d),
            _ => "Partial or malformed event".to_string(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
    EmptyEvent,
    InvalidUtf8,
}

/// Extract the first N bytes as hex string for debugging
pub fn format_hex_preview(data: &[u8], max_bytes: usize) -> String {
    let preview_len = std::cmp::min(max_bytes, data.len());
    let preview = &data[..preview_len];
    format!("{:02x?}", preview)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_event() {
        let data = b"add@/devices/pci0000:00/0000:00:14.0/usb1/1-1\0SUBSYSTEM=usb\0DEVNAME=/dev/bus/usb/001/002\0";
        let event = UdevEvent::parse(data).unwrap();

        assert_eq!(event.action, Some("add".to_string()));
        assert_eq!(
            event.devpath,
            Some("/devices/pci0000:00/0000:00:14.0/usb1/1-1".to_string())
        );
        assert_eq!(event.subsystem, Some("usb".to_string()));
        assert_eq!(event.devname, Some("/dev/bus/usb/001/002".to_string()));
    }

    #[test]
    fn test_parse_event_with_properties() {
        let data = b"change@/devices/virtual/block/loop0\0SUBSYSTEM=block\0DEVNAME=/dev/loop0\0MAJOR=7\0MINOR=0\0";
        let event = UdevEvent::parse(data).unwrap();

        assert_eq!(event.action, Some("change".to_string()));
        assert_eq!(event.properties.get("MAJOR"), Some(&"7".to_string()));
        assert_eq!(event.properties.get("MINOR"), Some(&"0".to_string()));
    }

    #[test]
    fn test_parse_minimal_event() {
        let data = b"remove@/devices/virtual/misc/cpu_dma_latency\0";
        let event = UdevEvent::parse(data).unwrap();

        assert_eq!(event.action, Some("remove".to_string()));
        assert_eq!(
            event.devpath,
            Some("/devices/virtual/misc/cpu_dma_latency".to_string())
        );
        assert_eq!(event.subsystem, None);
        assert_eq!(event.devname, None);
    }

    #[test]
    fn test_parse_empty_event() {
        let data = b"";
        let result = UdevEvent::parse(data);
        assert_eq!(result, Err(ParseError::EmptyEvent));
    }

    #[test]
    fn test_parse_event_without_action() {
        let data = b"SUBSYSTEM=block\0DEVNAME=/dev/sda\0";
        let event = UdevEvent::parse(data).unwrap();

        assert_eq!(event.action, None);
        assert_eq!(event.devpath, None);
        assert_eq!(event.subsystem, Some("block".to_string()));
    }

    #[test]
    fn test_summary_full() {
        let event = UdevEvent {
            action: Some("add".to_string()),
            devpath: Some("/devices/virtual/block/loop0".to_string()),
            subsystem: Some("block".to_string()),
            devname: Some("/dev/loop0".to_string()),
            properties: HashMap::new(),
        };

        assert_eq!(
            event.summary(),
            "add action on /devices/virtual/block/loop0 [block] (/dev/loop0)"
        );
    }

    #[test]
    fn test_summary_partial() {
        let event = UdevEvent {
            action: Some("remove".to_string()),
            devpath: Some("/devices/test".to_string()),
            subsystem: None,
            devname: None,
            properties: HashMap::new(),
        };

        assert_eq!(event.summary(), "remove action on /devices/test");
    }

    #[test]
    fn test_format_hex_preview() {
        let data = b"Hello, World!";
        assert_eq!(format_hex_preview(data, 5), "[48, 65, 6c, 6c, 6f]");

        assert_eq!(
            format_hex_preview(data, 100),
            "[48, 65, 6c, 6c, 6f, 2c, 20, 57, 6f, 72, 6c, 64, 21]"
        );
    }
}
