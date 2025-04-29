// memory mapping handling

/*
             The format of the file is:

                 address           perms offset  dev   inode       pathname
                 00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/dbus-daemon
                 00651000-00652000 r--p 00051000 08:02 173521      /usr/bin/dbus-daemon
                 00652000-00655000 rw-p 00052000 08:02 173521      /usr/bin/dbus-daemon
                 00e03000-00e24000 rw-p 00000000 00:00 0           [heap]
                 00e24000-011f7000 rw-p 00000000 00:00 0           [heap]
                 ...
                 35b1800000-35b1820000 r-xp 00000000 08:02 135522  /usr/lib64/ld-2.15.so
                 35b1a1f000-35b1a20000 r--p 0001f000 08:02 135522  /usr/lib64/ld-2.15.so
                 35b1a20000-35b1a21000 rw-p 00020000 08:02 135522  /usr/lib64/ld-2.15.so
                 35b1a21000-35b1a22000 rw-p 00000000 00:00 0
                 35b1c00000-35b1dac000 r-xp 00000000 08:02 135870  /usr/lib64/libc-2.15.so
                 35b1dac000-35b1fac000 ---p 001ac000 08:02 135870  /usr/lib64/libc-2.15.so
                 35b1fac000-35b1fb0000 r--p 001ac000 08:02 135870  /usr/lib64/libc-2.15.so
                 35b1fb0000-35b1fb2000 rw-p 001b0000 08:02 135870  /usr/lib64/libc-2.15.so
                 ...
                 f2c6ff8c000-7f2c7078c000 rw-p 00000000 00:00 0    [stack:986]
                 ...
                 7fffb2c0d000-7fffb2c2e000 rw-p 00000000 00:00 0   [stack]
                 7fffb2d48000-7fffb2d49000 r-xp 00000000 00:00 0   [vdso]

             The address field is the address space in the process that
             the mapping occupies.  The perms field is a set of
             permissions:

                 r = read
                 w = write
                 x = execute
                 s = shared
                 p = private (copy on write)
*/

use log::{debug, error, warn};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

// Define Address as u64 to match the expected return type
type Address = u64;

#[derive(Debug, Clone, PartialEq)]
pub struct MemoryMapEntry {
    address: Address,
    size: usize,
    perms: String,
    pathname: String,
}

impl MemoryMapEntry {
    pub fn new(line: &str) -> Self {
        let parts: Vec<&str> = line.split_whitespace().collect();

        // First 5 parts are fixed format: address perms offset dev inode
        if parts.len() < 6 {
            return MemoryMapEntry {
                address: 0,
                size: 0,
                perms: "".to_string(),
                pathname: "".to_string(),
            };
        }

        // Parse address range like "00400000-00452000"
        let address_parts: Vec<&str> = parts[0].split('-').collect();
        if address_parts.len() != 2 {
            return MemoryMapEntry {
                address: 0,
                size: 0,
                perms: "".to_string(),
                pathname: "".to_string(),
            };
        }

        let address = u64::from_str_radix(address_parts[0], 16).unwrap_or(0);
        let end_address = u64::from_str_radix(address_parts[1], 16).unwrap_or(0);

        // Calculate size safely, avoiding overflow
        let size = if end_address > address {
            (end_address - address) as usize
        } else {
            0
        };

        let perms = parts[1].to_string();

        // Join the remaining parts as pathname, which could contain spaces
        let pathname = if parts.len() > 5 {
            parts[5..].join(" ")
        } else {
            "".to_string()
        };

        MemoryMapEntry {
            address,
            size,
            perms,
            pathname,
        }
    }

    pub fn is_memory_accessible(&self) -> bool {
        self.perms.contains('r') || self.perms.contains('w') || self.perms.contains('x')
    }

    // Add getter methods for private fields
    pub fn get_address(&self) -> Address {
        self.address
    }

    pub fn get_pathname(&self) -> &str {
        &self.pathname
    }

    pub fn get_size(&self) -> usize {
        self.size
    }

    pub fn get_perms(&self) -> &str {
        &self.perms
    }
}

pub struct MemoryMap {
    entries: BTreeMap<usize, MemoryMapEntry>,
}

impl MemoryMap {
    pub fn new() -> Self {
        MemoryMap {
            entries: BTreeMap::new(),
        }
    }

    /// Returns only if existed before
    pub fn add_from_line(&mut self, line: &str) -> Option<MemoryMapEntry> {
        let entry = MemoryMapEntry::new(line);
        return self.add_or_update_entry(entry.clone());
    }

    /// Internal implementation of scan that actually updates the memory map
    /// and returns new entries
    fn scan_internal(&mut self) -> Vec<MemoryMapEntry> {
        // Read /proc/self/maps and parse the memory map
        let maps = match std::fs::read_to_string("/proc/self/maps") {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read /proc/self/maps: {}", e);
                return Vec::new();
            }
        };

        let mut new_entries = Vec::new();

        for line in maps.lines() {
            let entry = MemoryMapEntry::new(line);
            match self.add_or_update_entry(entry.clone()) {
                Some(__existing_entry) => {}
                None => new_entries.push(entry),
            }
        }

        new_entries
    }

    /// Adds a new entry or updates an existing one with the same address.
    ///
    /// Returns the previous entry if one existed, or None if this is a new entry.
    fn add_or_update_entry(&mut self, entry: MemoryMapEntry) -> Option<MemoryMapEntry> {
        self.entries.insert(entry.address as usize, entry)
    }

    pub fn get_entry(&self, address: Address) -> Option<&MemoryMapEntry> {
        self.entries.get(&(address as usize))
    }

    pub fn get_entry_by_name(&self, name: &str) -> Option<&MemoryMapEntry> {
        // Return both the full path name match and base name match
        self.entries.values().find(|entry| {
            entry.pathname.ends_with(name)
                || Path::new(&entry.pathname)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map_or(false, |basename| basename == name)
        })
    }
}

// Use Mutex<MemoryMap> for thread-safe interior mutability
lazy_static::lazy_static! {
    pub static ref MEMORY_MAP: Mutex<MemoryMap> = Mutex::new(MemoryMap::new());
}

// A safer way to obtain the mutex guard that doesn't panic
fn get_memory_map_guard() -> Option<MutexGuard<'static, MemoryMap>> {
    match MEMORY_MAP.try_lock() {
        Ok(guard) => Some(guard),
        Err(std::sync::TryLockError::WouldBlock) => {
            debug!("Memory map mutex is already locked by another thread");
            None
        }
        Err(std::sync::TryLockError::Poisoned(e)) => {
            // If the mutex is poisoned, recover and return a new guard
            warn!("Memory map mutex was poisoned, recovering");
            Some(e.into_inner())
        }
    }
}

// Add the global scan method that internally locks the mutex
impl MemoryMap {
    /// Scan memory maps, with thread safety built-in
    /// Returns new entries found during this scan
    pub fn scan() -> Vec<MemoryMapEntry> {
        // Try to lock the global memory map for the duration of the scan
        // Handle initialization case and mutex poisoning gracefully
        match get_memory_map_guard() {
            Some(mut guard) => {
                // Use the internal scan method
                guard.scan_internal()
            }
            None => {
                // Another thread is holding the lock or there was an issue
                // Fall back to a direct scan that doesn't use the global state
                debug!("Using direct scan as fallback");
                MemoryMap::scan_direct()
            }
        }
    }

    /// Function for direct scanning without using the global mutex
    /// This is safer to use during initialization or in contexts where
    /// the global state might not be fully set up
    pub fn scan_direct() -> Vec<MemoryMapEntry> {
        // Use a try_catch block to handle any panics that might occur
        let result = std::panic::catch_unwind(|| {
            let mut local_map = MemoryMap::new();
            local_map.scan_internal()
        });

        match result {
            Ok(entries) => entries,
            Err(e) => {
                error!("Panic in scan_direct: {:?}", e);
                Vec::new() // Return empty vector on error
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &MemoryMapEntry> {
        self.entries.values()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;

    use std::fs::{File, create_dir_all};
    use std::path::Path;

    // create "/tmp/le_test_dir"
    lazy_static! {
        static ref test_dir: &'static Path = {
            let dir = Path::new("/tmp/le_test_dir");
            if !dir.exists() {
                create_dir_all(dir).unwrap();
            }
            dir
        };
    }

    #[test]
    fn test_add_new_entry() {
        let mut map = MemoryMap::new();
        let entry = MemoryMapEntry {
            address: 0x1000,
            size: 0x1000,
            perms: "r-xp".to_string(),
            pathname: "/test/path".to_string(),
        };

        // When adding a new entry, previous should be None
        assert_eq!(map.add_or_update_entry(entry), None);

        // Entry should now be in the map
        let stored = map.get_entry(0x1000).unwrap();
        assert_eq!(stored.address, 0x1000);
        assert_eq!(stored.size, 0x1000);
        assert_eq!(stored.perms, "r-xp");
        assert_eq!(stored.pathname, "/test/path");
    }

    #[test]
    fn test_update_existing_entry() {
        let mut map = MemoryMap::new();

        // Add first entry
        let entry1 = MemoryMapEntry {
            address: 0x2000,
            size: 0x1000,
            perms: "r-xp".to_string(),
            pathname: "/test/path1".to_string(),
        };
        map.add_or_update_entry(entry1.clone());

        // Update with new entry at same address
        let entry2 = MemoryMapEntry {
            address: 0x2000,
            size: 0x2000,
            perms: "rwxp".to_string(),
            pathname: "/test/path2".to_string(),
        };

        // Should return the previous entry
        let previous = map.add_or_update_entry(entry2.clone()).unwrap();
        assert_eq!(previous.address, entry1.address);
        assert_eq!(previous.size, entry1.size);
        assert_eq!(previous.perms, entry1.perms);
        assert_eq!(previous.pathname, entry1.pathname);

        // Storage should contain updated entry
        let stored = map.get_entry(0x2000).unwrap();
        assert_eq!(stored.address, 0x2000);
        assert_eq!(stored.size, 0x2000);
        assert_eq!(stored.perms, "rwxp");
        assert_eq!(stored.pathname, "/test/path2");
    }

    #[test]
    fn test_get_entry_by_name() {
        let mut map = MemoryMap::new();
        // add entry with spaces
        let line = "00400000-00452000 r-xp 00000000 08:02 173521 /test/path to/file with spaces";
        // ensure it it parsed correct
        let entry = MemoryMapEntry::new(line);

        // should return None
        assert_eq!(map.add_from_line(line), None);
        assert_eq!(map.len(), 1);

        match map.add_from_line(line) {
            Some(_) => {}
            None => {
                panic!("Entry should be already in map) ");
            }
        }
        map.add_from_line(
            "01400000-01452000 r-xp 00000000 08:02 173521 /test/path to/file with spaces",
        );
        assert_eq!(map.len(), 2);

        // just the base name
        match map.get_entry_by_name("file with spaces") {
            Some(found) => assert_eq!(found.address, entry.address),
            None => panic!("Entry not found"),
        }

        // Test with full path
        let found = map
            .get_entry_by_name("/test/path to/file with spaces")
            .unwrap();
        assert_eq!(found.address, entry.address);
    }

    #[test]
    fn test_global_map() {
        // Test the global memory map
        match MEMORY_MAP.lock() {
            Ok(map) => {
                assert_eq!(map.len(), 0, "Global memory map should be empty initially");
            }
            Err(e) => {
                panic!("Failed to lock global memory map: {}", e);
            }
        }

        // let new_entries: Vec<MemoryMapEntry> = MEMORY_MAP.lock().unwrap().scan_internal();
        let new_entries = MemoryMap::scan();
        assert!(new_entries.len() > 0, "Scan should return new entries");

        match MEMORY_MAP.lock() {
            Ok(map) => {
                assert_ne!(
                    map.len(),
                    0,
                    "Global memory map should not be empty after scan"
                );
            }
            Err(e) => {
                panic!("Failed to lock global memory map: {}", e);
            }
        }
        let empty_entries = MemoryMap::scan();
        assert_eq!(empty_entries.len(), 0, "Scan should return no new entries");

        // mmap this file into memory
        use memmap2::Mmap;
        use uuid::Uuid;

        let file_name = format!("mmap_test_{}", Uuid::new_v4());
        let file_path = test_dir.join(file_name);
        // create the file with 4096 bytes

        let file = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();
        let _ = file.set_len(4096).unwrap();

        let _mmap = unsafe { Mmap::map(&file).unwrap() };

        let new_entries = MemoryMap::scan();
        assert!(new_entries.len() == 1, "Scan should return new entries");
        let entry = new_entries.get(0).unwrap();
        assert!(
            entry.pathname == file_path.to_str().unwrap(),
            "Entry should match the mmaped file"
        );
        match MEMORY_MAP.lock() {
            Ok(map) => {
                let only_name = file_path.file_name().unwrap().to_str().unwrap();
                assert_eq!(
                    map.get_entry_by_name(only_name).unwrap().address,
                    entry.address
                );
            }
            Err(e) => {
                panic!("Failed to lock global memory map: {}", e);
            }
        }
    }
}
