pub const UNIX_SOCKET_PATH: &str = "/run/udev-forwarder.sock";
pub const NETLINK_KOBJECT_UEVENT: i32 = 15;
pub const NETLINK_MULTICAST_GROUP: u32 = 2; // Multicast group for udev events

#[repr(C)]
pub struct NetlinkMsgHeader {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

// Re-export message functions for backward compatibility
pub use crate::message::{pack_message, unpack_message};
