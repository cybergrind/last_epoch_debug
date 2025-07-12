pub const UNIX_SOCKET_PATH: &str = "/run/udev-forwarder.sock";
pub const NETLINK_KOBJECT_UEVENT: i32 = 15;

#[repr(C)]
pub struct NetlinkMsgHeader {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

pub fn pack_message(payload: &[u8]) -> Vec<u8> {
    let size = payload.len() as u32;
    let mut message = Vec::with_capacity(4 + payload.len());
    message.extend_from_slice(&size.to_le_bytes());
    message.extend_from_slice(payload);
    message
}

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
