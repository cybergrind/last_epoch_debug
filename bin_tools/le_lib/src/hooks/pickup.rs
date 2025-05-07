use crate::echo::Registers;
use log::info;

#[repr(C)]
#[derive(Debug)]
struct GameString {
    // skip 0x10 bytes
    __pad: [u8; 0x10],
    pub length: u32,
    pub first_char: u16,
}

impl GameString {
    pub fn to_string(&self) -> String {
        unsafe {
            // copy ptr.legth bytes to string, starting from ptr.first_char
            let length = self.length as usize;
            info!("GameString length: {}", length);
            info!("GameString first_char: {}", self.first_char);
            // first char pointer == self pointer + 0x14 bytes
            let first_char_ptr = (self as *const GameString as usize + 0x14) as *const u16;
            info!("GameString first_char_ptr: {:?}", first_char_ptr);

            let char_count = length;
            let utf16_slice: &[u16] = std::slice::from_raw_parts(first_char_ptr, char_count);
            String::from_utf16_lossy(utf16_slice)
        }
    }
    pub fn read_from_ptr(ptr: u64) -> String {
        unsafe {
            let ptr = ptr as *const GameString;
            (*ptr).to_string()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn le_lib_pickup(registers_ptr: u64) {
    info!("le_lib_pickup called");
    let registers = Registers::from_saved_pointer(registers_ptr);
    let string_ptr = registers.rdi;

    let game_string = GameString::read_from_ptr(string_ptr);
    info!("GameString: {:?}", game_string);
}
