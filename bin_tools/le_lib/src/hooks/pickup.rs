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
    #[inline(always)]
    fn first_char_ptr(&self) -> *const u16 {
        &self.first_char as *const u16
    }

    #[inline(always)]
    fn to_string(&self) -> String {
        unsafe {
            let utf16_slice: &[u16] =
                std::slice::from_raw_parts(self.first_char_ptr(), self.length as usize);
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
