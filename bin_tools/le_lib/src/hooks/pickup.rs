use crate::constants::GAME_DLL;
use crate::echo::Registers;
use crate::low_level_tools::hook_tools::get_module_base_address;
use log::info;

#[repr(C)]
#[derive(Debug)]
struct GameString {
    // skip 0x10 bytes
    __pad: [u8; 0x10],
    pub length: u32,
    pub first_char: u16,
}

struct StackFromPointer {
    var0: u64,
    var1: u64,
    var2: u64,
    var3: u64,
    var4: u64,
    var5: u64,
    var6: u64,
    var7: u64,
    var8: u64,
    var9: u64,
    var10: u64,
    var11: u64,
    var12: u64,
    var13: u64,
    var14: u64,
    var15: u64,
}
struct StackExplorer {
    dll_base_address: u64,
    base_address: u64,
    var0: u64,
    var1: u64,
    var2: u64,
    var3: u64,
    var4: u64,
    var5: u64,
    var6: u64,
    var7: u64,
    var8: u64,
    var9: u64,
    var10: u64,
    var11: u64,
    var12: u64,
    var13: u64,
    var14: u64,
    var15: u64,
}

impl StackExplorer {
    pub fn new(base_address: u64) -> Self {
        let from_pointer = unsafe { &*(base_address as *const StackFromPointer) };
        StackExplorer {
            dll_base_address: get_module_base_address(GAME_DLL).unwrap(),
            base_address,
            var0: from_pointer.var0,
            var1: from_pointer.var1,
            var2: from_pointer.var2,
            var3: from_pointer.var3,
            var4: from_pointer.var4,
            var5: from_pointer.var5,
            var6: from_pointer.var6,
            var7: from_pointer.var7,
            var8: from_pointer.var8,
            var9: from_pointer.var9,
            var10: from_pointer.var10,
            var11: from_pointer.var11,
            var12: from_pointer.var12,
            var13: from_pointer.var13,
            var14: from_pointer.var14,
            var15: from_pointer.var15,
        }
    }

    #[inline(always)]
    fn fmt(&self, current_base: u64, var1: u64, var2: u64) -> String {
        format!(
            "0x{:<8X} 0x{:<16X} / 0x{:<16X} 0x{:<16X} / 0x{:<16X}",
            current_base,
            var1,
            if var1 > self.dll_base_address {
                var1 - self.dll_base_address
            } else {
                0
            },
            var2,
            if var2 > self.dll_base_address {
                var2 - self.dll_base_address
            } else {
                0
            }
        )
    }

    pub fn print(&self) {
        let mut to_join: Vec<String> = Vec::new();
        info!(
            "DLL Base Address: {:#X} Explorer at: {:#X}",
            self.dll_base_address, self.base_address
        );
        to_join.push(format!("Stack Explorer at: {:#X}", self.base_address));
        // print 2 variables per line
        // address at left, 2 values at right
        let current_base = self.base_address;
        to_join.push(self.fmt(current_base + 0x00, self.var0, self.var1));
        to_join.push(self.fmt(current_base + 0x10, self.var2, self.var3));
        to_join.push(self.fmt(current_base + 0x20, self.var4, self.var5));
        to_join.push(self.fmt(current_base + 0x30, self.var6, self.var7));
        to_join.push(self.fmt(current_base + 0x40, self.var8, self.var9));
        to_join.push(self.fmt(current_base + 0x50, self.var10, self.var11));
        to_join.push(self.fmt(current_base + 0x60, self.var12, self.var13));
        to_join.push(self.fmt(current_base + 0x70, self.var14, self.var15));

        info!("{}", to_join.join("\n"));
    }

    pub fn just_print(rsp: u64) {
        let stack_explorer = StackExplorer::new(rsp);
        stack_explorer.print();
    }
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

const GOOD_POINTER: u64 = 0x1EBC067;
const AUTOPICKUP_PARTS: &[&str] = &["Shard", "Glyph", "Rune"];

#[unsafe(no_mangle)]
pub extern "C" fn le_lib_pickup(registers_ptr: u64) {
    info!("le_lib_pickup called");
    let registers = Registers::from_saved_pointer(registers_ptr);
    let string_ptr = registers.rdi;

    let se = StackExplorer::new(registers.rsp + 0xf0);
    if se.var1 == (GOOD_POINTER + se.dll_base_address) {
        return;
    }

    let game_string = GameString::read_from_ptr(string_ptr);

    // info!("GameString: {:?}", game_string);
    for part in AUTOPICKUP_PARTS {
        if game_string.contains(part) {
            info!("Autopickup: {}", part);
        }
    }

    // our target is probably at rsp + 0xf8
    // StackExplorer::just_print(registers.rsp + 0xf0);
    // StackExplorer::just_print(registers.rsp + 0xf0 + 0x80);
    // StackExplorer::just_print(registers.rsp + 0xf0 + 0x100);
}
