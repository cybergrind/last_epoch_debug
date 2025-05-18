// when max potions and hp is not max - game will use a potion automatically
// we need to notify keypress_server that potions were used, to track buff duration
// when potions are used

use crate::hooks::Registers;

const USE_POTION_PTR: u64 = 0x1ed4943;

#[unsafe(no_mangle)]
pub extern "C" fn le_lib_potions_hook(registers_ptr: u64) {
    info!("le_lib_potions_hook called");
    let registers = Registers::from_saved_pointer(registers_ptr);
}
