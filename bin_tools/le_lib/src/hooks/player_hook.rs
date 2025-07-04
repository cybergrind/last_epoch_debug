use crate::{
    echo::Registers,
    hooks::keypress_server::{on_low_health, on_potions_update},
};
use lazy_static::lazy_static;
use log::info;
use std::sync::RwLock;

#[repr(C)]
#[derive(Debug)]
pub struct PlayerHealth {
    // drop this field from debug info
    _pad0: [u32; 32],
    pub max_health: f32,
    pub health: f32,
}
impl PlayerHealth {
    pub fn from_ptr(ptr: u64) -> Self {
        if ptr == 0 {
            info!("PlayerHealth: ptr is null");
            return PlayerHealth {
                _pad0: [0; 32],
                max_health: 0.0,
                health: 0.0,
            };
        }
        unsafe {
            let player_health = std::ptr::read(ptr as *const PlayerHealth);
            return player_health;
        }
    }
    pub fn debug_info(&self) {
        info!("PlayerHealth: {}/{}", self.health, self.max_health);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn le_lib_player_hook(registers_ptr: u64) {
    let registers = Registers::from_saved_pointer(registers_ptr);

    info!("le_lib_player_hook called {}", registers.rbx);
}

lazy_static! {
    static ref PLAYER_HEALTH_PTR: RwLock<u64> = RwLock::new(0);
}

const LOW_HEALTH_THRESHOLD: f32 = 0.35;

#[unsafe(no_mangle)]
pub extern "C" fn le_lib_health_hook(registers_ptr: u64) {
    // info!("le_lib_health_hook called");
    let registers = Registers::from_saved_pointer(registers_ptr);
    let player_health = PlayerHealth::from_ptr(registers.rbx + 0xa0);
    if player_health.health == 0.0 {
        // dead player
        return;
    }
    if player_health.max_health < 0.0 || player_health.max_health > 10000.0 {
        // invalid max health, skip
        return;
    }
    if player_health.health < 0.0 || player_health.health > 10000.0 {
        // invalid health, skip
        return;
    }

    if player_health.health / player_health.max_health < LOW_HEALTH_THRESHOLD {
        info!(
            "!!![LOW] PlayerHealth: {}/{}",
            player_health.health, player_health.max_health
        );
        on_low_health(player_health.health, player_health.max_health);
    }
    let mut player_health = PLAYER_HEALTH_PTR.write().unwrap();
    *player_health = registers.rbx + 0xa0;
}

#[repr(C)]
#[derive(Debug)]
struct PotionMessage {
    pub charges: u32,
    pub max_charges: u32,
}
impl PotionMessage {
    pub fn from_ptr(ptr: u64) -> Self {
        if ptr == 0 {
            info!("PotionMessage: ptr is null");
            return PotionMessage {
                charges: 0,
                max_charges: 0,
            };
        }
        unsafe {
            let potion_message = std::ptr::read(ptr as *const PotionMessage);
            return potion_message;
        }
    }
}

#[unsafe(no_mangle)]
pub fn le_lib_potions_hook(registers_ptr: u64) {
    info!("le_lib_potions_hook called");
    let registers = Registers::from_saved_pointer(registers_ptr);

    let potion_message = PotionMessage::from_ptr(registers.rdx + 0x4);
    info!(
        "PotionMessage: charges: {}, max_charges: {}",
        potion_message.charges, potion_message.max_charges
    );
    let charges = potion_message.charges;
    let max_charges = potion_message.max_charges;
    on_potions_update(charges, max_charges);
}
