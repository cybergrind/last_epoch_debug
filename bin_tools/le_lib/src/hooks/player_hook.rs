use crate::{
    constants::GAME_DLL, echo::Registers, low_level_tools::hook_tools::get_module_base_address,
};
use lazy_static::lazy_static;
use log::info;
use std::sync::RwLock;

#[repr(C)]
#[derive(Debug)]
pub struct BaseHealth {
    _pad0: [u8; 0x50],
    actor: *const Actor,
    pub max_health: i32,
    pub current_health: f32,
}
impl BaseHealth {
    pub fn from_ptr(ptr: u64) -> Self {
        unsafe {
            let base_health = std::ptr::read(ptr as *const BaseHealth);
            return base_health;
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Actor {
    _pad0: [u8; 0x30],
    base_health: *const BaseHealth,
}

impl Actor {
    pub fn from_ptr(ptr: u64) -> Self {
        unsafe {
            let actor = std::ptr::read(ptr as *const Actor);
            return actor;
        }
    }

    pub fn debug_info(&self) {
        let base_health = unsafe {
            if self.base_health.is_null() {
                info!("Actor: base_health is null");
                return;
            }
            let base_health = std::ptr::read(self.base_health);
            (base_health.current_health, base_health.max_health)
        };
        info!(
            "Actor: {:#?}, Health: ({}, {})",
            self, base_health.0, base_health.1
        );
    }
}

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

#[repr(C)]
#[derive(Debug)]
pub struct PlayerSync {
    _pad0: [u8; 0x40],
    pub actor: *const Actor,
}

impl PlayerSync {
    pub fn from_ptr(ptr: u64) -> Self {
        unsafe {
            let player = std::ptr::read(ptr as *const PlayerSync);
            return player;
        }
    }
    pub fn debug_info(&self) {
        let health = unsafe {
            if self.actor.is_null() {
                info!("PlayerSync: actor is null");
                return;
            }
            let actor = std::ptr::read(self.actor);
            if actor.base_health.is_null() {
                info!("PlayerSync: actor.base_health is null");
                return;
            }

            info!("PlayerSync: base_health is not null");
            let base_health = std::ptr::read(actor.base_health);
            (base_health.current_health, base_health.max_health)
        };
        info!(
            "PlayerSync: {:#?}, Health: ({}, {})",
            self, health.0, health.1
        );
    }
}

#[repr(C)]
#[derive(Debug)]
struct ActorSync {
    _pad0: [u8; 0x50],
    pub actor: *const Actor,
}
impl ActorSync {
    pub fn from_ptr(ptr: u64) -> Self {
        unsafe {
            let actor_sync = std::ptr::read(ptr as *const ActorSync);
            return actor_sync;
        }
    }
    pub fn debug_info(&self) {
        let actor = unsafe {
            if self.actor.is_null() {
                info!("ActorSync: actor is null");
                return;
            }
            std::ptr::read(self.actor)
        };
        let health = unsafe {
            if actor.base_health.is_null() {
                info!("ActorSync: actor.base_health is null");
                return;
            }
            let base_health = std::ptr::read(actor.base_health);
            (base_health.current_health, base_health.max_health)
        };
        info!(
            "ActorSync: {:#?}, Health: ({}, {})",
            self, health.0, health.1
        );
    }
}

const PLAYER_FINDER_GET_ACTOR_PTR: u64 = 0x1052bc0;

fn get_player_health() -> Actor {
    // call PLAYER_FINDER_GET_HEALTH_PTR
    // pointer will be returned in rax
    let base_address = get_module_base_address(GAME_DLL).unwrap();
    let ptr: u64 = PLAYER_FINDER_GET_ACTOR_PTR + base_address;
    unsafe {
        let rax: u64;
        std::arch::asm!(
            "xor ecx, ecx",
            "call {}",
            in(reg) ptr,
            out("rax") rax,
        );
        let actor = std::ptr::read(rax as *const Actor);
        actor
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn le_lib_player_hook(registers_ptr: u64) {
    info!("le_lib_player_hook called");
    let registers = Registers::from_saved_pointer(registers_ptr);

    //let player_sync = Actor::from_ptr(registers.rax);
    //player_sync.debug_info();
}

lazy_static! {
    static ref PLAYER_HEALTH_PTR: RwLock<u64> = RwLock::new(0);
}

#[unsafe(no_mangle)]
pub extern "C" fn le_lib_health_hook(registers_ptr: u64) {
    info!("le_lib_health_hook called");
    let registers = Registers::from_saved_pointer(registers_ptr);
    let new_player_health = PlayerHealth::from_ptr(registers.rbx + 0xa0);
    new_player_health.debug_info();
    let mut player_health = PLAYER_HEALTH_PTR.write().unwrap();
    *player_health = registers.rbx + 0xa0;
}
