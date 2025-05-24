use crate::echo::Registers;
use crate::hooks::keypress_server::on_skill_used;
use crate::pickup::GameString;
#[allow(unused_imports)]
use log::info;

#[repr(C)]
#[derive(Debug)]
struct Ability {
    _pad0: [u64; 0x3],
    pub name: *const GameString,
}

impl Clone for Ability {
    fn clone(&self) -> Self {
        Ability {
            _pad0: self._pad0,
            name: self.name,
        }
    }
}
impl Copy for Ability {}

#[repr(C)]
#[derive(Debug)]
struct CastingData {
    _pad0: [u64; 0x2],
    pub ability: *const Ability,
    pub ability_id: u16,
    pub increased_cast_speed: f32,
    pub mana_cost: f32,
    pub free_when_out_of_mana: bool,
    pub instant_cast: bool,
    pub ability_animation: u8,
    pub animation_speed_modifier: f32,
    pub can_be_low_priority: bool,
    pub requires_button_press: bool,
    pub player_cast_vfx: u8,
    pub gamepad_targeting: u32,
    pub backup_gamepad_targeting: u32,
    pub duration: f32,
}

impl Clone for CastingData {
    fn clone(&self) -> Self {
        CastingData {
            _pad0: self._pad0,
            ability: self.ability,
            ability_id: self.ability_id,
            increased_cast_speed: self.increased_cast_speed,
            mana_cost: self.mana_cost,
            free_when_out_of_mana: self.free_when_out_of_mana,
            instant_cast: self.instant_cast,
            ability_animation: self.ability_animation,
            animation_speed_modifier: self.animation_speed_modifier,
            can_be_low_priority: self.can_be_low_priority,
            requires_button_press: self.requires_button_press,
            player_cast_vfx: self.player_cast_vfx,
            gamepad_targeting: self.gamepad_targeting,
            backup_gamepad_targeting: self.backup_gamepad_targeting,
            duration: self.duration,
        }
    }
}

impl CastingData {
    pub fn from_saved_pointer(saved_registers_ptr: u64) -> Self {
        unsafe {
            let ptr = saved_registers_ptr as *const CastingData;
            (*ptr).clone()
        }
    }

    pub fn set_instant_cast_from_ptr(ptr: u64) {
        unsafe {
            let inc_cast_speed_ptr = (ptr + 0x1c) as *mut f32;
            *inc_cast_speed_ptr *= 2e38;

            let use_duration = (ptr + 0x7c) as *mut f32;
            *use_duration = 0.0;

            let use_delay = (ptr + 0x80) as *mut f32;
            *use_delay = 0.001;
        }
    }
}

// 731 - aerial assault
// 379 - ballista
const FORCE_INSTANT_CAST: &[u16] = &[731, 379];

pub fn set_r8(registers_ptr: u64, value: u64) {
    unsafe {
        let r8_offset = std::mem::offset_of!(Registers, r8);
        let r8_ptr = (registers_ptr as usize + r8_offset) as *mut u64;
        *r8_ptr = value;
    }
}

#[unsafe(no_mangle)]
pub fn le_lib_ability_hook(registers_ptr: u64) {
    // Convert the pointer to a reference to Registers
    // info!("le_lib_ability_hook: registers_ptr: {:#x}", registers_ptr);
    // flush log
    let _ = log::logger().flush();

    let registers = Registers::from_saved_pointer(registers_ptr);
    // Call the function to handle the registers
    // info!("le_lib_ability_hook: registers: {:#?}", registers);
    let _ = log::logger().flush();
    let casting_data_ptr = registers.rax;

    // copy value of instant_cast to r9
    let instant_cast_ptr = (casting_data_ptr + 0x29) as *const u8;
    let instant_cast = unsafe { *instant_cast_ptr };
    set_r8(registers_ptr, instant_cast as u64);

    let casting_data = CastingData::from_saved_pointer(casting_data_ptr);
    // info!("le_lib_ability_hook: casting_data: {:#?}", casting_data);
    let _ = log::logger().flush();

    // Fix the way we access the ability name
    #[allow(unused)]
    let ability_str = unsafe {
        if !casting_data.ability.is_null() && !(*casting_data.ability).name.is_null() {
            GameString::read_from_ptr((*casting_data.ability).name as u64)
        } else {
            String::from("unknown_ability")
        }
    };

    // info!(
    //     "le_lib_ability_hook: Ability ID: {}, Name: {}, Mana Cost: {}, Instant Cast: {}",
    //     casting_data.ability_id, ability_str, casting_data.mana_cost, casting_data.instant_cast
    // );

    if FORCE_INSTANT_CAST.contains(&casting_data.ability_id) {
        // info!(
        //     "le_lib_ability_hook: Setting instant cast for ability ID {}",
        //     casting_data.ability_id
        // );
        CastingData::set_instant_cast_from_ptr(registers.rax);
        on_skill_used(&ability_str);
        //set_r8(registers_ptr, 0x1);
        //let registers2 = Registers::from_saved_pointer(registers_ptr);
        //info!("registers.r8: {} vs {}", registers.r8, registers2.r8);
    }
}
