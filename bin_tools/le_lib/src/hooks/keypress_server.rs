use lazy_static::lazy_static;
use log::info;
use std::sync::{RwLock, RwLockWriteGuard};

const KEYPRESS_COOLDOWN: f32 = 0.2;
const SERVER_BASE: &str = "http://192.168.88.38:8766";
lazy_static! {
    static ref LAST_KEYPRESS: RwLock<f32> = RwLock::new(0.0);
    static ref LAST_POTION: RwLock<f32> = RwLock::new(0.0);
}

pub fn is_on_cooldown(cooldown: f32, mut cooldown_value: RwLockWriteGuard<f32>) -> bool {
    let last_keypress = *cooldown_value;
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f32();
    if current_time - last_keypress < cooldown {
        *cooldown_value = current_time;
        return true;
    }
    false
}

pub fn on_skill_used(skill_name: &str) {
    // use reqwest
    if is_on_cooldown(KEYPRESS_COOLDOWN, LAST_KEYPRESS.write().unwrap()) {
        return;
    }
    let url = format!("{}/skill/{}", SERVER_BASE, skill_name);
    match reqwest::blocking::get(&url) {
        Ok(response) => {
            if response.status().is_success() {
                // info!("Successfully sent keypress for skill: {}", skill_name);
            } else {
                info!(
                    "Failed to send keypress for skill: {}. Status: {}",
                    skill_name,
                    response.status()
                );
            }
        }
        Err(e) => {
            info!(
                "Error sending keypress for skill: {}. Error: {}",
                skill_name, e
            );
        }
    }
}

#[derive(serde::Serialize)]
struct LowHealthRequest {
    health: f32,
    max_health: f32,
}

pub fn on_low_health(health: f32, max_health: f32) {
    if is_on_cooldown(0.1, LAST_POTION.write().unwrap()) {
        return;
    }
    let url = format!("{}/low_health", SERVER_BASE);
    let request = LowHealthRequest { health, max_health };

    match reqwest::blocking::Client::new()
        .post(&url)
        .json(&request)
        .send()
    {
        Ok(response) => {
            if response.status().is_success() {
            } else {
                info!(
                    "Failed to send low health data. Status: {}",
                    response.status()
                );
            }
        }
        Err(e) => {
            info!("Error sending low health data. Error: {}", e);
        }
    }
}

#[derive(serde::Serialize)]
struct PotionsUpdate {
    charges: u32,
    max_charges: u32,
}

pub fn on_potions_update(charges: u32, max_charges: u32) {
    let url = format!("{}/potions", SERVER_BASE);
    let request = PotionsUpdate {
        charges,
        max_charges,
    };

    match reqwest::blocking::Client::new()
        .post(&url)
        .json(&request)
        .send()
    {
        Ok(response) => {
            if response.status().is_success() {
            } else {
                info!(
                    "Failed to send potions update. Status: {}",
                    response.status()
                );
            }
        }
        Err(e) => {
            info!("Error sending potions update. Error: {}", e);
        }
    }
}
