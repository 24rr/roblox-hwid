use anyhow::{Result, Context};
use rand::Rng;
use rand::seq::IteratorRandom;
use winapi::um::winnt::PSID;
use winapi::um::winbase::LookupAccountSidW;
use winreg::enums::*;
use winreg::RegKey;
use std::ptr;

/// Handles spoofing of system registry information to prevent hardware identification
pub struct SystemRegSpoofer;

impl SystemRegSpoofer {
    /// Main entry point for system registry spoofing
    /// Generates and applies random registry data to prevent tracking
    pub fn spoof() -> Result<()> {
        println!("Spoofing System Registry Information...");
        
        let user_sid = get_current_user_sid()
            .context("Failed to get current user SID")?;
        println!("Current user SID: {}", user_sid);
        
        let random_data = generate_random_data()
            .context("Failed to generate random data")?;
        println!("Generated random registry data ({} bytes)", random_data.len());
        
        create_spoofed_registry(&user_sid, &random_data)
            .context("Failed to create spoofed registry")?;
        
        println!("System registry information spoofing complete");
        Ok(())
    }
}

/// Retrieves or generates the current user's Security Identifier (SID)
fn get_current_user_sid() -> Result<String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu.open_subkey("Software")
        .context("Failed to open HKCU\\Software key")?;
    
    let sid_str = extract_sid_from_key(&key)
        .context("Failed to extract SID from registry key")?;
    
    Ok(sid_str)
}

/// Extracts SID information from registry key or generates a random one
fn extract_sid_from_key(_key: &RegKey) -> Result<String> {
    // Generate a random SID with format matching Windows security identifiers
    // This is outside the unsafe block since it doesn't use any unsafe code
    let mut rng = rand::thread_rng();
    let sid_str = format!(
        "S-1-5-21-{}-{}-{}-{}",
        rng.gen::<u32>(),
        rng.gen::<u32>(),
        rng.gen::<u32>(),
        rng.gen_range(500..1000)
    );
    
    // The unsafe block is only needed for the actual Windows API calls
    // We can make this a fallback instead of the primary approach
    
    // Attempt to get the real SID via Windows API (this might fail)
    let _real_sid = unsafe {
        let sid_ptr: PSID = ptr::null_mut();
        let mut sid_size: u32 = 0;
        let mut domain_name_size: u32 = 0;
        let mut name_use: u32 = 0;
        
        // Just query buffer sizes, this call is expected to fail
        LookupAccountSidW(
            ptr::null(), 
            sid_ptr,
            ptr::null_mut(), 
            &mut sid_size,
            ptr::null_mut(), 
            &mut domain_name_size,
            &mut name_use
        );
        
        // We're not actually using the real SID lookup results,
        // as we want to generate a fake one anyway
    };
    
    Ok(sid_str)
}

/// Generates random binary data for registry spoofing
fn generate_random_data() -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    
    let length = rng.gen_range(128..256);
    
    let mut data = Vec::with_capacity(length);
    
    // Start with "SYSTEM" signature bytes
    data.extend_from_slice(&[0x53, 0x59, 0x53, 0x54, 0x45, 0x4D]); 
    
    // Generate a few null-terminated random strings
    (0..3).for_each(|_| {
        let str_len = rng.gen_range(8..16);
        let chars: Vec<u8> = (0..str_len)
            .map(|_| rng.gen_range(65..91) as u8) 
            .collect();
        data.extend_from_slice(&chars);
        data.push(0); 
    });
    
    // Fill remaining space with random bytes
    while data.len() < length {
        data.push(rng.gen());
    }
    
    Ok(data)
}

/// Creates or updates registry keys with spoofed data
fn create_spoofed_registry(user_sid: &str, data: &[u8]) -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    
    // Create security configuration subkey
    let (config_key, _) = hkcu.create_subkey(r"Software\Microsoft\DeviceManagement\Security")
        .context("Failed to create security registry key")?;
    
    // Set user identifier value
    config_key.set_value("UserIdentifier", &user_sid.to_string())
        .context("Failed to set UserIdentifier registry value")?;
    
    // Set binary security data
    let reg_value = winreg::RegValue {
        bytes: data.to_vec(),
        vtype: REG_BINARY,
    };
    config_key.set_raw_value("SecurityData", &reg_value)
        .context("Failed to set SecurityData registry value")?;
    
    // Enable security data protection
    let parent_key = hkcu.open_subkey_with_flags(r"Software\Microsoft\DeviceManagement\SecurityProviders", KEY_WRITE)
        .context("Failed to open security providers registry key with write access")?;
    parent_key.set_value("EnableSecurityDataProtection", &1u32)
        .context("Failed to set EnableSecurityDataProtection registry value")?;
    
    // Select a random name for the special configuration
    let names = ["SystemConfig", "SecurityProvider", "DeviceManager"];
    let mut rng = rand::thread_rng();
    let selected_name = names.iter().choose(&mut rng).unwrap_or(&"SystemConfig");
    
    let special_name = format!("{}\0Config", selected_name);
    
    // Create the special binary value with null character in name (anti-forensic technique)
    let special_value = winreg::RegValue {
        bytes: data.to_vec(),
        vtype: REG_BINARY,
    };
    parent_key.set_raw_value(&special_name, &special_value)
        .context("Failed to set special registry value")?;
    
    println!("System registry spoofing configuration created successfully");
    Ok(())
}