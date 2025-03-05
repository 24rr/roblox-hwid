use anyhow::{Result, Context};
use rand::{distributions::Alphanumeric, Rng};
use rand::seq::SliceRandom;
use winreg::enums::*;
use winreg::RegKey;

/// Handles spoofing of memory devices information (RAM) to prevent hardware fingerprinting.
///
/// Memory devices such as RAM modules have unique serial numbers that can be used
/// to identify a computer. This module generates realistic but fake serial numbers
/// and manufacturer information to help avoid hardware bans.
pub struct MemoryDevicesSpoofer;

impl MemoryDevicesSpoofer {
    /// Main entry point for memory device spoofing.
    ///
    /// This method performs the following operations:
    /// 1. Generates random serial numbers for memory modules
    /// 2. Sets up registry entries for memory device spoofing
    /// 3. Adds detailed memory device information with realistic manufacturer details
    ///
    /// # Returns
    ///
    /// A `Result` indicating whether the operation was successful.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the spoofing steps fail.
    pub fn run() -> Result<()> {
        println!("Spoofing Memory Device Information...");
        
        let serials = generate_random_serials(4)
            .context("Failed to generate random serials")?;
        
        setup_memory_device_spoofing(&serials)
            .context("Failed to setup memory device spoofing")?;
        
        setup_memory_device_info(&serials)
            .context("Failed to setup memory device info")?;
        
        println!("[+] Memory device information spoofing complete");
        Ok(())
    }
}

/// Creates a set of random memory module serial numbers with realistic manufacturer prefixes.
///
/// This function generates serial numbers that mimic those used by actual RAM manufacturers,
/// starting with recognizable prefixes like "KHX" for Kingston HyperX, "CMK" for Corsair, etc.
///
/// # Arguments
///
/// * `count` - The number of serial numbers to generate
///
/// # Returns
///
/// A `Result` containing a vector of generated serial numbers.
///
/// # Errors
///
/// Returns an error if the generation process fails for any reason.
fn generate_random_serials(count: usize) -> Result<Vec<String>> {
    let mut rng = rand::thread_rng();
    let mut serials = Vec::with_capacity(count);
    
    // Common memory manufacturer prefixes
    let prefixes = ["KHX", "CMK", "BLS", "TF", "CT", "HX", "F4", "TD"];
    
    (0..count).for_each(|_| {
        let prefix = prefixes.choose(&mut rng).unwrap_or(&"CM");
        
        let random_chars: String = (&mut rng)
            .sample_iter(&Alphanumeric)
            .take(12)
            .map(char::from)
            .collect();
        
        let serial = format!("{}{}", prefix, random_chars);
        serials.push(serial);
    });
    
    serials.iter().enumerate().for_each(|(i, serial)| {
        println!("Generated memory serial #{}: {}", i+1, serial);
    });
    
    Ok(serials)
}

/// Configures registry entries for memory device spoofing.
///
/// This function creates registry entries that will be used to intercept and modify
/// memory device information queries from applications trying to identify the system.
///
/// # Arguments
///
/// * `serials` - A slice of serial number strings to use for memory devices
///
/// # Returns
///
/// A `Result` indicating whether the operation was successful.
///
/// # Errors
///
/// Returns an error if any registry operations fail.
fn setup_memory_device_spoofing(serials: &[String]) -> Result<()> {
    println!("Setting up memory device registry entries...");
    
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    
    let (mem_key, _) = hkcu.create_subkey(r"Software\Microsoft\DeviceManagement\Memory")
        .context("Failed to create memory registry key")?;
    
    mem_key.set_value("DeviceCount", &(serials.len() as u32))
        .context("Failed to set DeviceCount registry value")?;
    
    serials.iter().enumerate().try_for_each(|(i, serial)| {
        mem_key.set_value(&format!("Device{}_Serial", i), serial)
            .context(format!("Failed to set Device{}_Serial registry value", i))
    })?;
    
    mem_key.set_value("MemoryDevicePrefix", &"C8j3kLs9wxF4Pq2Z7tR6")
        .context("Failed to set MemoryDevicePrefix registry value")?;
    
    let parent_key = hkcu.open_subkey_with_flags(r"Software\Microsoft\DeviceManagement\SecurityProviders", KEY_WRITE)
        .context("Failed to open security providers registry key with write access")?;
    parent_key.set_value("EnableMemoryProtection", &1u32)
        .context("Failed to set EnableMemoryProtection registry value")?;
    
    println!("Memory device spoofing configuration created successfully");
    Ok(())
}

/// Sets up detailed memory device information with realistic manufacturer details.
///
/// This function creates registry entries containing detailed information about
/// each memory module, including manufacturer, capacity, and speed.
///
/// # Arguments
///
/// * `serials` - A slice of serial number strings to use for memory devices
///
/// # Returns
///
/// A `Result` indicating whether the operation was successful.
///
/// # Errors
///
/// Returns an error if any registry operations fail.
fn setup_memory_device_info(serials: &[String]) -> Result<()> {
    println!("Setting up memory device information...");
    
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    
    let (memory_info_key, _) = hkcu.create_subkey(r"Software\Microsoft\DeviceManagement\MemoryInfo")
        .context("Failed to create memory info registry key")?;
    
    // List of common memory manufacturers
    let manufacturers = ["Kingston", "Corsair", "G.Skill", "Crucial", "HyperX"];
    let mut rng = rand::thread_rng();
    
    serials.iter().enumerate().try_for_each(|(i, serial)| -> Result<()> {
        let manufacturer = manufacturers.choose(&mut rng).unwrap_or(&"Kingston");
        let sizes = [8, 16, 32];
        let size = sizes.choose(&mut rng).unwrap_or(&16);
        
        let (device_key, _) = memory_info_key.create_subkey(&format!("Device{}", i))
            .context(format!("Failed to create Device{} registry key", i))?;
        
        device_key.set_value("SerialNumber", serial)
            .context("Failed to set SerialNumber registry value")?;
        device_key.set_value("Manufacturer", manufacturer)
            .context("Failed to set Manufacturer registry value")?;
        device_key.set_value("Capacity", &format!("{} GB", size))
            .context("Failed to set Capacity registry value")?;
        device_key.set_value("Speed", &format!("{} MHz", 1600 + (rng.gen::<u16>() % 2400)))
            .context("Failed to set Speed registry value")?;
        device_key.set_value("DeviceLocator", &format!("DIMM{}", i))
            .context("Failed to set DeviceLocator registry value")?;
        
        Ok(())
    })?;
    
    println!("Memory device information setup successfully");
    Ok(())
} 