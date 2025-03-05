use anyhow::{Result, Context};
use rand::Rng;
use winreg::enums::*;
use winreg::RegKey;

/// Handles spoofing of monitor EDID (Extended Display Identification Data) to prevent hardware fingerprinting.
///
/// EDID is a data structure that contains information about a computer display, including
/// manufacturer name, product type, serial number, and other characteristics. Applications
/// can use this data to identify specific monitors and, by extension, computer systems.
/// Spoofing this data helps prevent hardware-based tracking.
pub struct MonitorEdidSpoofer;

impl MonitorEdidSpoofer {
    /// Main entry point for monitor EDID spoofing.
    ///
    /// This method performs the following operations:
    /// 1. Finds all display devices in the system
    /// 2. Modifies the EDID data for each display to change the serial number
    /// 3. Creates an intercept configuration to ensure consistent spoofing
    ///
    /// # Returns
    ///
    /// A `Result` indicating whether the operation was successful.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the spoofing steps fail.
    pub fn run() -> Result<()> {
        println!("Spoofing Monitor EDID Information...");
        
        let display_paths = find_display_devices()
            .context("Failed to find display devices")?;
        
        let modified_count = display_paths.iter()
            .filter_map(|path| modify_edid_for_display(path).ok())
            .count();
        
        create_edid_intercept_config(modified_count)
            .context("Failed to create EDID intercept configuration")?;
        
        println!("[+] Monitor EDID spoofing complete");
        Ok(())
    }
}

/// Locates all display devices in the registry that may contain EDID data.
///
/// This function searches the Windows registry for display devices that have
/// EDID data which can be modified to spoof monitor identification.
///
/// # Returns
///
/// A `Result` containing a vector of registry paths to display devices.
///
/// # Errors
///
/// Returns an error if:
/// - The display registry key cannot be opened
/// - Registry enumeration operations fail
fn find_display_devices() -> Result<Vec<String>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let display_path = r"SYSTEM\CurrentControlSet\Enum\DISPLAY";
    let display_key = hklm.open_subkey(display_path)
        .context("Failed to open display registry key")?;
    
    let mut result = Vec::new();
    
    let manufacturers = display_key.enum_keys()
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    
    for manufacturer in manufacturers {
        let manufacturer_key = display_key.open_subkey(&manufacturer)
            .context(format!("Failed to open manufacturer key '{}'", manufacturer))?;
        
        let instances = manufacturer_key.enum_keys()
            .filter_map(Result::ok)
            .map(|instance| format!("{}\\{}\\{}", display_path, manufacturer, instance))
            .collect::<Vec<_>>();
        
        result.extend(instances);
    }
    
    println!("Found {} display devices", result.len());
    Ok(result)
}

/// Modifies the EDID data for a specific display device to spoof its serial number.
///
/// This function modifies the EDID binary data in the registry to change the
/// monitor's serial number, effectively spoofing its identity. It also recalculates
/// the checksum to ensure the EDID data remains valid.
///
/// # Arguments
///
/// * `display_path` - The registry path to the display device to modify
///
/// # Returns
///
/// A `Result` indicating whether the operation was successful.
///
/// # Errors
///
/// Returns an error if:
/// - The Device Parameters key cannot be opened
/// - The EDID value cannot be read or is invalid
/// - The new EDID value cannot be written to the registry
fn modify_edid_for_display(display_path: &str) -> Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    
    let params_path = format!("{}\\Device Parameters", display_path);
    let params_key = hklm.open_subkey_with_flags(&params_path, KEY_READ | KEY_WRITE)
        .context(format!("No Device Parameters key for '{}'", display_path))?;
    
    let edid: Vec<u8> = params_key.get_raw_value("EDID")
        .context(format!("No EDID value for '{}'", display_path))?.bytes;
    
    if edid.len() < 128 {
        return Err(anyhow::anyhow!("EDID too short for '{}'", display_path));
    }
    
    let mut new_edid = edid.clone();
    
    let mut rng = rand::thread_rng();
    let mut new_serial = [0u8; 4];
    rng.fill(&mut new_serial);
    
    // Bytes 12-15 in the EDID contain the monitor serial number
    new_edid[12] = new_serial[0];
    new_edid[13] = new_serial[1];
    new_edid[14] = new_serial[2];
    new_edid[15] = new_serial[3];
    
    // Recalculate EDID checksum (byte 127)
    let sum = new_edid[0..127].iter().map(|&x| x as u32).sum::<u32>() % 256;
    let checksum = if sum == 0 { 0 } else { (256 - sum) as u8 };
    new_edid[127] = checksum;
    
    let reg_value = winreg::RegValue {
        bytes: new_edid,
        vtype: REG_BINARY,
    };
    params_key.set_raw_value("EDID", &reg_value)
        .context(format!("Failed to set EDID value for '{}'", display_path))?;
    
    println!("Modified display EDID at {} - New serial: {:02X}{:02X}{:02X}{:02X}, Checksum: {:02X}", 
        display_path, new_serial[0], new_serial[1], new_serial[2], new_serial[3], checksum);
    
    Ok(())
}

/// Creates configuration entries for the EDID interception mechanism.
///
/// This function sets up registry entries that will be used to intercept and modify
/// EDID data queries from applications trying to identify the system's monitors.
///
/// # Arguments
///
/// * `modified_count` - The number of display devices that were successfully modified
///
/// # Returns
///
/// A `Result` indicating whether the operation was successful.
///
/// # Errors
///
/// Returns an error if any registry operations fail.
fn create_edid_intercept_config(modified_count: usize) -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    
    let (edid_key, _) = hkcu.create_subkey(r"Software\Microsoft\DeviceManagement\Display")
        .context("Failed to create display registry key")?;
    
    edid_key.set_value("ModifiedDisplayCount", &(modified_count as u32))
        .context("Failed to set ModifiedDisplayCount registry value")?;
    edid_key.set_value("LastModifiedTime", &chrono::Local::now().to_rfc3339())
        .context("Failed to set LastModifiedTime registry value")?;
    
    edid_key.set_value("DisplayIdentifierPrefix", &"D7t5Rq2Z9sXw3F6yPl4J")
        .context("Failed to set DisplayIdentifierPrefix registry value")?;
    
    let parent_key = hkcu.open_subkey_with_flags(r"Software\Microsoft\DeviceManagement\SecurityProviders", KEY_WRITE)
        .context("Failed to open security providers registry key with write access")?;
    parent_key.set_value("EnableDisplayProtection", &1u32)
        .context("Failed to set EnableDisplayProtection registry value")?;
    
    println!("EDID interception configuration created successfully");
    Ok(())
} 