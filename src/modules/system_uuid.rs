use anyhow::{Result, Context};
use uuid::Uuid;
use winreg::enums::*;
use winreg::RegKey;

/// Handles spoofing of the system UUID/GUID to prevent hardware fingerprinting.
///
/// The system UUID is a unique identifier that is often used by software applications
/// to identify specific hardware. By spoofing this value, we can help prevent tracking
/// and potentially avoid hardware bans.
pub struct SystemUuidSpoofer;

impl SystemUuidSpoofer {
    /// Main entry point for system UUID spoofing.
    ///
    /// This method performs the following operations:
    /// 1. Retrieves the current system UUID
    /// 2. Generates a new random UUID
    /// 3. Sets the new UUID in the system registry
    /// 4. Creates an intercept configuration to ensure consistent spoofing
    ///
    /// # Returns
    ///
    /// A `Result` indicating whether the operation was successful.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the spoofing steps fail.
    pub fn run() -> Result<()> {
        println!("Spoofing System UUID...");
        
        let current_uuid = get_current_system_uuid()
            .context("Failed to retrieve current system UUID")?;
        println!("Current system UUID: {}", current_uuid);
        
        let new_uuid = Uuid::new_v4();
        println!("Generated new system UUID: {}", new_uuid);
        
        set_spoofed_uuid(&new_uuid)
            .context("Failed to set spoofed UUID")?;
        
        create_uuid_intercept_config(&current_uuid, &new_uuid)
            .context("Failed to create UUID intercept configuration")?;
        
        println!("[+] System UUID spoofing complete");
        Ok(())
    }
}

/// Retrieves the current system UUID from the registry.
///
/// This function reads the ComputerHardwareId value from the system registry
/// and parses it into a Uuid object.
///
/// # Returns
///
/// A `Result` containing the current system UUID.
///
/// # Errors
///
/// Returns an error if:
/// - The registry key could not be opened
/// - The ComputerHardwareId value could not be read
/// - The UUID string could not be parsed
fn get_current_system_uuid() -> Result<Uuid> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let info_key = hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\SystemInformation")
        .context("Failed to open system information registry key")?;
    
    let uuid_string: String = info_key.get_value("ComputerHardwareId")
        .context("Failed to read ComputerHardwareId value")?;
    let uuid = Uuid::parse_str(&uuid_string)
        .context("Failed to parse UUID string")?;
    
    Ok(uuid)
}

/// Sets the spoofed UUID in the registry to replace the original one.
///
/// # Arguments
///
/// * `uuid` - The new UUID to set in the registry
///
/// # Returns
///
/// A `Result` indicating whether the operation was successful.
///
/// # Errors
///
/// Returns an error if:
/// - The registry key could not be opened with write access
/// - The ComputerHardwareId value could not be set
fn set_spoofed_uuid(uuid: &Uuid) -> Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let info_key = hklm.open_subkey_with_flags(
        r"SYSTEM\CurrentControlSet\Control\SystemInformation",
        KEY_SET_VALUE
    ).context("Failed to open system information registry key with write access")?;
    
    info_key.set_value("ComputerHardwareId", &uuid.to_string())
        .context("Failed to set ComputerHardwareId registry value")?;
    
    Ok(())
}

/// Creates configuration entries for UUID interception mechanism.
///
/// This function stores both the original and spoofed UUIDs in the registry
/// for reference and sets up the necessary configuration for UUID interception.
///
/// # Arguments
///
/// * `original_uuid` - The original system UUID before spoofing
/// * `spoofed_uuid` - The new spoofed UUID
///
/// # Returns
///
/// A `Result` indicating whether the operation was successful.
///
/// # Errors
///
/// Returns an error if any registry operations fail.
fn create_uuid_intercept_config(original_uuid: &Uuid, spoofed_uuid: &Uuid) -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    
    let (uuid_key, _) = hkcu.create_subkey(r"Software\Microsoft\DeviceManagement\SystemIdentifiers")
        .context("Failed to create system identifiers registry key")?;
    
    uuid_key.set_value("OriginalIdentifier", &original_uuid.to_string())
        .context("Failed to set OriginalIdentifier registry value")?;
    uuid_key.set_value("SystemIdentifier", &spoofed_uuid.to_string())
        .context("Failed to set SystemIdentifier registry value")?;
    
    uuid_key.set_value("IdentifierPrefix", &"B5x2T8nP6kQz7mJy3wRe")
        .context("Failed to set IdentifierPrefix registry value")?;
    
    let parent_key = hkcu.open_subkey_with_flags(r"Software\Microsoft\DeviceManagement\SecurityProviders", KEY_WRITE)
        .context("Failed to open security providers registry key with write access")?;
    parent_key.set_value("EnableIdentifierProtection", &1u32)
        .context("Failed to set EnableIdentifierProtection registry value")?;
    
    println!("UUID interception configuration created successfully");
    Ok(())
} 