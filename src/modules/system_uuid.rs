use anyhow::{Result, Context};
use uuid::Uuid;
use winreg::enums::*;
use winreg::RegKey;

/// Handles spoofing of the system UUID/GUID to prevent hardware fingerprinting
pub struct SystemUuidSpoofer;

impl SystemUuidSpoofer {
    /// Main entry point for system UUID spoofing
    /// Generates a random UUID and applies it to system registry
    pub fn spoof() -> Result<()> {
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
        
        println!("System UUID spoofing complete");
        Ok(())
    }
}

/// Retrieves the current system UUID from the registry
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

/// Sets the spoofed UUID in the registry to replace the original one
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

/// Creates configuration entries for UUID interception mechanism
/// Stores both original and spoofed UUIDs for reference
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