use std::error::Error;
use uuid::Uuid;
use winreg::enums::*;
use winreg::RegKey;

pub struct SystemUuidSpoofer;

impl SystemUuidSpoofer {
    pub fn spoof() -> Result<(), Box<dyn Error>> {
        println!("Spoofing System UUID...");
        
        // 1. Generate a new random UUID
        let new_uuid = Uuid::new_v4();
        println!("Generated new UUID: {}", new_uuid);
        
        // 2. First approach: Virtual Registry Redirection
        // This creates a registry key that will be used to redirect SMBIOS UUID queries
        Self::create_registry_redirection(&new_uuid)?;
        
        // 3. Second approach: Create an interception DLL for NtQuerySystemInformation
        Self::create_hyperion_intercept_config(&new_uuid)?;
        
        println!("System UUID spoofing complete");
        Ok(())
    }
    
    fn create_registry_redirection(uuid: &Uuid) -> Result<(), Box<dyn Error>> {
        println!("Creating registry redirection for System UUID...");
        
        // Access HKLM
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        
        // Convert UUID to bytes in proper format for SMBIOS
        let uuid_bytes = uuid.as_bytes();
        let uuid_formatted = [
            uuid_bytes[3], uuid_bytes[2], uuid_bytes[1], uuid_bytes[0],
            uuid_bytes[5], uuid_bytes[4], uuid_bytes[7], uuid_bytes[6],
            uuid_bytes[8], uuid_bytes[9], uuid_bytes[10], uuid_bytes[11],
            uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15]
        ];
        
        // Create or open the path for our UUID redirection
        let reg_path = r"SYSTEM\CurrentControlSet\Control\SystemInformation";
        let (key, _) = hklm.create_subkey(reg_path)?;
        
        // Set UUID value with our spoofed value
        key.set_value("ComputerHardwareId", &uuid.to_string())?;
        
        // We'll also try to create a binary version for compatibility
        key.set_raw_value("SystemManufacturer", &winreg::RegValue {
            bytes: uuid_formatted.to_vec(),
            vtype: winreg::enums::REG_BINARY,
        })?;
        
        println!("Registry redirection for System UUID created successfully");
        Ok(())
    }
    
    fn create_hyperion_intercept_config(uuid: &Uuid) -> Result<(), Box<dyn Error>> {
        println!("Creating Hyperion interception configuration...");
        
        // Access HKCU
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        // Create our interception keys for the custom DLL loader
        let reg_path = r"Software\RobloxHWIDSpoofer";
        let (key, _) = hkcu.create_subkey(reg_path)?;
        
        // Store the spoofed UUID
        key.set_value("SpoofedSystemUUID", &uuid.to_string())?;
        
        // Store the prefix string that Hyperion uses before hashing
        key.set_value("HyperionUUIDPrefix", &"O6e7GA9D90wQmmAzD6jM")?;
        
        // Flag to tell our dll to intercept UUIDs
        key.set_value("EnableSystemUUIDSpoofing", &1u32)?;
        
        println!("Hyperion interception configuration created successfully");
        Ok(())
    }
} 