use std::error::Error;
use uuid::Uuid;
use winreg::enums::*;
use winreg::RegKey;

pub struct SystemUuidSpoofer;

impl SystemUuidSpoofer {
    pub fn spoof() -> Result<(), Box<dyn Error>> {
        println!("Spoofing System UUID...");
        
        
        let new_uuid = Uuid::new_v4();
        println!("Generated new UUID: {}", new_uuid);
        
        
        
        Self::create_registry_redirection(&new_uuid)?;
        
        
        Self::create_hyperion_intercept_config(&new_uuid)?;
        
        println!("System UUID spoofing complete");
        Ok(())
    }
    
    fn create_registry_redirection(uuid: &Uuid) -> Result<(), Box<dyn Error>> {
        println!("Creating registry redirection for System UUID...");
        
        
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        
        
        let uuid_bytes = uuid.as_bytes();
        let uuid_formatted = [
            uuid_bytes[3], uuid_bytes[2], uuid_bytes[1], uuid_bytes[0],
            uuid_bytes[5], uuid_bytes[4], uuid_bytes[7], uuid_bytes[6],
            uuid_bytes[8], uuid_bytes[9], uuid_bytes[10], uuid_bytes[11],
            uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15]
        ];
        
        
        let reg_path = r"SYSTEM\CurrentControlSet\Control\SystemInformation";
        let (key, _) = hklm.create_subkey(reg_path)?;
        
        
        key.set_value("ComputerHardwareId", &uuid.to_string())?;
        
        
        key.set_raw_value("SystemManufacturer", &winreg::RegValue {
            bytes: uuid_formatted.to_vec(),
            vtype: winreg::enums::REG_BINARY,
        })?;
        
        println!("Registry redirection for System UUID created successfully");
        Ok(())
    }
    
    fn create_hyperion_intercept_config(uuid: &Uuid) -> Result<(), Box<dyn Error>> {
        println!("Creating Hyperion interception configuration...");
        
        
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        
        let reg_path = r"Software\RobloxHWIDSpoofer";
        let (key, _) = hkcu.create_subkey(reg_path)?;
        
        
        key.set_value("SpoofedSystemUUID", &uuid.to_string())?;
        
        
        key.set_value("HyperionUUIDPrefix", &"O6e7GA9D90wQmmAzD6jM")?;
        
        
        key.set_value("EnableSystemUUIDSpoofing", &1u32)?;
        
        println!("Hyperion interception configuration created successfully");
        Ok(())
    }
} 