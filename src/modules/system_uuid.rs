use std::error::Error;
use uuid::Uuid;
use winreg::enums::*;
use winreg::RegKey;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

pub struct SystemUuidSpoofer;

impl SystemUuidSpoofer {
    pub fn spoof() -> Result<(), Box<dyn Error>> {
        println!("Spoofing System UUID...");
        
        
        let current_uuid = Self::get_current_system_uuid()?;
        println!("Current system UUID: {}", current_uuid);
        
        
        let new_uuid = Uuid::new_v4();
        println!("Generated new system UUID: {}", new_uuid);
        
        
        Self::set_spoofed_uuid(&new_uuid)?;
        
        
        Self::create_uuid_intercept_config(&current_uuid, &new_uuid)?;
        
        println!("System UUID spoofing complete");
        Ok(())
    }
    
    fn get_current_system_uuid() -> Result<Uuid, Box<dyn Error>> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let info_key = hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\SystemInformation")?;
        
        let uuid_string: String = info_key.get_value("ComputerHardwareId")?;
        let uuid = Uuid::parse_str(&uuid_string)?;
        
        Ok(uuid)
    }
    
    fn set_spoofed_uuid(uuid: &Uuid) -> Result<(), Box<dyn Error>> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let info_key = hklm.open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Control\SystemInformation",
            KEY_SET_VALUE
        )?;
        
        info_key.set_value("ComputerHardwareId", &uuid.to_string())?;
        
        Ok(())
    }
    
    fn create_uuid_intercept_config(original_uuid: &Uuid, spoofed_uuid: &Uuid) -> Result<(), Box<dyn Error>> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        
        let (uuid_key, _) = hkcu.create_subkey(r"Software\Microsoft\DeviceManagement\SystemIdentifiers")?;
        
        
        uuid_key.set_value("OriginalIdentifier", &original_uuid.to_string())?;
        uuid_key.set_value("SystemIdentifier", &spoofed_uuid.to_string())?;
        
        
        uuid_key.set_value("IdentifierPrefix", &"B5x2T8nP6kQz7mJy3wRe")?;
        
        
        let parent_key = hkcu.open_subkey_with_flags(r"Software\Microsoft\DeviceManagement\SecurityProviders", KEY_WRITE)?;
        parent_key.set_value("EnableIdentifierProtection", &1u32)?;
        
        println!("UUID interception configuration created successfully");
        Ok(())
    }
} 