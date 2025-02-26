use std::error::Error;
use rand::Rng;
use winreg::enums::*;
use winreg::RegKey;

pub struct MonitorEdidSpoofer;

impl MonitorEdidSpoofer {
    pub fn spoof() -> Result<(), Box<dyn Error>> {
        println!("Spoofing Monitor EDID Information...");
        
        
        let display_paths = Self::find_display_devices()?;
        
        
        let mut modified_count = 0;
        
        
        for display_path in display_paths {
            if let Ok(()) = Self::modify_edid_for_display(&display_path) {
                modified_count += 1;
            }
        }
        
        
        Self::create_edid_intercept_config(modified_count)?;
        
        println!("Monitor EDID spoofing complete");
        Ok(())
    }
    
    fn find_display_devices() -> Result<Vec<String>, Box<dyn Error>> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let display_path = r"SYSTEM\CurrentControlSet\Enum\DISPLAY";
        let display_key = hklm.open_subkey(display_path)?;
        
        let mut result = Vec::new();
        
        
        for manufacturer in display_key.enum_keys().map(|x| x.unwrap()) {
            let manufacturer_key = display_key.open_subkey(&manufacturer)?;
            
            
            for instance in manufacturer_key.enum_keys().map(|x| x.unwrap()) {
                let full_path = format!("{}\\{}\\{}", display_path, manufacturer, instance);
                result.push(full_path);
            }
        }
        
        println!("Found {} display devices", result.len());
        Ok(result)
    }
    
    fn modify_edid_for_display(display_path: &str) -> Result<(), Box<dyn Error>> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        
        
        let params_path = format!("{}\\Device Parameters", display_path);
        let params_key = match hklm.open_subkey_with_flags(&params_path, KEY_READ | KEY_WRITE) {
            Ok(key) => key,
            Err(_) => return Err("No Device Parameters key".into()),
        };
        
        
        let edid: Vec<u8> = match params_key.get_raw_value("EDID") {
            Ok(value) => value.bytes,
            Err(_) => return Err("No EDID value".into()),
        };
        
        
        if edid.len() < 128 {
            return Err("EDID too short".into());
        }
        
        
        let mut new_edid = edid.clone();
        
        
        let mut rng = rand::thread_rng();
        let mut new_serial = [0u8; 4];
        rng.fill(&mut new_serial);
        
        
        new_edid[12] = new_serial[0];
        new_edid[13] = new_serial[1];
        new_edid[14] = new_serial[2];
        new_edid[15] = new_serial[3];
        
        
        
        let sum = new_edid[0..127].iter().map(|&x| x as u32).sum::<u32>() % 256;
        let checksum = if sum == 0 { 0 } else { (256 - sum) as u8 };
        new_edid[127] = checksum;
        
        
        let reg_value = winreg::RegValue {
            bytes: new_edid,
            vtype: REG_BINARY,
        };
        params_key.set_raw_value("EDID", &reg_value)?;
        
        
        println!("Modified display EDID at {} - New serial: {:02X}{:02X}{:02X}{:02X}, Checksum: {:02X}", 
            display_path, new_serial[0], new_serial[1], new_serial[2], new_serial[3], checksum);
        
        Ok(())
    }
    
    fn create_edid_intercept_config(modified_count: usize) -> Result<(), Box<dyn Error>> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        
        let (edid_key, _) = hkcu.create_subkey(r"Software\Microsoft\DeviceManagement\Display")?;
        
        
        edid_key.set_value("ModifiedDisplayCount", &(modified_count as u32))?;
        edid_key.set_value("LastModifiedTime", &chrono::Local::now().to_rfc3339())?;
        
        
        edid_key.set_value("DisplayIdentifierPrefix", &"D7t5Rq2Z9sXw3F6yPl4J")?;
        
        
        let parent_key = hkcu.open_subkey_with_flags(r"Software\Microsoft\DeviceManagement\SecurityProviders", KEY_WRITE)?;
        parent_key.set_value("EnableDisplayProtection", &1u32)?;
        
        println!("EDID interception configuration created successfully");
        Ok(())
    }
} 