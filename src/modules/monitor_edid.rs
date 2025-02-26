use std::error::Error;
use rand::Rng;
use winreg::enums::*;
use winreg::RegKey;

pub struct MonitorEdidSpoofer;

impl MonitorEdidSpoofer {
    pub fn spoof() -> Result<(), Box<dyn Error>> {
        println!("Spoofing Monitor EDID Information...");
        
        
        let displays = Self::find_display_devices()?;
        
        if displays.is_empty() {
            println!("No display devices found in registry");
            return Ok(());
        }
        
        
        for display_path in displays {
            Self::modify_edid_for_display(&display_path)?;
        }
        
        
        Self::create_edid_intercept_config()?;
        
        println!("Monitor EDID spoofing complete");
        Ok(())
    }
    
    fn find_display_devices() -> Result<Vec<String>, Box<dyn Error>> {
        println!("Finding display devices in registry...");
        
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let display_enum = hklm.open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Enum\DISPLAY", KEY_READ)?;
        
        let mut display_paths = Vec::new();
        
        
        for device_type in display_enum.enum_keys().filter_map(Result::ok) {
            let device_type_key = display_enum.open_subkey_with_flags(&device_type, KEY_READ)?;
            
            
            for instance in device_type_key.enum_keys().filter_map(Result::ok) {
                let path = format!(r"SYSTEM\CurrentControlSet\Enum\DISPLAY\{}\{}", device_type, instance);
                display_paths.push(path);
            }
        }
        
        println!("Found {} display devices", display_paths.len());
        Ok(display_paths)
    }
    
    fn modify_edid_for_display(display_path: &str) -> Result<(), Box<dyn Error>> {
        println!("Modifying EDID for display at path: {}", display_path);
        
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let display_key = match hklm.open_subkey_with_flags(display_path, KEY_READ | KEY_WRITE) {
            Ok(key) => key,
            Err(e) => {
                println!("  Error accessing display key: {}", e);
                return Ok(());
            }
        };
        
        
        let device_params_key = match display_key.open_subkey_with_flags("Device Parameters", KEY_READ | KEY_WRITE) {
            Ok(key) => key,
            Err(e) => {
                println!("  No Device Parameters key found: {}", e);
                return Ok(());
            }
        };
        
        
        let edid_data: Vec<u8> = match device_params_key.get_raw_value("EDID") {
            Ok(value) => value.bytes,
            Err(e) => {
                println!("  No EDID data found: {}", e);
                return Ok(());
            }
        };
        
        if edid_data.len() < 128 {
            println!("  EDID data is too short: {} bytes", edid_data.len());
            return Ok(());
        }
        
        
        
        let mut new_edid = edid_data.clone();
        
        
        let new_serial: Vec<u8> = (0..4).map(|_| rand::thread_rng().gen::<u8>()).collect();
        
        
        new_edid[0x0C] = new_serial[0];
        new_edid[0x0D] = new_serial[1];
        new_edid[0x0E] = new_serial[2];
        new_edid[0x0F] = new_serial[3];
        
        
        let sum = new_edid[0..127].iter().map(|&x| x as u32).sum::<u32>() % 256;
        let checksum = if sum == 0 { 0 } else { (256 - sum) as u8 };
        new_edid[127] = checksum;
        
        println!("  Generated new EDID with serial: {:02X}{:02X}{:02X}{:02X}, checksum: {:02X}",
            new_serial[0], new_serial[1], new_serial[2], new_serial[3], checksum);
        
        
        device_params_key.set_raw_value("EDID", &winreg::RegValue {
            bytes: new_edid,
            vtype: REG_BINARY,
        })?;
        
        
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (spoof_key, _) = hkcu.create_subkey(r"Software\RobloxHWIDSpoofer\MonitorEDID")?;
        
        
        let display_count: u32 = spoof_key.get_value("DisplayCount").unwrap_or(0);
        spoof_key.set_value(&format!("DisplayPath{}", display_count), &display_path)?;
        
        
        spoof_key.set_raw_value(&format!("OriginalSerial{}", display_count), &winreg::RegValue {
            bytes: edid_data[0x0C..=0x0F].to_vec(),
            vtype: REG_BINARY,
        })?;
        
        spoof_key.set_raw_value(&format!("NewSerial{}", display_count), &winreg::RegValue {
            bytes: new_serial.clone(),
            vtype: REG_BINARY,
        })?;
        
        
        spoof_key.set_value("DisplayCount", &(display_count + 1))?;
        
        println!("  Successfully modified EDID for display at path: {}", display_path);
        Ok(())
    }
    
    fn create_edid_intercept_config() -> Result<(), Box<dyn Error>> {
        println!("Creating EDID interception configuration...");
        
        
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        
        let (key, _) = hkcu.create_subkey(r"Software\RobloxHWIDSpoofer")?;
        
        
        key.set_value("HyperionEDIDPrefix", &"0LaUoAv5C6K5n1JciQzY")?;
        
        
        key.set_value("EnableEDIDSpoofing", &1u32)?;
        
        println!("EDID interception configuration created successfully");
        Ok(())
    }
} 