use std::error::Error;
use rand::{distributions::Alphanumeric, Rng};
use winreg::enums::*;
use winreg::RegKey;
use rand::seq::SliceRandom;

pub struct MemoryDevicesSpoofer;

impl MemoryDevicesSpoofer {
    pub fn spoof() -> Result<(), Box<dyn Error>> {
        println!("Spoofing Memory Device Information...");
        
        
        let mut rng = rand::thread_rng();
        let random_serials: Vec<String> = (0..4)
            .map(|_| {
                
                
                let manufacturers = ["HX", "CM", "KG", "CT", "F4", "TD"];
                let manufacturer = *manufacturers.choose(&mut rng).unwrap();
                
                
                let serial_part = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(12)
                    .map(char::from)
                    .collect::<String>();
                
                format!("{}{}", manufacturer, serial_part)
            })
            .collect();
            
        println!("Generated new memory serials: {:?}", random_serials);
        
        
        Self::setup_memory_device_spoofing(&random_serials)?;
        
        
        Self::setup_wmi_intercept(&random_serials)?;
        
        println!("Memory device information spoofing complete");
        Ok(())
    }
    
    fn setup_memory_device_spoofing(serials: &[String]) -> Result<(), Box<dyn Error>> {
        println!("Setting up memory device spoofing configuration...");
        
        
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        
        let reg_path = r"Software\RobloxHWIDSpoofer\MemoryDevices";
        let (key, _) = hkcu.create_subkey(reg_path)?;
        
        
        for (i, serial) in serials.iter().enumerate() {
            key.set_value(&format!("Serial{}", i), serial)?;
        }
        
        
        key.set_value("DeviceCount", &(serials.len() as u32))?;
        
        
        key.set_value("HyperionMemoryPrefix", &"IZwIkbqUBIqYN2Un2duD")?;
        
        
        let parent_key = hkcu.open_subkey_with_flags(r"Software\RobloxHWIDSpoofer", KEY_WRITE)?;
        parent_key.set_value("EnableMemoryDeviceSpoofing", &1u32)?;
        
        println!("Memory device spoofing configuration created successfully");
        Ok(())
    }
    
    fn setup_wmi_intercept(serials: &[String]) -> Result<(), Box<dyn Error>> {
        println!("Setting up WMI query interception for memory devices...");
        
        
        
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        
        
        let reg_path = r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0";
        let (key, _) = hklm.create_subkey(reg_path)?;
        
        
        let manufacturers = ["Kingston", "Corsair", "G.Skill", "Crucial", "HyperX"];
        let mut rng = rand::thread_rng();
        let manufacturer = manufacturers.choose(&mut rng).unwrap();
        
        key.set_value("SerialNumber", &serials[0])?;
        key.set_value("Identifier", &format!("{} RAM {}", manufacturer, serials[0]))?;
        
        println!("WMI interception for memory devices configured");
        Ok(())
    }
} 