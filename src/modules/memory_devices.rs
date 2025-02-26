use std::error::Error;
use rand::{distributions::Alphanumeric, Rng};
use winreg::enums::*;
use winreg::RegKey;
use rand::seq::SliceRandom;

pub struct MemoryDevicesSpoofer;

impl MemoryDevicesSpoofer {
    pub fn spoof() -> Result<(), Box<dyn Error>> {
        println!("Spoofing Memory Device Information...");
        
        // Generate random serial numbers for memory devices
        let mut rng = rand::thread_rng();
        let random_serials: Vec<String> = (0..4)
            .map(|_| {
                // Generate a realistic looking memory serial
                // Most memory serials are alphanumeric with some specific patterns
                let manufacturers = ["HX", "CM", "KG", "CT", "F4", "TD"];
                let manufacturer = *manufacturers.choose(&mut rng).unwrap();
                
                // 12-16 alphanumeric characters after manufacturer code
                let serial_part = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(12)
                    .map(char::from)
                    .collect::<String>();
                
                format!("{}{}", manufacturer, serial_part)
            })
            .collect();
            
        println!("Generated new memory serials: {:?}", random_serials);
        
        // Store the spoofed memory information in registry for our interceptor
        Self::setup_memory_device_spoofing(&random_serials)?;
        
        // Create WMI query interceptor configuration
        Self::setup_wmi_intercept(&random_serials)?;
        
        println!("Memory device information spoofing complete");
        Ok(())
    }
    
    fn setup_memory_device_spoofing(serials: &[String]) -> Result<(), Box<dyn Error>> {
        println!("Setting up memory device spoofing configuration...");
        
        // Access HKCU
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        // Create our interception keys
        let reg_path = r"Software\RobloxHWIDSpoofer\MemoryDevices";
        let (key, _) = hkcu.create_subkey(reg_path)?;
        
        // Store each serial in the registry
        for (i, serial) in serials.iter().enumerate() {
            key.set_value(&format!("Serial{}", i), serial)?;
        }
        
        // Store the number of memory devices
        key.set_value("DeviceCount", &(serials.len() as u32))?;
        
        // Store the prefix Hyperion uses for memory device hashing
        key.set_value("HyperionMemoryPrefix", &"IZwIkbqUBIqYN2Un2duD")?;
        
        // Enable memory device spoofing
        let parent_key = hkcu.open_subkey_with_flags(r"Software\RobloxHWIDSpoofer", KEY_WRITE)?;
        parent_key.set_value("EnableMemoryDeviceSpoofing", &1u32)?;
        
        println!("Memory device spoofing configuration created successfully");
        Ok(())
    }
    
    fn setup_wmi_intercept(serials: &[String]) -> Result<(), Box<dyn Error>> {
        println!("Setting up WMI query interception for memory devices...");
        
        // Since WMI queries are complex to intercept directly, we'll set up registry values
        // that our injected DLL will use to respond to WMI queries
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        
        // Create fake memory device entries
        let reg_path = r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0";
        let (key, _) = hklm.create_subkey(reg_path)?;
        
        // Manufacturers commonly seen
        let manufacturers = ["Kingston", "Corsair", "G.Skill", "Crucial", "HyperX"];
        let mut rng = rand::thread_rng();
        let manufacturer = manufacturers.choose(&mut rng).unwrap();
        
        key.set_value("SerialNumber", &serials[0])?;
        key.set_value("Identifier", &format!("{} RAM {}", manufacturer, serials[0]))?;
        
        println!("WMI interception for memory devices configured");
        Ok(())
    }
} 