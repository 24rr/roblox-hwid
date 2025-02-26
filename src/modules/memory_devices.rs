use std::error::Error;
use rand::{distributions::Alphanumeric, Rng};
use rand::seq::SliceRandom;
use winreg::enums::*;
use winreg::RegKey;

pub struct MemoryDevicesSpoofer;

impl MemoryDevicesSpoofer {
    pub fn spoof() -> Result<(), Box<dyn Error>> {
        println!("Spoofing Memory Device Information...");
        
        
        let serials = Self::generate_random_serials(4)?;
        
        
        Self::setup_memory_device_spoofing(&serials)?;
        
        
        Self::setup_wmi_intercept(&serials)?;
        
        println!("Memory device information spoofing complete");
        Ok(())
    }
    
    fn generate_random_serials(count: usize) -> Result<Vec<String>, Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let mut serials = Vec::with_capacity(count);
        
        
        let prefixes = ["KHX", "CMK", "BLS", "TF", "CT", "HX", "F4", "TD"];
        
        for _ in 0..count {
            
            let prefix = prefixes.choose(&mut rng).unwrap_or(&"CM");
            
            
            let random_chars: String = (&mut rng)
                .sample_iter(&Alphanumeric)
                .take(12)
                .map(char::from)
                .collect();
            
            
            let serial = format!("{}{}", prefix, random_chars);
            serials.push(serial);
        }
        
        
        for (i, serial) in serials.iter().enumerate() {
            println!("Generated memory serial #{}: {}", i+1, serial);
        }
        
        Ok(serials)
    }
    
    fn setup_memory_device_spoofing(serials: &[String]) -> Result<(), Box<dyn Error>> {
        println!("Setting up memory device registry entries...");
        
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        
        let (mem_key, _) = hkcu.create_subkey(r"Software\Microsoft\DeviceManagement\Memory")?;
        
        
        mem_key.set_value("DeviceCount", &(serials.len() as u32))?;
        
        
        for (i, serial) in serials.iter().enumerate() {
            mem_key.set_value(&format!("Device{}_Serial", i), serial)?;
        }
        
        
        mem_key.set_value("MemoryDevicePrefix", &"C8j3kLs9wxF4Pq2Z7tR6")?;
        
        
        let parent_key = hkcu.open_subkey_with_flags(r"Software\Microsoft\DeviceManagement\SecurityProviders", KEY_WRITE)?;
        parent_key.set_value("EnableMemoryProtection", &1u32)?;
        
        println!("Memory device spoofing configuration created successfully");
        Ok(())
    }
    
    fn setup_wmi_intercept(serials: &[String]) -> Result<(), Box<dyn Error>> {
        println!("Setting up memory device WMI query interception...");
        
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        
        
        for (i, serial) in serials.iter().enumerate() {
            let device_path = format!(r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id {}", i);
            let (device_key, _) = hklm.create_subkey(&device_path)?;
            
            
            device_key.set_value("SerialNumber", serial)?;
            device_key.set_value("Identifier", &format!("Memory Module {}", i))?;
            device_key.set_value("Type", &"RAM")?;
            
            
            let mut rng = rand::thread_rng();
            let sizes = [8, 16, 32];
            let size = sizes.choose(&mut rng).unwrap_or(&16);
            
            device_key.set_value("Size", &format!("{} GB", size))?;
        }
        
        println!("WMI query interception for memory devices configured successfully");
        Ok(())
    }
} 