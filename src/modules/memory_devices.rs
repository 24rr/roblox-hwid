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
        
        Self::setup_memory_device_info(&serials)?;
        
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
    
    fn setup_memory_device_info(serials: &[String]) -> Result<(), Box<dyn Error>> {
        println!("Setting up memory device information...");
        
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        let (memory_info_key, _) = hkcu.create_subkey(r"Software\Microsoft\DeviceManagement\MemoryInfo")?;
        
        let manufacturers = ["Kingston", "Corsair", "G.Skill", "Crucial", "HyperX"];
        let mut rng = rand::thread_rng();
        
        for (i, serial) in serials.iter().enumerate() {
            let manufacturer = manufacturers.choose(&mut rng).unwrap_or(&"Kingston");
            let sizes = [8, 16, 32];
            let size = sizes.choose(&mut rng).unwrap_or(&16);
            
            let (device_key, _) = memory_info_key.create_subkey(&format!("Device{}", i))?;
            
            device_key.set_value("SerialNumber", serial)?;
            device_key.set_value("Manufacturer", manufacturer)?;
            device_key.set_value("Capacity", &format!("{} GB", size))?;
            device_key.set_value("Speed", &format!("{} MHz", 1600 + (rng.gen::<u16>() % 2400)))?;
            device_key.set_value("DeviceLocator", &format!("DIMM{}", i))?;
        }
        
        println!("Memory device information setup successfully");
        Ok(())
    }
} 