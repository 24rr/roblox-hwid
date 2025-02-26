use std::error::Error;
use rand::Rng;
use rand::seq::IteratorRandom;
use winapi::um::winnt::PSID;
use winapi::um::winbase::LookupAccountSidW;
use winreg::enums::*;
use winreg::RegKey;
use std::ptr;

pub struct SystemRegSpoofer;

impl SystemRegSpoofer {
    pub fn spoof() -> Result<(), Box<dyn Error>> {
        println!("Spoofing System Registry Information...");
        
        
        let user_sid = Self::get_current_user_sid()?;
        println!("Current user SID: {}", user_sid);
        
        
        let random_data = Self::generate_random_data()?;
        println!("Generated random registry data ({} bytes)", random_data.len());
        
        
        Self::create_spoofed_registry(&user_sid, &random_data)?;
        
        println!("System registry information spoofing complete");
        Ok(())
    }
    
    fn get_current_user_sid() -> Result<String, Box<dyn Error>> {
        
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu.open_subkey("Software")?;
        
        
        let sid_str = Self::extract_sid_from_key(&key)?;
        
        Ok(sid_str)
    }
    
    fn extract_sid_from_key(key: &RegKey) -> Result<String, Box<dyn Error>> {
        
        let _handle = key.raw_handle();
        
        unsafe {
            
            let sid_ptr: PSID = ptr::null_mut();
            let mut sid_size: u32 = 0;
            let mut domain_name_size: u32 = 0;
            let mut name_use: u32 = 0;
            
            
            LookupAccountSidW(
                ptr::null(), 
                sid_ptr,
                ptr::null_mut(), 
                &mut sid_size,
                ptr::null_mut(), 
                &mut domain_name_size,
                &mut name_use
            );
            
            
            let sid_str = "S-1-5-21-".to_string() + 
                &rand::thread_rng().gen::<u32>().to_string() + "-" +
                &rand::thread_rng().gen::<u32>().to_string() + "-" +
                &rand::thread_rng().gen::<u32>().to_string() + "-" +
                &rand::thread_rng().gen_range(500..1000).to_string();
            
            Ok(sid_str)
        }
    }
    
    fn generate_random_data() -> Result<Vec<u8>, Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        
        
        let length = rng.gen_range(128..256);
        
        
        let mut data = Vec::with_capacity(length);
        
        
        data.extend_from_slice(&[0x53, 0x59, 0x53, 0x54, 0x45, 0x4D]); 
        
        
        for _ in 0..3 {
            let str_len = rng.gen_range(8..16);
            let chars: Vec<u8> = (0..str_len)
                .map(|_| rng.gen_range(65..91) as u8) 
                .collect();
            data.extend_from_slice(&chars);
            data.push(0); 
        }
        
        
        while data.len() < length {
            data.push(rng.gen());
        }
        
        Ok(data)
    }
    
    fn create_spoofed_registry(user_sid: &str, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        
        let (config_key, _) = hkcu.create_subkey(r"Software\Microsoft\DeviceManagement\Security")?;
        
        
        config_key.set_value("UserIdentifier", &user_sid.to_string())?;
        
        
        let reg_value = winreg::RegValue {
            bytes: data.to_vec(),
            vtype: REG_BINARY,
        };
        config_key.set_raw_value("SecurityData", &reg_value)?;
        
        
        let parent_key = hkcu.open_subkey_with_flags(r"Software\Microsoft\DeviceManagement\SecurityProviders", KEY_WRITE)?;
        parent_key.set_value("EnableSecurityDataProtection", &1u32)?;
        
        
        
        let names = ["SystemConfig", "SecurityProvider", "DeviceManager"];
        let mut rng = rand::thread_rng();
        let selected_name = names.iter().choose(&mut rng).unwrap_or(&"SystemConfig");
        
        let special_name = format!("{}\0Config", selected_name);
        
        
        let special_value = winreg::RegValue {
            bytes: data.to_vec(),
            vtype: REG_BINARY,
        };
        parent_key.set_raw_value(&special_name, &special_value)?;
        
        println!("System registry spoofing configuration created successfully");
        Ok(())
    }
} 