use std::error::Error;
use std::fmt;
use std::ptr::null_mut;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use rand::Rng;
use winapi::um::winnt::{HANDLE, TOKEN_QUERY, TOKEN_USER, PSID, SID_NAME_USE};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::winbase::LookupAccountSidW;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::handleapi::CloseHandle;
use winapi::shared::minwindef::{DWORD, BYTE};
use winreg::enums::*;
use winreg::RegKey;
use winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER;

#[derive(Debug)]
struct CustomError(String);

impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for CustomError {}

pub struct SystemRegSpoofer;

impl SystemRegSpoofer {
    pub fn spoof() -> Result<(), Box<dyn Error>> {
        println!("Spoofing Roblox-specific SystemReg Registry Value...");
        
        // Get the current user's SID
        let sid = Self::get_current_user_sid()?;
        println!("Current user SID: {}", sid);
        
        // Target the specific registry path with null terminator
        let registry_path = format!(r"{}\System\CurrentControlSet\Control", sid);
        
        // Create spoofed value for SystemReg
        let spoofed_data = Self::generate_random_data();
        
        // Back up the original value if it exists
        Self::backup_original_value(&registry_path)?;
        
        // Set the new spoofed value
        Self::set_special_registry_value(&registry_path, &spoofed_data)?;
        
        // Create interception configuration
        Self::create_intercept_config(&sid, &spoofed_data)?;
        
        println!("SystemReg spoofing complete");
        Ok(())
    }
    
    fn get_current_user_sid() -> Result<String, Box<dyn Error>> {
        // Open handle to current process token
        let mut token_handle: HANDLE = null_mut();
        unsafe {
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
                return Err(Box::new(CustomError("Failed to open process token".into())));
            }
        }
        
        // First call to get buffer size
        let mut token_info_len: DWORD = 0;
        unsafe {
            GetTokenInformation(
                token_handle,
                winapi::um::winnt::TokenUser,
                null_mut(),
                0,
                &mut token_info_len
            );
        }
        
        // Allocate buffer and get token information
        let mut buffer: Vec<BYTE> = vec![0; token_info_len as usize];
        let success = unsafe {
            GetTokenInformation(
                token_handle,
                winapi::um::winnt::TokenUser,
                buffer.as_mut_ptr() as *mut _,
                token_info_len,
                &mut token_info_len
            )
        };
        
        if success == 0 {
            unsafe { CloseHandle(token_handle) };
            return Err(Box::new(CustomError("Failed to get token information".into())));
        }
        
        // Get SID from token information
        let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
        let sid = token_user.User.Sid;
        
        // Convert SID to string
        let sid_string = Self::sid_to_string(sid)?;
        
        // Clean up
        unsafe { CloseHandle(token_handle) };
        
        Ok(sid_string)
    }
    
    fn sid_to_string(sid: PSID) -> Result<String, Box<dyn Error>> {
        let mut name_buffer: Vec<u16> = vec![0; 256];
        let mut domain_buffer: Vec<u16> = vec![0; 256];
        let mut name_size: DWORD = name_buffer.len() as DWORD;
        let mut domain_size: DWORD = domain_buffer.len() as DWORD;
        let mut sid_type: SID_NAME_USE = 0;
        
        let success = unsafe {
            LookupAccountSidW(
                null_mut(),
                sid,
                name_buffer.as_mut_ptr(),
                &mut name_size,
                domain_buffer.as_mut_ptr(),
                &mut domain_size,
                &mut sid_type
            )
        };
        
        if success == 0 {
            return Err(Box::new(CustomError("Failed to lookup account SID".into())));
        }
        
        let name = OsString::from_wide(&name_buffer[0..name_size as usize]);
        let domain = OsString::from_wide(&domain_buffer[0..domain_size as usize]);
        
        Ok(format!("{}\\{}", domain.to_string_lossy(), name.to_string_lossy()))
    }
    
    fn generate_random_data() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut data = Vec::new();
        
        // Generate 32-64 random bytes
        let length = rng.gen_range(32..64);
        
        for _ in 0..length {
            data.push(rng.gen::<u8>());
        }
        
        data
    }
    
    fn backup_original_value(registry_path: &str) -> Result<(), Box<dyn Error>> {
        println!("Backing up original SystemReg value if exists...");
        
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        // Try to open the key
        let _control_key = match hkcu.open_subkey_with_flags(registry_path, KEY_READ) {
            Ok(key) => key,
            Err(_) => {
                println!("  No existing key found to backup");
                return Ok(());
            }
        };
        
        // See if we can read the SystemReg value
        let value_data: Result<Vec<u8>, _> = unsafe {
            // We need to use unsafe win32 API to read a null-prefixed value name
            let mut handle = std::mem::zeroed();
            let path_utf16: Vec<u16> = registry_path.encode_utf16().chain(std::iter::once(0)).collect();
            
            let res = winapi::um::winreg::RegOpenKeyExW(
                HKEY_CURRENT_USER,
                path_utf16.as_ptr(),
                0,
                KEY_READ,
                &mut handle,
            );
            
            if res != 0 {
                return Err(Box::new(CustomError(format!("Failed to open registry key: {}", res))));
            }
            
            // The SystemReg value has a null byte at the start
            let name = vec![0, 83, 121, 115, 116, 101, 109, 82, 101, 103, 0]; // "\0SystemReg"
            
            let mut data_type = 0;
            let mut data_size = 0;
            
            // First call to get size
            let res = winapi::um::winreg::RegQueryValueExA(
                handle,
                name.as_ptr() as *const i8,
                std::ptr::null_mut(),
                &mut data_type,
                std::ptr::null_mut(),
                &mut data_size,
            );
            
            if res != 0 && res != ERROR_INSUFFICIENT_BUFFER as i32 {
                winapi::um::winreg::RegCloseKey(handle);
                return Err(Box::new(CustomError(format!("Failed to query value size: {}", res))));
            }
            
            // Allocate buffer and get data
            let mut buffer = vec![0u8; data_size as usize];
            let res = winapi::um::winreg::RegQueryValueExA(
                handle,
                name.as_ptr() as *const i8,
                std::ptr::null_mut(),
                &mut data_type,
                buffer.as_mut_ptr(),
                &mut data_size,
            );
            
            winapi::um::winreg::RegCloseKey(handle);
            
            if res != 0 {
                Err(std::io::Error::from_raw_os_error(res))
            } else {
                Ok(buffer)
            }
        };
        
        // If successful, store the backup
        match value_data {
            Ok(data) => {
                println!("  Found existing SystemReg value, backing up {} bytes of data", data.len());
                
                // Store backup in our config
                let (config_key, _) = hkcu.create_subkey(r"Software\RobloxHWIDSpoofer\SystemReg")?;
                config_key.set_raw_value("OriginalData", &winreg::RegValue {
                    bytes: data,
                    vtype: REG_BINARY,
                })?;
                
                config_key.set_value("HasBackup", &1u32)?;
            },
            Err(e) => {
                println!("  No existing SystemReg value found or error reading: {}", e);
            }
        }
        
        Ok(())
    }
    
    fn set_special_registry_value(registry_path: &str, data: &[u8]) -> Result<(), Box<dyn Error>> {
        println!("Setting spoofed SystemReg value with null terminator...");
        
        // We need to use unsafe win32 API to write a null-prefixed value name
        unsafe {
            let mut handle = std::mem::zeroed();
            let path_utf16: Vec<u16> = registry_path.encode_utf16().chain(std::iter::once(0)).collect();
            
            let res = winapi::um::winreg::RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path_utf16.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                KEY_WRITE | KEY_READ,
                std::ptr::null_mut(),
                &mut handle,
                std::ptr::null_mut(),
            );
            
            if res != 0 {
                return Err(Box::new(CustomError(format!("Failed to create registry key: {}", res))));
            }
            
            // The SystemReg value has a null byte at the start
            let name = vec![0, 83, 121, 115, 116, 101, 109, 82, 101, 103, 0]; // "\0SystemReg"
            
            // Set the value - Fix: Use the constant value for REG_BINARY (3)
            let res = winapi::um::winreg::RegSetValueExA(
                handle,
                name.as_ptr() as *const i8,
                0,
                3, // REG_BINARY value
                data.as_ptr(),
                data.len() as u32,
            );
            
            winapi::um::winreg::RegCloseKey(handle);
            
            if res != 0 {
                return Err(Box::new(CustomError(format!("Failed to set registry value: {}", res))));
            }
        }
        
        println!("  Successfully set spoofed SystemReg value");
        Ok(())
    }
    
    fn create_intercept_config(sid: &str, spoofed_data: &[u8]) -> Result<(), Box<dyn Error>> {
        println!("Creating interception configuration for SystemReg...");
        
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        
        // Create our interception keys
        let (spoof_key, _) = hkcu.create_subkey(r"Software\RobloxHWIDSpoofer\SystemReg")?;
        
        // Store the SID - Fix: Add borrow operator to convert &str to &String
        spoof_key.set_value("UserSID", &sid.to_string())?;
        
        // Store our spoofed data
        spoof_key.set_raw_value("SpoofedData", &winreg::RegValue {
            bytes: spoofed_data.to_vec(),
            vtype: REG_BINARY,
        })?;
        
        // Store the Hyperion prefix string
        spoof_key.set_value("HyperionSystemRegPrefix", &"eOj7IvEHtbPqBn5MLun2")?;
        
        // Enable SystemReg spoofing in main config
        let parent_key = hkcu.open_subkey_with_flags(r"Software\RobloxHWIDSpoofer", KEY_WRITE)?;
        parent_key.set_value("EnableSystemRegSpoofing", &1u32)?;
        
        println!("SystemReg interception configuration created successfully");
        Ok(())
    }
} 