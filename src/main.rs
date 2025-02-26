mod modules;

use std::io::{self, Write};
use std::error::Error;
use modules::system_uuid::SystemUuidSpoofer;
use modules::memory_devices::MemoryDevicesSpoofer;
use modules::monitor_edid::MonitorEdidSpoofer;
use modules::system_reg::SystemRegSpoofer;
use winapi::um::winnt::{TOKEN_QUERY, TOKEN_ELEVATION};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::shared::minwindef::DWORD;
use winapi::um::securitybaseapi::GetTokenInformation;
use std::time::Duration;
use std::thread;
use winreg::enums::*;
use winreg::RegKey;

fn main() -> Result<(), Box<dyn Error>> {
    print_banner();
    
    
    if !is_running_as_admin() {
        println!("[ERROR] This program must be run with Administrator privileges!");
        println!("Please right-click and select 'Run as Administrator'");
        wait_for_exit();
        return Ok(());
    }
    
    
    setup_main_config()?;
    
    println!("\n[+] Beginning HWID spoofing sequence...");
    
    
    let spoofers = [
        ("System UUID", run_system_uuid_spoofer as fn() -> Result<(), Box<dyn Error>>),
        ("Memory Devices", run_memory_devices_spoofer as fn() -> Result<(), Box<dyn Error>>),
        ("Monitor EDID", run_monitor_edid_spoofer as fn() -> Result<(), Box<dyn Error>>),
        ("System Registry", run_system_reg_spoofer as fn() -> Result<(), Box<dyn Error>>),
    ];
    
    for (name, spoofer_fn) in spoofers.iter() {
        println!("\n[-] Running {} Spoofer", name);
        
        match spoofer_fn() {
            Ok(_) => println!("[+] {} Spoofing Successful", name),
            Err(e) => println!("[!] {} Spoofing Failed: {}", name, e),
        }
        
        
        thread::sleep(Duration::from_millis(500));
    }
    
    println!("\n[+] HWID spoofing complete! Your hardware identifiers have been modified.");
    println!("[*] Roblox will now detect different hardware identifiers on this machine.");
    println!("[*] Remember that spoofed IDs persist across reboots but may reset with Windows updates.");
    
    wait_for_exit();
    Ok(())
}

fn setup_main_config() -> Result<(), Box<dyn Error>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    
    
    let (config_key, _) = hkcu.create_subkey(r"Software\Microsoft\DeviceManagement\SecurityProviders")?;
    
    
    let prev_run: Option<u32> = config_key.get_value("ConfigVersion").ok();
    
    if let Some(version) = prev_run {
        println!("[*] Detected previous configuration (version {})", version);
    } else {
        println!("[*] First-time setup detected, creating new configuration");
        config_key.set_value("ConfigVersion", &1u32)?;
        config_key.set_value("SetupDate", &chrono::Local::now().to_rfc3339())?;
    }
    
    Ok(())
}

fn is_running_as_admin() -> bool {
    use winapi::um::securitybaseapi::AllocateAndInitializeSid;
    use winapi::um::securitybaseapi::CheckTokenMembership;
    use winapi::um::winnt::{SECURITY_NT_AUTHORITY, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS};
    use winapi::um::winnt::SID_IDENTIFIER_AUTHORITY;
    
    unsafe {
        let mut authority = SID_IDENTIFIER_AUTHORITY {
            Value: SECURITY_NT_AUTHORITY
        };
        let mut sid = std::ptr::null_mut();
        
        let result = AllocateAndInitializeSid(
            &mut authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &mut sid
        );
        
        if result == 0 {
            return false;
        }
        
        let mut is_member = 0;
        let member_check = CheckTokenMembership(std::ptr::null_mut(), sid, &mut is_member);
        
        winapi::um::securitybaseapi::FreeSid(sid);
        
        member_check != 0 && is_member != 0
    }
}

fn wait_for_exit() {
    println!("\nPress Enter to exit...");
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
}

fn print_banner() {
    println!("╔═════════════════════════════════════════════════╗");
    println!("║                                                 ║");
    println!("║  Hardware ID Spoofer Tool for Windows           ║");
    println!("║  Version 0.1.0                                  ║");
    println!("║                                                 ║");
    println!("║  [Security Notice]                              ║");
    println!("║  This tool modifies system registry values.     ║");
    println!("║  Use at your own risk. For educational          ║");
    println!("║  purposes only.                                 ║");
    println!("║                                                 ║");
    println!("╚═════════════════════════════════════════════════╝");
    println!("");
}

fn run_system_uuid_spoofer() -> Result<(), Box<dyn Error>> {
    SystemUuidSpoofer::spoof()
}

fn run_memory_devices_spoofer() -> Result<(), Box<dyn Error>> {
    MemoryDevicesSpoofer::spoof()
}

fn run_monitor_edid_spoofer() -> Result<(), Box<dyn Error>> {
    MonitorEdidSpoofer::spoof()
}

fn run_system_reg_spoofer() -> Result<(), Box<dyn Error>> {
    SystemRegSpoofer::spoof()
}
