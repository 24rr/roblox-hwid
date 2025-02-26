mod modules;

use std::io;
use anyhow::{Result, Context};
use modules::system_uuid::SystemUuidSpoofer;
use modules::memory_devices::MemoryDevicesSpoofer;
use modules::monitor_edid::MonitorEdidSpoofer;
use modules::system_reg::SystemRegSpoofer;
use std::time::Duration;
use std::thread;
use winreg::enums::*;
use winreg::RegKey;

fn main() -> Result<()> {
    print_banner();
    
    if !is_running_as_admin() {
        println!("[ERROR] This program must be run with Administrator privileges!");
        println!("Please right-click and select 'Run as Administrator'");
        wait_for_exit();
        return Ok(());
    }
    
    setup_main_config().context("Failed to setup main configuration")?;
    
    loop {
        match show_menu().context("Failed to display menu")? {
            1 => spoof_all().context("Failed to spoof all hardware IDs")?,
            2 => {
                println!("\n[-] Running System UUID Spoofer");
                run_system_uuid_spoofer()
                    .map(|_| println!("[+] System UUID Spoofing Successful"))
                    .unwrap_or_else(|e| println!("[!] System UUID Spoofing Failed: {}", e));
                wait_to_continue().context("Failed to wait for user input")?;
            },
            3 => {
                println!("\n[-] Running Memory Devices Spoofer");
                run_memory_devices_spoofer()
                    .map(|_| println!("[+] Memory Devices Spoofing Successful"))
                    .unwrap_or_else(|e| println!("[!] Memory Devices Spoofing Failed: {}", e));
                wait_to_continue().context("Failed to wait for user input")?;
            },
            4 => {
                println!("\n[-] Running Monitor EDID Spoofer");
                run_monitor_edid_spoofer()
                    .map(|_| println!("[+] Monitor EDID Spoofing Successful"))
                    .unwrap_or_else(|e| println!("[!] Monitor EDID Spoofing Failed: {}", e));
                wait_to_continue().context("Failed to wait for user input")?;
            },
            5 => {
                println!("\n[-] Running System Registry Spoofer");
                run_system_reg_spoofer()
                    .map(|_| println!("[+] System Registry Spoofing Successful"))
                    .unwrap_or_else(|e| println!("[!] System Registry Spoofing Failed: {}", e));
                wait_to_continue().context("Failed to wait for user input")?;
            },
            6 => {
                println!("\nExiting. Hardware ID Spoofer closed.");
                break;
            },
            _ => println!("Invalid option. Please enter a number between 1 and 6."),
        }
    }
    
    Ok(())
}

fn show_menu() -> Result<u32> {
    println!("\n==== Hardware ID Spoofer Menu ====");
    println!("1. Spoof All Hardware IDs");
    println!("2. Spoof System UUID only");
    println!("3. Spoof Memory Devices only");
    println!("4. Spoof Monitor EDID only");
    println!("5. Spoof System Registry only");
    println!("6. Exit");
    println!("\nEnter your choice (1-6): ");
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).context("Failed to read user input")?;
    
    let parsed = input.trim().parse::<u32>().unwrap_or(0);
    Ok(parsed)
}

fn spoof_all() -> Result<()> {
    println!("\n[+] Beginning HWID spoofing sequence...");
    
    let spoofers = [
        ("System UUID", run_system_uuid_spoofer as fn() -> Result<()>),
        ("Memory Devices", run_memory_devices_spoofer as fn() -> Result<()>),
        ("Monitor EDID", run_monitor_edid_spoofer as fn() -> Result<()>),
        ("System Registry", run_system_reg_spoofer as fn() -> Result<()>),
    ];
    
    spoofers.iter().for_each(|(name, spoofer_fn)| {
        println!("\n[-] Running {} Spoofer", name);
        
        spoofer_fn()
            .map(|_| println!("[+] {} Spoofing Successful", name))
            .unwrap_or_else(|e| println!("[!] {} Spoofing Failed: {}", name, e));
        
        thread::sleep(Duration::from_millis(500));
    });
    
    println!("\n[+] HWID spoofing complete! Your hardware identifiers have been modified.");
    println!("[*] Roblox will now detect different hardware identifiers on this machine.");
    println!("[*] Remember that spoofed IDs persist across reboots but may reset with Windows updates.");
    
    wait_to_continue().context("Failed to wait for user input")?;
    Ok(())
}

fn setup_main_config() -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    
    let (config_key, _) = hkcu.create_subkey(r"Software\Microsoft\DeviceManagement\SecurityProviders")
        .context("Failed to create config registry key")?;
    
    let prev_run: Option<u32> = config_key.get_value("ConfigVersion").ok();
    
    if let Some(version) = prev_run {
        println!("[*] Detected previous configuration (version {})", version);
    } else {
        println!("[*] First-time setup detected, creating new configuration");
        config_key.set_value("ConfigVersion", &1u32)
            .context("Failed to set ConfigVersion registry value")?;
        config_key.set_value("SetupDate", &chrono::Local::now().to_rfc3339())
            .context("Failed to set SetupDate registry value")?;
    }
    
    Ok(())
}

fn wait_to_continue() -> Result<()> {
    println!("\nPress Enter to continue...");
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).context("Failed to read user input")?;
    
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
        
        // Initialize SID
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
        
        // Check if user is a member of the admin group
        let mut is_member = 0;
        let member_check = CheckTokenMembership(std::ptr::null_mut(), sid, &mut is_member);
        
        // Free allocated SID
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
    println!("║  Hardware ID Spoofer Tool for Roblox            ║");
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

fn run_system_uuid_spoofer() -> Result<()> {
    SystemUuidSpoofer::spoof().context("System UUID spoofing failed")
}

fn run_memory_devices_spoofer() -> Result<()> {
    MemoryDevicesSpoofer::spoof().context("Memory devices spoofing failed")
}

fn run_monitor_edid_spoofer() -> Result<()> {
    MonitorEdidSpoofer::spoof().context("Monitor EDID spoofing failed")
}

fn run_system_reg_spoofer() -> Result<()> {
    SystemRegSpoofer::spoof().context("System registry spoofing failed")
}
