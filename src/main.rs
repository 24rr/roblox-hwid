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

fn main() -> Result<(), Box<dyn Error>> {
    print_banner();
    
    if !is_admin() {
        println!("WARNING: This application requires administrator privileges to function properly.");
        println!("Please run this application as administrator.");
        println!("Press Enter to continue anyway (some features may not work)...");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
    }
    
    println!("Roblox HWID Spoofer - Bypass Hyperion Alt Detection");
    println!("--------------------------------------------------");
    println!("This tool will spoof hardware identifiers used by Roblox Hyperion");
    println!("to detect alt accounts. Use at your own risk.\n");
    
    loop {
        match show_menu()? {
            1 => spoof_all()?,
            2 => spoof_system_uuid()?,
            3 => spoof_memory_devices()?,
            4 => spoof_monitor_edid()?,
            5 => spoof_system_reg()?,
            6 => {
                println!("\nExiting HWID Spoofer. Goodbye!");
                break;
            },
            _ => println!("Invalid option. Please try again."),
        }
    }
    
    Ok(())
}

fn is_admin() -> bool {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    
    let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut size: DWORD = std::mem::size_of::<TOKEN_ELEVATION>() as DWORD;
    
    let result = unsafe {
        GetTokenInformation(
            token,
            winapi::um::winnt::TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size
        )
    };
    
    if result == 0 {
        return false;
    }
    
    elevation.TokenIsElevated != 0
}

fn print_banner() {
    println!("
+-----------------------------------------------+
|                                               |
|          ROBLOX HWID SPOOFER v1.0             |
|     Bypass Hyperion Alt Detection System      |
|                                               |
+-----------------------------------------------+
");
}

fn show_menu() -> Result<u32, Box<dyn Error>> {
    println!("\nSelect an option:");
    println!("1. Spoof All Hardware IDs");
    println!("2. Spoof System UUID only");
    println!("3. Spoof Memory Devices only");
    println!("4. Spoof Monitor EDID only");
    println!("5. Spoof SystemReg only");
    println!("6. Exit");
    
    print!("\nEnter your choice (1-6): ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    match input.trim().parse() {
        Ok(choice) => Ok(choice),
        Err(_) => Ok(0),
    }
}

fn spoof_all() -> Result<(), Box<dyn Error>> {
    println!("\nSpoofing all hardware identifiers...");
    
    
    spoof_system_uuid()?;
    spoof_memory_devices()?;
    spoof_monitor_edid()?;
    spoof_system_reg()?;
    
    println!("\nAll hardware identifiers spoofed successfully!");
    println!("You can now launch Roblox with reduced risk of Hyperion alt detection.");
    
    
    print!("\nPress Enter to return to menu...");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    Ok(())
}

fn spoof_system_uuid() -> Result<(), Box<dyn Error>> {
    println!("\n🔧 Spoofing System UUID...");
    SystemUuidSpoofer::spoof()?;
    println!("✅ System UUID spoofed successfully!");
    Ok(())
}

fn spoof_memory_devices() -> Result<(), Box<dyn Error>> {
    println!("\n🔧 Spoofing Memory Devices...");
    MemoryDevicesSpoofer::spoof()?;
    println!("✅ Memory Devices spoofed successfully!");
    Ok(())
}

fn spoof_monitor_edid() -> Result<(), Box<dyn Error>> {
    println!("\n🔧 Spoofing Monitor EDID...");
    MonitorEdidSpoofer::spoof()?;
    println!("✅ Monitor EDID spoofed successfully!");
    Ok(())
}

fn spoof_system_reg() -> Result<(), Box<dyn Error>> {
    println!("\n🔧 Spoofing SystemReg...");
    SystemRegSpoofer::spoof()?;
    println!("✅ SystemReg spoofed successfully!");
    Ok(())
}
