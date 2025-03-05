mod modules;

use std::io;
use anyhow::{Result, Context};
use modules::system_uuid::SystemUuidSpoofer;
use modules::memory_devices::MemoryDevicesSpoofer;
use modules::monitor_edid::MonitorEdidSpoofer;
use modules::system_reg::SystemRegSpoofer;
use std::io::Write;
use winreg::enums::*;
use winreg::RegKey;

/// Main entry point for the Roblox HWID Spoofer application.
///
/// This application provides functionality to spoof various hardware identifiers
/// to help avoid hardware bans. It requires administrator privileges to work properly.
///
/// # Errors
///
/// Returns an error if any spoofer operations fail.
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
                run_system_uuid_spoofer().context("Failed to spoof System UUID")?;
                wait_to_continue()?;
            },
            3 => {
                println!("\n[-] Running Memory Devices Spoofer");
                run_memory_devices_spoofer().context("Failed to spoof Memory Devices")?;
                wait_to_continue()?;
            },
            4 => {
                println!("\n[-] Running Monitor EDID Spoofer");
                run_monitor_edid_spoofer().context("Failed to spoof Monitor EDID")?;
                wait_to_continue()?;
            },
            5 => {
                println!("\n[-] Running System Registry Spoofer");
                run_system_reg_spoofer().context("Failed to spoof System Registry")?;
                wait_to_continue()?;
            },
            6 => {
                println!("\n[+] Exiting...");
                break;
            },
            _ => println!("[!] Invalid option, please try again."),
        }
    }
    
    Ok(())
}

/// Displays the main menu and gets user selection.
///
/// # Returns
///
/// A `Result` containing the selected menu option as u32.
///
/// # Errors
///
/// Returns an error if reading user input fails.
fn show_menu() -> Result<u32> {
    println!("\n≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡");
    println!("                    MAIN MENU                          ");
    println!("≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡");
    println!("[1] Spoof All");
    println!("[2] Spoof System UUID");
    println!("[3] Spoof Memory Devices");
    println!("[4] Spoof Monitor EDID");
    println!("[5] Spoof System Registry");
    println!("[6] Exit");
    println!("≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡");
    
    print!("Enter choice [1-6]: ");
    io::stdout().flush().unwrap();
    
    let mut choice = String::new();
    io::stdin().read_line(&mut choice).context("Failed to read user input")?;
    
    Ok(choice.trim().parse::<u32>().unwrap_or(0))
}

/// Executes all spoofing operations sequentially.
///
/// # Returns
///
/// A `Result` indicating whether all spoofing operations were successful.
///
/// # Errors
///
/// Returns an error if any spoofing operation fails.
fn spoof_all() -> Result<()> {
    println!("\n[-] Running ALL Spoofers");
    
    println!("\n[1/4] Running System UUID Spoofer");
    run_system_uuid_spoofer().context("Failed to spoof System UUID")?;
    
    println!("\n[2/4] Running Memory Devices Spoofer");
    run_memory_devices_spoofer().context("Failed to spoof Memory Devices")?;
    
    println!("\n[3/4] Running Monitor EDID Spoofer");
    run_monitor_edid_spoofer().context("Failed to spoof Monitor EDID")?;
    
    println!("\n[4/4] Running System Registry Spoofer");
    run_system_reg_spoofer().context("Failed to spoof System Registry")?;
    
    println!("\n[+] All spoofing operations completed successfully.");
    
    wait_to_continue()?;
    Ok(())
}

/// Sets up the main configuration in the registry.
///
/// Creates necessary registry keys and values for the application to function.
///
/// # Returns
///
/// A `Result` indicating whether the configuration was set up successfully.
///
/// # Errors
///
/// Returns an error if registry operations fail.
fn setup_main_config() -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = "SOFTWARE\\RobloxHWIDSpoofer";
    
    let (key, disp) = hkcu
        .create_subkey(path)
        .context("Failed to create or open registry key")?;
    
    // Only set default values if the key was newly created
    if disp == REG_CREATED_NEW_KEY {
        key.set_value("FirstRun", &1u32)
            .context("Failed to set FirstRun registry value")?;
        println!("[+] First run detected, configured default settings");
    }
    
    Ok(())
}

/// Waits for user input to continue.
///
/// # Returns
///
/// A `Result` indicating whether the operation was successful.
///
/// # Errors
///
/// Returns an error if reading user input fails.
fn wait_to_continue() -> Result<()> {
    print!("\nPress enter to continue...");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).context("Failed to read user input")?;
    Ok(())
}

/// Checks if the program is running with administrator privileges.
///
/// # Returns
///
/// A boolean indicating whether the program has admin rights.
fn is_running_as_admin() -> bool {
    use std::process::Command;
    
    // Try to execute a command that requires admin privileges
    // If it works, we're running as admin
    match Command::new("cmd.exe")
        .args(&["/C", "net session >nul 2>&1"])
        .output()
    {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Waits for user to press a key before exiting.
///
/// Used when the program cannot continue due to lack of admin privileges.
fn wait_for_exit() {
    println!("\nPress any key to exit...");
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
}

/// Prints the application banner/logo.
fn print_banner() {
    println!("
██████╗  ██████╗ ██████╗ ██╗      ██████╗ ██╗  ██╗    ██╗  ██╗██╗    ██╗██╗██████╗     ███████╗██████╗  ██████╗  ██████╗ ███████╗███████╗██████╗ 
██╔══██╗██╔═══██╗██╔══██╗██║     ██╔═══██╗╚██╗██╔╝    ██║  ██║██║    ██║██║██╔══██╗    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗
██████╔╝██║   ██║██████╔╝██║     ██║   ██║ ╚███╔╝     ███████║██║ █╗ ██║██║██║  ██║    ███████╗██████╔╝██║   ██║██║   ██║█████╗  █████╗  ██████╔╝
██╔══██╗██║   ██║██╔══██╗██║     ██║   ██║ ██╔██╗     ██╔══██║██║███╗██║██║██║  ██║    ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██╔══██╗
██║  ██║╚██████╔╝██████╔╝███████╗╚██████╔╝██╔╝ ██╗    ██║  ██║╚███╔███╔╝██║██████╔╝    ███████║██║     ╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝╚═════╝     ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝
    ");
}

/// Runs the System UUID spoofing operation.
///
/// # Returns
///
/// A `Result` indicating whether the operation was successful.
///
/// # Errors
///
/// Returns an error if the spoofing operation fails.
fn run_system_uuid_spoofer() -> Result<()> {
    SystemUuidSpoofer::run()
}

/// Runs the Memory Devices spoofing operation.
///
/// # Returns
///
/// A `Result` indicating whether the operation was successful.
///
/// # Errors
///
/// Returns an error if the spoofing operation fails.
fn run_memory_devices_spoofer() -> Result<()> {
    MemoryDevicesSpoofer::run()
}

/// Runs the Monitor EDID spoofing operation.
///
/// # Returns
///
/// A `Result` indicating whether the operation was successful.
///
/// # Errors
///
/// Returns an error if the spoofing operation fails.
fn run_monitor_edid_spoofer() -> Result<()> {
    MonitorEdidSpoofer::run()
}

/// Runs the System Registry spoofing operation.
///
/// # Returns
///
/// A `Result` indicating whether the operation was successful.
///
/// # Errors
///
/// Returns an error if the spoofing operation fails.
fn run_system_reg_spoofer() -> Result<()> {
    SystemRegSpoofer::run()
}
