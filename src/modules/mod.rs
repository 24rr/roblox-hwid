/// This module contains the core spoofing implementations for various hardware identifiers
/// Each submodule handles a specific hardware component that needs spoofing to prevent tracking
/// 
/// All modules use anyhow for error handling and follow functional programming patterns where possible.
pub mod system_uuid;
pub mod memory_devices;
pub mod monitor_edid;
pub mod system_reg; 