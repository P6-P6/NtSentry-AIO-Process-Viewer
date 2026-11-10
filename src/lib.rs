//! Tamper detection and system inventory for a human defender.
//!
//! Scans are read-only: they never write to another process, change memory
//! protection, or restore bytes. They produce [`findings::Finding`]s that are
//! logged and shown for review. The only changes the program makes are explicit
//! process actions (end, suspend, resume, quarantine, restore) and startup entry
//! switches that the user confirms; see [`system`], [`quarantine`] and
//! [`startup_control`].

#[cfg(not(windows))]
compile_error!("ntsentry inspects Windows images and processes; build it for a Windows target.");

pub mod autostart;
pub mod dialogs;
pub mod driver_audit;
pub mod eventlog;
pub mod explain;
pub mod export;
pub mod file_icon;
pub mod findings;
pub mod integrity_monitor;
pub mod inventory;
pub mod module_audit;
pub mod pe;
pub mod persistence_audit;
pub mod process_inventory;
pub mod quarantine;
pub mod service_control;
pub mod settings;
pub mod signature;
pub mod startup_control;
pub mod storage;
pub mod system;
pub mod winutil;
pub mod worker;
