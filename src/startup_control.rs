//! Turns startup entries off and on the way Windows does. Task Manager's Startup
//! apps page and Settings > Apps > Startup keep one value per entry under
//! `...\Explorer\StartupApproved`, in the same hive as the entry. No value means
//! enabled. The entry itself (its Run value or shortcut) is never touched, so a
//! change can always be undone, here or in Windows.
//!
//! A value is 12 bytes: a flags word whose low bit means "disabled", then the
//! FILETIME of the change (zero when enabled). Only that bit is changed, so
//! whatever else Windows keeps in the flags survives a round trip.

use crate::system::{AutorunInfo, list_autoruns};
use crate::winutil::wide;
use std::ptr::{null, null_mut};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_BINARY, REG_OPTION_NON_VOLATILE,
    RRF_RT_REG_BINARY, RRF_SUBKEY_WOW6464KEY, RegCloseKey, RegCreateKeyExW, RegGetValueW, RegSetValueExW,
};

const APPROVED_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
/// 64-bit Run keys, and every HKCU Run key.
pub const RUN: &str = "Run";
/// HKLM's 32-bit Run key.
pub const RUN32: &str = "Run32";
pub const STARTUP_FOLDER: &str = "StartupFolder";

const DISABLED_BIT: u32 = 1;
/// The flags Windows writes for an enabled entry that has no value yet.
const DEFAULT_FLAGS: u32 = 2;
const VALUE_LEN: usize = 12;
/// 100 ns intervals from 1601 (FILETIME) to 1970 (Unix).
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hive {
    CurrentUser,
    LocalMachine,
}

impl Hive {
    fn root(self) -> HKEY {
        match self {
            Hive::CurrentUser => HKEY_CURRENT_USER,
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
        }
    }
}

/// Where one entry's on/off value lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Switch {
    pub hive: Hive,
    /// Subkey of `StartupApproved`: [`RUN`], [`RUN32`] or [`STARTUP_FOLDER`].
    pub group: &'static str,
    /// The Run value's name, or the file's name in a startup folder.
    pub value: String,
}

impl Switch {
    /// The switch for a file in a startup folder. desktop.ini only holds the
    /// folder's display settings and never runs, so it has none.
    pub fn for_folder_file(hive: Hive, file_name: &str) -> Option<Self> {
        (!file_name.eq_ignore_ascii_case("desktop.ini")).then(|| Switch {
            hive,
            group: STARTUP_FOLDER,
            value: file_name.to_string(),
        })
    }

    fn key(&self) -> String {
        format!("{APPROVED_KEY}\\{}", self.group)
    }

    pub fn is_disabled(&self) -> Result<bool, String> {
        read(self.hive.root(), &self.key(), &self.value)
            .map(|data| data.is_some_and(|d| disabled_in(&d)))
            .map_err(|status| format!("registry error {status}"))
    }
}

fn disabled_in(data: &[u8]) -> bool {
    data.first().is_some_and(|flags| u32::from(*flags) & DISABLED_BIT != 0)
}

/// The value to store, keeping the other flags of the `existing` value.
fn encode(existing: Option<&[u8]>, disabled: bool, now: u64) -> [u8; VALUE_LEN] {
    let flags = existing.and_then(|d| d.first_chunk::<4>()).map_or(DEFAULT_FLAGS, |b| u32::from_le_bytes(*b));
    let flags = if disabled { flags | DISABLED_BIT } else { flags & !DISABLED_BIT };
    let mut data = [0; VALUE_LEN];
    data[..4].copy_from_slice(&flags.to_le_bytes());
    if disabled {
        data[4..].copy_from_slice(&now.to_le_bytes());
    }
    data
}

fn filetime_now() -> u64 {
    let since_1970 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    FILETIME_UNIX_EPOCH + (since_1970.as_nanos() / 100) as u64
}

/// The stored value, or None when there is none. Errors are Win32 status codes.
fn read(root: HKEY, key: &str, value: &str) -> Result<Option<Vec<u8>>, u32> {
    let (key, value) = (wide(key), wide(value));
    let mut data = [0u8; 64];
    let mut len = data.len() as u32;
    let status = unsafe {
        RegGetValueW(
            root,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_BINARY | RRF_SUBKEY_WOW6464KEY,
            null_mut(),
            data.as_mut_ptr() as _,
            &mut len,
        )
    };
    match status {
        ERROR_SUCCESS => Ok(Some(data[..len as usize].to_vec())),
        ERROR_FILE_NOT_FOUND => Ok(None),
        other => Err(other),
    }
}

fn write(root: HKEY, key: &str, value: &str, disabled: bool, now: u64) -> Result<(), u32> {
    let data = encode(read(root, key, value)?.as_deref(), disabled, now);
    let (key, value) = (wide(key), wide(value));
    let mut handle: HKEY = null_mut();
    // A profile that never disabled anything may not have this key yet.
    let status = unsafe {
        RegCreateKeyExW(
            root,
            key.as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            null(),
            &mut handle,
            null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(status);
    }
    let status = unsafe { RegSetValueExW(handle, value.as_ptr(), 0, REG_BINARY, data.as_ptr(), VALUE_LEN as u32) };
    unsafe { RegCloseKey(handle) };
    if status == ERROR_SUCCESS { Ok(()) } else { Err(status) }
}

/// Switches an entry off or on for future sign-ins, but only if it is still
/// listed exactly as the user saw it when they confirmed.
pub fn set_disabled(entry: &AutorunInfo, disabled: bool) -> Result<(), String> {
    let current = list_autoruns()?;
    let found = current
        .iter()
        .find(|a| a.location == entry.location && a.name == entry.name && a.command == entry.command)
        .ok_or("the entry changed or was removed after it was listed; nothing was changed")?;
    let switch = found.switch.as_ref().ok_or("Windows has no on/off switch for this entry")?;
    write(switch.hive.root(), &switch.key(), &switch.value, disabled, filetime_now()).map_err(|status| match status {
        ERROR_ACCESS_DENIED => "access denied; all-users entries need NtSentry running as administrator".to_string(),
        other => format!("registry error {other}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Registry::RegDeleteTreeW;

    const TIME: u64 = 0x0102_0304_0506_0708;
    const TIME_BYTES: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];

    fn value(flags: u8, time: [u8; 8]) -> [u8; VALUE_LEN] {
        let mut data = [0; VALUE_LEN];
        data[0] = flags;
        data[4..].copy_from_slice(&time);
        data
    }

    #[test]
    fn the_low_bit_means_disabled() {
        assert!(!disabled_in(&value(2, [0; 8])));
        assert!(disabled_in(&value(3, TIME_BYTES)));
        assert!(!disabled_in(&value(6, [0; 8])), "Windows also writes 06 for an enabled entry");
        assert!(disabled_in(&value(7, TIME_BYTES)));
        assert!(!disabled_in(&[]));
    }

    #[test]
    fn a_new_value_has_the_bytes_windows_writes() {
        assert_eq!(encode(None, true, TIME), value(3, TIME_BYTES));
        assert_eq!(encode(None, false, TIME), value(2, [0; 8]), "enabled values carry no time");
    }

    #[test]
    fn other_flags_survive_a_round_trip() {
        let original = value(6, [0; 8]);
        let off = encode(Some(&original), true, TIME);
        assert_eq!(off, value(7, TIME_BYTES));
        assert_eq!(encode(Some(&off), false, TIME), original);
    }

    #[test]
    fn a_short_value_is_replaced_with_defaults() {
        assert_eq!(encode(Some(&[3, 0]), false, TIME), value(2, [0; 8]));
    }

    #[test]
    fn filetime_is_counted_from_1601() {
        // 2020-01-01 00:00:00 UTC, in 100 ns units from 1601.
        assert!(filetime_now() > 132_223_104_000_000_000);
    }

    #[test]
    fn desktop_ini_has_no_switch() {
        assert_eq!(Switch::for_folder_file(Hive::CurrentUser, "Desktop.INI"), None);
        let switch = Switch::for_folder_file(Hive::LocalMachine, "Example App.lnk").unwrap();
        assert_eq!((switch.hive, switch.group, switch.value.as_str()), (Hive::LocalMachine, STARTUP_FOLDER, "Example App.lnk"));
    }

    /// A throwaway key, so tests never touch the real StartupApproved values.
    struct ScratchKey(String);

    impl Drop for ScratchKey {
        fn drop(&mut self) {
            let path = wide(&self.0);
            unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, path.as_ptr()) };
        }
    }

    #[test]
    fn values_are_written_and_read_back_in_a_scratch_key() {
        let scratch = ScratchKey(format!(r"Software\NtSentryTest-{}", std::process::id()));
        let key = format!(r"{}\{RUN}", scratch.0);
        assert_eq!(read(HKEY_CURRENT_USER, &key, "Example App"), Ok(None), "a missing key reads as no value");
        write(HKEY_CURRENT_USER, &key, "Example App", true, TIME).expect("creates the key and disables");
        assert_eq!(read(HKEY_CURRENT_USER, &key, "Example App"), Ok(Some(value(3, TIME_BYTES).to_vec())));
        write(HKEY_CURRENT_USER, &key, "Example App", false, TIME).expect("enables");
        assert_eq!(read(HKEY_CURRENT_USER, &key, "Example App"), Ok(Some(value(2, [0; 8]).to_vec())));
    }

    #[test]
    fn an_entry_that_is_no_longer_listed_is_not_written() {
        let switch = Switch { hive: Hive::CurrentUser, group: RUN, value: "NtSentry Example Entry".into() };
        let stale = AutorunInfo {
            location: r"HKCU\Example\Run".into(),
            name: switch.value.clone(),
            command: r"C:\Example\app.exe".into(),
            switch: Some(switch.clone()),
            disabled: false,
        };
        assert!(set_disabled(&stale, true).unwrap_err().contains("nothing was changed"));
        assert_eq!(read(HKEY_CURRENT_USER, &switch.key(), &switch.value), Ok(None));
    }
}
